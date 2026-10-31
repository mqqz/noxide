//! Core action execution and transactional replay semantics.
#[cfg(test)]
mod computation_tests;
#[cfg(test)]
mod membership_tests;
mod targets;
use super::{Application, EditReceipt, RequestError, navigation};
use crate::{
    auth,
    database::{Param, Transaction},
    manifest,
    repository::{self, Effects, StoredRecord},
    security::{self, RecordTarget, Token},
};
use anyhow::{Result, ensure};
use noxide_protocol::{
    Action, ActionTarget, Fields, Input, OperationKind, RedirectSource, RequestKind, RequestView,
    ResponseIntent, Revision, Step, TargetSource, VERSION,
};
pub(super) use targets::ReviewConflict;
use tokio::time::Instant;

/// Execution view of an approved action.
#[derive(Clone, Copy)]
pub(crate) struct ActionCore<'a> {
    pub id: u32,
    pub version: u32,
    pub inputs: &'a [Input],
    pub steps: &'a [Step],
    pub targets: &'a [ActionTarget],
}
impl<'a> ActionCore<'a> {
    pub fn of(action: &'a Action) -> Result<Self> {
        Ok(Self {
            id: action.id,
            version: action.version,
            inputs: &action.inputs,
            steps: &action.steps,
            targets: &action.targets,
        })
    }

    pub fn uses_time(self) -> bool {
        self.steps.iter().any(|step| {
            step.guards.iter().any(|guard| guard.condition.uses_time())
                || step
                    .assign
                    .iter()
                    .any(|assignment| match &assignment.change {
                        noxide_protocol::Change::Set(value) => value.uses_time(),
                        noxide_protocol::Change::Increase { by, .. }
                        | noxide_protocol::Change::Decrease { by, .. } => by.uses_time(),
                    })
        })
    }

    pub fn first_operation(self) -> u32 {
        self.steps[0].operation
    }
}

/// A host-canonicalized request bound to the approved execution contract.
pub(super) struct CanonicalActionInput {
    action: u32,
    version: u32,
    contract: String,
    fields: Fields,
    selections: std::collections::BTreeMap<String, String>,
    digest: String,
}
impl CanonicalActionInput {
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn web_fields(&self) -> Fields {
        let mut fields = self.fields.clone();
        for (name, handle) in &self.selections {
            fields.insert(format!("_target_{name}"), handle.clone());
        }
        fields
    }
}

/// Sealed target proof constructed only by verified host admission.
/// Current read/edit authority is checked after committed-receipt recovery.
pub(super) struct TargetGrant {
    target: RecordTarget,
    expires: Option<i64>,
}

impl TargetGrant {
    pub(super) fn identity(&self) -> &RecordTarget {
        &self.target
    }
}

/// Transaction-scoped execution identity; guests and adapters cannot supply a principal.
pub(super) struct InvocationContext<'a> {
    action: ActionCore<'a>,
    input: Fields,
    principal: auth::Principal,
    targets: std::collections::BTreeMap<String, TargetGrant>,
    capability: Option<String>,
    observed: i64,
    identity: String,
    nonce: String,
    subject: String,
    expires: i64,
    navigation: Option<NavigationPlan<'a>>,
}

#[derive(Clone, Copy)]
pub(super) struct NavigationPlan<'a> {
    pub source: &'a RedirectSource,
    pub destination_resource: Option<u32>,
    pub destination_route: u32,
}
impl<'a> NavigationPlan<'a> {
    pub fn web(
        manifest: &noxide_protocol::Manifest,
        binding: &'a noxide_protocol::WebBinding,
    ) -> Result<Self> {
        let destination = manifest::route(manifest, binding.redirect.route)?;
        Ok(Self {
            source: &binding.redirect.source,
            destination_resource: destination.resource,
            destination_route: destination.id,
        })
    }
}

/// One action attempt; completed mutations still await response preparation and commit.
pub(super) enum Attempt {
    Commit {
        tx: Transaction,
        receipt: Committed,
        nonce: String,
    },
    Replay {
        tx: Transaction,
        receipt: Committed,
    },
    Settled(Settled),
}
pub(super) struct Committed {
    pub payload: String,
    pub targets: std::collections::BTreeMap<String, RecordTarget>,
    pub principal: auth::Principal,
}
pub(super) enum Settled {
    Unavailable,
    Conflict {
        target: RecordTarget,
        stored: StoredRecord,
    },
    TargetConflict,
    Rejected {
        field_errors: Fields,
        message: String,
    },
    GuardRejected {
        input: Option<String>,
        message: String,
    },
}

impl Application {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn attempt_action(
        &self,
        mut tx: Transaction,
        context: InvocationContext<'_>,
        budget: &mut ExecutionBudget,
    ) -> Result<Attempt> {
        let deadline = budget.deadline;
        let InvocationContext {
            action: a,
            input,
            principal,
            targets: grants,
            capability,
            observed,
            identity,
            nonce,
            subject,
            expires,
            navigation,
        } = context;
        let sealed: std::collections::BTreeMap<_, _> = grants
            .iter()
            .map(|(name, grant)| (name.clone(), grant.target.clone()))
            .collect();
        let input_hash = identity.as_str();
        let claimed = tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES($1,$2,$3,$4,$5,'',$6) ON CONFLICT(nonce) DO NOTHING", &[
            nonce.as_str().into(), subject.as_str().into(), self.contract.as_str().into(), Param::Number(a.id.into()), input_hash.into(), Param::Number(expires),
        ]).await?;
        if claimed == 0 {
            let [digest, outcome] = self
                .load_receipt(&mut tx, &nonce, &subject)
                .await?
                .ok_or_else(|| anyhow::anyhow!("receipt unavailable"))?;
            ensure!(digest == input_hash, RequestError::InvalidRequest);
            return Ok(Attempt::Replay {
                tx,
                receipt: Committed {
                    payload: outcome,
                    targets: sealed,
                    principal,
                },
            });
        }
        let time = if a.uses_time() || crate::authority::uses_time(&self.manifest) {
            budget.spend(1)?;
            Some(self.temporal_after_admission(&mut tx).await?)
        } else {
            None
        };
        let mut authority = self.authority_context(time)?;
        if self.authorize_create(a, &principal).is_err() {
            tx.rollback().await?;
            return Ok(Attempt::Settled(Settled::Unavailable));
        }
        let (records, capability_grant) = match self
            .resolve_action_targets(
                &mut tx,
                &mut authority,
                a,
                &grants,
                &principal,
                capability.as_deref(),
                observed,
                budget,
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                if error.is::<targets::ReviewConflict>()
                    && a.targets.len() == 1
                    && matches!(a.targets[0].source, TargetSource::Page { .. })
                {
                    let target = grants[&a.targets[0].name].target.clone();
                    budget.spend(2)?;
                    let stored =
                        repository::load(&mut tx, &self.manifest, target.resource, target.id)
                            .await?
                            .ok_or(repository::ReferenceUnavailable)?;
                    tx.rollback().await?;
                    return Ok(Attempt::Settled(Settled::Conflict { target, stored }));
                }
                tx.rollback().await?;
                if error.is::<targets::ReviewConflict>() {
                    return Ok(Attempt::Settled(Settled::TargetConflict));
                }
                if error.is::<repository::ReferenceUnavailable>() {
                    return Ok(Attempt::Settled(Settled::Unavailable));
                }
                return Err(error);
            }
        };
        let gated_destination = navigation
            .and_then(|plan| plan.destination_resource)
            .map(|id| manifest::resource(&self.manifest, id))
            .transpose()?
            .is_some_and(|resource| resource.gate.is_some());
        if navigation.is_some() {
            budget.parent_redirect_attempt(gated_destination)?;
        }
        let original = records.clone();
        let response_principal = principal.clone();
        let inspection = a
            .targets
            .iter()
            .filter_map(|target| target.inspect.as_ref().map(|inspect| (target, inspect)))
            .map(|(target, inspect)| {
                let proof = &sealed[&target.name];
                let stored = &records[&(proof.resource, proof.id)];
                (
                    target.name.clone(),
                    inspect
                        .fields
                        .iter()
                        .map(|field| (field.clone(), stored.record.fields[field].clone()))
                        .collect(),
                )
            })
            .collect();
        let request = RequestView {
            params: Default::default(),
            available_forms: Vec::new(),
            version: VERSION,
            kind: RequestKind::Action(a.id),
            target: a
                .targets
                .iter()
                .find(|target| matches!(target.source, TargetSource::Page { .. }))
                .and_then(|target| sealed.get(&target.name))
                .map(|target| target.id),
            input: input.clone(),
            inspection,
        };
        let effects = Effects {
            authority,
            provenance: Default::default(),
            follow_sources: Vec::new(),
            invoked: Default::default(),
            list_bytes: 0,
            list_calls: crate::repository::MAX_LIST_DATABASE_CALLS,
            result_limit: noxide_protocol::MAX_RESULT_BYTES,
            truncated: false,
            see_all: Vec::new(),
            plans: self.plans.clone(),
            tx,
            manifest: self.manifest.clone(),
            principal,
            request: request.clone(),
            capability_grant,
            grants: sealed.clone(),
            target_rows: records,
            calls: budget.database_calls,
            cursor: None,
            more: None,
        };
        budget.wasm = Some(
            self.admission_limits
                .wasm()
                .acquire()
                .await
                .map_err(|_| RequestError::Busy)?,
        );
        let attempt = self
            .runtime
            .run(
                request,
                Some(effects),
                budget.fuel,
                budget.host_calls,
                deadline,
            )
            .await;
        budget.fuel = attempt.fuel_left;
        budget.host_calls = attempt.calls_left;
        let mut effects = attempt
            .effects
            .ok_or_else(|| anyhow::anyhow!("missing request state"))?;
        budget.database_calls = effects.calls;
        let outcome = match attempt.result {
            Ok(value) => value,
            Err(error) => {
                effects.tx.rollback().await?;
                if error.is::<crate::repository::ReferenceUnavailable>() {
                    return Ok(Attempt::Settled(Settled::Unavailable));
                }
                return Err(error);
            }
        };
        if let ResponseIntent::Rejected {
            field_errors,
            message,
        } = &outcome
        {
            effects.tx.rollback().await?;
            return Ok(Attempt::Settled(Settled::Rejected {
                field_errors: field_errors.clone(),
                message: message.clone(),
            }));
        }
        ensure!(
            outcome == ResponseIntent::Execute,
            "invalid action decision"
        );
        let outcomes = match effects.execute_transaction(a, time).await {
            Ok(outcomes) => outcomes,
            Err(error) => {
                budget.database_calls = effects.calls;
                effects.tx.rollback().await?;
                if error.is::<repository::ReferenceUnavailable>() {
                    return Ok(Attempt::Settled(Settled::Unavailable));
                }
                if error.is::<repository::CalculationUnavailable>() {
                    return Err(RequestError::InvalidRequest.into());
                }
                if let Some(guard) = error.downcast_ref::<repository::GuardFailure>() {
                    return Ok(Attempt::Settled(Settled::GuardRejected {
                        input: guard.input.clone(),
                        message: guard.message.clone(),
                    }));
                }
                return Err(error);
            }
        };
        budget.database_calls = effects.calls;
        let destination = if let Some(plan) = navigation {
            self.capture_destination(&mut effects.tx, plan, &sealed, &original, &outcomes)
                .await?
        } else {
            None
        };
        let handover = outcomes
            .iter()
            .zip(a.steps)
            .find_map(|(outcome, step)| {
                let operation = manifest::operation(&self.manifest, step.operation).ok()?;
                (manifest::is_public(operation) && operation.kind == OperationKind::Create)
                    .then_some(outcome)
            })
            .map(|outcome| -> Result<EditReceipt> {
                Ok(EditReceipt {
                    resource: outcome.resource,
                    id: outcome.id,
                    incarnation: outcome.incarnation.clone(),
                    cap_version: 1,
                    key_id: self.keys.signing_edit_key()?,
                })
            })
            .transpose()?;
        let receipt = serde_json::to_string(&navigation::SemanticReceipt {
            version: 3,
            outcomes,
            source: navigation.map(|plan| plan.source.clone()),
            destination,
            handover,
        })?;
        Ok(Attempt::Commit {
            tx: effects.tx,
            receipt: Committed {
                payload: receipt,
                targets: sealed,
                principal: response_principal,
            },
            nonce,
        })
    }

    /// Browser adapter admission. Service admission deliberately has no constructor
    /// until persisted grant/job/fence checks exist (P10).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn admit_web_invocation<'a>(
        &'a self,
        tx: &mut Transaction,
        binding: u32,
        cookie: &str,
        submission: &str,
        csrf: &str,
        canonical: &CanonicalActionInput,
        capability: Option<&str>,
    ) -> Result<(InvocationContext<'a>, Token, i64)> {
        let binding = manifest::web_binding(&self.manifest, binding)?;
        let action = manifest::action(&self.manifest, binding.action)?;
        let core = ActionCore::of(action)?;
        ensure!(
            canonical.action == action.id
                && canonical.version == action.version
                && canonical.contract == self.contract,
            RequestError::InvalidRequest
        );
        let input = canonical.fields.clone();
        let selections = &canonical.selections;
        let input_hash = canonical.digest();
        let now = self.observe_clock_write(tx, security::now()?).await?;
        let (token, session, principal) = self
            .submission_identity(tx, core, cookie, submission, csrf, now)
            .await?;
        let targets =
            self.web_target_grants(&token, core, binding, selections, &session, &principal, now)?;
        let sealed: std::collections::BTreeMap<_, _> = targets
            .iter()
            .map(|(name, grant)| (name.clone(), grant.target.clone()))
            .collect();
        let identity = self
            .web_invocation_identity(binding, &token, &session, &principal, input_hash, &sealed)?;
        let context = InvocationContext {
            action: core,
            input,
            principal,
            targets,
            capability: capability.map(str::to_owned),
            observed: now,
            identity,
            nonce: token.nonce,
            subject: session.nonce.clone(),
            expires: token.expires,
            navigation: Some(NavigationPlan::web(&self.manifest, binding)?),
        };
        Ok((context, session, now))
    }

    pub(super) fn web_invocation_identity(
        &self,
        binding: &noxide_protocol::WebBinding,
        token: &Token,
        session: &Token,
        principal: &auth::Principal,
        input_hash: &str,
        targets: &std::collections::BTreeMap<String, RecordTarget>,
    ) -> Result<String> {
        use base64::Engine;
        use sha2::Digest;
        let subject = match principal {
            auth::Principal::Anonymous => ("anonymous", "", ""),
            auth::Principal::User(user) => ("user", user.id.as_str(), user.tenant.as_str()),
        };
        let action = manifest::action(&self.manifest, binding.action)?;
        // Existing receipt columns persist this digest. It binds every execution
        // identity field; changing an adapter or binding cannot reuse its claim.
        let mut targets = targets.clone();
        for (name, target) in &mut targets {
            if manifest::action_target(&action.targets, name)?.revision == Revision::Identity {
                target.revision = 0;
            }
        }
        let canonical = serde_json::to_vec(&(
            VERSION,
            "web",
            self.submission_contract(),
            subject,
            &session.nonce,
            action.id,
            action.version,
            binding.id,
            binding.version,
            input_hash,
            targets,
            &token.nonce,
        ))?;
        Ok(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(canonical)),
        )
    }

    // Called by the binding after response preparation, preserving the original
    // response -> receipt update -> deadline -> commit ordering.
    pub(super) async fn write_receipt(
        tx: &mut Transaction,
        nonce: &str,
        payload: &str,
        deadline: Instant,
    ) -> Result<()> {
        tx.execute(
            "UPDATE nx_receipts SET outcome=$1 WHERE nonce=$2",
            &[payload.into(), nonce.into()],
        )
        .await?;
        ensure!(Instant::now() < deadline, "request deadline");
        Ok(())
    }
}

impl Application {
    pub(super) fn authorize_create(
        &self,
        action: ActionCore<'_>,
        principal: &auth::Principal,
    ) -> Result<()> {
        for step in action.steps {
            let op = manifest::operation(&self.manifest, step.operation)?;
            if op.kind != OperationKind::Create {
                continue;
            }
            ensure!(
                repository::create_prerequisites(op, principal),
                repository::ReferenceUnavailable
            );
        }
        Ok(())
    }
}

fn input_digest(action: ActionCore<'_>, input: &Fields) -> Result<String> {
    use base64::Engine;
    use sha2::Digest;
    Ok(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(
            serde_json::to_vec(&(VERSION, action.version, action.inputs, input))?,
        )),
    )
}

// One budget survives every transaction retry; admission waits and bounded
// transaction cleanup are separate from this execution deadline.
pub(super) struct ExecutionBudget {
    pub(super) deadline: Instant,
    pub(super) fuel: u64,
    pub(super) host_calls: u32,
    pub(super) database_calls: u32,
    parent_navigation_reserved: bool,
    navigation_calls: u32,
    // Hold admission through binding response preparation and receipt persistence.
    pub(super) wasm: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl ExecutionBudget {
    pub(super) fn spend(&mut self, calls: u32) -> Result<()> {
        self.database_calls = self
            .database_calls
            .checked_sub(calls)
            .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
        Ok(())
    }
    pub(super) fn parent_redirect_attempt(&mut self, gated: bool) -> Result<()> {
        // Navigation runs once after the successful commit, outside all retries.
        // Its quota covers begin/commit, the target lookup and its optional gate.
        if !self.parent_navigation_reserved {
            let reserved = 4 + 2 * u32::from(gated);
            self.database_calls = self
                .database_calls
                .checked_sub(reserved)
                .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
            self.parent_navigation_reserved = true;
            self.navigation_calls = reserved;
        }
        // Each attempt actually captures the parent with storage_resource + load.
        // Charge before calling it so errors and rolled-back work stay charged.
        self.database_calls = self
            .database_calls
            .checked_sub(2)
            .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
        Ok(())
    }
    pub(super) fn take_delivery_calls(&mut self) -> Result<u32> {
        let calls = self
            .database_calls
            .checked_add(self.navigation_calls)
            .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
        self.database_calls = 0;
        self.navigation_calls = 0;
        Ok(calls)
    }
    pub(super) fn new(limits: &crate::runtime::Limits, deadline: Instant) -> Self {
        Self {
            deadline,
            fuel: limits.fuel,
            host_calls: limits.host_calls,
            database_calls: 16,
            parent_navigation_reserved: false,
            navigation_calls: 0,
            wasm: None,
        }
    }
}

/// Common host admission envelope. A grant never replaces these permits.
pub(super) struct InvocationAdmission {
    _request: std::sync::Arc<tokio::sync::OwnedSemaphorePermit>,
    _database: tokio::sync::OwnedSemaphorePermit,
    _anonymous_write: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Application {
    pub(super) async fn admit_invocation(
        &self,
        anonymous: bool,
    ) -> std::result::Result<InvocationAdmission, RequestError> {
        let request = self
            .admission_limits
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::Busy)?;
        let anonymous_write = self.anonymous_write(anonymous).await?;
        let database = self
            .admission_limits
            .database()
            .acquire()
            .await
            .map_err(|_| RequestError::Busy)?;
        Ok(InvocationAdmission {
            _request: request,
            _database: database,
            _anonymous_write: anonymous_write,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn headless_core_requires_no_route_or_redirect() {
        let mut manifest = crate::test_support::manifest();
        manifest.web_bindings.clear();
        manifest.routes.clear();
        manifest::validate(&manifest).unwrap();
        let action = &manifest.actions[0];
        let core = ActionCore::of(action).unwrap();
        assert_eq!(core.id, action.id);
        assert_eq!(core.steps, action.steps);
        assert_eq!(core.inputs, action.inputs);
        assert_eq!(core.targets, action.targets);
        // No production service constructor exists: a headless declaration alone
        // cannot enter the web adapter or create a service invocation context.
        assert!(manifest::web_action(&manifest, action.id).is_err());
        let app = Application::new(
            &crate::test_support::component(None),
            &serde_json::to_vec(&manifest).unwrap(),
            manifest::digest(&manifest).unwrap(),
            crate::Database::sqlite(":memory:"),
            crate::HostKeys::generate().unwrap(),
            crate::runtime::Limits::default(),
            crate::assets::AssetBundle::default(),
        )
        .unwrap();
        assert!(matches!(
            app.submit("unverified", action.id, "", "", Fields::new())
                .await,
            Err(RequestError::InvalidRequest)
        ));
    }
    #[tokio::test]
    async fn web_binding_seal_and_receipt_identity_reject_adapter_substitution() {
        use crate::{Database, HostKeys, runtime::Limits, test_support as fixture};
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::sqlite(tmp.path().join("binding-identity.db"));
        db.initialize().await.unwrap();
        db.create_account("alice", "binding identity test password", "tenant")
            .await
            .unwrap();
        let mut manifest = fixture::manifest();
        let mut second = manifest.web_bindings[0].clone();
        second.id = 91;
        second.version = 7;
        manifest.web_bindings.push(second);
        manifest.routes[0].forms.push(91);
        let app = std::sync::Arc::new(
            Application::new(
                &fixture::component(None),
                &serde_json::to_vec(&manifest).unwrap(),
                manifest::digest(&manifest).unwrap(),
                db.clone(),
                HostKeys::generate().unwrap(),
                Limits::default(),
                crate::assets::AssetBundle::default(),
            )
            .unwrap(),
        );
        app.activate().await.unwrap();
        let challenge = app.login_challenge().await.unwrap();
        let cookie = app
            .login(
                &challenge.cookie,
                &challenge.csrf,
                "alice",
                "binding identity test password",
            )
            .await
            .unwrap();
        let page = app.view(&cookie, 1, None).await.unwrap();
        let html = String::from_utf8(page.body).unwrap();
        let submission = fixture::hidden(&html, "_submission");
        let csrf = fixture::hidden(&html, "_csrf");
        let input = Fields::from([("body".into(), "one canonical execution".into())]);
        assert!(matches!(
            app.submit(&cookie, 91, &submission, &csrf, input.clone())
                .await,
            Err(RequestError::InvalidRequest)
        ));
        let first = app
            .submit(&cookie, 1, &submission, &csrf, input.clone())
            .await
            .unwrap();
        let replay = app
            .submit(&cookie, 1, &submission, &csrf, input.clone())
            .await
            .unwrap();
        assert_eq!(first.location, replay.location);
        assert!(matches!(
            app.submit(&cookie, 91, &submission, &csrf, input.clone())
                .await,
            Err(RequestError::InvalidRequest)
        ));
        let now = security::now().unwrap();
        let token = app.keys.verify(&submission, now).unwrap();
        let session = app.keys.verify(&cookie, now).unwrap();
        let mut tx = db
            .begin((Instant::now() + std::time::Duration::from_secs(3)).into_std())
            .await
            .unwrap();
        let (_, principal) = auth::authenticate(&mut tx, &app.keys, &cookie, now)
            .await
            .unwrap();
        let digest = input_digest(ActionCore::of(&manifest.actions[0]).unwrap(), &input).unwrap();
        let binding = &manifest.web_bindings[0];
        let identity = app
            .web_invocation_identity(
                binding,
                &token,
                &session,
                &principal,
                &digest,
                &Default::default(),
            )
            .unwrap();
        assert_eq!(
            app.load_receipt(&mut tx, &token.nonce, &session.nonce)
                .await
                .unwrap()
                .unwrap()[0],
            identity
        );
        let mut substituted = binding.clone();
        substituted.version += 1;
        assert_ne!(
            identity,
            app.web_invocation_identity(
                &substituted,
                &token,
                &session,
                &principal,
                &digest,
                &Default::default()
            )
            .unwrap()
        );
        assert_ne!(
            identity,
            app.web_invocation_identity(
                &manifest.web_bindings[1],
                &token,
                &session,
                &principal,
                &digest,
                &Default::default()
            )
            .unwrap()
        );
        assert_eq!(
            tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
                .await
                .unwrap()[0][0],
            "1"
        );
        tx.rollback().await.unwrap();
        // A different binding ID is a valid presentation of canonical action 1.
        // The guest still receives RequestKind::Action(1); recovery uses binding 91.
        let alternate = manifest::web_action(&manifest, 91).unwrap();
        let credentials = app
            .credentials(
                &alternate,
                &session,
                security::now().unwrap(),
                Default::default(),
                Fields::new(),
            )
            .unwrap();
        let saved = app
            .submit(
                &cookie,
                91,
                &credentials.submission,
                &credentials.csrf,
                input.clone(),
            )
            .await
            .unwrap();
        assert_ne!(saved.location, first.location);
        let recovered = app
            .recover_form(
                &cookie,
                91,
                &credentials.submission,
                &credentials.csrf,
                &input,
                true,
            )
            .await
            .unwrap();
        assert_eq!(saved.location, recovered.location);
        let replay = app
            .submit(
                &cookie,
                91,
                &credentials.submission,
                &credentials.csrf,
                input,
            )
            .await
            .unwrap();
        assert_eq!(saved.location, replay.location);
    }

    #[tokio::test]
    async fn target_reads_require_both_declared_and_issuing_route_authority() {
        use crate::{Database, HostKeys, runtime::Limits, test_support as fixture};
        let mut manifest = fixture::manifest();
        let mut independent = manifest.operations[1].clone();
        independent.id = 9;
        manifest.operations.push(independent);
        manifest.actions[0].targets = vec![fixture::page_target(1, vec![9], Revision::Exact)];
        manifest.routes[0].forms.clear();
        manifest.routes[1].forms = vec![1];
        let directory = tempfile::tempdir().unwrap();
        let database = Database::sqlite(directory.path().join("target-authority.db"));
        database.initialize().await.unwrap();
        let app = Application::new(
            &fixture::component(None),
            &serde_json::to_vec(&manifest).unwrap(),
            manifest::digest(&manifest).unwrap(),
            database,
            HostKeys::generate().unwrap(),
            Limits::default(),
            crate::assets::AssetBundle::default(),
        )
        .unwrap();
        let principal = auth::Principal::User(auth::User {
            id: "owner".into(),
            tenant: "tenant".into(),
            roles: vec![],
        });
        let stored = StoredRecord {
            record: noxide_protocol::Record {
                resource: 1,
                id: 1,
                fields: Fields::from([("body".into(), "private".into())]),
            },
            owner: "owner".into(),
            tenant: "tenant".into(),
            incarnation: "sealed".into(),
            revision: 1,
            cap_version: None,
        };
        assert!(
            !app.test_target_allowed(
                ActionCore::of(&manifest.actions[0]).unwrap(),
                Some(2),
                &principal,
                &stored
            )
            .await
            .unwrap()
        );
        let mut core = manifest.actions[0].clone();
        core.targets[0].source = TargetSource::Page { reads: vec![2] };
        assert!(
            app.test_target_allowed(ActionCore::of(&core).unwrap(), Some(2), &principal, &stored)
                .await
                .unwrap()
        );
        assert!(
            !app.test_target_allowed(
                ActionCore::of(&core).unwrap(),
                Some(2),
                &auth::Principal::Anonymous,
                &stored
            )
            .await
            .unwrap()
        );
    }
    #[tokio::test]
    async fn edit_grant_cannot_authorize_guest_inspection() {
        use crate::{Database, HostKeys, runtime::Limits, test_support as fixture};
        use noxide_protocol::{Access, Inspection, Policy, Predicate, Target};
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::sqlite(tmp.path().join("edit-inspection.db"));
        db.initialize().await.unwrap();
        let mut manifest = fixture::manifest();
        manifest.operations[2].policy = Policy {
            any: vec![vec![Predicate::Public]],
        };
        let mut update = manifest.operations[2].clone();
        update.id = 4;
        update.kind = OperationKind::Update;
        update.policy = Policy {
            any: vec![vec![Predicate::Capability]],
        };
        manifest.operations.push(update);
        let mut edit = fixture::action(
            2,
            "Edit",
            4,
            Target::Named("target".into()),
            &manifest.resources[0],
            &["body"],
            2,
        );
        edit.targets[0].inspect = Some(Inspection {
            operation: 2,
            fields: vec!["body".into()],
        });
        fixture::register_action(&mut manifest, edit);
        manifest.routes[0].access = Access::PublicOptional;
        manifest.routes[1].access = Access::PublicOptional;
        manifest.routes[1].forms.push(2);
        let app = std::sync::Arc::new(
            Application::new(
                &fixture::component(None),
                &serde_json::to_vec(&manifest).unwrap(),
                manifest::digest(&manifest).unwrap(),
                db.clone(),
                HostKeys::generate().unwrap(),
                Limits::default(),
                crate::assets::AssetBundle::default(),
            )
            .unwrap(),
        );
        app.activate().await.unwrap();
        let page = app.view_page(None, 1, None, None).await.unwrap();
        let cookie = page.anonymous_cookie.unwrap();
        let html = String::from_utf8(page.body).unwrap();
        let saved = app
            .submit(
                &cookie,
                1,
                &fixture::hidden(&html, "_submission"),
                &fixture::hidden(&html, "_csrf"),
                Fields::from([("body".into(), "secret inspection".into())]),
            )
            .await
            .unwrap();
        let html = String::from_utf8(saved.body).unwrap();
        let secret = html
            .split_once("<pre>")
            .unwrap()
            .1
            .split_once("</pre>")
            .unwrap()
            .0;
        let mut tx = db
            .begin((Instant::now() + std::time::Duration::from_secs(3)).into_std())
            .await
            .unwrap();
        let id: u64 = tx
            .fetch::<1>("SELECT CAST(id AS TEXT) FROM nx_records", &[])
            .await
            .unwrap()[0][0]
            .parse()
            .unwrap();
        let stored = repository::load(&mut tx, &manifest, 1, id)
            .await
            .unwrap()
            .unwrap();
        let target = RecordTarget {
            resource: 1,
            id,
            incarnation: stored.incarnation,
            revision: stored.revision,
            route: Some(2),
        };
        let grants = std::collections::BTreeMap::from([(
            "target".into(),
            TargetGrant {
                target,
                expires: None,
            },
        )]);
        let mut budget = ExecutionBudget::new(
            app.runtime.limits(),
            Instant::now() + std::time::Duration::from_secs(3),
        );
        assert!(
            app.resolve_action_targets(
                &mut tx,
                &mut Default::default(),
                ActionCore::of(&manifest.actions[1]).unwrap(),
                &grants,
                &auth::Principal::Anonymous,
                Some(secret),
                security::now().unwrap(),
                &mut budget
            )
            .await
            .is_err()
        );
        let mut mutation_only = manifest.actions[1].clone();
        mutation_only.targets[0].inspect = None;
        assert!(
            app.resolve_action_targets(
                &mut tx,
                &mut Default::default(),
                ActionCore::of(&mutation_only).unwrap(),
                &grants,
                &auth::Principal::Anonymous,
                Some(secret),
                security::now().unwrap(),
                &mut budget
            )
            .await
            .is_ok()
        );
        tx.rollback().await.unwrap();
    }
    #[test]
    fn forged_web_bindings_and_target_read_declarations_fail_admission() {
        let baseline = crate::test_support::manifest();
        for alteration in 0..5 {
            let mut forged = baseline.clone();
            match alteration {
                0 => forged.web_bindings[0].action = u32::MAX,
                1 => forged.web_bindings[0].version = 0,
                2 => forged.web_bindings.push(forged.web_bindings[0].clone()),
                3 => forged.web_bindings[0].redirect.route = u32::MAX,
                4 => {
                    forged.actions[0].targets = vec![crate::test_support::page_target(
                        1,
                        vec![3],
                        Revision::Exact,
                    )]
                } // mutation cannot supply reads
                _ => unreachable!(),
            }
            assert!(
                manifest::validate(&forged).is_err(),
                "alteration {alteration}"
            );
        }
        let mut wire = serde_json::to_value(&baseline).unwrap();
        wire["actions"][0]["redirect"] = serde_json::json!({"route":2,"source":{"step":0}});
        assert!(manifest::parse(&serde_json::to_vec(&wire).unwrap()).is_err());
        let mut wire = serde_json::to_value(&baseline).unwrap();
        wire["workers"] = serde_json::json!([{"action":1,"enabled":true}]);
        assert!(manifest::parse(&serde_json::to_vec(&wire).unwrap()).is_err());
    }

    #[test]
    fn binding_registry_order_is_canonical_but_binding_authority_changes_digest() {
        let mut manifest = crate::test_support::manifest();
        let mut second = manifest.web_bindings[0].clone();
        second.id = 91;
        manifest.web_bindings.push(second);
        let original = manifest::digest(&manifest).unwrap();
        manifest.web_bindings.reverse();
        assert_eq!(original, manifest::digest(&manifest).unwrap());
        manifest.web_bindings[0].version += 1;
        assert_ne!(original, manifest::digest(&manifest).unwrap());
    }
}
