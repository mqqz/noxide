//! Core action execution and transactional replay semantics.
use super::{Application, EditReceipt, RequestError, navigation, submission::ExecutionBudget};
use crate::{
    auth,
    database::{Param, Transaction},
    manifest,
    repository::{self, Effects, StoredRecord},
    security::{self, RecordTarget, Token},
};
use anyhow::{Result, ensure};
use noxide_protocol::{
    Action, Fields, Input, Inspection, Manifest, OperationKind, RedirectSource, RequestKind,
    RequestView, ResponseIntent, Revision, Step, VERSION,
};
use tokio::time::Instant;

/// Execution view of an approved action.
#[derive(Clone, Copy)]
pub(crate) struct ActionCore<'a> {
    pub id: u32,
    pub version: u32,
    pub inputs: &'a [Input],
    pub revision: &'a Revision,
    pub steps: &'a [Step],
    pub inspect: Option<&'a Inspection>,
    pub source: &'a RedirectSource,
    pub destination_resource: Option<u32>,
    /// Opaque identity retained to preserve the serialized receipt contract.
    pub destination_route: u32,
}
impl<'a> ActionCore<'a> {
    pub fn of(manifest: &Manifest, action: &'a Action) -> Result<Self> {
        let destination = manifest::route(manifest, action.redirect.route())?;
        Ok(Self {
            id: action.id,
            version: action.version,
            inputs: &action.inputs,
            revision: &action.revision,
            steps: &action.steps,
            inspect: action.inspect.as_ref(),
            source: &action.redirect.source,
            destination_resource: destination.resource,
            destination_route: destination.id,
        })
    }

    pub fn first_operation(self) -> u32 {
        self.steps[0].operation
    }
}

/// Credentials resolved under the action's write transaction.
pub(super) struct Submitter<'a> {
    pub cookie: &'a str,
    pub submission: &'a str,
    pub csrf: &'a str,
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
    pub target: Option<RecordTarget>,
    pub principal: auth::Principal,
}
pub(super) enum Settled {
    Unavailable,
    Conflict {
        target: RecordTarget,
        stored: StoredRecord,
        session: Box<Token>,
        now: i64,
    },
    Rejected {
        field_errors: Fields,
        message: String,
    },
    GuardRejected {
        input: String,
        message: String,
    },
}

impl Application {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn attempt_action(
        &self,
        submitter: Submitter<'_>,
        a: ActionCore<'_>,
        input: &Fields,
        input_hash: &str,
        capability: Option<&str>,
        budget: &mut ExecutionBudget,
    ) -> Result<Attempt> {
        let deadline = budget.deadline;
        let mut tx = self.database.begin(deadline.into_std()).await?;
        self.admission(&mut tx, false).await?;
        let now = security::now()?;
        let now = self.observe_clock_write(&mut tx, now).await?;
        let (token, session, principal) = self
            .submission_identity(
                &mut tx,
                a,
                submitter.cookie,
                submitter.submission,
                submitter.csrf,
                now,
            )
            .await?;
        let target = self.submission_target(&token, a)?;
        let claimed = tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES($1,$2,$3,$4,$5,'',$6) ON CONFLICT(nonce) DO NOTHING", &[
            token.nonce.as_str().into(), session.nonce.as_str().into(), self.contract.as_str().into(), Param::Number(a.id.into()), input_hash.into(), Param::Number(token.expires),
        ]).await?;
        if claimed == 0 {
            let [digest, outcome] = self
                .load_receipt(&mut tx, &token.nonce, &session.nonce)
                .await?
                .ok_or_else(|| anyhow::anyhow!("receipt unavailable"))?;
            ensure!(digest == input_hash, RequestError::InvalidRequest);
            return Ok(Attempt::Replay {
                tx,
                receipt: Committed {
                    payload: outcome,
                    target,
                    principal,
                },
            });
        }
        let record = if let Some(target) = &target {
            let Some(stored) = self
                .authorized_target(&mut tx, a, target, &principal, capability)
                .await?
            else {
                tx.rollback().await?;
                return Ok(Attempt::Settled(Settled::Unavailable));
            };
            if *a.revision == Revision::Exact && stored.revision != target.revision {
                tx.rollback().await?;
                return Ok(Attempt::Settled(Settled::Conflict {
                    target: target.clone(),
                    stored,
                    session: Box::new(session),
                    now,
                }));
            }
            Some(stored)
        } else {
            if self.authorize_create(a, &principal).is_err() {
                tx.rollback().await?;
                return Ok(Attempt::Settled(Settled::Unavailable));
            }
            None
        };
        let gated_destination = a
            .destination_resource
            .map(|id| manifest::resource(&self.manifest, id))
            .transpose()?
            .is_some_and(|resource| resource.gate.is_some());
        budget.parent_redirect_attempt(gated_destination)?;
        let signed_target = target.clone();
        let original = record.clone();
        let response_principal = principal.clone();
        let inspection = a.inspect.map(|inspect| {
            let stored = record
                .as_ref()
                .expect("validated inspection requires a target");
            inspect
                .fields
                .iter()
                .map(|name| (name.clone(), stored.record.fields[name].clone()))
                .collect()
        });
        let request = RequestView {
            params: Default::default(),
            available_forms: Vec::new(),
            version: VERSION,
            kind: RequestKind::Action(a.id),
            target: target.as_ref().map(|t| t.id),
            input: input.clone(),
            inspection,
        };
        let effects = Effects {
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
            capability_grant: if manifest::is_capability(manifest::operation(
                &self.manifest,
                a.first_operation(),
            )?) {
                target.clone()
            } else {
                None
            },
            grant: target,
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
        let outcomes = match effects.execute_transaction(a).await {
            Ok(outcomes) => outcomes,
            Err(error) => {
                budget.database_calls = effects.calls;
                effects.tx.rollback().await?;
                if error.is::<repository::ReferenceUnavailable>() {
                    return Ok(Attempt::Settled(Settled::Unavailable));
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
        let destination = self
            .capture_destination(
                &mut effects.tx,
                a,
                signed_target.as_ref(),
                original.as_ref(),
                &outcomes,
            )
            .await?;
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
            version: 1,
            outcomes,
            source: a.source.clone(),
            destination,
            handover,
        })?;
        Ok(Attempt::Commit {
            tx: effects.tx,
            receipt: Committed {
                payload: receipt,
                target: None,
                principal: response_principal,
            },
            nonce: token.nonce,
        })
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
                manifest::is_public(op)
                    || principal.user().is_ok_and(|user| repository::allowed(
                        &op.policy,
                        principal,
                        crate::policy::Row {
                            owner: &user.id,
                            tenant: &user.tenant,
                            fields: &Default::default()
                        }
                    )),
                repository::ReferenceUnavailable
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_view_preserves_execution_fields_and_validates_destination() {
        let manifest = crate::test_support::manifest();
        let mut action = manifest.actions[0].clone();
        action.id = 17;
        action.version = 23;
        action.revision = Revision::Identity;
        action.inspect = Some(Inspection {
            operation: 2,
            fields: vec!["body".into()],
        });
        action.redirect.source = RedirectSource::Reference {
            step: 0,
            field: "parent".into(),
        };
        let core = ActionCore::of(&manifest, &action).unwrap();
        assert_eq!(core.id, action.id);
        assert_eq!(core.version, action.version);
        assert_eq!(core.inputs, action.inputs);
        assert_eq!(core.revision, &action.revision);
        assert_eq!(core.steps, action.steps);
        assert_eq!(core.inspect, action.inspect.as_ref());
        assert_eq!(core.source, &action.redirect.source);
        assert_eq!(core.destination_resource, Some(1));
        assert_eq!(core.destination_route, action.redirect.route());
        assert_eq!(core.first_operation(), action.steps[0].operation);

        action.inspect = None;
        action.redirect.route = 1;
        let core = ActionCore::of(&manifest, &action).unwrap();
        assert!(core.inspect.is_none());
        assert!(core.destination_resource.is_none());
        assert_eq!(core.destination_route, 1);
        action.redirect.route = u32::MAX;
        assert!(ActionCore::of(&manifest, &action).is_err());
    }
}
