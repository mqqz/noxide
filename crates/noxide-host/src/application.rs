use crate::{
    Database, HostKeys, auth,
    database::{Param, Transaction, retryable},
    manifest,
    render::{self, FormCredentials, RenderContext, Rendered},
    repository::{self, Effects, StoredRecord},
    runtime::{Limits, Runtime},
    security::{self, RecordTarget, Token, TokenKind},
};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_protocol::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};

#[derive(Debug)]
pub enum RequestError {
    Authentication,
    InvalidRequest,
    Rejected,
    Busy,
    OutcomeUnknown,
}
impl RequestError {
    fn database(error: anyhow::Error) -> Self {
        if retryable(&error) {
            Self::Busy
        } else {
            Self::Rejected
        }
    }
}
impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Authentication => "Sign in to continue.",
                Self::InvalidRequest => "This request is invalid or has expired.",
                Self::Rejected => "The request could not be completed.",
                Self::Busy => "The service is busy. Retry this request.",
                Self::OutcomeUnknown =>
                    "The save result is not yet confirmed. Retry the same submission to recover it.",
            }
        )
    }
}
impl std::error::Error for RequestError {}

pub struct Application {
    pub(crate) presentation: crate::Presentation,
    pub(crate) manifest: Arc<Manifest>,
    pub(crate) keys: Arc<HostKeys>,
    database: Database,
    runtime: Runtime,
    contract: String,
    deployment: String,
    generation: OnceLock<String>,
    permits: Semaphore,
    login_permits: Arc<Semaphore>,
}

pub struct LoginChallenge {
    pub cookie: String,
    pub csrf: String,
}

impl Application {
    /// Validate persisted schema compatibility before accepting any traffic.
    /// Data requests repeat this fence inside their transaction.
    pub async fn activate(&self) -> Result<()> {
        self.presentation.validate(&self.manifest)?;
        let mut tx = self
            .database
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await?;
        tx.check_storage().await?;
        tx.bind_schema(&self.manifest).await?;
        let generation = tx
            .deployment(&self.deployment, self.keys.incarnation(), true)
            .await?;
        ensure!(
            self.generation.get().is_none_or(|g| g == &generation),
            "application generation retired"
        );
        tx.commit().await?;
        ensure!(
            self.generation.get_or_init(|| generation.clone()) == &generation,
            "concurrent activation differs"
        );
        Ok(())
    }

    async fn admission(&self, tx: &mut Transaction, activate: bool) -> Result<()> {
        tx.check_storage().await?;
        tx.bind_schema(&self.manifest).await?;
        let generation = tx
            .deployment(&self.deployment, self.keys.incarnation(), activate)
            .await?;
        ensure!(
            self.generation.get() == Some(&generation),
            "application is unactivated or retired"
        );
        Ok(())
    }

    fn submission_contract(&self) -> String {
        format!(
            "{}:{}",
            self.contract,
            self.generation.get().expect("admission precedes token use")
        )
    }
    /// The approval digest comes from operator policy, separately from the
    /// application bundle. Compilation retains immutable admitted bytes.
    pub fn new(
        component: &[u8],
        declarations: &[u8],
        approved: [u8; 32],
        database: Database,
        keys: HostKeys,
        limits: Limits,
    ) -> Result<Self> {
        let m = manifest::parse(declarations)?;
        let digest = manifest::digest(&m)?;
        ensure!(
            digest == approved,
            "deployment did not approve this contract"
        );
        let concurrency = limits.concurrency;
        let mut identity = Sha256::new();
        identity.update(digest);
        identity.update(Sha256::digest(component));
        let deployment = URL_SAFE_NO_PAD.encode(identity.finalize());
        let runtime = Runtime::compile(component, limits)?;
        Ok(Self {
            presentation: crate::Presentation::default(),
            manifest: Arc::new(m),
            keys: Arc::new(keys),
            database,
            runtime,
            contract: URL_SAFE_NO_PAD.encode(digest),
            deployment,
            generation: OnceLock::new(),
            permits: Semaphore::new(concurrency),
            login_permits: Arc::new(Semaphore::new(2)),
        })
    }

    /// Configure trusted HTTP presentation before sharing or activating the application.
    pub fn with_presentation(mut self, presentation: crate::Presentation) -> Result<Self> {
        presentation.validate(&self.manifest)?;
        self.presentation = presentation;
        Ok(self)
    }

    pub async fn login_challenge(&self) -> std::result::Result<LoginChallenge, RequestError> {
        let mut tx = self
            .database
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .map_err(|_| RequestError::Busy)?;
        self.admission(&mut tx, false)
            .await
            .map_err(|_| RequestError::Rejected)?;
        let now = security::now().map_err(|_| RequestError::Rejected)?;
        security::observe_clock(&mut tx, now)
            .await
            .map_err(RequestError::database)?;
        let (token, cookie) = self
            .keys
            .issue(TokenKind::Login, "", now, 900)
            .map_err(|_| RequestError::Rejected)?;
        tx.commit().await.map_err(|_| RequestError::Busy)?;
        Ok(LoginChallenge {
            cookie,
            csrf: self.keys.csrf(&token.nonce),
        })
    }

    pub async fn login(
        &self,
        challenge: &str,
        csrf: &str,
        username: &str,
        password: &str,
    ) -> std::result::Result<String, RequestError> {
        let permit = self
            .login_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| RequestError::Busy)?;
        let deadline = Instant::now() + std::time::Duration::from_secs(3);
        timeout_at(deadline, async {
            let mut tx = self
                .database
                .begin(deadline.into_std())
                .await
                .map_err(|_| RequestError::Busy)?;
            self.admission(&mut tx, false)
                .await
                .map_err(|_| RequestError::Rejected)?;
            let now = security::now().map_err(|_| RequestError::Rejected)?;
            let token = self
                .keys
                .verify(challenge, now)
                .map_err(|_| RequestError::InvalidRequest)?;
            if token.kind != TokenKind::Login {
                return Err(RequestError::InvalidRequest);
            }
            self.keys
                .verify_csrf(&token.nonce, csrf)
                .map_err(|_| RequestError::InvalidRequest)?;
            security::observe_clock(&mut tx, now)
                .await
                .map_err(RequestError::database)?;
            let signed = auth::login(&mut tx, &self.keys, username, password, now, permit)
                .await
                .map_err(|_| RequestError::Authentication)?;
            tx.commit().await.map_err(|_| RequestError::Busy)?;
            Ok(signed)
        })
        .await
        .map_err(|_| RequestError::Busy)?
    }

    pub async fn logout(&self, cookie: &str, csrf: &str) -> std::result::Result<(), RequestError> {
        let mut tx = self
            .database
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .map_err(|_| RequestError::Busy)?;
        self.admission(&mut tx, false)
            .await
            .map_err(|_| RequestError::Rejected)?;
        let now = security::now().map_err(|_| RequestError::Rejected)?;
        let (session, _) = auth::authenticate(&mut tx, &self.keys, cookie, now)
            .await
            .map_err(|_| RequestError::Authentication)?;
        security::observe_clock(&mut tx, now)
            .await
            .map_err(RequestError::database)?;
        self.keys
            .verify_csrf(&session.nonce, csrf)
            .map_err(|_| RequestError::InvalidRequest)?;
        tx.execute(
            "DELETE FROM nx_sessions WHERE id=$1",
            &[session.nonce.into()],
        )
        .await
        .map_err(|_| RequestError::Rejected)?;
        tx.commit().await.map_err(|_| RequestError::Busy)
    }

    fn credentials(
        &self,
        action: &Action,
        session: &Token,
        now: i64,
        target: Option<RecordTarget>,
        values: Fields,
    ) -> Result<FormCredentials> {
        let (_, submission) = self.keys.issue(
            TokenKind::Submission {
                contract: self.submission_contract(),
                action: action.id,
                version: action.version,
                target,
            },
            &session.nonce,
            now,
            900,
        )?;
        Ok(FormCredentials {
            csrf: self.keys.csrf(&session.nonce),
            submission,
            values,
        })
    }

    fn submission_target(&self, token: &Token, action: &Action) -> Result<Option<RecordTarget>> {
        let TokenKind::Submission {
            contract,
            action: id,
            version,
            target,
        } = &token.kind
        else {
            anyhow::bail!(RequestError::InvalidRequest)
        };
        ensure!(
            contract == &self.submission_contract()
                && *id == action.id
                && *version == action.version,
            RequestError::InvalidRequest
        );
        let op = manifest::operation(&self.manifest, action.operation)?;
        match (&op.kind, target) {
            (OperationKind::Create, None) => {}
            (OperationKind::Update | OperationKind::Delete, Some(target)) => {
                let route = manifest::route(&self.manifest, target.route)?;
                ensure!(
                    target.resource == op.resource
                        && target.id > 0
                        && target.id <= i64::MAX as u64
                        && target.revision > 0
                        && !target.incarnation.is_empty()
                        && target.incarnation.len() <= 64
                        && route.resource == Some(op.resource)
                        && route.forms.contains(&action.id),
                    RequestError::InvalidRequest
                );
            }
            _ => anyhow::bail!(RequestError::InvalidRequest),
        }
        Ok(target.clone())
    }

    fn target_allowed(
        &self,
        action: &Action,
        route: u32,
        principal: &auth::Principal,
        stored: &StoredRecord,
    ) -> Result<bool> {
        let op = manifest::operation(&self.manifest, action.operation)?;
        let permitted = |op: &Operation| {
            repository::allowed(&op.policy, principal, &stored.owner, &stored.tenant)
        };
        let route = manifest::route(&self.manifest, route)?;
        let readable = route
            .operations
            .iter()
            .any(|id| manifest::operation(&self.manifest, *id).is_ok_and(permitted));
        let inspection = action
            .inspect
            .as_ref()
            .map(|i| manifest::operation(&self.manifest, i.operation).map(permitted))
            .transpose()?
            .unwrap_or(true);
        Ok(route.resource == Some(op.resource)
            && stored.record.resource == op.resource
            && readable
            && inspection
            && permitted(op))
    }

    async fn current_target(
        &self,
        tx: &mut Transaction,
        action: &Action,
        target: &RecordTarget,
        principal: &auth::Principal,
    ) -> Result<Option<StoredRecord>> {
        let stored = repository::load(tx, &self.manifest, target.resource, target.id).await?;
        match stored {
            Some(stored)
                if stored.incarnation == target.incarnation
                    && self.target_allowed(action, target.route, principal, &stored)? =>
            {
                Ok(Some(stored))
            }
            _ => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn forms(
        &self,
        tx: &mut Transaction,
        route: u32,
        target: Option<u64>,
        session: &Token,
        principal: &auth::Principal,
        now: i64,
    ) -> Result<BTreeMap<u32, Option<FormCredentials>>> {
        let r = manifest::route(&self.manifest, route)?;
        let stored = match (r.resource, target) {
            (Some(resource), Some(id)) => {
                repository::load(tx, &self.manifest, resource, id).await?
            }
            _ => None,
        };
        let mut forms = BTreeMap::new();
        for id in &r.forms {
            let action = manifest::action(&self.manifest, *id)?;
            let op = manifest::operation(&self.manifest, action.operation)?;
            let credentials = if op.kind == OperationKind::Create {
                if repository::allowed(&op.policy, principal, &principal.id, &principal.tenant) {
                    Some(self.credentials(action, session, now, None, Fields::new())?)
                } else {
                    None
                }
            } else if let Some(record) = &stored {
                if self.target_allowed(action, route, principal, record)? {
                    let grant = RecordTarget {
                        resource: op.resource,
                        id: record.record.id,
                        incarnation: record.incarnation.clone(),
                        revision: record.revision,
                        route,
                    };
                    let values = action
                        .fields
                        .iter()
                        .map(|name| (name.clone(), record.record.fields[name].clone()))
                        .collect();
                    Some(self.credentials(action, session, now, Some(grant), values)?)
                } else {
                    None
                }
            } else {
                None
            };
            forms.insert(*id, credentials);
        }
        Ok(forms)
    }

    fn conflict(
        &self,
        action: &Action,
        session: &Token,
        now: i64,
        mut target: RecordTarget,
        stored: &StoredRecord,
        input: &Fields,
    ) -> Result<Rendered> {
        target.revision = stored.revision;
        let credentials = self.credentials(action, session, now, Some(target), Fields::new())?;
        let current = if manifest::operation(&self.manifest, action.operation)?.kind
            == OperationKind::Delete
        {
            stored.record.fields.clone()
        } else {
            action
                .fields
                .iter()
                .map(|name| (name.clone(), stored.record.fields[name].clone()))
                .collect()
        };
        render::recovery(
            &self.presentation,
            &self.manifest,
            action.id,
            &credentials,
            input,
            render::Recovery::Conflict { current: &current },
        )
    }

    fn receipt(
        &self,
        action: &Action,
        target: Option<&RecordTarget>,
        outcome: &str,
    ) -> Result<Rendered> {
        let intent: ResponseIntent = serde_json::from_str(outcome)?;
        let op = manifest::operation(&self.manifest, action.operation)?;
        let (kind, resource, id, destination) = match &intent {
            ResponseIntent::Created {
                resource,
                id,
                destination,
            } => (OperationKind::Create, *resource, *id, destination),
            ResponseIntent::Updated {
                resource,
                id,
                destination,
            } => (OperationKind::Update, *resource, *id, destination),
            ResponseIntent::Deleted {
                resource,
                id,
                destination,
            } => (OperationKind::Delete, *resource, *id, destination),
            _ => anyhow::bail!("invalid receipt"),
        };
        ensure!(
            kind == op.kind
                && resource == op.resource
                && id > 0
                && id <= i64::MAX as u64
                && destination.route == action.redirect,
            "receipt outcome differs"
        );
        ensure!(
            destination.target
                == if kind == OperationKind::Delete {
                    None
                } else {
                    Some(id)
                },
            "receipt destination differs"
        );
        if let Some(target) = target {
            ensure!(id == target.id, "receipt target differs");
        }
        render::render(
            &intent,
            &RenderContext {
                presentation: &self.presentation,
                manifest: Some(&self.manifest),
                ..RenderContext::empty()
            },
        )
    }

    pub async fn view(
        &self,
        cookie: &str,
        route: u32,
        target: Option<u64>,
    ) -> std::result::Result<Rendered, RequestError> {
        self.view_page(cookie, route, target, None).await
    }

    pub async fn view_page(
        &self,
        cookie: &str,
        route: u32,
        target: Option<u64>,
        cursor: Option<u64>,
    ) -> std::result::Result<Rendered, RequestError> {
        let _permit = self.permits.try_acquire().map_err(|_| RequestError::Busy)?;
        if cursor.is_some_and(|c| c == 0 || c > i64::MAX as u64 || target.is_some()) {
            return Err(RequestError::InvalidRequest);
        }
        let reference = RouteRef { route, target };
        render::resolve(&self.manifest, &reference).map_err(|_| RequestError::InvalidRequest)?;
        let deadline = Instant::now() + self.runtime.limits().wall_time;
        timeout_at(deadline, async {
            let mut tx = self
                .database
                .begin(deadline.into_std())
                .await
                .map_err(|_| RequestError::Busy)?;
            self.admission(&mut tx, false)
                .await
                .map_err(|_| RequestError::Rejected)?;
            let now = security::now().map_err(|_| RequestError::Rejected)?;
            security::observe_clock(&mut tx, now)
                .await
                .map_err(RequestError::database)?;
            let (session, principal) = auth::authenticate(&mut tx, &self.keys, cookie, now)
                .await
                .map_err(|_| RequestError::Authentication)?;
            let forms = self
                .forms(&mut tx, route, target, &session, &principal, now)
                .await
                .map_err(|_| RequestError::Rejected)?;
            let request = RequestView {
                available_forms: forms
                    .iter()
                    .filter_map(|(id, form)| form.as_ref().map(|_| *id))
                    .collect(),
                version: VERSION,
                kind: RequestKind::Route(route),
                target,
                input: Fields::new(),
                inspection: None,
            };
            let effects = Effects {
                tx,
                manifest: self.manifest.clone(),
                principal,
                request: request.clone(),
                outcome: None,
                grant: None,
                record: None,
                calls: 16,
                cursor,
                more: None,
            };
            let attempt = self
                .runtime
                .run(
                    request,
                    Some(effects),
                    self.runtime.limits().fuel,
                    self.runtime.limits().host_calls,
                    deadline,
                )
                .await;
            let mut effects = attempt.effects.ok_or(RequestError::Rejected)?;
            let response = attempt.result.map_err(|_| RequestError::Rejected)?;
            if !matches!(
                response,
                ResponseIntent::Page(_) | ResponseIntent::NotFound(_) | ResponseIntent::Redirect(_)
            ) {
                return Err(RequestError::Rejected);
            }
            let next_page = effects.more.map(|id| {
                format!(
                    "{}?before={id}",
                    manifest::route(&self.manifest, route)
                        .expect("validated route")
                        .path
                )
            });
            let rendered = render::render(
                &response,
                &RenderContext {
                    presentation: &self.presentation,
                    manifest: Some(&self.manifest),
                    forms,
                    logout_csrf: Some(self.keys.csrf(&session.nonce)),
                    next_page,
                },
            )
            .map_err(|_| RequestError::Rejected)?;
            effects.tx.commit().await.map_err(|_| RequestError::Busy)?;
            Ok(rendered)
        })
        .await
        .map_err(|_| RequestError::Busy)?
    }

    pub async fn submit(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        input: Fields,
    ) -> std::result::Result<Rendered, RequestError> {
        let _permit = self.permits.try_acquire().map_err(|_| RequestError::Busy)?;
        let a =
            manifest::action(&self.manifest, action).map_err(|_| RequestError::InvalidRequest)?;
        let input = manifest::canonical_input(&self.manifest, a, &input)
            .map_err(|_| RequestError::InvalidRequest)?;
        manifest::validate_input(&self.manifest, a, &input)
            .map_err(|_| RequestError::InvalidRequest)?;
        let input_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(
            serde_json::to_vec(&(VERSION, a.version, &input))
                .map_err(|_| RequestError::InvalidRequest)?,
        ));
        let deadline = Instant::now() + self.runtime.limits().wall_time;
        let mut fuel = self.runtime.limits().fuel;
        let mut calls = self.runtime.limits().host_calls;
        let mut db_calls = 16;
        for _ in 0..3 {
            let prepared = timeout_at(
                deadline,
                self.prepare(
                    cookie,
                    action,
                    submission,
                    csrf,
                    &input,
                    &input_hash,
                    &mut fuel,
                    &mut calls,
                    &mut db_calls,
                    deadline,
                ),
            )
            .await;
            let (mut tx, response) = match prepared {
                Err(_) => return Err(RequestError::Rejected),
                Ok(Err(error)) if retryable(&error) && Instant::now() < deadline => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Ok(Err(error)) => {
                    return Err(error
                        .downcast::<RequestError>()
                        .unwrap_or(RequestError::Rejected));
                }
                Ok(Ok(prepared)) => prepared,
            };
            let Some(mut tx) = tx.take() else {
                return Ok(response);
            };
            match timeout_at(deadline, tx.commit()).await {
                Ok(Ok(())) => return Ok(response),
                Ok(Err(error)) if retryable(&error) => {
                    // SQLite busy can leave COMMIT's transaction active. A new
                    // attempt is legal only after this rollback succeeds.
                    if tx.rollback().await.is_err() {
                        return Err(RequestError::OutcomeUnknown);
                    }
                }
                _ => return Err(RequestError::OutcomeUnknown),
            }
        }
        Err(RequestError::Busy)
    }

    pub(crate) async fn recover_form(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        input: &Fields,
        unknown: bool,
    ) -> Result<Rendered> {
        let _permit = self.permits.try_acquire()?;
        let deadline = Instant::now() + self.runtime.limits().wall_time;
        timeout_at(deadline, async {
            let a = manifest::action(&self.manifest, action)?;
            let mut tx = self.database.begin(deadline.into_std()).await?;
            self.admission(&mut tx, false).await?;
            let now = security::now()?;
            let token = self.keys.verify(submission, now)?;
            let target = self.submission_target(&token, a)?;
            security::observe_clock(&mut tx, now).await?;
            let (session, principal) = auth::authenticate(&mut tx, &self.keys, cookie, now).await?;
            ensure!(session.nonce == token.subject, "submission subject");
            self.keys.verify_csrf(&session.nonce, csrf)?;
            let sql = format!("SELECT subject,contract,input,{} FROM nx_receipts WHERE nonce=$1", tx.bounded_text("outcome", 1024));
            let rows = tx.fetch::<4>(&sql, &[token.nonce.into()]).await?;
            if let Some([subject, contract, digest, outcome]) = rows.first() {
                ensure!(*subject == session.nonce && *contract == self.contract, "receipt scope differs");
                let canonical = manifest::canonical_input(&self.manifest, a, input).ok();
                let expected = canonical.as_ref().map(|input| serde_json::to_vec(&(VERSION, a.version, input))).transpose()?.map(|bytes| URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)));

                let response = if expected.as_ref() == Some(digest) { self.receipt(a, target.as_ref(), outcome)? } else {
                    let mut response = render::render(&ResponseIntent::Page(Document::new("Form already used", vec![
                        Instruction::Text("This form already committed different input. Return home to start a new form.".into()),
                        Instruction::Link { destination: RouteRef { route: self.manifest.routes.iter().find(|r| r.path == "/").expect("index route").id, target: None }, text: "Return home".into() },
                    ])), &RenderContext { presentation: &self.presentation, manifest: Some(&self.manifest), ..RenderContext::empty() })?;
                    response.status = 409; response
                };
                tx.commit().await?;
                return Ok(response);
            }
            if let Some(target) = target {
                let Some(stored) = self.current_target(&mut tx, a, &target, &principal).await? else { return render::unavailable(&self.presentation, &self.manifest); };
                if stored.revision != target.revision && !unknown {
                    return self.conflict(a, &session, now, target, &stored, input);
                }
            } else {
                let op = manifest::operation(&self.manifest, a.operation)?;
                ensure!(repository::allowed(&op.policy, &principal, &principal.id, &principal.tenant), "policy denied");
            }
            let credentials = FormCredentials { csrf: csrf.into(), submission: submission.into(), values: Fields::new() };
            let rendered = render::recovery(&self.presentation, &self.manifest, action, &credentials, input, render::Recovery::Retry { unknown })?;
            tx.commit().await?;
            Ok(rendered)
        }).await?
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        input: &Fields,
        input_hash: &str,
        fuel: &mut u64,
        calls: &mut u32,
        db_calls: &mut u32,
        deadline: Instant,
    ) -> Result<(Option<Transaction>, Rendered)> {
        let a = manifest::action(&self.manifest, action)?;
        let mut tx = self.database.begin(deadline.into_std()).await?;
        self.admission(&mut tx, false).await?;
        let now = security::now()?;
        let token = self
            .keys
            .verify(submission, now)
            .map_err(|_| RequestError::InvalidRequest)?;
        let target = self.submission_target(&token, a)?;
        security::observe_clock(&mut tx, now).await?;
        let (session, principal) = auth::authenticate(&mut tx, &self.keys, cookie, now)
            .await
            .map_err(|_| RequestError::Authentication)?;
        ensure!(token.subject == session.nonce, RequestError::InvalidRequest);
        self.keys
            .verify_csrf(&session.nonce, csrf)
            .map_err(|_| RequestError::InvalidRequest)?;
        let claimed = tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES($1,$2,$3,$4,$5,'',$6) ON CONFLICT(nonce) DO NOTHING", &[
            token.nonce.as_str().into(), session.nonce.as_str().into(), self.contract.as_str().into(), Param::Number(action.into()), input_hash.into(), Param::Number(token.expires),
        ]).await?;
        if claimed == 0 {
            let sql = format!(
                "SELECT subject,contract,input,{} FROM nx_receipts WHERE nonce=$1",
                tx.bounded_text("outcome", 1024)
            );
            let rows = tx.fetch::<4>(&sql, &[token.nonce.into()]).await?;
            let [subject, contract, digest, outcome] = rows
                .first()
                .ok_or_else(|| anyhow::anyhow!("receipt unavailable"))?;
            ensure!(
                *subject == session.nonce && *contract == self.contract && digest == input_hash,
                RequestError::InvalidRequest
            );
            let response = self.receipt(a, target.as_ref(), outcome)?;
            return Ok((Some(tx), response));
        }
        let record = if let Some(target) = &target {
            let Some(stored) = self.current_target(&mut tx, a, target, &principal).await? else {
                let response = render::unavailable(&self.presentation, &self.manifest)?;
                tx.rollback().await?;
                return Ok((None, response));
            };
            if stored.revision != target.revision {
                let response = self.conflict(a, &session, now, target.clone(), &stored, input)?;
                tx.rollback().await?;
                return Ok((None, response));
            }
            Some(stored)
        } else {
            let op = manifest::operation(&self.manifest, a.operation)?;
            ensure!(
                repository::allowed(&op.policy, &principal, &principal.id, &principal.tenant),
                "policy denied"
            );
            None
        };
        let inspection = a.inspect.as_ref().map(|inspect| {
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
            available_forms: Vec::new(),
            version: VERSION,
            kind: RequestKind::Action(action),
            target: target.as_ref().map(|t| t.id),
            input: input.clone(),
            inspection,
        };
        let effects = Effects {
            tx,
            manifest: self.manifest.clone(),
            principal,
            request: request.clone(),
            outcome: None,
            grant: target,
            record,
            calls: *db_calls,
            cursor: None,
            more: None,
        };
        let attempt = self
            .runtime
            .run(request, Some(effects), *fuel, *calls, deadline)
            .await;
        *fuel = attempt.fuel_left;
        *calls = attempt.calls_left;
        let mut effects = attempt
            .effects
            .ok_or_else(|| anyhow::anyhow!("missing request state"))?;
        *db_calls = effects.calls;
        let outcome = match attempt.result {
            Ok(value) => value,
            Err(error) => {
                effects.tx.rollback().await?;
                return Err(error);
            }
        };
        if let ResponseIntent::Rejected {
            field_errors,
            message,
        } = &outcome
        {
            let response = render::recovery(
                &self.presentation,
                &self.manifest,
                action,
                &FormCredentials {
                    csrf: csrf.into(),
                    submission: submission.into(),
                    values: Fields::new(),
                },
                input,
                render::Recovery::Rejected {
                    errors: field_errors,
                    message,
                },
            )?;
            effects.tx.rollback().await?;
            return Ok((None, response));
        }
        ensure!(
            effects.outcome.as_ref() == Some(&outcome),
            "action outcome differs from granted mutation"
        );
        let response = render::render(
            &outcome,
            &RenderContext {
                presentation: &self.presentation,
                manifest: Some(&self.manifest),
                ..RenderContext::empty()
            },
        )?;
        effects
            .tx
            .execute(
                "UPDATE nx_receipts SET outcome=$1 WHERE nonce=$2",
                &[serde_json::to_string(&outcome)?.into(), token.nonce.into()],
            )
            .await?;
        ensure!(Instant::now() < deadline, "request deadline");
        Ok((Some(effects.tx), response))
    }
}
