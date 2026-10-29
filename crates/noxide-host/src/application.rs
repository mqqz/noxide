mod capabilities;
mod submission;
use crate::{
    Database, HostKeys, auth,
    database::{Param, Transaction, retryable},
    manifest,
    render::{self, FormCredentials, RenderContext, Rendered},
    repository::{self, Effects, StoredRecord},
    runtime::{
        Limits, Runtime,
        limiter::{AdmissionLimits, HashPermits},
    },
    security::{self, RecordTarget, Token, TokenKind},
};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_protocol::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicI64, Ordering},
    },
};
use tokio::time::{Instant, timeout_at};

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
    pub(crate) registration: auth::Registration,
    pub(crate) manifest: Arc<Manifest>,
    pub(crate) keys: Arc<HostKeys>,
    database: Database,
    runtime: Runtime,
    contract: String,
    deployment: String,
    generation: OnceLock<String>,
    clock: AtomicI64,
    checkpointed: AtomicI64,
    pub(crate) admission_limits: AdmissionLimits,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EditReceipt {
    resource: u32,
    id: u64,
    cap_version: u64,
    key_id: u32,
}

pub struct LoginChallenge {
    pub cookie: String,
    pub csrf: String,
}

impl Application {
    pub fn with_registration(mut self, registration: auth::Registration) -> Self {
        self.registration = registration;
        self
    }
    pub(crate) async fn register(
        &self,
        challenge: &str,
        csrf: &str,
        username: &str,
        password: &str,
        invite: Option<&str>,
    ) -> std::result::Result<(), RequestError> {
        if self.registration == auth::Registration::Closed {
            return Err(RequestError::InvalidRequest);
        }
        let request = self
            .admission_limits
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::Busy)?;
        let database = Arc::new(
            self.admission_limits
                .database()
                .acquire()
                .await
                .map_err(|_| RequestError::Busy)?,
        );
        let deadline = Instant::now() + std::time::Duration::from_secs(3);
        timeout_at(deadline, async {
            let mut tx = self
                .database
                .begin(deadline.into_std())
                .await
                .map_err(|_| RequestError::Busy)?;
            self.admission(&mut tx, false)
                .await
                .map_err(RequestError::database)?;
            let now = self
                .observe_clock_write(
                    &mut tx,
                    security::now().map_err(|_| RequestError::Rejected)?,
                )
                .await
                .map_err(RequestError::database)?;
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
            if !self.admission_limits.argon2_attempts.allow() {
                return Err(RequestError::Busy);
            }
            let permit = self
                .admission_limits
                .argon2
                .acquire()
                .await
                .map_err(|_| RequestError::Busy)?;
            let permits = HashPermits {
                _argon2: permit,
                _request: request.clone(),
                _database: database.clone(),
                #[cfg(test)]
                gate: self.admission_limits.hash_gate.lock().unwrap().clone(),
            };
            auth::register(
                &mut tx,
                self.registration,
                username,
                password,
                invite,
                now,
                permits,
            )
            .await
            .map_err(|_| RequestError::Rejected)?;
            tx.commit().await.map_err(|_| RequestError::Rejected)
        })
        .await
        .map_err(|_| RequestError::Busy)?
    }
    pub fn with_signed_in_reserve(mut self, reserve: u8) -> Result<Self> {
        ensure!(reserve <= 50, "signed_in_reserve must be between 0 and 50");
        self.admission_limits = AdmissionLimits::new(
            reserve,
            self.manifest
                .routes
                .iter()
                .any(|r| r.access != noxide_protocol::Access::Public),
        )
        .with_wasm_capacity(self.runtime.limits().concurrency);
        Ok(self)
    }
    pub(crate) async fn session_candidate(
        &self,
        cookie: &str,
    ) -> std::result::Result<Option<String>, RequestError> {
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        timeout_at(deadline, async {
            let _request = self
                .admission_limits
                .session_requests()
                .acquire()
                .await
                .map_err(|_| RequestError::Busy)?;
            let _database = self
                .admission_limits
                .session_database()
                .acquire()
                .await
                .map_err(|_| RequestError::Busy)?;
            let mut tx = self
                .database
                .begin_read(deadline.into_std())
                .await
                .map_err(|_| RequestError::Busy)?;
            // Scheduling preflight only; the request repeats admission and
            // authorization inside its own transaction.
            let now = security::now()
                .map_err(|_| RequestError::Rejected)?
                .max(self.clock.load(Ordering::Relaxed));
            let principal = match auth::authenticate(&mut tx, &self.keys, cookie, now).await {
                Ok((_, auth::Principal::User(user))) => Some(user.id),
                Err(auth::AuthError::Invalid) => None,
                _ => return Err(RequestError::Busy),
            };
            tx.commit().await.map_err(|_| RequestError::Busy)?;
            Ok(principal)
        })
        .await
        .map_err(|_| RequestError::Busy)?
    }
    pub(crate) fn session_envelope(&self, cookie: &str) -> bool {
        security::now()
            .ok()
            .and_then(|now| {
                self.keys
                    .verify(cookie, now.max(self.clock.load(Ordering::Relaxed)))
                    .ok()
            })
            .is_some_and(|t| t.kind == TokenKind::Session)
    }

    /// Validate persisted schema compatibility before accepting any traffic.
    /// Data requests repeat this fence inside their transaction.
    pub async fn activate(&self) -> Result<()> {
        let _request = self
            .admission_limits
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::Busy)?;
        let _database = self
            .admission_limits
            .database()
            .acquire()
            .await
            .map_err(|_| RequestError::Busy)?;
        if self
            .manifest
            .operations
            .iter()
            .any(manifest::anonymous_action)
        {
            self.keys.signing_edit_key()?;
        }
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
        let rows = tx
            .fetch::<1>(
                "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
                &[],
            )
            .await?;
        let observed = rows
            .first()
            .ok_or_else(|| anyhow::anyhow!("clock missing"))?[0]
            .parse()?;
        tx.commit().await?;
        self.clock.fetch_max(observed, Ordering::Relaxed);
        self.checkpointed.fetch_max(observed, Ordering::Relaxed);
        ensure!(
            self.generation.get_or_init(|| generation.clone()) == &generation,
            "concurrent activation differs"
        );
        Ok(())
    }

    async fn admission(&self, tx: &mut Transaction, activate: bool) -> Result<()> {
        tx.check_storage().await?;
        tx.check_schema(&self.manifest).await?;
        let generation = tx
            .deployment(&self.deployment, self.keys.incarnation(), activate)
            .await?;
        ensure!(
            self.generation.get() == Some(&generation),
            "application is unactivated or retired"
        );
        Ok(())
    }

    async fn observe_clock_write(&self, tx: &mut Transaction, now: i64) -> Result<i64> {
        // Check raw wall time against both watermarks before substituting the
        // effective time. Persist read-only advances with the write itself.
        let effective = security::observe_clock_read(tx, now, &self.clock).await?;
        let effective = security::observe_clock(tx, effective).await?;
        self.clock.fetch_max(effective, Ordering::Relaxed);
        Ok(effective)
    }

    pub(crate) async fn checkpoint_clock(&self) -> Result<()> {
        let m = self.clock.load(Ordering::Relaxed);
        if m <= self.checkpointed.load(Ordering::Relaxed) {
            return Ok(());
        }
        let deadline = Instant::now() + security::CLOCK_CHECKPOINT_BEGIN_DEADLINE;
        timeout_at(deadline, async {
            let _request = self.admission_limits.requests().request().await?;
            let _database = self.admission_limits.database().acquire().await?;
            let mut tx = self.database.begin(deadline.into_std()).await?;
            self.admission(&mut tx, false).await?;
            tx.execute(
                "UPDATE nx_clock SET observed=$1 WHERE singleton=1 AND observed<$1",
                &[m.into()],
            )
            .await?;
            tx.commit().await?;
            self.checkpointed.fetch_max(m, Ordering::Relaxed);
            Ok(())
        })
        .await?
    }

    pub(crate) async fn checkpoint_clocks(&self) {
        let mut ticks = tokio::time::interval_at(
            Instant::now() + security::CLOCK_CHECKPOINT_INTERVAL,
            security::CLOCK_CHECKPOINT_INTERVAL,
        );
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            let _ = self.checkpoint_clock().await;
        }
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
        let mut identity = Sha256::new();
        identity.update(digest);
        identity.update(Sha256::digest(component));
        let deployment = URL_SAFE_NO_PAD.encode(identity.finalize());
        let concurrency = limits.concurrency;
        let runtime = Runtime::compile(component, limits)?;
        let admission_limits = AdmissionLimits::new(
            25,
            m.routes
                .iter()
                .any(|r| r.access != noxide_protocol::Access::Public),
        )
        .with_wasm_capacity(concurrency);
        Ok(Self {
            presentation: crate::Presentation::default(),
            registration: auth::Registration::Closed,
            manifest: Arc::new(m),
            keys: Arc::new(keys),
            database,
            runtime,
            contract: URL_SAFE_NO_PAD.encode(digest),
            deployment,
            generation: OnceLock::new(),
            clock: AtomicI64::new(0),
            checkpointed: AtomicI64::new(0),
            admission_limits,
        })
    }

    /// Configure trusted HTTP presentation before sharing or activating the application.
    pub fn with_presentation(mut self, presentation: crate::Presentation) -> Result<Self> {
        presentation.validate(&self.manifest)?;
        self.presentation = presentation;
        Ok(self)
    }

    pub async fn login_challenge(&self) -> std::result::Result<LoginChallenge, RequestError> {
        let _request = self
            .admission_limits
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::Busy)?;
        let _database = self
            .admission_limits
            .database()
            .acquire()
            .await
            .map_err(|_| RequestError::Busy)?;
        let mut tx = self
            .database
            .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .map_err(|_| RequestError::Busy)?;
        self.admission(&mut tx, false)
            .await
            .map_err(RequestError::database)?;
        let now = security::now().map_err(|_| RequestError::Rejected)?;
        let now = security::observe_clock_read(&mut tx, now, &self.clock)
            .await
            .map_err(RequestError::database)?;
        self.clock.fetch_max(now, Ordering::Relaxed);

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
        let request = self
            .admission_limits
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::Busy)?;
        let database = Arc::new(
            self.admission_limits
                .database()
                .acquire()
                .await
                .map_err(|_| RequestError::Busy)?,
        );
        let deadline = Instant::now() + std::time::Duration::from_secs(3);
        timeout_at(deadline, async {
            let mut tx = self
                .database
                .begin(deadline.into_std())
                .await
                .map_err(|_| RequestError::Busy)?;
            self.admission(&mut tx, false)
                .await
                .map_err(RequestError::database)?;
            let now = security::now().map_err(|_| RequestError::Rejected)?;
            let now = self
                .observe_clock_write(&mut tx, now)
                .await
                .map_err(RequestError::database)?;
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

            if !self.admission_limits.argon2_attempts.allow() {
                return Err(RequestError::Busy);
            }
            let permit = self
                .admission_limits
                .argon2
                .acquire()
                .await
                .map_err(|_| RequestError::Busy)?;
            let permits = HashPermits {
                _argon2: permit,
                _request: request.clone(),
                _database: database.clone(),
                #[cfg(test)]
                gate: self.admission_limits.hash_gate.lock().unwrap().clone(),
            };
            let signed = auth::login(&mut tx, &self.keys, username, password, now, permits)
                .await
                .map_err(|_| RequestError::Authentication)?;
            tx.commit().await.map_err(|_| RequestError::Busy)?;
            Ok(signed)
        })
        .await
        .map_err(|_| RequestError::Busy)?
    }

    pub async fn logout(&self, cookie: &str, csrf: &str) -> std::result::Result<(), RequestError> {
        let _request = self
            .admission_limits
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::Busy)?;
        let _database = self
            .admission_limits
            .database()
            .acquire()
            .await
            .map_err(|_| RequestError::Busy)?;
        let mut tx = self
            .database
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .map_err(|_| RequestError::Busy)?;
        self.admission(&mut tx, false)
            .await
            .map_err(RequestError::database)?;
        let now = security::now().map_err(|_| RequestError::Rejected)?;
        let now = self
            .observe_clock_write(&mut tx, now)
            .await
            .map_err(RequestError::database)?;
        let (session, _) = auth::authenticate(&mut tx, &self.keys, cookie, now)
            .await
            .map_err(|_| RequestError::Authentication)?;

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

    async fn anonymous_write(
        &self,
        required: bool,
    ) -> std::result::Result<Option<tokio::sync::OwnedSemaphorePermit>, RequestError> {
        if !required {
            return Ok(None);
        }
        if !self.admission_limits.anonymous_write_attempts.allow() {
            return Err(RequestError::Busy);
        }
        self.admission_limits
            .anonymous_writes
            .acquire()
            .await
            .map(Some)
            .map_err(|_| RequestError::Busy)
    }
    async fn submission_identity(
        &self,
        tx: &mut Transaction,
        action: &Action,
        cookie: &str,
        submission: &str,
        csrf: &str,
        now: i64,
    ) -> Result<(Token, Token, auth::Principal)> {
        let op = manifest::operation(&self.manifest, action.operation)?;
        if manifest::anonymous_action(op) {
            let anonymous = self
                .keys
                .anonymous(cookie, now)
                .map_err(|_| RequestError::InvalidRequest)?;
            self.keys
                .verify_csrf(&anonymous.nonce, csrf)
                .map_err(|_| RequestError::InvalidRequest)?;
            let token = self
                .keys
                .verify(submission, now)
                .map_err(|_| RequestError::InvalidRequest)?;
            ensure!(
                matches!(token.kind, TokenKind::AnonymousSubmission { .. })
                    && token.subject == anonymous.nonce,
                RequestError::InvalidRequest
            );
            Ok((token, anonymous, auth::Principal::Anonymous))
        } else {
            let token = self
                .keys
                .verify(submission, now)
                .map_err(|_| RequestError::InvalidRequest)?;
            ensure!(
                matches!(token.kind, TokenKind::Submission { .. }),
                RequestError::InvalidRequest
            );
            let (session, principal) = auth::authenticate(tx, &self.keys, cookie, now)
                .await
                .map_err(|_| RequestError::Authentication)?;
            ensure!(token.subject == session.nonce, RequestError::InvalidRequest);
            self.keys
                .verify_csrf(&session.nonce, csrf)
                .map_err(|_| RequestError::InvalidRequest)?;
            Ok((token, session, principal))
        }
    }
    async fn authorized_target(
        &self,
        tx: &mut Transaction,
        action: &Action,
        target: &RecordTarget,
        principal: &auth::Principal,
        capability: Option<&str>,
    ) -> Result<Option<StoredRecord>> {
        if !manifest::is_capability(manifest::operation(&self.manifest, action.operation)?) {
            return self.current_target(tx, action, target, principal).await;
        }
        let Some(stored) = repository::load(tx, &self.manifest, target.resource, target.id).await?
        else {
            return Ok(None);
        };
        let storage = u32::try_from(tx.storage_resource(&self.manifest, target.resource).await?)?;
        self.keys
            .verify_edit(
                capability.ok_or(RequestError::InvalidRequest)?,
                storage,
                target.id,
                stored.cap_version.ok_or(RequestError::InvalidRequest)?,
            )
            .map_err(|_| RequestError::InvalidRequest)?;
        if let Some(inspection) = &action.inspect {
            let op = manifest::operation(&self.manifest, inspection.operation)?;
            ensure!(
                repository::allowed(&op.policy, principal, &stored.owner, &stored.tenant),
                "inspection policy denied"
            );
        }
        ensure!(
            stored.incarnation == target.incarnation,
            RequestError::InvalidRequest
        );
        Ok(Some(stored))
    }
    async fn edit_handover(
        &self,
        tx: &mut Transaction,
        receipt: &EditReceipt,
        route: u32,
    ) -> Result<Rendered> {
        let record = repository::load(tx, &self.manifest, receipt.resource, receipt.id).await?;
        if receipt.cap_version == 0
            || record
                .as_ref()
                .and_then(|r| r.cap_version)
                .and_then(|v| u64::try_from(v).ok())
                != Some(receipt.cap_version)
        {
            return render::capability_handover(None, None);
        }
        let storage = u32::try_from(
            tx.storage_resource(&self.manifest, receipt.resource)
                .await?,
        )?;
        let Ok(secret) =
            self.keys
                .edit_secret(receipt.key_id, storage, receipt.id, receipt.cap_version)
        else {
            return render::capability_handover(None, None);
        };
        let link = render::resolve(
            &self.manifest,
            &RouteRef {
                route,
                target: Some(receipt.id),
            },
        )?;
        render::capability_handover(Some(&secret), Some(&link))
    }
    async fn receipt_response(
        &self,
        tx: &mut Transaction,
        action: &Action,
        target: Option<&RecordTarget>,
        outcome: &str,
    ) -> Result<Rendered> {
        let op = manifest::operation(&self.manifest, action.operation)?;
        if manifest::is_public(op) && op.kind == OperationKind::Create {
            let receipt: EditReceipt = serde_json::from_str(outcome)?;
            ensure!(receipt.resource == op.resource, "receipt resource differs");
            self.edit_handover(tx, &receipt, action.redirect).await
        } else {
            self.receipt(action, target, outcome)
        }
    }

    fn credentials(
        &self,
        action: &Action,
        session: &Token,
        now: i64,
        target: Option<RecordTarget>,
        values: Fields,
    ) -> Result<FormCredentials> {
        let kind = if session.kind == TokenKind::Anonymous {
            TokenKind::AnonymousSubmission {
                contract: self.submission_contract(),
                action: action.id,
                version: action.version,
                target,
            }
        } else {
            TokenKind::Submission {
                contract: self.submission_contract(),
                action: action.id,
                version: action.version,
                target,
            }
        };
        let (_, submission) = self.keys.issue(kind, &session.nonce, now, 900)?;
        Ok(FormCredentials {
            csrf: self.keys.csrf(&session.nonce),
            submission,
            values,
        })
    }

    fn submission_target(&self, token: &Token, action: &Action) -> Result<Option<RecordTarget>> {
        let (TokenKind::Submission {
            contract,
            action: id,
            version,
            target,
        }
        | TokenKind::AnonymousSubmission {
            contract,
            action: id,
            version,
            target,
        }) = &token.kind
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
        session: Option<&Token>,
        anonymous: Option<&Token>,
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
            let subject = if manifest::anonymous_action(op) {
                anonymous
            } else {
                session
            };
            let Some(subject) = subject else {
                forms.insert(*id, None);
                continue;
            };
            let credentials = if op.kind == OperationKind::Create {
                if manifest::is_public(op)
                    || principal.user().is_ok_and(|user| {
                        repository::allowed(&op.policy, principal, &user.id, &user.tenant)
                    })
                {
                    Some(self.credentials(action, subject, now, None, Fields::new())?)
                } else {
                    None
                }
            } else if let Some(record) = &stored {
                if (manifest::is_capability(op) && record.cap_version.is_some())
                    || self.target_allowed(action, route, principal, record)?
                {
                    let grant = RecordTarget {
                        resource: op.resource,
                        id: record.record.id,
                        incarnation: record.incarnation.clone(),
                        revision: record.revision,
                        route,
                    };
                    let values = if manifest::is_capability(op) {
                        Fields::new()
                    } else {
                        action
                            .fields
                            .iter()
                            .map(|name| (name.clone(), record.record.fields[name].clone()))
                            .collect()
                    };
                    Some(self.credentials(action, subject, now, Some(grant), values)?)
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
        let operation = manifest::operation(&self.manifest, action.operation)?;
        // An edit capability grants mutation authority, never a read projection.
        let current = if manifest::is_capability(operation) {
            Fields::new()
        } else if operation.kind == OperationKind::Delete {
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
        self.view_page(Some(cookie), route, target, None).await
    }

    pub async fn view_page(
        &self,
        cookie: Option<&str>,
        route: u32,
        target: Option<u64>,
        cursor: Option<u64>,
    ) -> std::result::Result<Rendered, RequestError> {
        self.view_page_anonymous(cookie, None, route, target, cursor)
            .await
    }
    pub(crate) async fn view_page_anonymous(
        &self,
        cookie: Option<&str>,
        anonymous_cookie: Option<&str>,
        route: u32,
        target: Option<u64>,
        cursor: Option<u64>,
    ) -> std::result::Result<Rendered, RequestError> {
        let _request = self
            .admission_limits
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::Busy)?;
        let _database = self
            .admission_limits
            .database()
            .acquire()
            .await
            .map_err(|_| RequestError::Busy)?;
        if cursor.is_some_and(|c| c == 0 || c > i64::MAX as u64 || target.is_some()) {
            return Err(RequestError::InvalidRequest);
        }
        let reference = RouteRef { route, target };
        render::resolve(&self.manifest, &reference).map_err(|_| RequestError::InvalidRequest)?;
        let deadline = Instant::now() + self.runtime.limits().wall_time;
        timeout_at(deadline, async {
            let mut tx = self
                .database
                .begin_read(deadline.into_std())
                .await
                .map_err(|_| RequestError::Busy)?;
            self.admission(&mut tx, false)
                .await
                .map_err(RequestError::database)?;
            let now = security::now().map_err(|_| RequestError::Rejected)?;
            let now = security::observe_clock_read(&mut tx, now, &self.clock)
                .await
                .map_err(RequestError::database)?;
            self.clock.fetch_max(now, Ordering::Relaxed);

            let access = &manifest::route(&self.manifest, route)
                .map_err(|_| RequestError::InvalidRequest)?
                .access;
            let authenticated = self.route_identity(&mut tx, access, cookie, now).await?;
            let (session, principal) = match authenticated {
                Some((token, principal)) => (Some(token), principal),
                None => (None, auth::Principal::Anonymous),
            };
            let needs_anonymous = manifest::route(&self.manifest, route).map_err(|_| RequestError::InvalidRequest)?.forms.iter().any(|id| manifest::action(&self.manifest,*id).ok().and_then(|a| manifest::operation(&self.manifest,a.operation).ok()).is_some_and(manifest::anonymous_action));
            let (anonymous, new_cookie) = if needs_anonymous {
                if let Some(token) = anonymous_cookie.and_then(|c| self.keys.anonymous(c, now).ok()) { (Some(token), None) }
                else { let (token,cookie) = self.keys.issue(TokenKind::Anonymous, "", now, security::ANONYMOUS_TTL).map_err(|_| RequestError::Rejected)?; (Some(token),Some(cookie)) }
            } else { (None,None) };
            let forms = self.forms(&mut tx, route, target, session.as_ref(), anonymous.as_ref(), &principal, now).await.map_err(|_| RequestError::Rejected)?;
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
                capability_grant: None,
                record: None,
                calls: 16,
                cursor,
                more: None,
            };
            let _wasm = self
                .admission_limits
                .wasm()
                .acquire()
                .await
                .map_err(|_| RequestError::Busy)?;
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
            let response = attempt.result.map_err(RequestError::database)?;
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
            let mut rendered = render::render(
                &response,
                &RenderContext {
                    presentation: &self.presentation,
                    manifest: Some(&self.manifest),
                    forms,
                    logout_csrf: session
                        .as_ref()
                        .map(|session| self.keys.csrf(&session.nonce)),
                    next_page,
                },
            )
            .map_err(|_| RequestError::Rejected)?;
            if let ResponseIntent::Page(doc) | ResponseIntent::NotFound(doc) = &response
                && doc.nodes.iter().any(|n| matches!(n, Instruction::Form { action } if manifest::action(&self.manifest,*action).ok().and_then(|a| manifest::operation(&self.manifest,a.operation).ok()).is_some_and(manifest::anonymous_action))) { rendered.anonymous_cookie = new_cookie; }
            effects.tx.commit().await.map_err(|_| RequestError::Busy)?;
            Ok(rendered)
        })
        .await
        .map_err(|_| RequestError::Busy)?
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    use crate::test_support as fixture;
    use std::time::Duration;

    async fn read_advance(app: &Application, now: i64) {
        let mut tx = app
            .database
            .begin_read(std::time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        security::observe_clock_read(&mut tx, now, &app.clock)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    async fn stored_clock(db: &Database) -> i64 {
        let mut tx = db
            .begin_read(std::time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let rows = tx
            .fetch::<1>(
                "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
                &[],
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        rows[0][0].parse().unwrap()
    }

    async fn write_clock_uses_read_watermark(db: Database) {
        db.initialize().await.unwrap();
        db.create_account("alice", "clock regression password", "")
            .await
            .unwrap();
        let m = fixture::manifest();
        let app = Application::new(
            &fixture::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db.clone(),
            HostKeys::generate().unwrap(),
            Limits::default(),
        )
        .unwrap();
        app.activate().await.unwrap();
        let wall = security::now().unwrap();
        let high = wall + 30;
        read_advance(&app, high).await;
        assert!(stored_clock(&db).await < high);
        let challenge = app.login_challenge().await.unwrap();
        assert_eq!(
            app.keys.verify(&challenge.cookie, high).unwrap().issued,
            high
        );
        let (expired_challenge, signed) =
            app.keys.issue(TokenKind::Login, "", wall - 60, 75).unwrap();
        assert!(app.keys.verify(&signed, wall).is_ok());
        assert!(matches!(
            app.login(
                &signed,
                &app.keys.csrf(&expired_challenge.nonce),
                "alice",
                "clock regression password"
            )
            .await,
            Err(RequestError::InvalidRequest)
        ));
        assert!(stored_clock(&db).await < high);

        let session = app
            .login(
                &challenge.cookie,
                &challenge.csrf,
                "alice",
                "clock regression password",
            )
            .await
            .unwrap();
        assert_eq!(app.keys.verify(&session, high).unwrap().issued, high);
        assert_eq!(stored_clock(&db).await, high);

        read_advance(&app, high + 1).await;
        let page = app.view(&session, 1, None).await.unwrap();
        let html = std::str::from_utf8(&page.body).unwrap();
        let submission = fixture::hidden(html, "_submission");
        let csrf = fixture::hidden(html, "_csrf");
        let token = app.keys.verify(&submission, high + 1).unwrap();
        let (_, expired) = app
            .keys
            .issue(token.kind.clone(), &token.subject, wall - 60, 75)
            .unwrap();
        assert!(app.keys.verify(&expired, wall).is_ok());
        let input = Fields::from([("body".into(), "read watermark".into())]);
        assert!(
            app.submit(&session, 1, &expired, &csrf, input.clone())
                .await
                .is_err()
        );
        assert!(
            app.recover_form(&session, 1, &expired, &csrf, &input, true)
                .await
                .is_err()
        );
        app.submit(&session, 1, &submission, &csrf, input.clone())
            .await
            .unwrap();
        assert_eq!(stored_clock(&db).await, high + 1);
        read_advance(&app, high + 2).await;
        app.recover_form(&session, 1, &submission, &csrf, &input, true)
            .await
            .unwrap();
        assert_eq!(stored_clock(&db).await, high + 2);
        read_advance(&app, high + 3).await;
        app.logout(&session, &csrf).await.unwrap();
        assert_eq!(stored_clock(&db).await, high + 3);

        // The exact boundary is evaluated against raw wall time, not an
        // already-substituted effective time, even if durable time lags.
        let mut tx = db
            .begin(std::time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            app.observe_clock_write(&mut tx, high + 3 - 60)
                .await
                .unwrap(),
            high + 3
        );
        assert_eq!(
            app.observe_clock_write(&mut tx, high + 3 - 61)
                .await
                .unwrap_err()
                .to_string(),
            "clock moved backwards beyond tolerance; use recover-clock with a fresh host key"
        );
        tx.rollback().await.unwrap();
        let durable = stored_clock(&db).await;
        read_advance(&app, wall + 120).await;
        let snapshot = {
            let mut tx = db
                .begin_read(std::time::Instant::now() + Duration::from_secs(2))
                .await
                .unwrap();
            let rows = tx.snapshot().await.unwrap();
            tx.commit().await.unwrap();
            rows
        };
        assert!(matches!(
            app.login(
                &challenge.cookie,
                &challenge.csrf,
                "alice",
                "clock regression password"
            )
            .await,
            Err(RequestError::Rejected)
        ));
        assert!(matches!(
            app.logout(&session, &csrf).await,
            Err(RequestError::Rejected)
        ));
        assert!(matches!(
            app.submit(&session, 1, &submission, &csrf, input.clone())
                .await,
            Err(RequestError::Rejected)
        ));
        assert!(
            app.recover_form(&session, 1, &submission, &csrf, &input, true)
                .await
                .is_err()
        );
        assert_eq!(stored_clock(&db).await, durable);
        let mut tx = db
            .begin_read(std::time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(tx.snapshot().await.unwrap(), snapshot);
        tx.commit().await.unwrap();
        db.recover_clock(&HostKeys::generate().unwrap())
            .await
            .unwrap();
        assert!(
            app.checkpoint_clock().await.is_err(),
            "a dirty retired process must not checkpoint"
        );
    }

    #[tokio::test]
    async fn sqlite_idle_checkpoint_takes_no_writer_lock() {
        let temp = tempfile::tempdir().unwrap();
        let db = Database::sqlite(temp.path().join("idle-checkpoint.db"));
        db.initialize().await.unwrap();
        let mut tx = db
            .begin(std::time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        security::observe_clock(&mut tx, 10_000).await.unwrap();
        tx.commit().await.unwrap();
        let m = fixture::manifest();
        let app = Application::new(
            &fixture::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db.clone(),
            HostKeys::generate().unwrap(),
            Limits::default(),
        )
        .unwrap();
        app.activate().await.unwrap();
        assert_eq!(app.checkpointed.load(Ordering::Relaxed), 10_000);
        let mut writer = db
            .begin(std::time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_millis(100), app.checkpoint_clock())
            .await
            .unwrap()
            .unwrap();
        writer.rollback().await.unwrap();

        let high = security::now().unwrap();
        read_advance(&app, high).await;
        app.checkpoint_clock().await.unwrap();
        assert_eq!(app.checkpointed.load(Ordering::Relaxed), high);
        assert_eq!(stored_clock(&db).await, high);
        let mut writer = db
            .begin(std::time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        // No read has advanced memory since the successful checkpoint. This
        // would hit the 200 ms deadline if a second checkpoint opened a writer.
        tokio::time::timeout(Duration::from_millis(100), app.checkpoint_clock())
            .await
            .unwrap()
            .unwrap();
        read_advance(&app, high + 1).await;
        assert!(app.checkpoint_clock().await.is_err());
        assert_eq!(app.checkpointed.load(Ordering::Relaxed), high);
        writer.rollback().await.unwrap();
        app.checkpoint_clock().await.unwrap();
        assert_eq!(app.checkpointed.load(Ordering::Relaxed), high + 1);
        assert_eq!(stored_clock(&db).await, high + 1);
    }

    #[tokio::test]
    async fn sqlite_writes_honor_read_clock_before_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        write_clock_uses_read_watermark(Database::sqlite(temp.path().join("read-clock.db"))).await;
    }

    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
    async fn postgres_writes_honor_read_clock_before_checkpoint() {
        use sqlx::Connection;
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "nx_read_write_clock_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut case = url::Url::parse(&url).unwrap();
        case.set_path(&format!("/{name}"));
        write_clock_uses_read_watermark(Database::postgres(case.as_str()).unwrap()).await;
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod identity_time_tests {
    use super::*;
    #[test]
    fn candidate_classification_uses_memory_effective_time_without_database_access() {
        let temp = tempfile::tempdir().unwrap();
        let m = crate::test_support::manifest();
        let app = Application::new(
            &crate::test_support::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            Database::sqlite(temp.path().join("absent.db")),
            HostKeys::generate().unwrap(),
            Limits::default(),
        )
        .unwrap();
        let now = security::now().unwrap();
        let (_, cookie) = app
            .keys
            .issue(TokenKind::Session, "alice", now, 10)
            .unwrap();
        assert!(app.keys.verify(&cookie, now).is_ok());
        assert!(app.session_envelope(&cookie));
        app.clock.fetch_max(now + 20, Ordering::Relaxed);
        assert!(!app.session_envelope(&cookie));
        assert!(!temp.path().join("absent.db").exists());
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    #[tokio::test]
    async fn elapsed_database_work_is_busy_but_schema_rejection_is_not() {
        let elapsed = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            std::future::pending::<()>(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            RequestError::database(elapsed.into()),
            RequestError::Busy
        ));
        assert!(matches!(
            RequestError::database(anyhow::anyhow!("stored schema differs from manifest")),
            RequestError::Rejected
        ));
    }
}

#[cfg(test)]
mod persistence_tests;

impl Application {
    async fn route_identity(
        &self,
        tx: &mut Transaction,
        access: &Access,
        cookie: Option<&str>,
        now: i64,
    ) -> std::result::Result<Option<(Token, auth::Principal)>, RequestError> {
        Ok(match access {
            Access::Public => None,
            Access::Authenticated => Some(
                auth::authenticate(
                    tx,
                    &self.keys,
                    cookie.ok_or(RequestError::Authentication)?,
                    now,
                )
                .await
                .map_err(|_| RequestError::Authentication)?,
            ),
            Access::PublicOptional => match cookie {
                None => None,
                Some(cookie) => match auth::authenticate(tx, &self.keys, cookie, now).await {
                    Ok(authenticated) => Some(authenticated),
                    Err(auth::AuthError::Invalid) => None,
                    Err(auth::AuthError::Unavailable) => return Err(RequestError::Busy),
                },
            },
        })
    }
}
