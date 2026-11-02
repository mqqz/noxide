#[cfg(test)]
use crate::auth::AccountAdmin as _;
mod action;
mod authority;
pub mod blobs;
use crate::database::lifecycle::{AdmissionOwner, Registry, RequestScope};
pub(crate) use action::ActionCore;
pub use action::{ActionRejection, ValidatedActionRejection};
use action::{CanonicalActionInput, ExecutionBudget};
mod capabilities;
pub mod clock;
mod effect_worker;
mod effects;
mod guests;
mod jobs;
mod navigation;
mod submission;
pub use jobs::JobRunOutcome;
mod job_selection;
pub mod job_worker;
use crate::{
    Database, HostKeys, auth,
    database::{Transaction, retryable},
    limiter::AdmissionLimits,
    manifest,
    render::{self, FormCredentials, RenderContext, Rendered},
    repository::{self, Effects, StoredRecord},
    runtime::Limits,
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

fn cursor_scope(
    identity: (&str, &str),
    route: u32,
    target: Option<u64>,
    scope_incarnation: Option<String>,
    list: Option<&Operation>,
    subject: &str,
    params: &Fields,
) -> serde_json::Result<String> {
    let (contract, deployment) = identity;
    if params.is_empty() {
        serde_json::to_string(&(
            contract,
            deployment,
            route,
            target,
            scope_incarnation,
            list,
            subject,
        ))
    } else {
        serde_json::to_string(&(
            contract,
            deployment,
            route,
            target,
            scope_incarnation,
            list,
            subject,
            params,
        ))
    }
}

#[cfg(test)]
mod query_compatibility_tests;

pub use crate::database::RequestError;
/// Time or capacity running out is the host's state, and the caller may retry later.
/// Anything else a guest attempt returns keeps its own classification.
pub(crate) fn guest_error(error: anyhow::Error) -> anyhow::Error {
    if error.is::<noxide_guest::GuestBusy>() {
        crate::database::lifecycle::Unavailable::Deadline.into()
    } else {
        error
    }
}
pub(crate) fn authentication_error(error: auth::AuthError) -> RequestError {
    match error {
        auth::AuthError::Invalid => RequestError::Authentication,
        auth::AuthError::Unavailable => RequestError::Busy,
    }
}

pub struct Application {
    pub presentation: crate::Presentation,
    pub assets: Arc<crate::assets::AssetBundle>,
    pub blobs: Option<blobs::BlobRuntime>,
    pub asset_responses: Arc<tokio::sync::Semaphore>,
    pub registration: auth::Registration,
    pub manifest: Arc<Manifest>,
    pub(crate) plans: BTreeMap<u32, Arc<crate::query_plan::ListPlan>>,
    pub(crate) keys: Arc<HostKeys>,
    database: Database,
    jobs: Option<job_worker::JobRuntime>,
    effects: Option<effect_worker::EffectRuntime>,
    runtime: guests::Guests,
    contract: String,
    deployment: String,
    generation: OnceLock<String>,
    clock: AtomicI64,
    checkpointed: AtomicI64,
    lifecycle_clock: crate::lifecycle_clock::Freshness,
    maintenance: Arc<tokio::sync::Semaphore>,
    maintenance_running: std::sync::atomic::AtomicBool,
    pub admission_limits: AdmissionLimits,
    pub(crate) request_lifecycle: Arc<Registry>,
    database_statement_limit: u16,
    #[cfg(any(test, feature = "test-support"))]
    pub postcommit_barrier:
        std::sync::Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    restore_fork: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EditReceipt {
    resource: u32,
    id: u64,
    incarnation: String,
    cap_version: u64,
    key_id: u32,
}

pub struct LoginChallenge {
    pub cookie: String,
    pub csrf: String,
}

impl Application {
    #[cfg(feature = "test-support")]
    pub fn test_database(&self) -> &Database {
        &self.database
    }

    #[cfg(feature = "test-support")]
    pub fn test_clock(&self) -> &AtomicI64 {
        &self.clock
    }

    #[cfg(feature = "test-support")]
    pub fn test_maintenance(&self) -> &Arc<tokio::sync::Semaphore> {
        &self.maintenance
    }

    #[cfg(feature = "test-support")]
    pub fn test_maintenance_running(&self) -> &std::sync::atomic::AtomicBool {
        &self.maintenance_running
    }

    /// Key access for tests of signed values; a deployed binary has no such route.
    #[cfg(feature = "test-support")]
    pub fn test_keys(&self) -> &Arc<HostKeys> {
        &self.keys
    }

    pub fn request_lifecycle(&self) -> Arc<Registry> {
        self.request_lifecycle.clone()
    }
    fn request_scope(&self, cap: std::time::Duration) -> RequestScope {
        RequestScope::current_or_new(
            self.request_lifecycle.clone(),
            cap,
            self.database_statement_limit,
        )
    }
    fn owned_request(
        &self,
        request: Arc<tokio::sync::OwnedSemaphorePermit>,
        database: Arc<tokio::sync::OwnedSemaphorePermit>,
        anonymous: Option<tokio::sync::OwnedSemaphorePermit>,
        cap: std::time::Duration,
    ) -> AdmissionOwner {
        AdmissionOwner::new(self.request_scope(cap), request, database, anonymous)
    }
    pub fn http_request_scope(
        &self,
        class: crate::limiter::RequestClass,
        path: &str,
        outer: Option<crate::limiter::TransportDeadline>,
    ) -> RequestScope {
        use crate::limiter::RequestClass;
        let cap = if matches!(class, RequestClass::PasswordHash) {
            std::time::Duration::from_secs(3)
        } else if path == self.presentation.login_path
            || path == self.presentation.registration_path
            || path == self.presentation.logout_path
        {
            std::time::Duration::from_secs(2)
        } else {
            self.runtime.limits().wall_time
        };
        let outer = outer.map_or_else(|| Instant::now() + cap, |outer| outer.0);
        RequestScope::new(
            self.request_lifecycle.clone(),
            outer,
            cap,
            self.database_statement_limit,
        )
    }
    async fn finish_commit<T>(
        tx: &mut Transaction,
        prepared: T,
    ) -> std::result::Result<T, RequestError> {
        tx.finish_commit(prepared).await
    }
    /// Lower the total actual provider-statement ceiling for an ordinary request.
    /// This supplements all existing action/list/query budgets.
    pub fn with_database_statement_limit(mut self, limit: u16) -> Result<Self> {
        self.request_lifecycle.ensure_idle()?;
        ensure!(
            (1..=256).contains(&limit),
            "database statement limit must be between 1 and 256"
        );
        self.database_statement_limit = limit;
        Ok(self)
    }
    /// Operator restore fencing only: activation may adopt an effect queue copied
    /// from another owner directory, pausing every capture in the same transaction.
    pub fn with_restore_fork(mut self) -> Self {
        self.restore_fork = true;
        self
    }
    pub fn with_registration(mut self, registration: auth::Registration) -> Self {
        self.registration = registration;
        self
    }
    pub async fn register(
        &self,
        challenge: &str,
        csrf: &str,
        username: &str,
        password: &str,
        invite: Option<&str>,
    ) -> std::result::Result<(), RequestError> {
        let entry_scope = self.request_scope(std::time::Duration::from_secs(3));
        entry_scope
            .run(async {
                if self.registration == auth::Registration::Closed {
                    return Err(RequestError::InvalidRequest);
                }
                let request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let database = Arc::new(
                    self.admission_limits
                        .database()
                        .acquire()
                        .await
                        .map_err(|_| RequestError::deadline())?,
                );
                let owner = self.owned_request(
                    request.clone(),
                    database.clone(),
                    None,
                    std::time::Duration::from_secs(3),
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        timeout_at(deadline, async {
                            let mut tx = self
                                .database
                                .begin(deadline.into_std())
                                .await
                                .map_err(|_| RequestError::deadline())?;
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
                                .map_err(|_| RequestError::deadline())?;
                            let permits = self.admission_limits.hash_permits(
                                permit,
                                request.clone(),
                                database.clone(),
                            );
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
                            .map_err(|error| {
                                if error.is::<crate::database::lifecycle::meter::StatementLimit>() {
                                    RequestError::Busy
                                } else {
                                    RequestError::Rejected
                                }
                            })?;
                            Self::finish_commit(&mut tx, ()).await
                        })
                        .await
                        .map_err(|_| RequestError::deadline())?
                    })
                    .await
            })
            .await
    }
    pub fn with_signed_in_reserve(mut self, reserve: u8) -> Result<Self> {
        self.request_lifecycle.ensure_idle()?;
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
    /// Authenticate host-owned account content through normal request admission.
    /// Scheduling preflight must never authorize a response.
    pub async fn account_identity(
        &self,
        cookie: &str,
    ) -> std::result::Result<String, RequestError> {
        let entry_scope = self.request_scope(self.runtime.limits().wall_time);
        entry_scope
            .run(async {
                let _request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let _database = self
                    .admission_limits
                    .database()
                    .acquire()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let owner = self.owned_request(
                    _request,
                    Arc::new(_database),
                    None,
                    self.runtime.limits().wall_time,
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        timeout_at(deadline, async {
                            let mut tx = self
                                .database
                                .begin_read(deadline.into_std())
                                .await
                                .map_err(|_| RequestError::deadline())?;
                            self.admission(&mut tx, false)
                                .await
                                .map_err(RequestError::database)?;
                            let wall = security::now().map_err(|_| RequestError::Rejected)?;
                            let now = security::observe_clock_read(&mut tx, wall, &self.clock)
                                .await
                                .map_err(RequestError::database)?;
                            self.clock.fetch_max(now, Ordering::Relaxed);
                            let (_, principal) = self
                                .route_identity(&mut tx, &Access::Authenticated, Some(cookie), now)
                                .await?
                                .ok_or(RequestError::Authentication)?;
                            let id = principal
                                .user()
                                .map_err(|_| RequestError::Authentication)?
                                .id
                                .clone();
                            Self::finish_commit(&mut tx, id).await
                        })
                        .await
                        .map_err(|_| RequestError::deadline())?
                    })
                    .await
            })
            .await
    }

    pub async fn session_candidate(
        &self,
        cookie: &str,
    ) -> std::result::Result<Option<String>, RequestError> {
        let entry_scope = self.request_scope(std::time::Duration::from_secs(1));
        entry_scope
            .run(async {
                let scope = self.request_scope(std::time::Duration::from_secs(1));
                let deadline = scope.work_deadline();
                timeout_at(deadline, async {
                    let _request = self
                        .admission_limits
                        .session_requests()
                        .acquire()
                        .await
                        .map_err(|_| RequestError::deadline())?;
                    let _database = self
                        .admission_limits
                        .session_database()
                        .acquire()
                        .await
                        .map_err(|_| RequestError::deadline())?;
                    let owner =
                        AdmissionOwner::new(scope, Arc::new(_request), Arc::new(_database), None);
                    owner
                        .run(async {
                            let mut tx = self
                                .database
                                .begin_read(deadline.into_std())
                                .await
                                .map_err(|_| RequestError::deadline())?;
                            // Scheduling preflight only; the request repeats admission and
                            // authorization inside its own transaction.
                            let now = security::now()
                                .map_err(|_| RequestError::Rejected)?
                                .max(self.clock.load(Ordering::Relaxed));
                            let principal =
                                match auth::authenticate(&mut tx, &self.keys, cookie, now).await {
                                    Ok((_, auth::Principal::User(user))) => Some(user.id),
                                    Err(auth::AuthError::Invalid) => None,
                                    _ => return Err(RequestError::Busy),
                                };
                            Self::finish_commit(&mut tx, principal).await
                        })
                        .await
                })
                .await
                .map_err(|_| RequestError::deadline())?
            })
            .await
    }
    pub fn session_envelope(&self, cookie: &str) -> bool {
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
        // effective time. Only the clock tick persists the mark.
        let effective = security::observe_clock_bounded(tx, now, &self.clock).await?;
        self.clock.fetch_max(effective, Ordering::Relaxed);
        Ok(effective)
    }

    #[cfg(test)]
    pub(crate) async fn checkpoint_clock(&self) -> Result<()> {
        let m = self.clock.load(Ordering::Relaxed);
        if m <= self.checkpointed.load(Ordering::Relaxed) {
            return Ok(());
        }
        let deadline = Instant::now() + security::CLOCK_CHECKPOINT_BEGIN_DEADLINE;
        timeout_at(deadline, async {
            let _maintenance = self.maintenance.try_acquire()?;
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

    fn submission_contract(&self) -> String {
        format!(
            "{}:{}",
            self.contract,
            self.generation.get().expect("admission precedes token use")
        )
    }
    /// An application that runs guest code in `pool`'s workers. The pool compiled
    /// `component` when it started, which is its admission check.
    pub fn with_workers(
        pool: Arc<noxide_guest::pool::GuestPool>,
        component: &[u8],
        declarations: &[u8],
        approved: [u8; 32],
        database: Database,
        keys: HostKeys,
        resources: crate::DeploymentResources,
    ) -> Result<Self> {
        Self::build(
            guests::Guests::workers(pool),
            component,
            declarations,
            approved,
            database,
            keys,
            resources,
        )
    }

    /// For operator commands that use the deployment's storage and run no guest code.
    /// Anything needing a guest reports no capacity.
    pub fn without_guests(
        component: &[u8],
        declarations: &[u8],
        approved: [u8; 32],
        database: Database,
        keys: HostKeys,
        limits: Limits,
        resources: crate::DeploymentResources,
    ) -> Result<Self> {
        Self::build(
            guests::Guests::none(limits),
            component,
            declarations,
            approved,
            database,
            keys,
            resources,
        )
    }

    /// Runs guest code in this process, so tests need no worker binary. Deployed
    /// binaries cannot call this: it needs `test-support`, and links Wasmtime.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(
        component: &[u8],
        declarations: &[u8],
        approved: [u8; 32],
        database: Database,
        keys: HostKeys,
        limits: Limits,
        resources: crate::DeploymentResources,
    ) -> Result<Self> {
        Self::build(
            guests::Guests::in_process(component, limits)?,
            component,
            declarations,
            approved,
            database,
            keys,
            resources,
        )
    }

    /// The approval digest comes from operator policy, separately from the
    /// application bundle.
    fn build(
        runtime: guests::Guests,
        component: &[u8],
        declarations: &[u8],
        approved: [u8; 32],
        database: Database,
        keys: HostKeys,
        resources: crate::DeploymentResources,
    ) -> Result<Self> {
        let m = manifest::parse(declarations)?;
        let approval = crate::deployment::approval(
            &m,
            resources.blobs.as_ref().map(|b| &b.ceilings),
            resources.jobs.as_ref(),
            resources.effects.as_ref(),
        )?;
        let digest = approval.digest;
        ensure!(
            digest == approved,
            "deployment did not approve this contract"
        );
        resources.assets.verify_declarations(&m.assets)?;
        let blobs = resources
            .blobs
            .map(|deployment| {
                blobs::BlobRuntime::open(
                    deployment,
                    approval.effective.expect("validated blob deployment"),
                )
            })
            .transpose()?;
        let mut identity = Sha256::new();
        identity.update(digest);
        identity.update(Sha256::digest(component));
        let deployment = URL_SAFE_NO_PAD.encode(identity.finalize());
        let concurrency = runtime.limits().concurrency;
        let admission_limits = AdmissionLimits::new(
            25,
            m.routes
                .iter()
                .any(|r| r.access != noxide_protocol::Access::Public),
        )
        .with_wasm_capacity(concurrency);
        Ok(Self {
            presentation: crate::Presentation::default(),
            assets: Arc::new(resources.assets),
            blobs,
            jobs: approval.effective_jobs.map(job_worker::JobRuntime::new),
            effects: approval
                .effective_effects
                .map(effect_worker::EffectRuntime::new),
            asset_responses: Arc::new(tokio::sync::Semaphore::new(8)),
            registration: auth::Registration::Closed,
            plans: crate::query_plan::compile_all(&m)?,
            manifest: Arc::new(m),
            keys: Arc::new(keys),
            database,
            runtime,
            contract: URL_SAFE_NO_PAD.encode(digest),
            deployment,
            generation: OnceLock::new(),
            clock: AtomicI64::new(0),
            checkpointed: AtomicI64::new(0),
            lifecycle_clock: crate::lifecycle_clock::Freshness::default(),
            maintenance: Arc::new(tokio::sync::Semaphore::new(1)),
            maintenance_running: std::sync::atomic::AtomicBool::new(false),
            admission_limits,
            request_lifecycle: Arc::new(Registry::default()),
            database_statement_limit: 256,
            restore_fork: false,
            #[cfg(any(test, feature = "test-support"))]
            postcommit_barrier: std::sync::Mutex::new(None),
        })
    }

    /// Configure trusted HTTP presentation before sharing or activating the application.
    pub fn with_presentation(mut self, presentation: crate::Presentation) -> Result<Self> {
        presentation.validate(&self.manifest)?;
        ensure!(
            [
                &presentation.csrf_field,
                &presentation.submission_field,
                &presentation.capability_field
            ]
            .iter()
            .all(|name| name.as_str() != "_upload"),
            "reserved upload field"
        );
        ensure!(
            [
                &presentation.login_path,
                &presentation.account_path,
                &presentation.logout_path,
                &presentation.action_path,
                &presentation.stylesheet_path,
                &presentation.registration_path,
                &presentation.capability_path
            ]
            .iter()
            .all(|path| path.as_str() != "/_noxide/download"),
            "reserved download path"
        );
        self.presentation = presentation;
        Ok(self)
    }

    pub async fn login_challenge(&self) -> std::result::Result<LoginChallenge, RequestError> {
        let entry_scope = self.request_scope(std::time::Duration::from_secs(2));
        entry_scope
            .run(async {
                let _request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let _database = self
                    .admission_limits
                    .database()
                    .acquire()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let owner = self.owned_request(
                    _request,
                    Arc::new(_database),
                    None,
                    std::time::Duration::from_secs(2),
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        let mut tx = self
                            .database
                            .begin_read(deadline.into_std())
                            .await
                            .map_err(|_| RequestError::deadline())?;
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
                            .map_err(|_| RequestError::Busy)?;
                        Self::finish_commit(
                            &mut tx,
                            LoginChallenge {
                                cookie,
                                csrf: self
                                    .keys
                                    .csrf(&token.nonce)
                                    .map_err(|_| RequestError::Busy)?,
                            },
                        )
                        .await
                    })
                    .await
            })
            .await
    }

    pub async fn login(
        &self,
        challenge: &str,
        csrf: &str,
        username: &str,
        password: &str,
    ) -> std::result::Result<String, RequestError> {
        let entry_scope = self.request_scope(std::time::Duration::from_secs(3));
        entry_scope
            .run(async {
                let request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let database = Arc::new(
                    self.admission_limits
                        .database()
                        .acquire()
                        .await
                        .map_err(|_| RequestError::deadline())?,
                );
                let owner = self.owned_request(
                    request.clone(),
                    database.clone(),
                    None,
                    std::time::Duration::from_secs(3),
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        timeout_at(deadline, async {
                            let mut tx = self
                                .database
                                .begin(deadline.into_std())
                                .await
                                .map_err(|_| RequestError::deadline())?;
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
                                .map_err(|_| RequestError::deadline())?;
                            let permits = self.admission_limits.hash_permits(
                                permit,
                                request.clone(),
                                database.clone(),
                            );
                            let signed = auth::login(
                                &mut tx, &self.keys, username, password, now, permits,
                            )
                            .await
                            .map_err(|error| {
                                if error.is::<crate::database::lifecycle::meter::StatementLimit>() {
                                    RequestError::Busy
                                } else {
                                    RequestError::Authentication
                                }
                            })?;
                            Self::finish_commit(&mut tx, signed).await
                        })
                        .await
                        .map_err(|_| RequestError::deadline())?
                    })
                    .await
            })
            .await
    }

    pub async fn logout(&self, cookie: &str, csrf: &str) -> std::result::Result<(), RequestError> {
        let entry_scope = self.request_scope(std::time::Duration::from_secs(2));
        entry_scope
            .run(async {
                let _request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let _database = self
                    .admission_limits
                    .database()
                    .acquire()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let owner = self.owned_request(
                    _request,
                    Arc::new(_database),
                    None,
                    std::time::Duration::from_secs(2),
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        let mut tx = self
                            .database
                            .begin(deadline.into_std())
                            .await
                            .map_err(|_| RequestError::deadline())?;
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
                            .map_err(crate::application::authentication_error)?;

                        self.keys
                            .verify_csrf(&session.nonce, csrf)
                            .map_err(|_| RequestError::InvalidRequest)?;
                        tx.run(
                            &noxide_store::statements::accounts::DELETE_SESSION,
                            &[session.nonce.into()],
                        )
                        .await
                        .map_err(|_| RequestError::Rejected)?;
                        Self::finish_commit(&mut tx, ()).await
                    })
                    .await
            })
            .await
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
            .map_err(|_| RequestError::deadline())
    }
    async fn submission_identity(
        &self,
        tx: &mut Transaction,
        action: ActionCore<'_>,
        cookie: &str,
        submission: &str,
        csrf: &str,
        now: i64,
    ) -> Result<(Token, Token, auth::Principal)> {
        let op = manifest::operation(&self.manifest, action.first_operation())?;
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
                .map_err(crate::application::authentication_error)?;
            ensure!(token.subject == session.nonce, RequestError::InvalidRequest);
            self.keys
                .verify_csrf(&session.nonce, csrf)
                .map_err(|_| RequestError::InvalidRequest)?;
            Ok((token, session, principal))
        }
    }
    async fn edit_handover(
        &self,
        tx: &mut Transaction,
        receipt: &EditReceipt,
        route: Option<u32>,
    ) -> Result<Rendered> {
        let record = repository::load(tx, &self.manifest, receipt.resource, receipt.id).await?;
        if record
            .as_ref()
            .is_none_or(|r| r.incarnation != receipt.incarnation)
            || receipt.cap_version == 0
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
        let link = route
            .map(|route| {
                render::resolve(
                    &self.manifest,
                    &RouteRef {
                        params: Default::default(),
                        route,
                        target: Some(receipt.id),
                    },
                )
            })
            .transpose()?;
        render::capability_handover(Some(&secret), link.as_deref())
    }
    fn credentials(
        &self,
        action: &manifest::WebAction<'_>,
        session: &Token,
        now: i64,
        targets: BTreeMap<String, RecordTarget>,
        values: Fields,
    ) -> Result<FormCredentials> {
        let kind = if session.kind == TokenKind::Anonymous {
            TokenKind::AnonymousSubmission {
                contract: self.submission_contract(),
                action: action.id,
                version: action.version,
                targets,
            }
        } else {
            TokenKind::Submission {
                contract: self.submission_contract(),
                action: action.id,
                version: action.version,
                targets,
            }
        };
        let (_, submission) = self.keys.issue(kind, &session.nonce, now, 900)?;
        let upload_ticket = self
            .blobs
            .as_ref()
            .filter(|blobs| {
                blobs
                    .policy
                    .uploads
                    .iter()
                    .any(|u| u.web_binding == action.id)
            })
            .map(|_| self.upload_ticket(action.id, &submission))
            .transpose()?;
        Ok(FormCredentials {
            upload_ticket,
            selections: Default::default(),
            selected: Default::default(),
            csrf: self.keys.csrf(&session.nonce)?,
            submission,
            values,
        })
    }

    async fn target_allowed(
        &self,
        context: &mut repository::ReadContext<'_>,
        action: ActionCore<'_>,
        route: Option<u32>,
        stored: &StoredRecord,
    ) -> Result<bool> {
        if !context.unexpired(stored)? {
            return Ok(false);
        }
        let route = route
            .map(|id| manifest::route(&self.manifest, id))
            .transpose()?;
        for target in action
            .targets
            .iter()
            .filter(|target| matches!(target.source, TargetSource::Page { .. }))
        {
            let TargetSource::Page { reads } = &target.source else {
                unreachable!()
            };
            if target.resource != stored.record.resource {
                return Ok(false);
            }
            let mut permitted = false;
            for id in reads
                .iter()
                .filter(|id| route.is_none_or(|route| route.operations.contains(id)))
            {
                if repository::authorize_stored_read(
                    context,
                    manifest::operation(&self.manifest, *id)?,
                    stored,
                )
                .await?
                {
                    permitted = true;
                    break;
                }
            }
            if !permitted {
                return Ok(false);
            }
            for projection in [target.projection.as_ref(), target.inspect.as_ref()]
                .into_iter()
                .flatten()
            {
                if !repository::authorize_stored_read(
                    context,
                    manifest::operation(&self.manifest, projection.operation)?,
                    stored,
                )
                .await?
                {
                    return Ok(false);
                }
            }
            for step in action.steps {
                let op = manifest::operation(&self.manifest, step.operation)?;
                if matches!(&step.target, Target::Named(name) if name == &target.name)
                    && !manifest::is_capability(op)
                    && !context.authorize(op, stored).await?
                {
                    return Ok(false);
                }
                for assignment in step.assign.iter().filter(|_| action.steps.len() == 1) {
                    if matches!(&assignment.change, Change::Set(Value::Target(name)) if name == &target.name)
                    {
                        let eligible = manifest::operation(
                            &self.manifest,
                            *op.bind
                                .get(&assignment.field)
                                .ok_or(repository::ReferenceUnavailable)?,
                        )?;
                        if !repository::authorize_stored_read(context, eligible, stored).await?
                            || manifest::resource(&self.manifest, op.resource)?
                                .gate
                                .as_ref()
                                .is_some_and(|gate| gate.field == assignment.field)
                                && !manifest::gate_permits(
                                    manifest::resource(&self.manifest, op.resource)?,
                                    &stored.record.fields,
                                    true,
                                )
                        {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        Ok(route.is_none_or(|route| route.resource == Some(stored.record.resource)))
    }

    #[allow(clippy::too_many_arguments)]
    async fn forms(
        &self,
        tx: &mut Transaction,
        authority: &mut crate::authority::Authority,
        database_calls: &mut usize,
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
                *database_calls = database_calls
                    .checked_sub(2)
                    .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
                repository::load(tx, &self.manifest, resource, id).await?
            }
            _ => None,
        };
        let mut forms = BTreeMap::new();
        for id in &r.forms {
            let action = manifest::web_action(&self.manifest, *id)?;
            let op = manifest::operation(
                &self.manifest,
                ActionCore::of(action.core)?.first_operation(),
            )?;
            let subject = if manifest::anonymous_action(op) {
                anonymous
            } else {
                session
            };
            let principal = if manifest::anonymous_action(op) {
                &auth::Principal::Anonymous
            } else {
                principal
            };
            let Some(subject) = subject else {
                forms.insert(*id, None);
                continue;
            };
            let credentials = if manifest::signed_resource(&self.manifest, &action)?.is_some() {
                if let Some(record) = &stored {
                    if crate::expiry::available(
                        manifest::resource(&self.manifest, record.record.resource)?,
                        &record.record.fields,
                        authority.time(),
                    )? && ((manifest::is_capability(op) && record.cap_version.is_some())
                        || self
                            .target_allowed(
                                &mut repository::ReadContext {
                                    tx,
                                    manifest: &self.manifest,
                                    principal,
                                    authority,
                                    budget: repository::ReadBudget::Query(database_calls),
                                },
                                ActionCore::of(action.core)?,
                                Some(route),
                                record,
                            )
                            .await?)
                    {
                        let grant = RecordTarget {
                            resource: record.record.resource,
                            id: record.record.id,
                            incarnation: record.incarnation.clone(),
                            revision: record.revision,
                            route: Some(route),
                        };
                        let values = if manifest::is_capability(op) {
                            Fields::new()
                        } else {
                            self.action_values(&action, &record.record.fields)
                        };
                        Some(self.credentials(
                            &action,
                            subject,
                            now,
                            Self::page_grants(action.core, &grant),
                            values,
                        )?)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else if self
                .authorize_create(ActionCore::of(action.core)?, principal)
                .is_ok()
            {
                Some(self.credentials(&action, subject, now, BTreeMap::new(), Fields::new())?)
            } else {
                None
            };
            forms.insert(*id, credentials);
        }
        Ok(forms)
    }

    fn action_values(&self, action: &manifest::WebAction<'_>, fields: &Fields) -> Fields {
        action
            .steps
            .iter()
            .filter(|step| matches!(&step.target, Target::Named(name) if action.targets.iter().any(|target| target.name == *name && matches!(target.source, TargetSource::Page { .. }))))
            .flat_map(|step| &step.assign)
            .filter_map(|assignment| {
                let Change::Set(Value::Input(name)) = &assignment.change else {
                    return None;
                };
                fields
                    .get(&assignment.field)
                    .map(|value| (name.clone(), value.clone()))
            })
            .collect()
    }

    fn conflict(
        &self,
        action: &manifest::WebAction<'_>,
        session: &Token,
        now: i64,
        mut target: RecordTarget,
        stored: &StoredRecord,
        input: &Fields,
    ) -> Result<Rendered> {
        target.revision = stored.revision;
        let credentials = self.credentials(
            action,
            session,
            now,
            Self::page_grants(action.core, &target),
            Fields::new(),
        )?;
        let operation = manifest::operation(
            &self.manifest,
            ActionCore::of(action.core)?.first_operation(),
        )?;
        let current = if manifest::is_capability(operation) {
            Fields::new()
        } else if operation.kind == OperationKind::Delete {
            stored.record.fields.clone()
        } else {
            self.action_values(action, &stored.record.fields)
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
        cursor: Option<&str>,
    ) -> std::result::Result<Rendered, RequestError> {
        self.view_page_anonymous(cookie, None, route, target, cursor)
            .await
    }
    pub async fn view_page_anonymous(
        &self,
        cookie: Option<&str>,
        anonymous_cookie: Option<&str>,
        route: u32,
        target: Option<u64>,
        cursor: Option<&str>,
    ) -> std::result::Result<Rendered, RequestError> {
        self.view_page_parameters(
            cookie,
            anonymous_cookie,
            route,
            target,
            cursor,
            Fields::new(),
        )
        .await
    }

    pub async fn view_page_parameters(
        &self,
        cookie: Option<&str>,
        anonymous_cookie: Option<&str>,
        route: u32,
        target: Option<u64>,
        cursor: Option<&str>,
        params: Fields,
    ) -> std::result::Result<Rendered, RequestError> {
        let entry_scope = self.request_scope(self.runtime.limits().wall_time);
        entry_scope.run(async {
        let _request = self
            .admission_limits
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::deadline())?;
        let _database = self
            .admission_limits
            .database()
            .acquire()
            .await
            .map_err(|_| RequestError::deadline())?;
        if cursor.is_some_and(|c| c.len() > 4096) {
            return Err(RequestError::InvalidCursor);
        }
        let mut params = params;
        let route_definition = manifest::route(&self.manifest, route)
            .map_err(|_| RequestError::InvalidRequest)?;
        manifest::validate_params(&self.manifest, route_definition, &params)
            .map_err(|_| RequestError::InvalidRequest)?;
        for (name, field) in manifest::parameter_fields(&self.manifest, route_definition)
            .map_err(|_| RequestError::InvalidRequest)? {
            if matches!(field, manifest::ParameterField::Search) {
                let raw = params.get(&name).ok_or(RequestError::InvalidRequest)?;
                let tokens = crate::search::canonical_query(raw, &mut RequestScope::checkpoint_current)
                    .map_err(|_| RequestError::InvalidRequest)?;
                params.insert(name, tokens.tokens().join(" "));
            }
        }
        let reference = RouteRef {
            params: params.clone(),
            route,
            target,
        };
        render::resolve(&self.manifest, &reference).map_err(|_| RequestError::InvalidRequest)?;
        let owner = self.owned_request(
            _request,
            Arc::new(_database),
            None,
            self.runtime.limits().wall_time,
        );
        let deadline = owner.work_deadline();
        owner.run(async {

        timeout_at(deadline, async {
            let mut tx = self
                .database
                .begin_read(deadline.into_std())
                .await
                .map_err(|_| RequestError::deadline())?;
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
            let mut database_calls = crate::repository::MAX_LIST_DATABASE_CALLS;
            let time = if crate::authority::uses_time(&self.manifest) {
                database_calls = database_calls.checked_sub(1).ok_or(RequestError::Busy)?;
                Some(self.temporal_after_admission(&mut tx).await?)
            } else { None };
            let mut authority = self.authority_context(time).map_err(RequestError::database)?;
            let list = manifest::route(&self.manifest,route).map_err(|_| RequestError::InvalidRequest)?.operations.iter().filter_map(|id| manifest::operation(&self.manifest,*id).ok()).find(|op| op.kind==OperationKind::List && !manifest::is_preview(op));
            let scope_incarnation = if let (Some(target),Some(op)) = (target,list) {
                if let Some(parent)=op.scope.as_deref().map(|field| manifest::reference_resource(&self.manifest,op.resource,field)).transpose().map_err(|_| RequestError::Rejected)?.flatten() {
                    database_calls = database_calls.checked_sub(2).ok_or(RequestError::Busy)?;
                    crate::repository::load(&mut tx,&self.manifest,parent.id,target).await.map_err(RequestError::database)?.map(|r|r.incarnation)
                } else {None}
            } else {None};
            let subject=principal.user().map(|u|u.id.as_str()).unwrap_or("");
            let scope=cursor_scope((&self.contract,&self.deployment),route,target,scope_incarnation,list,subject,&params).map_err(|_|RequestError::Rejected)?;
            // A fixed-size digest binds every approved setting without exposing it in URLs.
            let scope=URL_SAFE_NO_PAD.encode(Sha256::digest(scope.as_bytes()));
            let preview_only = list.is_none() && manifest::route(&self.manifest, route).map_err(|_| RequestError::InvalidRequest)?.operations.iter().any(|id| manifest::operation(&self.manifest,*id).is_ok_and(manifest::is_preview));
            if preview_only && cursor.is_some() { return Err(RequestError::InvalidCursor); }
            let cursor = cursor.map(|encoded| {
                let token = self.keys.verify_cursor(encoded, now).map_err(|_| RequestError::InvalidCursor)?;
                let TokenKind::Cursor { scope: bound, after } = token.kind else { return Err(RequestError::InvalidCursor); };
                let op = list.ok_or(RequestError::InvalidCursor)?;
                if bound != scope { return Err(RequestError::InvalidCursor); }
                self.plans.get(&op.id).ok_or(RequestError::InvalidCursor)?
                    .validate_cursor(&self.manifest, &after).map_err(|_| RequestError::InvalidCursor)?;
                Ok(after)
            }).transpose()?;
            let needs_anonymous = manifest::route(&self.manifest, route).map_err(|_| RequestError::InvalidRequest)?.forms.iter().any(|id| manifest::web_action(&self.manifest,*id).ok().and_then(|a| ActionCore::of(a.core).ok()).and_then(|a| manifest::operation(&self.manifest,a.first_operation()).ok()).is_some_and(manifest::anonymous_action));
            let (anonymous, new_cookie) = if needs_anonymous {
                if let Some(token) = anonymous_cookie.and_then(|c| self.keys.anonymous(c, now).ok()) { (Some(token), None) }
                else { let (token,cookie) = self.keys.issue(TokenKind::Anonymous, "", now, security::ANONYMOUS_TTL).map_err(|_| RequestError::Rejected)?; (Some(token),Some(cookie)) }
            } else { (None,None) };
            let mut forms = self.forms(&mut tx, &mut authority, &mut database_calls, route, target, session.as_ref(), anonymous.as_ref(), &principal, now).await.map_err(|_| RequestError::Rejected)?;
            let request = RequestView {
                params: params.clone(),
                available_forms: forms
                    .iter()
                    .filter_map(|(id, form)| form.as_ref().map(|_| *id))
                    .collect(),
                version: VERSION,
                kind: RequestKind::Route(route),
                target,
                input: Fields::new(),
                inspection: BTreeMap::new(),
            };
            let effects = Effects {
                authority,
                upload: None,
                blob_reads: Default::default(),
                provenance: Default::default(),
                follow_sources: Vec::new(),
                invoked: Default::default(),
                list_bytes: 0,
                list_calls: database_calls,
                result_limit: noxide_protocol::MAX_RESULT_BYTES,
                truncated: false,
                see_all: Vec::new(),
                plans: self.plans.clone(),
                tx,
                manifest: self.manifest.clone(),
                principal,
                request: request.clone(),
                grants: BTreeMap::new(),
                target_rows: BTreeMap::new(),
                written_rows: Default::default(),
                capability_grant: None,
                calls: 16,
                cursor,
                more: None,
            };
            let _wasm = self
                .admission_limits
                .wasm()
                .acquire()
                .await
                .map_err(|_| RequestError::deadline())?;
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
            let response = attempt
                .result
                .map_err(|error| RequestError::database(guest_error(error)))?;
            if !matches!(
                response,
                ResponseIntent::Page(_) | ResponseIntent::NotFound(_) | ResponseIntent::Redirect(_)
            ) {
                return Err(RequestError::Rejected);
            }
            let next_page = effects.more.take().map(|after| {
                let (_,encoded)=self.keys.issue(TokenKind::Cursor {scope:scope.clone(),after},"",now,900).map_err(|_|RequestError::Rejected)?;
                let path = crate::routing::resolve(&self.manifest,&reference).expect("validated route");
                Ok(format!("{path}{}cursor={encoded}", if params.is_empty() { "?" } else { "&" }))
            }).transpose()?;
            self.complete_target_forms(&mut effects, &response, &mut forms, session.as_ref(), anonymous.as_ref(), now).await.map_err(RequestError::database)?;
            let mut rendered = render::render(
                &response,
                &RenderContext {
                    checkpoint: RequestScope::checkpoint_current,
                    presentation: &self.presentation,
                    assets: &self.assets,
                    manifest: Some(&self.manifest),
                    forms,
                    logout_csrf: session
                        .as_ref()
                        .map(|session| self.keys.csrf(&session.nonce))
                        .transpose()
                        .map_err(|_| RequestError::Busy)?,
                    next_page,
                    preview_links: effects.see_all.clone(),
                    downloads: self.download_links(&effects, session.as_ref(), now).map_err(RequestError::database)?,
                },
            )
            .map_err(RequestError::database)?;
            if let ResponseIntent::Page(doc) | ResponseIntent::NotFound(doc) = &response
                && doc.nodes.iter().any(|n| matches!(n, Instruction::Form { action } if manifest::web_action(&self.manifest,*action).ok().and_then(|a| ActionCore::of(a.core).ok()).and_then(|a| manifest::operation(&self.manifest,a.first_operation()).ok()).is_some_and(manifest::anonymous_action))) { rendered.anonymous_cookie = new_cookie; }
            Self::finish_commit(&mut effects.tx, rendered).await
        })
        .await
        .map_err(|_| RequestError::deadline())?
        }).await
        }).await
    }
}

#[cfg(test)]
mod clock_tests;

#[cfg(test)]
mod identity_time_tests;

#[cfg(test)]
mod deadline_tests;

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
                .map_err(crate::application::authentication_error)?,
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
