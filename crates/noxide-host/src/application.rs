#[cfg(test)]
use crate::auth::AccountAdmin as _;
mod accounts;
mod action;
mod authority;
pub(crate) mod blobs;
use crate::database::lifecycle::{AdmissionOwner, Registry, RequestScope};
pub(crate) use action::ActionCore;
pub use action::{ActionRejection, ValidatedActionRejection};
use action::{CanonicalActionInput, ExecutionBudget};
mod capabilities;
pub(crate) mod clock;
mod effect_worker;
mod effects;
mod forms;
mod guests;
mod jobs;
mod navigation;
mod page;
mod state;
mod submission;
pub use accounts::LoginChallenge;
pub use jobs::JobRunOutcome;
mod job_selection;
pub(crate) mod job_worker;
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

pub struct Application {
    pub(crate) identity: state::Identity,
    pub(crate) web: state::Web,
    pub(crate) limits: state::RequestLimits,
    pub(crate) services: state::Services,
    time: state::Time,
    pub(crate) keys: Arc<HostKeys>,
    database: Database,
    runtime: guests::Guests,
    pub(crate) request_lifecycle: Arc<Registry>,
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

impl Application {
    #[cfg(feature = "test-support")]
    pub fn test_database(&self) -> &Database {
        &self.database
    }

    #[cfg(feature = "test-support")]
    pub fn test_clock(&self) -> &AtomicI64 {
        &self.time.observed
    }

    #[cfg(feature = "test-support")]
    pub fn test_maintenance(&self) -> &Arc<tokio::sync::Semaphore> {
        &self.time.maintenance
    }

    #[cfg(feature = "test-support")]
    pub fn test_maintenance_running(&self) -> &std::sync::atomic::AtomicBool {
        &self.time.maintenance_running
    }

    /// Key access for tests of signed values; a deployed binary has no such route.
    #[cfg(feature = "test-support")]
    pub fn test_keys(&self) -> &Arc<HostKeys> {
        &self.keys
    }

    #[cfg(feature = "test-support")]
    pub async fn test_reconcile_blobs(&self, deadline: Instant) -> Result<()> {
        self.reconcile_blobs(deadline).await
    }

    #[cfg(feature = "test-support")]
    pub async fn test_temporal_attempt(
        &self,
        tx: &mut Transaction,
    ) -> std::result::Result<crate::lifecycle_clock::AttemptTime, RequestError> {
        self.temporal_attempt(tx).await
    }

    #[cfg(feature = "test-support")]
    pub async fn test_admission_owner(&self) -> std::result::Result<AdmissionOwner, RequestError> {
        Ok(self.admit_invocation(false).await?.owner)
    }

    /// The admitted manifest.
    pub fn manifest(&self) -> &Arc<Manifest> {
        &self.identity.manifest
    }
    pub fn presentation(&self) -> &crate::Presentation {
        &self.web.presentation
    }
    pub fn registration(&self) -> auth::Registration {
        self.web.registration
    }
    pub fn assets(&self) -> &Arc<crate::assets::AssetBundle> {
        &self.web.assets
    }
    /// Bounds how many asset responses are streaming at once.
    pub fn asset_responses(&self) -> &Arc<tokio::sync::Semaphore> {
        &self.web.asset_responses
    }
    pub fn admission_limits(&self) -> &AdmissionLimits {
        &self.limits.admission
    }
    /// The blob runtime, when this deployment approved blobs.
    pub fn blobs(&self) -> Option<&blobs::BlobRuntime> {
        self.services.blobs.as_ref()
    }

    pub fn request_lifecycle(&self) -> Arc<Registry> {
        self.request_lifecycle.clone()
    }
    fn request_scope(&self, cap: std::time::Duration) -> RequestScope {
        RequestScope::current_or_new(
            self.request_lifecycle.clone(),
            cap,
            self.limits.database_statements,
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
    /// The root scope for one HTTP request. `cap` is `None` for the guest's wall time.
    pub fn http_request_scope(
        &self,
        cap: Option<std::time::Duration>,
        outer: Option<crate::limiter::TransportDeadline>,
    ) -> RequestScope {
        let cap = cap.unwrap_or(self.runtime.limits().wall_time);
        let outer = outer.map_or_else(|| Instant::now() + cap, |outer| outer.0);
        RequestScope::new(
            self.request_lifecycle.clone(),
            outer,
            cap,
            self.limits.database_statements,
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
        self.limits.database_statements = limit;
        Ok(self)
    }
    /// Operator restore fencing only: activation may adopt an effect queue copied
    /// from another owner directory, pausing every capture in the same transaction.
    pub fn with_restore_fork(mut self) -> Self {
        self.restore_fork = true;
        self
    }
    pub fn with_registration(mut self, registration: auth::Registration) -> Self {
        self.web.registration = registration;
        self
    }
    pub fn with_signed_in_reserve(mut self, reserve: u8) -> Result<Self> {
        self.request_lifecycle.ensure_idle()?;
        ensure!(reserve <= 50, "signed_in_reserve must be between 0 and 50");
        self.limits.admission = AdmissionLimits::new(
            reserve,
            self.identity
                .manifest
                .routes
                .iter()
                .any(|r| r.access != noxide_protocol::Access::Public),
        )
        .with_wasm_capacity(self.runtime.limits().concurrency);
        Ok(self)
    }

    /// Validate persisted schema compatibility before accepting any traffic.
    /// Data requests repeat this fence inside their transaction.
    async fn admission(&self, tx: &mut Transaction, activate: bool) -> Result<()> {
        tx.check_storage().await?;
        tx.check_schema(&self.identity.manifest).await?;
        let generation = tx
            .deployment(&self.identity.deployment, self.keys.incarnation(), activate)
            .await?;
        ensure!(
            self.identity.generation.get() == Some(&generation),
            "application is unactivated or retired"
        );
        Ok(())
    }

    async fn observe_clock_write(&self, tx: &mut Transaction, now: i64) -> Result<i64> {
        // Check raw wall time against both watermarks before substituting the
        // effective time. Only the clock tick persists the mark.
        let effective = security::observe_clock_bounded(tx, now, &self.time.observed).await?;
        self.time.observed.fetch_max(effective, Ordering::Relaxed);
        Ok(effective)
    }

    #[cfg(test)]
    pub(crate) async fn checkpoint_clock(&self) -> Result<()> {
        let m = self.time.observed.load(Ordering::Relaxed);
        if m <= self.time.checkpointed.load(Ordering::Relaxed) {
            return Ok(());
        }
        let deadline = Instant::now() + security::CLOCK_CHECKPOINT_BEGIN_DEADLINE;
        timeout_at(deadline, async {
            let _maintenance = self.time.maintenance.try_acquire()?;
            let mut tx = self.database.begin(deadline.into_std()).await?;
            self.admission(&mut tx, false).await?;
            tx.execute(
                "UPDATE nx_clock SET observed=$1 WHERE singleton=1 AND observed<$1",
                &[m.into()],
            )
            .await?;
            tx.commit().await?;
            self.time.checkpointed.fetch_max(m, Ordering::Relaxed);
            Ok(())
        })
        .await?
    }

    fn submission_contract(&self) -> String {
        format!(
            "{}:{}",
            self.identity.contract,
            self.identity
                .generation
                .get()
                .expect("admission precedes token use")
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
            web: state::Web {
                presentation: crate::Presentation::default(),
                assets: Arc::new(resources.assets),
                asset_responses: Arc::new(tokio::sync::Semaphore::new(8)),
                registration: auth::Registration::Closed,
            },
            services: state::Services {
                blobs,
                jobs: approval.effective_jobs.map(job_worker::JobRuntime::new),
                effects: approval
                    .effective_effects
                    .map(effect_worker::EffectRuntime::new),
            },
            identity: state::Identity {
                plans: crate::query_plan::compile_all(&m)?,
                manifest: Arc::new(m),
                contract: URL_SAFE_NO_PAD.encode(digest),
                deployment,
                generation: OnceLock::new(),
            },
            time: state::Time {
                observed: AtomicI64::new(0),
                checkpointed: AtomicI64::new(0),
                freshness: crate::lifecycle_clock::Freshness::default(),
                maintenance: Arc::new(tokio::sync::Semaphore::new(1)),
                maintenance_running: std::sync::atomic::AtomicBool::new(false),
            },
            limits: state::RequestLimits {
                admission: admission_limits,
                database_statements: 256,
            },
            keys: Arc::new(keys),
            database,
            runtime,
            request_lifecycle: Arc::new(Registry::default()),
            restore_fork: false,
            #[cfg(any(test, feature = "test-support"))]
            postcommit_barrier: std::sync::Mutex::new(None),
        })
    }

    /// Configure trusted HTTP presentation before sharing or activating the application.
    pub fn with_presentation(mut self, presentation: crate::Presentation) -> Result<Self> {
        presentation.validate(&self.identity.manifest)?;
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
        self.web.presentation = presentation;
        Ok(self)
    }

    async fn anonymous_write(
        &self,
        required: bool,
    ) -> std::result::Result<Option<tokio::sync::OwnedSemaphorePermit>, RequestError> {
        if !required {
            return Ok(None);
        }
        if !self.limits.admission.anonymous_write_attempts.allow() {
            return Err(RequestError::Busy);
        }
        self.limits
            .admission
            .anonymous_writes
            .acquire()
            .await
            .map(Some)
            .map_err(|_| RequestError::deadline())
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
