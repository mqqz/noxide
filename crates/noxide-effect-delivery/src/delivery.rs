//! Effect delivery, run outside the serving process. It holds the store, the
//! effect tables, the secret paths and the Tor proxy address; it holds no host
//! keys, no guest runtime, no blob store and no listener.
//! Delivery has a separate 30-second host invocation, never a guest executor.
//! All phases share its deadline, logical allowance and native statement meter.
use crate::{
    owner::{DeliveryOwner, OwnerLease, PhysicalAttempt},
    transport, worker,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_admission::manifest;
use noxide_effects::{
    DeliveryResult, EffectClaim, Finalized, OutboxContext, Preflight,
    directory::DirectoryPreparation,
    effect_deployment::{EffectDeployment, EffectiveEffectDeployment},
};
use noxide_protocol::Manifest;
use noxide_store::{
    Database,
    database::{
        MaintenanceLease, MaintenanceUncertain, RequestError, Transaction,
        lifecycle::{AdmissionOwner, Registry, RequestScope},
    },
    lifecycle_clock::{self, AttemptTime},
};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectRunOutcome {
    Delivered,
    Retrying(noxide_protocol::time::Timestamp),
    Dead,
    Paused,
    Superseded,
}
impl From<Finalized> for EffectRunOutcome {
    fn from(value: Finalized) -> Self {
        match value {
            Finalized::Delivered => Self::Delivered,
            Finalized::Retrying(at) => Self::Retrying(at),
            Finalized::Dead => Self::Dead,
            Finalized::Paused => Self::Paused,
            Finalized::Superseded => Self::Superseded,
        }
    }
}

pub struct LeasePreparation {
    started: AtomicBool,
    result: OnceLock<std::result::Result<Arc<OwnerLease>, ()>>,
    changed: tokio::sync::Notify,
}
pub struct DeliveryRuntime {
    pub effective: EffectiveEffectDeployment,
    pub directory: Arc<DirectoryPreparation>,
    lease: Arc<LeasePreparation>,
    database: Arc<Semaphore>,
    pub lifecycle: Arc<Registry>,
    pub owner: Mutex<Option<Arc<DeliveryOwner>>>,
    running: AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    pub test_roots: Mutex<Option<rustls::RootCertStore>>,
}
impl DeliveryRuntime {
    fn new(effective: EffectiveEffectDeployment) -> Self {
        let concurrency = usize::from(effective.limits.worker_concurrency);
        Self {
            effective,
            directory: DirectoryPreparation::new(),
            lease: Arc::new(LeasePreparation {
                started: AtomicBool::new(false),
                result: OnceLock::new(),
                changed: tokio::sync::Notify::new(),
            }),
            database: Arc::new(Semaphore::new(concurrency)),
            lifecycle: Arc::new(Registry::default()),
            owner: Mutex::new(None),
            running: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            test_roots: Mutex::new(None),
        }
    }
    pub fn delivery_owner(&self) -> Result<Arc<DeliveryOwner>> {
        let mut current = self.owner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(owner) = current.as_ref() {
            return Ok(owner.clone());
        }
        let lease = self
            .lease
            .result
            .get()
            .context("effect database binding not activated")?
            .as_ref()
            .map_err(|_| anyhow::anyhow!("effect owner preparation failed"))?
            .clone();
        let proxy = transport::TorProxy::loopback(self.effective.tor_proxy)
            .map_err(|_| anyhow::anyhow!("invalid effect Tor proxy"))?;
        let transport = transport::Transport::new(proxy);
        #[cfg(any(test, feature = "test-support"))]
        let transport = match self
            .test_roots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            Some(roots) => transport::Transport::with_test_roots(proxy, roots.clone()),
            None => transport,
        };
        let owner =
            DeliveryOwner::claim(lease, self.effective.limits.worker_concurrency, transport)?;
        *current = Some(owner.clone());
        Ok(owner)
    }
    pub fn release_owner(&self, owner: Arc<DeliveryOwner>) {
        let mut current = self.owner.lock().unwrap_or_else(|e| e.into_inner());
        if current
            .as_ref()
            .is_some_and(|stored| Arc::ptr_eq(stored, &owner))
            && Arc::strong_count(&owner) == 2
        {
            // Drop both final Arcs while this mutex prevents claiming the same
            // prepared file description before the old owner unlocks it.
            drop(current.take());
            drop(owner);
        }
    }
}

/// What a PostgreSQL role needs to run delivery, for `ROLE` in these templates.
/// It excludes accounts, records, sessions, blobs and jobs. SQLite has no roles:
/// a worker on SQLite can read the whole database file.
pub const POSTGRES_WORKER_GRANTS: &[&str] = &[
    "GRANT SELECT ON nx_storage,nx_schema_definition,nx_resource_catalog,nx_deployment,nx_job_runtime,nx_effect_grants,nx_effect_secrets TO ROLE",
    // A shared row lock needs UPDATE on some column. `singleton` is fixed by a check;
    // rewriting a grant's `deployment` can only make that grant stop matching.
    "GRANT UPDATE (singleton) ON nx_job_runtime,nx_deployment TO ROLE",
    "GRANT UPDATE (deployment) ON nx_effect_grants,nx_effect_secrets TO ROLE",
    "GRANT SELECT,UPDATE ON nx_clock,nx_effect_queue,nx_effect_tenants,nx_outbox TO ROLE",
];

/// The delivery half of an approved deployment.
pub struct EffectDelivery {
    database: Database,
    manifest: Arc<Manifest>,
    deployment: String,
    contract: String,
    generation: OnceLock<String>,
    statement_limit: u16,
    clock: AtomicI64,
    lifecycle_clock: lifecycle_clock::Freshness,
    maintenance: Arc<Semaphore>,
    pub runtime: DeliveryRuntime,
}
impl EffectDelivery {
    /// Validate the approved contract without host keys or compiling the guest.
    pub fn new(
        component: &[u8],
        declarations: &[u8],
        approved: [u8; 32],
        database: Database,
        effects: EffectDeployment,
    ) -> Result<Self> {
        let manifest = manifest::parse(declarations)?;
        // Blob ceilings and job approvals bind only the digest, supplied by the
        // caller, and are verified by the CLI's approval check before this call.
        let effective =
            effects.effective(manifest.effects.as_ref().context("no declared effects")?)?;
        let mut identity = Sha256::new();
        identity.update(approved);
        identity.update(Sha256::digest(component));
        Ok(Self::from_parts(
            database,
            Arc::new(manifest),
            URL_SAFE_NO_PAD.encode(identity.finalize()),
            URL_SAFE_NO_PAD.encode(approved),
            effective,
            256,
        ))
    }
    pub fn from_parts(
        database: Database,
        manifest: Arc<Manifest>,
        deployment: String,
        contract: String,
        effective: EffectiveEffectDeployment,
        statement_limit: u16,
    ) -> Self {
        Self {
            database,
            manifest,
            deployment,
            contract,
            generation: OnceLock::new(),
            statement_limit,
            clock: AtomicI64::new(0),
            lifecycle_clock: lifecycle_clock::Freshness::default(),
            maintenance: Arc::new(Semaphore::new(1)),
            runtime: DeliveryRuntime::new(effective),
        }
    }
    pub fn with_database_statement_limit(mut self, limit: u16) -> Result<Self> {
        ensure!(
            (1..=256).contains(&limit),
            "database statement limit must be between 1 and 256"
        );
        self.statement_limit = limit;
        Ok(self)
    }

    /// Join a deployment the serving process activated. Writes no deployment
    /// state: a worker cannot supersede, bind or migrate anything.
    pub async fn activate(&self) -> Result<()> {
        // Another process's clock tick can hold the write lock for one attempt.
        let mut attempts = 10;
        loop {
            match self.activate_once().await {
                Err(_) if attempts > 1 => attempts -= 1,
                result => return result,
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    async fn activate_once(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        timeout_at(deadline, async {
            let runtime = &self.runtime;
            DirectoryPreparation::prepare(
                &runtime.directory,
                &runtime.effective,
                deadline.into_std(),
            )
            .await?;
            let permit = self.maintenance.clone().try_acquire_owned()?;
            let mut lease =
                MaintenanceLease::new(permit, deadline.into_std(), self.lifecycle_clock.clone());
            lease.begin(&self.database).await?;
            let tx = lease.tx();
            tx.check_storage().await?;
            tx.check_schema(&self.manifest).await?;
            let generation = tx.deployment_generation(&self.deployment).await?;
            let outcome = lifecycle_clock::tick(tx, &self.clock).await;
            lease.finish().await?;
            let tick = outcome?;
            self.activate_lease(deadline.into_std()).await?;
            ensure!(
                self.generation.get_or_init(|| generation.clone()) == &generation,
                "effect delivery generation changed"
            );
            self.publish_clock(tick)
        })
        .await?
    }
    /// Wait for cleanup that startup transactions left running, so the runtime
    /// that activated this delivery can stop without abandoning provider work.
    pub async fn settled(&self) -> Result<()> {
        self.runtime.lifecycle.drain().await
    }
    fn publish_clock(&self, tick: lifecycle_clock::CommittedTick) -> Result<()> {
        let seconds = tick.credential_seconds;
        self.lifecycle_clock.committed(tick)?;
        self.clock.fetch_max(seconds, Ordering::Relaxed);
        Ok(())
    }
    async fn tick_clock(&self) -> Result<()> {
        let deadline = Instant::now() + lifecycle_clock::CLOCK_CHECKPOINT_BEGIN_DEADLINE;
        let permit = self.maintenance.clone().try_acquire_owned()?;
        let mut lease =
            MaintenanceLease::new(permit, deadline.into_std(), self.lifecycle_clock.clone());
        lease.begin(&self.database).await?;
        let outcome = async {
            self.admission(lease.tx()).await?;
            lifecycle_clock::tick(lease.tx(), &self.clock).await
        }
        .await;
        lease.finish().await?;
        self.publish_clock(outcome?)
    }
    async fn admission(&self, tx: &mut Transaction) -> Result<()> {
        tx.check_storage().await?;
        tx.check_schema(&self.manifest).await?;
        let generation = tx.deployment_generation(&self.deployment).await?;
        ensure!(
            self.generation.get() == Some(&generation),
            "effect delivery is unactivated or retired"
        );
        Ok(())
    }
    async fn temporal_attempt(
        &self,
        tx: &mut Transaction,
    ) -> std::result::Result<AttemptTime, RequestError> {
        self.admission(tx).await.map_err(RequestError::database)?;
        self.lifecycle_clock
            .attempt(tx)
            .await
            .map_err(|_| RequestError::Busy)
    }
    /// Deliver until `shutdown` resolves, keeping this process's durable clock
    /// fresh. Provider work is drained before return.
    pub async fn serve(
        self: &Arc<Self>,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<()> {
        let service = self.start_effect_service()?;
        let mut ticks = tokio::time::interval(lifecycle_clock::TICK_INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(shutdown);
        let result = loop {
            tokio::select! {biased;
                _ = &mut shutdown => break Ok(()),
                _ = ticks.tick() => {}
            }
            if let Err(error) = self.tick_clock().await
                && error.is::<MaintenanceUncertain>()
            {
                self.lifecycle_clock.quarantine();
                break Err(error);
            }
        };
        let stopped = service.shutdown().await;
        result?;
        stopped
    }

    /// This binds/open-prepares the lock file, but takes no exclusive ownership.
    /// A live operator App can activate while another App delivers effects.
    async fn activate_lease(&self, deadline: std::time::Instant) -> Result<()> {
        let runtime = &self.runtime;
        let mut tx = self.database.begin_read(deadline).await?;
        let rows = tx
            .rows(&noxide_store::statements::effects::QUEUE_OWNER, &[])
            .await?;
        let [store_id, directory_digest] =
            rows.first().context("effect database binding missing")?;
        ensure!(
            directory_digest == runtime.directory.digest()?,
            "effect owner directory changed"
        );
        let store_id = store_id.clone();
        tx.commit().await?;
        let directory = runtime.directory.prepared()?.clone();
        let state = runtime.lease.clone();
        if state
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let worker = state.clone();
            tokio::task::spawn_blocking(move || {
                let result = OwnerLease::open(directory, &store_id, deadline)
                    .map(Arc::new)
                    .map_err(|_| ());
                let _ = worker.result.set(result);
                worker.changed.notify_waiters();
            });
        }
        loop {
            let changed = state.changed.notified();
            if let Some(result) = state.result.get() {
                return result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|_| anyhow::anyhow!("effect owner file preparation failed"));
            }
            timeout_at(deadline.into(), changed)
                .await
                .context("effect owner file preparation deadline")?;
        }
    }
    pub fn effect_request_scope(&self) -> std::result::Result<RequestScope, RequestError> {
        let runtime = &self.runtime;
        Ok(RequestScope::current_or_new(
            runtime.lifecycle.clone(),
            Duration::from_secs(30),
            self.statement_limit,
        ))
    }
    async fn admit_effect_database(
        &self,
        scope: &RequestScope,
        physical: &PhysicalAttempt,
    ) -> std::result::Result<AdmissionOwner, RequestError> {
        let runtime = &self.runtime;
        let database = timeout_at(
            scope.work_deadline(),
            runtime.database.clone().acquire_owned(),
        )
        .await
        .map_err(|_| RequestError::Busy)?
        .map_err(|_| RequestError::Busy)?;
        Ok(AdmissionOwner::new(
            scope.clone(),
            physical.request(),
            Arc::new(database),
            None,
        ))
    }
    pub async fn claim_effect(
        &self,
        scope: &RequestScope,
        physical: &PhysicalAttempt,
        owner: &Arc<DeliveryOwner>,
        calls: &mut u32,
    ) -> std::result::Result<Option<EffectClaim>, RequestError> {
        // Keep the real active-ID snapshot serialized until this claim is
        // registered. A forward wall jump cannot admit its live socket twice.
        let _claim = timeout_at(scope.work_deadline(), owner.claim_lock.lock())
            .await
            .map_err(|_| RequestError::Busy)?;
        let admission = self.admit_effect_database(scope, physical).await?;
        admission
            .run(async {
                let mut tx = self
                    .database
                    .begin(admission.work_deadline().into_std())
                    .await
                    .map_err(RequestError::database)?;
                *calls = calls.checked_sub(1).ok_or(RequestError::Rejected)?;
                let now = self.temporal_attempt(&mut tx).await?.timestamp();
                let generation = self.generation.get().ok_or(RequestError::Busy)?;
                let owner_directory = self
                    .runtime
                    .directory
                    .digest()
                    .map_err(RequestError::database)?;
                let claim = OutboxContext { tx: &mut tx, calls }
                    .claim(
                        generation,
                        &self.contract,
                        owner_directory,
                        now,
                        &owner.active_claims(),
                    )
                    .await
                    .map_err(RequestError::database)?;
                if let Some(claim) = &claim {
                    physical.mark_claim(claim.id());
                }
                tx.finish_commit(claim).await
            })
            .await
    }
    pub async fn preflight_effect(
        &self,
        scope: &RequestScope,
        physical: &PhysicalAttempt,
        claim: &EffectClaim,
        calls: &mut u32,
    ) -> std::result::Result<Preflight, RequestError> {
        let admission = self.admit_effect_database(scope, physical).await?;
        admission
            .run(async {
                let mut tx = self
                    .database
                    .begin(admission.work_deadline().into_std())
                    .await
                    .map_err(RequestError::database)?;
                *calls = calls.checked_sub(1).ok_or(RequestError::Rejected)?;
                let now = self.temporal_attempt(&mut tx).await?.timestamp();
                let ready = OutboxContext { tx: &mut tx, calls }
                    .preflight(claim, now)
                    .await
                    .map_err(RequestError::database)?;
                tx.finish_commit(ready).await
            })
            .await
    }
    /// Best-effort return of a claim whose preflight failed; lease expiry
    /// remains the fallback when this transaction cannot commit either.
    async fn release_effect(
        &self,
        scope: &RequestScope,
        physical: &PhysicalAttempt,
        claim: &EffectClaim,
        calls: &mut u32,
    ) -> std::result::Result<(), RequestError> {
        let admission = self.admit_effect_database(scope, physical).await?;
        admission
            .run(async {
                let mut tx = self
                    .database
                    .begin(admission.work_deadline().into_std())
                    .await
                    .map_err(RequestError::database)?;
                *calls = calls.checked_sub(1).ok_or(RequestError::Rejected)?;
                OutboxContext { tx: &mut tx, calls }
                    .release_unsent(claim)
                    .await
                    .map_err(RequestError::database)?;
                tx.finish_commit(()).await
            })
            .await
    }
    pub async fn finalize_effect(
        &self,
        scope: &RequestScope,
        physical: &PhysicalAttempt,
        claim: &EffectClaim,
        calls: &mut u32,
        result: DeliveryResult,
    ) -> std::result::Result<EffectRunOutcome, RequestError> {
        let admission = self.admit_effect_database(scope, physical).await?;
        admission
            .run(async {
                let mut tx = self
                    .database
                    .begin(admission.work_deadline().into_std())
                    .await
                    .map_err(RequestError::database)?;
                *calls = calls.checked_sub(1).ok_or(RequestError::Rejected)?;
                let now = self.temporal_attempt(&mut tx).await?.timestamp();
                let outcome = OutboxContext { tx: &mut tx, calls }
                    .finalize(claim, now, result)
                    .await
                    .map_err(RequestError::database)?;
                tx.finish_commit(outcome.into()).await
            })
            .await
    }
    async fn run_effect_owned(
        &self,
        owner: &Arc<DeliveryOwner>,
    ) -> std::result::Result<Option<EffectRunOutcome>, RequestError> {
        let scope = self.effect_request_scope()?;
        let physical = owner
            .try_attempt(scope.deadline())
            .map_err(|_| RequestError::Busy)?;
        let result = scope
            .run(async {
                let mut calls = 16;
                let Some(claim) = self
                    .claim_effect(&scope, &physical, owner, &mut calls)
                    .await?
                else {
                    return Ok(None);
                };
                let prepared = match self
                    .preflight_effect(&scope, &physical, &claim, &mut calls)
                    .await
                {
                    Ok(Preflight::Send(prepared)) => prepared,
                    Ok(Preflight::Settled(outcome)) => return Ok(Some(outcome.into())),
                    Err(error) => {
                        // Nothing was sent. Without this, a transient failure such
                        // as a serialization conflict strands the row for its lease.
                        let _ = self
                            .release_effect(&scope, &physical, &claim, &mut calls)
                            .await;
                        return Err(error);
                    }
                };
                let runtime = &self.runtime;
                let deadline = scope
                    .work_deadline()
                    .checked_sub(Duration::from_secs(2))
                    .ok_or(RequestError::Busy)?;
                if Instant::now() >= deadline {
                    return Err(RequestError::Busy);
                }
                // No transaction is live across secret reads or transport work.
                let secret = if let Some(slot) = &prepared.captured.binding().endpoint.secret_slot {
                    let path = runtime
                        .effective
                        .secrets
                        .iter()
                        .find(|s| &s.slot == slot)
                        .ok_or(RequestError::Rejected)?
                        .path
                        .clone();
                    let hold = physical.native_hold();
                    let worker = tokio::task::spawn_blocking(move || {
                        crate::owner::read_secret(&path, deadline.into_std(), hold)
                    });
                    match timeout_at(deadline, worker).await {
                        Ok(Ok(Ok(secret))) => Some(secret),
                        _ => {
                            return self
                                .finalize_effect(
                                    &scope,
                                    &physical,
                                    &claim,
                                    &mut calls,
                                    DeliveryResult::Retry {
                                        retry_after_seconds: None,
                                    },
                                )
                                .await
                                .map(Some);
                        }
                    }
                } else {
                    None
                };
                let capture = &prepared.captured;
                let endpoint = transport::Endpoint::checked(
                    &capture.binding().host,
                    capture.binding().port,
                    &capture.binding().path,
                )
                .map_err(|_| RequestError::Rejected)?;
                let body = transport::JsonBody::checked(capture.body().to_vec())
                    .map_err(|_| RequestError::Rejected)?;
                let key = transport::IdempotencyKey::from_host(
                    capture.receiver_key().map_err(RequestError::database)?,
                )
                .map_err(|_| RequestError::Rejected)?;
                let result = owner
                    .transport
                    .post(&endpoint, &body, &key, secret.as_ref(), deadline)
                    .await;
                let delivery = worker::classify(result);
                self.finalize_effect(&scope, &physical, &claim, &mut calls, delivery)
                    .await
                    .map(Some)
            })
            .await;
        // This waits for actual file/provider stop using the admitted original
        // outer deadline. Unknown stop retains its slot and owner permanently.
        physical.finish().await.map_err(RequestError::database)?;
        result
    }
    pub async fn run_effect_once(
        &self,
    ) -> std::result::Result<Option<EffectRunOutcome>, RequestError> {
        let runtime = &self.runtime;
        runtime
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RequestError::Busy)?;
        struct Running<'a>(&'a AtomicBool);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _running = Running(&runtime.running);
        runtime
            .lifecycle
            .ensure_idle()
            .map_err(RequestError::database)?;
        let owner = runtime.delivery_owner().map_err(RequestError::database)?;
        let result = self.run_effect_owned(&owner).await;
        owner.drain().await.map_err(RequestError::database)?;
        runtime.release_owner(owner);
        result
    }
    pub fn start_effect_service(self: &Arc<Self>) -> Result<EffectService> {
        let runtime = &self.runtime;
        ensure!(
            self.generation.get().is_some(),
            "application is not activated"
        );
        runtime.lifecycle.ensure_idle()?;
        runtime
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("effect service already running"))?;
        let owner = match runtime.delivery_owner() {
            Ok(owner) => owner,
            Err(e) => {
                runtime.running.store(false, Ordering::Release);
                return Err(e);
            }
        };
        let (stop, stopping) = tokio::sync::watch::channel(false);
        let concurrency = runtime.effective.limits.worker_concurrency;
        let app = self.clone();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..concurrency {
                let app = app.clone();
                let owner = owner.clone();
                let mut stopping = stopping.clone();
                tasks.spawn(async move {
                    let mut poll = tokio::time::interval(Duration::from_secs(1));
                    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tokio::select! {biased; _=stopping.changed()=>return,_=poll.tick()=>{}}
                        if *stopping.borrow() {
                            return;
                        }
                        let _ = app.run_effect_owned(&owner).await;
                    }
                });
            }
            let mut failed = false;
            while let Some(result) = tasks.join_next().await {
                failed |= result.is_err();
            }
            let runtime = &app.runtime;
            let physical = owner.drain().await;
            let providers = runtime.lifecycle.shutdown().await;
            physical?;
            providers?;
            ensure!(!failed, "effect worker task failed");
            runtime.release_owner(owner);
            runtime.running.store(false, Ordering::Release);
            Ok(())
        });
        Ok(EffectService {
            stop: Some(stop),
            task: Some(task),
        })
    }
}
pub struct EffectService {
    stop: Option<tokio::sync::watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl EffectService {
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        self.task.take().expect("effect supervisor").await?
    }
}
impl Drop for EffectService {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
    }
}
