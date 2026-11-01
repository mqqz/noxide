//! Delivery has a separate 30-second host invocation, never a guest executor.
//! All phases share its deadline, logical allowance and native statement meter.
use super::*;
use crate::{
    effect_deployment::EffectiveEffectDeployment,
    effects::owner::{DeliveryOwner, OwnerDirectory, OwnerLease, PhysicalAttempt},
    effects::{self, DeliveryResult, EffectClaim, Finalized, OutboxContext, Preflight},
};
use anyhow::Context;
use std::{
    sync::{Mutex, atomic::AtomicBool},
    time::Duration,
};
use tokio::sync::Semaphore;

struct DirectoryPreparation {
    started: AtomicBool,
    result: OnceLock<std::result::Result<Arc<OwnerDirectory>, ()>>,
    changed: tokio::sync::Notify,
}
struct LeasePreparation {
    started: AtomicBool,
    result: OnceLock<std::result::Result<Arc<OwnerLease>, ()>>,
    changed: tokio::sync::Notify,
}
pub(crate) struct EffectRuntime {
    effective: EffectiveEffectDeployment,
    directory: Arc<DirectoryPreparation>,
    lease: Arc<LeasePreparation>,
    database: Arc<Semaphore>,
    pub(super) lifecycle: Arc<Registry>,
    owner: Mutex<Option<Arc<DeliveryOwner>>>,
    running: AtomicBool,
    #[cfg(test)]
    test_roots: Mutex<Option<rustls::RootCertStore>>,
}
impl EffectRuntime {
    pub(crate) fn new(effective: EffectiveEffectDeployment) -> Self {
        let concurrency = usize::from(effective.limits.worker_concurrency);
        Self {
            effective,
            directory: Arc::new(DirectoryPreparation {
                started: AtomicBool::new(false),
                result: OnceLock::new(),
                changed: tokio::sync::Notify::new(),
            }),
            lease: Arc::new(LeasePreparation {
                started: AtomicBool::new(false),
                result: OnceLock::new(),
                changed: tokio::sync::Notify::new(),
            }),
            database: Arc::new(Semaphore::new(concurrency)),
            lifecycle: Arc::new(Registry::default()),
            owner: Mutex::new(None),
            running: AtomicBool::new(false),
            #[cfg(test)]
            test_roots: Mutex::new(None),
        }
    }
    pub(crate) fn effective(&self) -> &EffectiveEffectDeployment {
        &self.effective
    }
    pub(crate) fn owner_directory_digest(&self) -> Result<&str> {
        Ok(self
            .directory
            .result
            .get()
            .context("effect directory not prepared")?
            .as_ref()
            .map_err(|_| anyhow::anyhow!("effect directory preparation failed"))?
            .digest())
    }
    fn delivery_owner(&self) -> Result<Arc<DeliveryOwner>> {
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
        let proxy = effects::transport::TorProxy::loopback(self.effective.tor_proxy)
            .map_err(|_| anyhow::anyhow!("invalid effect Tor proxy"))?;
        let transport = effects::transport::Transport::new(proxy);
        #[cfg(test)]
        let transport = match self
            .test_roots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            Some(roots) => effects::transport::Transport::with_test_roots(proxy, roots.clone()),
            None => transport,
        };
        let owner =
            DeliveryOwner::claim(lease, self.effective.limits.worker_concurrency, transport)?;
        *current = Some(owner.clone());
        Ok(owner)
    }
    fn release_owner(&self, owner: Arc<DeliveryOwner>) {
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
impl Application {
    /// Trusted local operator entry point; no HTTP/guest capability invokes it.
    pub async fn operate_effects(
        &self,
        command: effects::EffectOperatorCommand,
    ) -> std::result::Result<effects::EffectOperatorResult, RequestError> {
        use effects::{EffectOperatorCommand as Command, EffectOperatorResult as Output};
        let scope = self.request_scope(self.runtime.limits().wall_time);
        scope
            .run(async {
                let admission = self.admit_invocation(false).await?;
                admission
                    .owner
                    .run(async {
                        let mut tx = self
                            .database
                            .begin(admission.owner.work_deadline().into_std())
                            .await
                            .map_err(RequestError::database)?;
                        let time = self.temporal_attempt(&mut tx).await?.timestamp();
                        let generation = self.generation.get().ok_or(RequestError::Busy)?;
                        let retry = matches!(&command, Command::Retry { .. });
                        let output = match command {
                            Command::Inspect { after } => Output::Effects(
                                tx.inspect_effects(generation, &after)
                                    .await
                                    .map_err(RequestError::database)?,
                            ),
                            Command::Cancel { id } => {
                                tx.cancel_effect(generation, &id)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::RevokeEndpoint { tenant, endpoint } => {
                                tx.revoke_effect_endpoint(generation, &tenant, &endpoint)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::RevokeSecret { slot } => {
                                tx.revoke_effect_secret(generation, &slot)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::GrantEndpoint { tenant, endpoint } => {
                                let runtime =
                                    self.effects.as_ref().ok_or(RequestError::Rejected)?;
                                let binding = runtime
                                    .effective
                                    .grants
                                    .iter()
                                    .find(|b| b.tenant == tenant && b.endpoint.name == endpoint)
                                    .ok_or(RequestError::Rejected)?;
                                tx.grant_effect_endpoint(generation, &self.contract, binding)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::GrantSecret { slot } => {
                                let runtime =
                                    self.effects.as_ref().ok_or(RequestError::Rejected)?;
                                tx.grant_effect_secret(
                                    generation,
                                    &self.contract,
                                    &slot,
                                    &runtime.effective,
                                )
                                .await
                                .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::Retry { id } | Command::Resume { id } => {
                                let runtime =
                                    self.effects.as_ref().ok_or(RequestError::Rejected)?;
                                let source = tx
                                    .effect_operator_source(generation, &id)
                                    .await
                                    .map_err(RequestError::database)?;
                                let action =
                                    manifest::action(&self.manifest, source.source_action().0)
                                        .map_err(RequestError::database)?;
                                tx.resume_effect(
                                    generation,
                                    &self.contract,
                                    &runtime.effective,
                                    &id,
                                    action.version,
                                    time,
                                    retry,
                                )
                                .await
                                .map_err(RequestError::database)?;
                                Output::Done
                            }
                        };
                        Self::finish_commit(&mut tx, output).await
                    })
                    .await
            })
            .await
    }
    /// At most one bounded native preparation per App. The blocking task owns
    /// its state through actual completion even if activation is cancelled.
    pub(super) async fn prepare_effect_delivery(&self, deadline: std::time::Instant) -> Result<()> {
        let Some(runtime) = &self.effects else {
            return Ok(());
        };
        let path = runtime
            .effective
            .runtime_directory
            .clone()
            .context("effect runtime directory missing")?;
        let state = runtime.directory.clone();
        if state
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let worker = state.clone();
            tokio::task::spawn_blocking(move || {
                let result = OwnerDirectory::open(&path, deadline)
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
                    .map_err(|_| anyhow::anyhow!("effect owner directory preparation failed"));
            }
            timeout_at(deadline.into(), changed)
                .await
                .context("effect directory preparation deadline")?;
        }
    }
    /// This binds/open-prepares the lock file, but takes no exclusive ownership.
    /// A live operator App can activate while another App delivers effects.
    pub(super) async fn activate_effect_delivery(
        &self,
        deadline: std::time::Instant,
    ) -> Result<()> {
        let Some(runtime) = &self.effects else {
            return Ok(());
        };
        let mut tx = self.database.begin_read(deadline).await?;
        let rows = tx
            .fetch::<2>(
                "SELECT store_id,owner_directory FROM nx_effect_queue WHERE singleton=1",
                &[],
            )
            .await?;
        let [store_id, directory_digest] =
            rows.first().context("effect database binding missing")?;
        ensure!(
            directory_digest == runtime.owner_directory_digest()?,
            "effect owner directory changed"
        );
        let store_id = store_id.clone();
        tx.commit().await?;
        let directory = runtime
            .directory
            .result
            .get()
            .context("effect directory not prepared")?
            .as_ref()
            .map_err(|_| anyhow::anyhow!("effect directory preparation failed"))?
            .clone();
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
    fn effect_request_scope(&self) -> std::result::Result<RequestScope, RequestError> {
        let runtime = self.effects.as_ref().ok_or(RequestError::Rejected)?;
        Ok(RequestScope::current_or_new(
            runtime.lifecycle.clone(),
            Duration::from_secs(30),
            self.database_statement_limit,
        ))
    }
    async fn admit_effect_database(
        &self,
        scope: &RequestScope,
        physical: &PhysicalAttempt,
    ) -> std::result::Result<AdmissionOwner, RequestError> {
        let runtime = self.effects.as_ref().ok_or(RequestError::Rejected)?;
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
    async fn claim_effect(
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
                    .effects
                    .as_ref()
                    .ok_or(RequestError::Rejected)?
                    .owner_directory_digest()
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
                Self::finish_commit(&mut tx, claim).await
            })
            .await
    }
    async fn preflight_effect(
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
                Self::finish_commit(&mut tx, ready).await
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
                Self::finish_commit(&mut tx, ()).await
            })
            .await
    }
    async fn finalize_effect(
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
                Self::finish_commit(&mut tx, outcome.into()).await
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
                let runtime = self.effects.as_ref().ok_or(RequestError::Rejected)?;
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
                        effects::owner::read_secret(&path, deadline.into_std(), hold)
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
                let endpoint = effects::transport::Endpoint::checked(
                    &capture.binding().host,
                    capture.binding().port,
                    &capture.binding().path,
                )
                .map_err(|_| RequestError::Rejected)?;
                let body = effects::transport::JsonBody::checked(capture.body().to_vec())
                    .map_err(|_| RequestError::Rejected)?;
                let key = effects::transport::IdempotencyKey::from_host(
                    capture.receiver_key().map_err(RequestError::database)?,
                )
                .map_err(|_| RequestError::Rejected)?;
                let result = owner
                    .transport
                    .post(&endpoint, &body, &key, secret.as_ref(), deadline)
                    .await;
                let delivery = effects::worker::classify(result);
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
        let runtime = self.effects.as_ref().ok_or(RequestError::Rejected)?;
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
    pub(crate) fn start_effect_service(self: &Arc<Self>) -> Result<Option<EffectService>> {
        let Some(runtime) = &self.effects else {
            return Ok(None);
        };
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
            let runtime = app.effects.as_ref().expect("effect runtime");
            let physical = owner.drain().await;
            let providers = runtime.lifecycle.shutdown().await;
            physical?;
            providers?;
            ensure!(!failed, "effect worker task failed");
            runtime.release_owner(owner);
            runtime.running.store(false, Ordering::Release);
            Ok(())
        });
        Ok(Some(EffectService {
            stop: Some(stop),
            task: Some(task),
        }))
    }
}
pub(crate) struct EffectService {
    stop: Option<tokio::sync::watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl EffectService {
    pub(crate) async fn shutdown(mut self) -> Result<()> {
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
#[cfg(test)]
mod tests;
