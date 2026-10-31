//! Private host request lifetime. Scope conveys limits and ownership, never authority.
use super::*;
use std::{collections::BTreeMap, sync::Mutex};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

#[cfg(test)]
mod action_meter_tests;
#[cfg(test)]
mod auth_meter_tests;
#[cfg(test)]
mod auth_tests;
mod checkpoint;
#[cfg(test)]
mod checkpoint_tests;
mod connect;
pub(crate) use checkpoint::OperatorCheckpoint;
pub(crate) mod meter;
#[cfg(test)]
mod meter_tests;
mod provider;
#[cfg(test)]
mod receipt_tests;
#[cfg(test)]
mod search_candidate_tests;
#[cfg(test)]
mod tests;

const CLEANUP_RESERVE: Duration = maintenance::CLEANUP_RESERVE;

#[derive(Debug)]
pub(crate) enum Unavailable {
    Deadline,
    Closed,
    Unconfirmed,
}
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Deadline => "database request phase deadline elapsed",
            Self::Closed => "database request service is stopped",
            Self::Unconfirmed => "database provider stop is unconfirmed; capacity retained",
        })
    }
}
impl std::error::Error for Unavailable {}

#[derive(Default)]
struct RegistryState {
    closed: bool,
    active: usize,
    quarantined: bool,
    deadlines: BTreeMap<tokio::time::Instant, usize>,
}
#[derive(Default)]
pub(crate) struct Registry {
    state: Mutex<RegistryState>,
    changed: Notify,
}
impl Registry {
    pub(crate) fn ensure_idle(&self) -> Result<()> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            state.active == 0 && !state.quarantined && !state.closed,
            Unavailable::Unconfirmed
        );
        Ok(())
    }
    fn register(self: &Arc<Self>, deadline: tokio::time::Instant) -> Result<Registration> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(!state.closed, Unavailable::Closed);
        state.active += 1;
        *state.deadlines.entry(deadline).or_default() += 1;
        Ok(Registration {
            registry: self.clone(),
            deadline,
            stopped: false,
        })
    }
    #[cfg(test)]
    pub(crate) async fn wait_idle_for_test(&self) -> Result<()> {
        loop {
            let changed = self.changed.notified();
            let deadline = {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.active == 0 {
                    ensure!(!state.quarantined, Unavailable::Unconfirmed);
                    return Ok(());
                }
                *state
                    .deadlines
                    .keys()
                    .next_back()
                    .context("active provider missing original deadline")?
            };
            tokio::time::timeout_at(deadline, changed)
                .await
                .map_err(|_| Unavailable::Unconfirmed)?;
        }
    }
    pub(crate) async fn shutdown(&self) -> Result<()> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        loop {
            let changed = self.changed.notified();
            let deadline = {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.active == 0 {
                    ensure!(!state.quarantined, Unavailable::Unconfirmed);
                    return Ok(());
                }
                *state
                    .deadlines
                    .keys()
                    .next_back()
                    .context("active provider missing original deadline")?
            };
            // This is an admitted phase's existing deadline, not a drain timeout.
            tokio::time::timeout_at(deadline, changed)
                .await
                .map_err(|_| Unavailable::Unconfirmed)?;
        }
    }
}

struct Registration {
    registry: Arc<Registry>,
    deadline: tokio::time::Instant,
    stopped: bool,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut state = self
            .registry
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state.active = state.active.checked_sub(1).expect("registered provider");
        let count = state
            .deadlines
            .get_mut(&self.deadline)
            .expect("registered deadline");
        *count -= 1;
        if *count == 0 {
            state.deadlines.remove(&self.deadline);
        }
        state.quarantined |= !self.stopped;
        self.registry.changed.notify_waiters();
    }
}

struct Root {
    registry: Arc<Registry>,
    outer: tokio::time::Instant,
    provider: Arc<Semaphore>,
    meter: Arc<meter::Meter>,
    cancelled: AtomicBool,
    search_candidates: std::sync::atomic::AtomicUsize,
}
/// One phase of a host-created request. Clones preserve the same root lifetime.
#[derive(Clone)]
pub(crate) struct RequestScope {
    root: Arc<Root>,
    deadline: tokio::time::Instant,
}
tokio::task_local! { static REQUEST: RequestScope; }
tokio::task_local! { static ADMISSION: AdmissionOwner; }
#[cfg(test)]
tokio::task_local! { static OBSERVED_ROOTS: Arc<Mutex<Vec<RequestScope>>>; }
#[cfg(test)]
async fn observe_roots<T>(future: impl std::future::Future<Output = T>) -> (T, Vec<RequestScope>) {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let result = OBSERVED_ROOTS.scope(observed.clone(), future).await;
    let roots = std::mem::take(&mut *observed.lock().unwrap());
    (result, roots)
}

impl RequestScope {
    pub(crate) fn new(
        registry: Arc<Registry>,
        outer: tokio::time::Instant,
        cap: Duration,
        statement_limit: u16,
    ) -> Self {
        let scope = Self {
            root: Arc::new(Root {
                registry,
                outer,
                provider: Arc::new(Semaphore::new(1)),
                meter: meter::Meter::new(statement_limit),
                cancelled: AtomicBool::new(false),
                search_candidates: std::sync::atomic::AtomicUsize::new(256),
            }),
            deadline: outer,
        };
        let scope = scope.phase(cap);
        #[cfg(test)]
        let _ = OBSERVED_ROOTS.try_with(|observed| observed.lock().unwrap().push(scope.clone()));
        scope
    }
    pub(crate) fn current_or_new(
        registry: Arc<Registry>,
        cap: Duration,
        statement_limit: u16,
    ) -> Self {
        REQUEST
            .try_with(|scope| {
                Arc::ptr_eq(&scope.root.registry, &registry).then(|| scope.narrow(cap))
            })
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                Self::new(
                    registry,
                    tokio::time::Instant::now() + cap,
                    cap,
                    statement_limit,
                )
            })
    }
    /// Explicit host phase transition, for approved multipart stages only.
    /// The immutable outer deadline remains the maximum across all phases.
    pub(crate) fn phase(&self, cap: Duration) -> Self {
        Self {
            root: self.root.clone(),
            deadline: self.root.outer.min(tokio::time::Instant::now() + cap),
        }
    }
    fn narrow(&self, cap: Duration) -> Self {
        Self {
            root: self.root.clone(),
            deadline: self.deadline.min(tokio::time::Instant::now() + cap),
        }
    }
    pub(crate) fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }
    pub(crate) fn work_deadline(&self) -> tokio::time::Instant {
        self.deadline
            .checked_sub(CLEANUP_RESERVE)
            .unwrap_or(self.deadline)
    }
    fn checkpoint(&self) -> Result<()> {
        ensure!(
            !self.root.cancelled.load(Ordering::Acquire),
            Unavailable::Closed
        );
        ensure!(
            tokio::time::Instant::now() < self.work_deadline(),
            Unavailable::Deadline
        );
        Ok(())
    }
    /// CPU work must already belong to an admitted host scope. No fallback scope,
    /// new timer or authority is constructed by this checkpoint.
    pub(crate) fn checkpoint_current() -> Result<()> {
        REQUEST
            .try_with(Self::checkpoint)
            .map_err(|_| Unavailable::Closed)?
    }
    pub(crate) fn search_candidates_remaining() -> Result<usize> {
        Self::checkpoint_current()?;
        REQUEST
            .try_with(|scope| scope.root.search_candidates.load(Ordering::Acquire))
            .map_err(|_| Unavailable::Closed.into())
    }
    pub(crate) fn charge_search_candidates(count: usize) -> Result<()> {
        Self::checkpoint_current()?;
        REQUEST
            .try_with(|scope| {
                scope
                    .root
                    .search_candidates
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                        remaining.checked_sub(count)
                    })
                    .map(|_| ())
                    .map_err(|_| anyhow::anyhow!("search candidate budget exhausted"))
            })
            .map_err(|_| Unavailable::Closed)?
    }
    pub(crate) fn active() -> bool {
        REQUEST.try_with(|_| ()).is_ok()
    }
    pub(crate) fn commit_pending() -> bool {
        ADMISSION
            .try_with(|owner| owner.0.commit_pending.load(Ordering::Acquire))
            .unwrap_or(false)
    }
    pub(crate) fn current_work_deadline() -> Option<tokio::time::Instant> {
        REQUEST.try_with(Self::work_deadline).ok()
    }
    pub(crate) fn run<T, F: std::future::Future<Output = T>>(
        &self,
        future: F,
    ) -> std::pin::Pin<Box<impl std::future::Future<Output = T> + use<T, F>>> {
        let scope = self.clone();
        Box::pin(async move {
            let mut cancellation = ScopeCancellation {
                root: scope.root.clone(),
                completed: false,
            };
            let result = REQUEST.scope(scope, future).await;
            cancellation.completed = true;
            result
        })
    }
}

struct ScopeCancellation {
    root: Arc<Root>,
    completed: bool,
}
impl Drop for ScopeCancellation {
    fn drop(&mut self) {
        if !self.completed {
            self.root.cancelled.store(true, Ordering::Release);
        }
    }
}

struct Admission {
    scope: RequestScope,
    request: Option<Arc<OwnedSemaphorePermit>>,
    database: Option<Arc<OwnedSemaphorePermit>>,
    anonymous: Option<Arc<OwnedSemaphorePermit>>,
    quarantined: AtomicBool,
    commit_pending: AtomicBool,
}
impl Drop for Admission {
    fn drop(&mut self) {
        if self.quarantined.load(Ordering::Acquire) {
            // Bounded by the admitted DB slots. Retaining one Arc prevents other
            // frontend/hash aliases from returning a quarantined permit later.
            if let Some(permit) = self.request.take() {
                std::mem::forget(permit);
            }
            if let Some(permit) = self.database.take() {
                std::mem::forget(permit);
            }
            if let Some(permit) = self.anonymous.take() {
                std::mem::forget(permit);
            }
        }
    }
}
#[derive(Clone)]
pub(crate) struct AdmissionOwner(Arc<Admission>);
impl AdmissionOwner {
    pub(crate) fn new(
        scope: RequestScope,
        request: Arc<OwnedSemaphorePermit>,
        database: Arc<OwnedSemaphorePermit>,
        anonymous: Option<OwnedSemaphorePermit>,
    ) -> Self {
        Self(Arc::new(Admission {
            scope,
            request: Some(request),
            database: Some(database),
            anonymous: anonymous.map(Arc::new),
            quarantined: AtomicBool::new(false),
            commit_pending: AtomicBool::new(false),
        }))
    }
    pub(crate) fn deadline(&self) -> tokio::time::Instant {
        self.0.scope.deadline()
    }
    pub(crate) fn work_deadline(&self) -> tokio::time::Instant {
        self.0.scope.work_deadline()
    }
    pub(crate) fn run<T, F: std::future::Future<Output = T>>(
        &self,
        future: F,
    ) -> std::pin::Pin<Box<impl std::future::Future<Output = T> + use<T, F>>> {
        let owner = self.clone();
        Box::pin(async move {
            ADMISSION
                .scope(owner.clone(), owner.0.scope.run(future))
                .await
        })
    }
    fn quarantine(&self) {
        self.0.quarantined.store(true, Ordering::Release);
    }
    async fn begin(
        &self,
        database: Database,
        requested: Instant,
        read_only: bool,
    ) -> Result<Transaction> {
        self.0.scope.checkpoint()?;
        let total = self.deadline();
        let work = self.work_deadline().min(requested.into());
        ensure!(tokio::time::Instant::now() < work, Unavailable::Deadline);
        let gate =
            tokio::time::timeout_at(work, self.0.scope.root.provider.clone().acquire_owned())
                .await??;
        let cleanup = self.0.scope.root.meter.reserve(match database.options {
            DatabaseOptions::Postgres(_) => meter::POSTGRES_CLEANUP,
            DatabaseOptions::Sqlite { .. } => 0,
        })?;
        let registration = self.0.scope.root.registry.register(total)?;
        let lease = ProviderLease {
            owner: self.clone(),
            meter: self.0.scope.root.meter.clone(),
            cleanup,
            gate: Some(gate),
            registration: Some(registration),
            total,
            work,
            started: false,
            stopped: false,
            runtime: tokio::runtime::Handle::current(),
        };
        let (deliver, receive) = tokio::sync::oneshot::channel();
        // Connecting belongs to the admitted owner, not the cancellable receiver.
        // A canceled frontend does not drop a half-created connection/BEGIN.
        tokio::spawn(async move {
            let result = connect::open(database, lease, read_only).await;
            if let Err(Ok(transaction)) = deliver.send(result) {
                drop(transaction); // owned Drop performs original-deadline cleanup
            }
        });
        receive
            .await
            .context("database provider owner unavailable")?
    }
}

pub(super) async fn begin(
    database: &Database,
    deadline: Instant,
    read_only: bool,
) -> Option<Result<Transaction>> {
    let Some(owner) = ADMISSION.try_with(Clone::clone).ok() else {
        // An HTTP scope may not fall through to an unowned connection merely
        // because a host adapter forgot its existing admission permits.
        return REQUEST.try_with(|_| Err(Unavailable::Closed.into())).ok();
    };
    Some(owner.begin(database.clone(), deadline, read_only).await)
}

pub(super) struct ProviderLease {
    owner: AdmissionOwner,
    meter: Arc<meter::Meter>,
    cleanup: Arc<meter::Cleanup>,
    gate: Option<OwnedSemaphorePermit>,
    registration: Option<Registration>,
    total: tokio::time::Instant,
    work: tokio::time::Instant,
    started: bool,
    stopped: bool,
    runtime: tokio::runtime::Handle,
}

pub(super) use provider::{Ordinary, drop_transaction, finish_transaction};
impl ProviderLease {
    fn commit_pending(&self, pending: bool) {
        self.owner
            .0
            .commit_pending
            .store(pending, Ordering::Release);
    }
    fn confirmed(&mut self) {
        self.cleanup.confirmed();
        self.stopped = true;
        if let Some(registration) = &mut self.registration {
            registration.stopped = true;
        }
    }
    fn no_provider(&mut self) {
        self.confirmed();
    }
}
impl Drop for ProviderLease {
    fn drop(&mut self) {
        if !self.stopped {
            if self.started {
                self.owner.quarantine();
                if let Some(gate) = self.gate.take() {
                    gate.forget();
                }
            } else {
                self.no_provider();
            }
        }
    }
}
