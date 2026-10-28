use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

pub(crate) const MAX_CONNECTIONS: usize = 256;
pub(crate) const MAX_CONNECTIONS_PER_CIRCUIT: usize = 4;
pub(crate) const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const PROXY_LINE_MAX: usize = 107;
pub(crate) const PROXY_LINE_TIMEOUT: Duration = Duration::from_secs(2);
const REQUESTS: usize = 64;
const REQUEST_WAITING: usize = 64;
const REQUEST_WAIT: Duration = Duration::from_secs(2);
const DATABASE: usize = 8;
const DATABASE_WAITING: usize = 16;
const DATABASE_WAIT: Duration = Duration::from_secs(1);
const WASM: usize = 8;
const WASM_WAITING: usize = 16;
const WASM_WAIT: Duration = Duration::from_secs(1);
const ARGON2: usize = 2;
const ARGON2_WAITING: usize = 8;
const ARGON2_WAIT: Duration = Duration::from_secs(1);
const ARGON2_PER_MINUTE: u32 = 60;

#[derive(Debug)]
pub(crate) struct Busy;
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("service busy")
    }
}
impl std::error::Error for Busy {}

pub(crate) struct BoundedPermits {
    sem: Arc<Semaphore>,
    waiting: AtomicUsize,
    max_waiting: usize,
    max_wait: Duration,
}
impl BoundedPermits {
    fn new(capacity: usize, max_waiting: usize, max_wait: Duration) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(capacity)),
            waiting: AtomicUsize::new(0),
            max_waiting,
            max_wait,
        }
    }
    pub(crate) async fn acquire(&self) -> Result<OwnedSemaphorePermit, Busy> {
        self.waiting
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
                (n < self.max_waiting).then(|| n + 1)
            })
            .map_err(|_| Busy)?;
        struct Waiting<'a>(&'a AtomicUsize);
        impl Drop for Waiting<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _waiting = Waiting(&self.waiting);
        tokio::time::timeout(self.max_wait, self.sem.clone().acquire_owned())
            .await
            .map_err(|_| Busy)?
            .map_err(|_| Busy)
    }
    pub(crate) async fn request(&self) -> Result<Arc<OwnedSemaphorePermit>, Busy> {
        if let Some(permit) = REQUEST
            .try_with(|request| {
                Arc::ptr_eq(&request.owner, &self.sem).then(|| request.permit.clone())
            })
            .ok()
            .flatten()
        {
            return Ok(permit);
        }
        self.acquire().await.map(Arc::new)
    }
    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.sem.available_permits()
    }
}

struct Request {
    owner: Arc<Semaphore>,
    permit: Arc<OwnedSemaphorePermit>,
}
tokio::task_local! { static REQUEST: Request; }

pub(crate) struct RateWindow {
    per_minute: u32,
    state: Mutex<RateState>,
}
struct RateState {
    credit: u128,
    last: Instant,
}
impl RateWindow {
    const TOKEN: u128 = 60_000_000_000;
    fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            state: Mutex::new(RateState {
                credit: u128::from(per_minute) * Self::TOKEN,
                last: Instant::now(),
            }),
        }
    }
    pub(crate) fn allow(&self) -> bool {
        self.at(Instant::now())
    }
    fn at(&self, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let refill = now
            .saturating_duration_since(state.last)
            .as_nanos()
            .saturating_mul(u128::from(self.per_minute));
        state.credit = state
            .credit
            .saturating_add(refill)
            .min(u128::from(self.per_minute) * Self::TOKEN);
        state.last = now;
        if state.credit < Self::TOKEN {
            return false;
        }
        state.credit -= Self::TOKEN;
        true
    }
}

pub(crate) struct AdmissionLimits {
    pub requests: BoundedPermits,
    pub database: BoundedPermits,
    pub wasm: BoundedPermits,
    pub argon2: BoundedPermits,
    pub argon2_attempts: RateWindow,
    #[cfg(test)]
    pub hash_gate: Mutex<Option<Arc<HashGate>>>,
}
impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            requests: BoundedPermits::new(REQUESTS, REQUEST_WAITING, REQUEST_WAIT),
            database: BoundedPermits::new(DATABASE, DATABASE_WAITING, DATABASE_WAIT),
            wasm: BoundedPermits::new(WASM, WASM_WAITING, WASM_WAIT),
            argon2: BoundedPermits::new(ARGON2, ARGON2_WAITING, ARGON2_WAIT),
            argon2_attempts: RateWindow::new(ARGON2_PER_MINUTE),
            #[cfg(test)]
            hash_gate: Mutex::new(None),
        }
    }
}
impl AdmissionLimits {
    pub(crate) async fn scope<T>(
        &self,
        permit: Arc<OwnedSemaphorePermit>,
        future: impl Future<Output = T>,
    ) -> T {
        REQUEST
            .scope(
                Request {
                    owner: self.requests.sem.clone(),
                    permit,
                },
                future,
            )
            .await
    }
}

pub(crate) struct HashPermits {
    pub _argon2: OwnedSemaphorePermit,
    pub _request: Arc<OwnedSemaphorePermit>,
    pub _database: Arc<OwnedSemaphorePermit>,
    #[cfg(test)]
    pub gate: Option<Arc<HashGate>>,
}
impl HashPermits {
    pub(crate) fn enter(&self) {
        #[cfg(test)]
        if let Some(gate) = &self.gate {
            gate.wait();
        }
    }
}

#[cfg(test)]
pub(crate) struct HashGate {
    pub entered: tokio::sync::Notify,
    finished: (Mutex<bool>, std::sync::Condvar),
}
#[cfg(test)]
impl HashGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Notify::new(),
            finished: (Mutex::new(false), std::sync::Condvar::new()),
        })
    }
    fn wait(&self) {
        let (lock, ready) = &self.finished;
        let mut finished = lock.lock().unwrap();
        self.entered.notify_one();
        while !*finished {
            finished = ready.wait(finished).unwrap();
        }
    }
    pub fn finish(&self) {
        *self.finished.0.lock().unwrap() = true;
        self.finished.1.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn waiting(permits: &BoundedPermits, count: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while permits.waiting.load(Ordering::Acquire) != count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn bounded_queue_fails_fast_and_cancellation_releases_waiter() {
        let permits = Arc::new(BoundedPermits::new(1, 1, Duration::from_secs(1)));
        let active = permits.acquire().await.unwrap();
        let queued = {
            let permits = permits.clone();
            tokio::spawn(async move { permits.acquire().await })
        };
        waiting(&permits, 1).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), permits.acquire())
                .await
                .unwrap()
                .is_err()
        );
        queued.abort();
        assert!(queued.await.unwrap_err().is_cancelled());
        assert_eq!(permits.waiting.load(Ordering::Acquire), 0);
        drop(active);
        assert!(permits.acquire().await.is_ok());
        assert_eq!(permits.available(), 1);
    }

    #[tokio::test]
    async fn bounded_queue_times_out_and_preserves_fifo() {
        let permits = Arc::new(BoundedPermits::new(1, 3, Duration::from_millis(30)));
        let active = permits.acquire().await.unwrap();
        let started = Instant::now();
        assert!(permits.acquire().await.is_err());
        assert!(started.elapsed() >= permits.max_wait);
        assert_eq!(permits.waiting.load(Ordering::Acquire), 0);
        drop(active);
        let permits = Arc::new(BoundedPermits::new(1, 3, Duration::from_secs(1)));
        let active = permits.acquire().await.unwrap();
        let (send, mut receive) = tokio::sync::mpsc::channel(3);
        let mut workers = tokio::task::JoinSet::new();
        for index in 0..3 {
            let (worker_permits, send) = (permits.clone(), send.clone());
            workers.spawn(async move {
                let _permit = worker_permits.acquire().await.unwrap();
                send.send(index).await.unwrap();
            });
            waiting(&permits, index + 1).await;
        }
        drop(active);
        for index in 0..3 {
            assert_eq!(receive.recv().await, Some(index));
        }
        while let Some(result) = workers.join_next().await {
            result.unwrap();
        }
        assert_eq!(permits.waiting.load(Ordering::Acquire), 0);
    }

    #[test]
    fn argon2_rate_bucket_uses_monotonic_fractional_refill() {
        let window = RateWindow::new(ARGON2_PER_MINUTE);
        let now = window.state.lock().unwrap().last;
        for _ in 0..ARGON2_PER_MINUTE {
            assert!(window.at(now));
        }
        assert!(!window.at(now));
        assert!(!window.at(now + Duration::from_millis(999)));
        assert!(window.at(now + Duration::from_secs(1)));
        assert!(!window.at(now + Duration::from_secs(1)));
        for _ in 0..ARGON2_PER_MINUTE {
            assert!(window.at(now + Duration::from_secs(600)));
        }
        assert!(!window.at(now + Duration::from_secs(600)));
    }

    #[tokio::test]
    async fn request_scope_reuses_only_its_own_application_capacity() {
        let first = AdmissionLimits::default();
        let second = AdmissionLimits::default();
        let request = first.requests.request().await.unwrap();
        first
            .scope(request.clone(), async {
                let nested = first.requests.request().await.unwrap();
                assert!(Arc::ptr_eq(&request, &nested));
                assert_eq!(first.requests.available(), REQUESTS - 1);
                let _other = second.requests.request().await.unwrap();
                assert_eq!(second.requests.available(), REQUESTS - 1);
            })
            .await;
        drop(request);
        assert_eq!(first.requests.available(), REQUESTS);
        assert_eq!(second.requests.available(), REQUESTS);
    }
}
