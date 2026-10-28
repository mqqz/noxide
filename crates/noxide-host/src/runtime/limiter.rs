use crate::http::Peer;
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    hash::Hash,
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

pub(crate) struct AdmissionContext {
    pub peer: Peer,
    pub identity: AdmissionIdentity,
    pub class: RequestClass,
}
pub(crate) enum AdmissionIdentity {
    Anonymous,
    Candidate,
    Verified { principal: String },
}
#[derive(Clone, Copy)]
pub(crate) enum RequestClass {
    Get,
    AuthenticatedAction,
    AnonymousAction,
    PasswordHash,
}
impl RequestClass {
    pub fn cost(self) -> u64 {
        match self {
            Self::Get => 1,
            Self::AuthenticatedAction => 5,
            Self::AnonymousAction => 10,
            Self::PasswordHash => 20,
        }
    }
}
const CIRCUIT_CAPACITY: u64 = 40_000;
const CIRCUIT_REFILL: u64 = 2_000;
const CIRCUIT_START: u64 = 5_000;
const TABLE_CAPACITY: usize = 65_536;
const PRINCIPAL_PER_MINUTE: u64 = 30;
struct Entry {
    millitokens: u64,
    last_refill: Instant,
    tick: u64,
}
struct Table<K> {
    entries: HashMap<K, Entry>,
    lru: BTreeMap<u64, K>,
    tick: u64,
}
struct Buckets<K> {
    table: Mutex<Table<K>>,
    capacity: u64,
    start: u64,
    refill: u64,
}
impl<K: Clone + Eq + Hash> Buckets<K> {
    fn new(capacity: u64, start: u64, refill: u64) -> Self {
        Self {
            table: Mutex::new(Table {
                entries: HashMap::new(),
                lru: BTreeMap::new(),
                tick: 0,
            }),
            capacity,
            start,
            refill,
        }
    }
    fn charge(&self, key: K, cost: u64, drain: bool, now: Instant) -> bool {
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        if !table.entries.contains_key(&key)
            && table.entries.len() == TABLE_CAPACITY
            && let Some((_, oldest)) = table.lru.pop_first()
        {
            table.entries.remove(&oldest);
        }
        // Renumber before wrapping so every live entry retains a unique LRU key.
        if table.tick == u64::MAX {
            let keys: Vec<_> = table.lru.values().cloned().collect();
            table.lru.clear();
            for (tick, key) in keys.into_iter().enumerate() {
                table.entries.get_mut(&key).unwrap().tick = tick as u64;
                table.lru.insert(tick as u64, key);
            }
            table.tick = table.entries.len() as u64;
        }
        let tick = table.tick;
        table.tick += 1;
        let entry = table.entries.entry(key.clone()).or_insert(Entry {
            millitokens: self.start,
            last_refill: now,
            tick,
        });
        let old_tick = entry.tick;
        let elapsed = now.saturating_duration_since(entry.last_refill);
        let refill = elapsed.as_nanos().saturating_mul(u128::from(self.refill)) / 1_000_000_000;
        entry.millitokens = u128::from(entry.millitokens)
            .saturating_add(refill)
            .min(u128::from(self.capacity)) as u64;
        // Preserve the fractional refill time instead of losing it on rapid access.
        if entry.millitokens == self.capacity {
            entry.last_refill = now;
        } else {
            let nanos = refill.saturating_mul(1_000_000_000) / u128::from(self.refill);
            entry.last_refill += Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64);
        }
        entry.tick = tick;
        let allowed = entry.millitokens >= cost;
        if allowed || drain {
            entry.millitokens = entry.millitokens.saturating_sub(cost);
        }
        table.lru.remove(&old_tick);
        table.lru.insert(tick, key);
        allowed
    }
}

pub(crate) struct Lane {
    pub requests: BoundedPermits,
    pub database: BoundedPermits,
    pub wasm: BoundedPermits,
}
fn shares(total: usize, session: usize, reserve: u8, authenticated: bool) -> (usize, usize, usize) {
    if reserve == 0 || !authenticated {
        return (total, 0, 0);
    }
    let verified = (total * usize::from(reserve) + 50) / 100;
    (total - session - verified, session, verified)
}
impl Lane {
    fn new(requests: usize, database: usize, wasm: usize) -> Self {
        Self {
            requests: BoundedPermits::new(
                requests,
                requests * REQUEST_WAITING / REQUESTS,
                REQUEST_WAIT,
            ),
            database: BoundedPermits::new(
                database,
                database * DATABASE_WAITING / DATABASE,
                DATABASE_WAIT,
            ),
            wasm: BoundedPermits::new(wasm, wasm * WASM_WAITING / WASM, WASM_WAIT),
        }
    }
}
struct ScopedContext {
    owner: Arc<Semaphore>,
    context: AdmissionContext,
}
tokio::task_local! { static CONTEXT: ScopedContext; }

pub(crate) struct AdmissionLimits {
    partitioned: bool,
    reserve: u8,
    pub requests: BoundedPermits,
    pub database: BoundedPermits,
    pub wasm: BoundedPermits,
    pub verified: Lane,
    pub session_check: Lane,
    circuits: Buckets<u32>,
    principals: Buckets<String>,
    pub argon2: BoundedPermits,
    pub argon2_attempts: RateWindow,
    #[cfg(test)]
    pub hash_gate: Mutex<Option<Arc<HashGate>>>,
}
impl Default for AdmissionLimits {
    fn default() -> Self {
        Self::new(0, false)
    }
}
impl AdmissionLimits {
    pub(crate) fn new(reserve: u8, authenticated: bool) -> Self {
        let (requests, sr, vr) = shares(REQUESTS, 4, reserve, authenticated);
        let (database, sd, vd) = shares(DATABASE, 1, reserve, authenticated);
        let (wasm, sw, vw) = shares(WASM, 0, reserve, authenticated);
        Self {
            requests: BoundedPermits::new(
                requests,
                requests * REQUEST_WAITING / REQUESTS,
                REQUEST_WAIT,
            ),
            database: BoundedPermits::new(
                database,
                database * DATABASE_WAITING / DATABASE,
                DATABASE_WAIT,
            ),
            wasm: BoundedPermits::new(wasm, wasm * WASM_WAITING / WASM, WASM_WAIT),
            partitioned: vr != 0,
            reserve: if authenticated { reserve } else { 0 },
            verified: Lane::new(vr, vd, vw),
            session_check: Lane::new(sr, sd, sw),
            circuits: Buckets::new(CIRCUIT_CAPACITY, CIRCUIT_START, CIRCUIT_REFILL),
            principals: Buckets::new(
                PRINCIPAL_PER_MINUTE * 1000,
                PRINCIPAL_PER_MINUTE * 1000,
                PRINCIPAL_PER_MINUTE * 1000 / 60,
            ),
            argon2: BoundedPermits::new(ARGON2, ARGON2_WAITING, ARGON2_WAIT),
            argon2_attempts: RateWindow::new(ARGON2_PER_MINUTE),
            #[cfg(test)]
            hash_gate: Mutex::new(None),
        }
    }
}
impl AdmissionLimits {
    pub(crate) fn with_wasm_capacity(mut self, concurrency: usize) -> Self {
        let (anonymous, _, verified) = shares(WASM.min(concurrency), 0, self.reserve, true);
        self.wasm = BoundedPermits::new(anonymous, anonymous * WASM_WAITING / WASM, WASM_WAIT);
        self.verified.wasm =
            BoundedPermits::new(verified, verified * WASM_WAITING / WASM, WASM_WAIT);
        self
    }
    fn is_verified(&self) -> bool {
        self.partitioned
            && CONTEXT
                .try_with(|c| {
                    Arc::ptr_eq(&c.owner, &self.requests.sem)
                        && matches!(c.context.identity, AdmissionIdentity::Verified { .. })
                })
                .unwrap_or(false)
    }
    pub(crate) fn requests(&self) -> &BoundedPermits {
        if self.is_verified() {
            &self.verified.requests
        } else {
            &self.requests
        }
    }
    pub(crate) fn database(&self) -> &BoundedPermits {
        if self.is_verified() {
            &self.verified.database
        } else {
            &self.database
        }
    }
    pub(crate) fn wasm(&self) -> &BoundedPermits {
        if self.is_verified() {
            &self.verified.wasm
        } else {
            &self.wasm
        }
    }
    pub(crate) fn session_requests(&self) -> &BoundedPermits {
        if self.partitioned {
            &self.session_check.requests
        } else {
            &self.requests
        }
    }
    pub(crate) fn session_database(&self) -> &BoundedPermits {
        if self.partitioned {
            &self.session_check.database
        } else {
            &self.database
        }
    }
    pub(crate) fn charge_circuit(&self, peer: Peer, class: RequestClass) -> bool {
        match peer {
            Peer::Local => true,
            Peer::Circuit(id) => {
                self.circuits
                    .charge(id, class.cost() * 1000, false, Instant::now())
            }
        }
    }
    pub(crate) fn failed_session(&self, peer: Peer) {
        if let Peer::Circuit(id) = peer {
            self.circuits.charge(id, 20_000, true, Instant::now());
        }
    }
    #[cfg(test)]
    pub(crate) fn circuit_millitokens(&self, id: u32) -> u64 {
        self.circuits.table.lock().unwrap().entries[&id].millitokens
    }
    pub(crate) fn principal_action(&self, principal: &str) -> bool {
        self.principals
            .charge(principal.to_owned(), 1000, false, Instant::now())
    }
    pub(crate) async fn context<T>(
        &self,
        context: AdmissionContext,
        future: impl Future<Output = T>,
    ) -> T {
        CONTEXT
            .scope(
                ScopedContext {
                    owner: self.requests.sem.clone(),
                    context,
                },
                future,
            )
            .await
    }
    pub(crate) async fn scope<T>(
        &self,
        permit: Arc<OwnedSemaphorePermit>,
        future: impl Future<Output = T>,
    ) -> T {
        REQUEST
            .scope(
                Request {
                    owner: self.requests().sem.clone(),
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

#[cfg(test)]
mod circuit_tests {
    use super::*;
    #[test]
    fn circuit_costs_and_refill_use_injected_monotonic_time() {
        let limits = AdmissionLimits::new(25, true);
        let now = Instant::now();
        for _ in 0..5 {
            assert!(limits.circuits.charge(1, 1000, false, now));
        }
        assert!(!limits.circuits.charge(1, 1000, false, now));
        assert!(
            !limits
                .circuits
                .charge(2, 10_000, false, now + Duration::from_millis(1))
        );
        assert!(
            !limits
                .circuits
                .charge(2, 10_000, false, now + Duration::from_millis(2500))
        );
        assert!(
            limits
                .circuits
                .charge(2, 10_000, false, now + Duration::from_millis(2501))
        );
        assert!(!limits.circuits.charge(3, 20_000, false, now));
        assert!(
            !limits
                .circuits
                .charge(3, 20_000, false, now + Duration::from_millis(7499))
        );
        assert!(
            limits
                .circuits
                .charge(3, 20_000, false, now + Duration::from_millis(7500))
        );
        // Many sub-millisecond accesses must retain their fractional refill.
        assert!(limits.circuits.charge(4, 5000, false, now));
        for n in 1..1000 {
            assert!(
                limits
                    .circuits
                    .charge(4, 0, false, now + Duration::from_micros(n))
            );
        }
        assert!(
            limits
                .circuits
                .charge(4, 2, false, now + Duration::from_millis(1))
        );
    }
    #[test]
    fn circuit_rotation_is_bounded_and_cannot_refresh_more_than_starting_credit() {
        let limits = AdmissionLimits::new(25, true);
        let now = Instant::now();
        for id in 1..=100_000 {
            assert!(limits.circuits.charge(id, 5000, false, now));
            assert!(!limits.circuits.charge(id, 1, false, now));
            if id % 1000 == 0 {
                assert!(limits.circuits.charge(
                    0,
                    1000,
                    false,
                    now + Duration::from_secs(u64::from(id / 1000))
                ));
            }
        }
        let table = limits.circuits.table.lock().unwrap();
        assert_eq!(table.entries.len(), TABLE_CAPACITY);
        assert_eq!(table.lru.len(), TABLE_CAPACITY);
        assert!(table.entries.contains_key(&0));
        drop(table);
        assert!(limits.circuits.charge(1, 5000, false, now));
        assert!(!limits.circuits.charge(1, 1, false, now));
    }
    #[test]
    fn principal_budget_is_shared_across_circuits_and_has_bounded_lru() {
        let limits = AdmissionLimits::new(25, true);
        let now = Instant::now();
        for _ in 0..30 {
            assert!(limits.principals.charge("alice".into(), 1000, false, now));
        }
        assert!(!limits.principals.charge("alice".into(), 1000, false, now));
        assert!(!limits.principals.charge(
            "alice".into(),
            1000,
            false,
            now + Duration::from_millis(1999)
        ));
        assert!(limits.principals.charge(
            "alice".into(),
            1000,
            false,
            now + Duration::from_secs(2)
        ));
        for n in 0..100_000 {
            assert!(limits.principals.charge(n.to_string(), 1000, false, now));
        }
        let table = limits.principals.table.lock().unwrap();
        assert_eq!(table.entries.len(), TABLE_CAPACITY);
        assert_eq!(table.lru.len(), TABLE_CAPACITY);
    }
    #[test]
    fn reserve_shares_and_public_only_apps_preserve_total_capacity() {
        assert_eq!(shares(64, 4, 25, true), (44, 4, 16));
        assert_eq!(shares(8, 1, 25, true), (5, 1, 2));
        assert_eq!(shares(8, 0, 25, true), (6, 0, 2));
        for reserve in 0..=50 {
            for (total, session) in [(64, 4), (8, 1), (8, 0)] {
                let (a, s, v) = shares(total, session, reserve, true);
                assert_eq!(a + s + v, total);
                assert_eq!(shares(total, session, reserve, false), (total, 0, 0));
            }
        }
        assert_eq!(shares(64, 4, 0, true), (64, 0, 0));
    }
    #[tokio::test]
    async fn verified_scope_uses_separate_resources_and_does_not_leak_between_apps() {
        let first = AdmissionLimits::new(25, true);
        let second = AdmissionLimits::new(25, true);
        let context = AdmissionContext {
            peer: Peer::Local,
            identity: AdmissionIdentity::Verified {
                principal: "alice".into(),
            },
            class: RequestClass::Get,
        };
        first
            .context(context, async {
                let _request = first.requests().request().await.unwrap();
                let _database = first.database().acquire().await.unwrap();
                let _wasm = first.wasm().acquire().await.unwrap();
                assert_eq!(first.requests.available(), 44);
                assert_eq!(first.verified.requests.available(), 15);
                assert_eq!(first.verified.database.available(), 1);
                assert_eq!(first.verified.wasm.available(), 1);
                assert!(std::ptr::eq(second.requests(), &second.requests));
            })
            .await;
        assert!(std::ptr::eq(first.requests(), &first.requests));
    }
}
