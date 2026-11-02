//! The server's side of worker processes. The server stays the authority: it checks
//! storage access on every call, counts calls, bounds the deadline, and decodes the
//! output itself. A worker that breaks the protocol is killed and never reused.
use crate::{
    Attempt, GuestBusy, Limits,
    broker::BrokerClient,
    wire::{self, FromWorker, Outcome, ToWorker},
};
use anyhow::{Context, Result, anyhow, ensure};
use noxide_host_calls::{HostCalls, Isolation};
use noxide_protocol::{MAX_REQUEST_BYTES, RequestView, ResponseIntent, decode_response};
use std::{
    io::Write,
    os::unix::net::UnixStream as StdStream,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::{net::UnixStream, sync::watch, time::Instant};

/// How long past the deadline a worker has to report it. A worker stops its guest at
/// the deadline itself, and reporting keeps it usable; this only limits how long the
/// server waits for one that does not.
const WORKER_GRACE: std::time::Duration = std::time::Duration::from_millis(100);

/// Largest component or compiled artifact a process accepts during startup.
pub const MAX_CODE_BYTES: usize = 256 * 1024 * 1024;

/// Write what a new worker needs on its stdin socket.
pub(crate) fn write_init(
    stream: &mut StdStream,
    code: &[u8],
    limits: &Limits,
    retire_after: u32,
) -> Result<()> {
    ensure!(code.len() <= MAX_CODE_BYTES, "code limit");
    stream.write_all(&(limits.memory_bytes as u64).to_le_bytes())?;
    stream.write_all(&limits.fuel.to_le_bytes())?;
    stream.write_all(&limits.host_calls.to_le_bytes())?;
    stream.write_all(&(limits.concurrency as u64).to_le_bytes())?;
    stream.write_all(&retire_after.to_le_bytes())?;
    stream.write_all(&(limits.wall_time.as_millis() as u64).to_le_bytes())?;
    stream.write_all(&(code.len() as u64).to_le_bytes())?;
    stream.write_all(code)?;
    Ok(())
}

/// What a worker or broker is told when it starts.
pub struct Startup {
    pub limits: Limits,
    pub retire_after: u32,
    /// The component for the broker and compile process; compiled code for a worker.
    pub code: Vec<u8>,
}

/// Read the startup message in a worker. Its limits come from the trusted server.
pub fn read_init(stream: &mut impl std::io::Read) -> Result<Startup> {
    fn u64(stream: &mut impl std::io::Read) -> Result<u64> {
        let mut bytes = [0; 8];
        stream.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    let memory_bytes = usize::try_from(u64(stream)?)?;
    let fuel = u64(stream)?;
    let mut calls = [0; 4];
    stream.read_exact(&mut calls)?;
    let concurrency = usize::try_from(u64(stream)?)?;
    let mut retire_after = [0; 4];
    stream.read_exact(&mut retire_after)?;
    let wall_time = std::time::Duration::from_millis(u64(stream)?);
    let length = usize::try_from(u64(stream)?)?;
    ensure!(length <= MAX_CODE_BYTES, "code limit");
    let mut code = vec![0; length];
    stream.read_exact(&mut code)?;
    let limits = Limits {
        memory_bytes,
        fuel,
        host_calls: u32::from_le_bytes(calls),
        wall_time,
        concurrency,
    };
    Ok(Startup {
        limits,
        retire_after: u32::from_le_bytes(retire_after),
        code,
    })
}

struct Worker {
    id: u32,
    served: u32,
    /// The key this worker has served. It serves no other.
    isolation: Option<String>,
    stream: Option<StdStream>,
    /// Absent only for a worker no broker started, in tests.
    broker: Option<Arc<BrokerClient>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Closing the socket ends a worker that follows the protocol; killing
        // covers one that does not.
        drop(self.stream.take());
        if let Some(broker) = &self.broker {
            broker.kill(self.id);
        }
    }
}

pub struct GuestPool {
    idle: Mutex<Vec<Worker>>,
    /// Bumped whenever a worker becomes idle or the pool closes.
    changed: watch::Sender<u64>,
    closed: AtomicBool,
    /// Workers idle, busy or starting.
    live: AtomicUsize,
    starting: AtomicUsize,
    waiting: AtomicUsize,
    started: AtomicUsize,
    retire_after: u32,
    limits: Limits,
    broker: Option<Arc<BrokerClient>>,
}

/// Requests a worker serves before it is replaced. One request each by default: a
/// guest that escapes Wasmtime then sees no later request, from anyone, and a worker
/// costs under a millisecond to start.
pub const DEFAULT_RETIRE_AFTER: u32 = 1;

/// Unassigned workers kept ready before anyone needs them. More start on demand, up
/// to `limits.concurrency`.
const WARM_WORKERS: usize = 4;

impl GuestPool {
    /// Start a broker, which compiles the component once as its admission check, and the
    /// warm workers. Call before confining: this is the last time this process can start anything.
    pub fn start(
        program: &Path,
        mode: &str,
        component: &[u8],
        limits: Limits,
        retire_after: u32,
    ) -> Result<Self> {
        ensure!(retire_after > 0, "a worker must serve at least one request");
        let broker = Arc::new(BrokerClient::start(
            program,
            mode,
            component,
            &limits,
            retire_after,
        )?);
        // Ready before the server listens, so the first accounts need no compile. These
        // threads end before this returns, which confinement requires.
        let warm = WARM_WORKERS.min(limits.concurrency);
        let idle = std::thread::scope(|scope| {
            let starting: Vec<_> = (0..warm).map(|_| scope.spawn(|| broker.worker())).collect();
            starting
                .into_iter()
                .map(|worker| {
                    let (id, stream) = worker
                        .join()
                        .expect("worker start")
                        .context("the component was rejected")?;
                    Ok(Worker {
                        id,
                        served: 0,
                        isolation: None,
                        stream: Some(stream),
                        broker: Some(broker.clone()),
                    })
                })
                .collect::<Result<Vec<_>>>()
        })?;
        Ok(Self {
            idle: Mutex::new(idle),
            changed: watch::Sender::new(0),
            closed: AtomicBool::new(false),
            live: AtomicUsize::new(warm),
            starting: AtomicUsize::new(0),
            waiting: AtomicUsize::new(0),
            started: AtomicUsize::new(warm),
            retire_after,
            limits,
            broker: Some(broker),
        })
    }

    /// Workers started so far, including those since replaced.
    pub fn workers_started(&self) -> usize {
        self.started.load(Ordering::Acquire)
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn idle_workers(&self) -> usize {
        self.idle.lock().unwrap().len()
    }

    /// Stop every idle worker and accept no more requests.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.idle.lock().unwrap().clear();
        self.changed.send_modify(|version| *version += 1);
    }

    /// Completes when the broker has stopped. No worker can be replaced after that,
    /// so a server should stop too and let its supervisor restart it.
    pub async fn broker_lost(&self) {
        match &self.broker {
            Some(broker) => broker.lost().await,
            None => std::future::pending().await,
        }
    }

    /// Stop the broker, as a crash would.
    pub fn stop_broker(&self) {
        if let Some(broker) = &self.broker {
            broker.stop();
        }
    }

    /// Start a worker off the async executor, if there is room for one.
    fn add_worker(self: &Arc<Self>) {
        let Some(broker) = self.broker.clone() else {
            return;
        };
        if self
            .live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                (live < self.limits.concurrency).then_some(live + 1)
            })
            .is_err()
        {
            return;
        }
        self.starting.fetch_add(1, Ordering::AcqRel);
        self.started.fetch_add(1, Ordering::AcqRel);
        let pool = self.clone();
        tokio::task::spawn_blocking(move || {
            let worker = broker.worker();
            pool.starting.fetch_sub(1, Ordering::AcqRel);
            match worker {
                Ok((id, stream)) => pool.park(Worker {
                    id,
                    served: 0,
                    isolation: None,
                    stream: Some(stream),
                    broker: Some(broker),
                }),
                Err(_) => {
                    pool.live.fetch_sub(1, Ordering::AcqRel);
                    pool.changed.send_modify(|version| *version += 1);
                }
            }
        });
    }

    fn park(&self, worker: Worker) {
        self.idle.lock().unwrap().push(worker);
        self.changed.send_modify(|version| *version += 1);
    }

    fn keep_warm(self: &Arc<Self>) {
        let unassigned = self
            .idle
            .lock()
            .unwrap()
            .iter()
            .filter(|worker| worker.isolation.is_none())
            .count();
        let ready = unassigned + self.starting.load(Ordering::Acquire);
        for _ in ready..WARM_WORKERS {
            self.add_worker();
        }
    }

    /// A worker already serving this key, or one that has served nobody. Another
    /// key's worker is never reused, only stopped to make room.
    fn take(&self, isolation: &Isolation) -> Option<Worker> {
        let mut idle = self.idle.lock().unwrap();
        let position = match isolation {
            Isolation::Shared(key) => idle
                .iter()
                .position(|worker| worker.isolation.as_deref() == Some(key.as_str())),
            Isolation::Single => None,
        }
        .or_else(|| idle.iter().position(|worker| worker.isolation.is_none()))?;
        Some(idle.swap_remove(position))
    }

    /// Make room for a new worker when every slot holds another key's idle worker.
    fn evict_one(self: &Arc<Self>) {
        if self.live.load(Ordering::Acquire) < self.limits.concurrency {
            return;
        }
        let mut idle = self.idle.lock().unwrap();
        let evicted = (!idle.is_empty()).then(|| idle.remove(0));
        drop(idle);
        if let Some(worker) = evicted {
            drop(worker);
            self.live.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Wait for a suitable worker, up to the deadline. The admission limit in front
    /// of this bounds how many can wait.
    async fn checkout(
        self: &Arc<Self>,
        isolation: &Isolation,
        deadline: Instant,
    ) -> Result<Worker> {
        let waiting = self.waiting.fetch_add(1, Ordering::AcqRel) + 1;
        let result = self.wait_for_worker(isolation, deadline, waiting).await;
        self.waiting.fetch_sub(1, Ordering::AcqRel);
        result
    }

    async fn wait_for_worker(
        self: &Arc<Self>,
        isolation: &Isolation,
        deadline: Instant,
        waiting: usize,
    ) -> Result<Worker> {
        let mut changes = self.changed.subscribe();
        loop {
            changes.borrow_and_update();
            if self.closed.load(Ordering::Acquire) {
                return Err(GuestBusy::Capacity.into());
            }
            if let Some(worker) = self.take(isolation) {
                self.keep_warm();
                return Ok(worker);
            }
            if self.broker.is_none() {
                return Err(GuestBusy::Capacity.into());
            }
            // Each waiter needs a worker of its own coming.
            if self.starting.load(Ordering::Acquire) < waiting {
                self.evict_one();
                self.add_worker();
            }
            tokio::time::timeout_at(deadline, changes.changed())
                .await
                .map_err(|_| GuestBusy::Deadline)?
                .map_err(|_| GuestBusy::Capacity)?;
        }
    }

    /// Discard a worker and start its replacement.
    fn discard(self: &Arc<Self>, worker: Worker) {
        drop(worker);
        self.live.fetch_sub(1, Ordering::AcqRel);
        // One for one, so load that needed this many workers still has them.
        self.add_worker();
        self.keep_warm();
    }

    pub async fn run<H: HostCalls>(
        self: &Arc<Self>,
        request: RequestView,
        mut effects: Option<H>,
        fuel: u64,
        calls: u32,
        deadline: Instant,
    ) -> Attempt<H> {
        let mut used = Used {
            fuel_left: fuel,
            calls_left: calls,
            failure: None,
        };
        // With no storage grant there is nothing of anyone's to protect.
        let isolation = effects
            .as_ref()
            .map_or(Isolation::Shared(String::new()), HostCalls::isolation);
        let mut worker = match self.checkout(&isolation, deadline).await {
            Ok(worker) => worker,
            Err(error) => {
                return Attempt {
                    result: Err(error),
                    effects,
                    fuel_left: fuel,
                    calls_left: calls,
                };
            }
        };
        let exchange = tokio::time::timeout_at(
            deadline + WORKER_GRACE,
            exchange(&mut worker, &request, &mut effects, &mut used, deadline),
        )
        .await;
        let (reusable, result): (bool, Result<ResponseIntent>) = match exchange {
            Err(_) => (false, Err(GuestBusy::Deadline.into())),
            Ok(Err(error)) => (false, Err(error)),
            Ok(Ok(Outcome::Output(bytes))) => {
                (true, decode_response(&bytes).map_err(|e| anyhow!(e)))
            }
            Ok(Ok(Outcome::Deadline)) => (true, Err(GuestBusy::Deadline.into())),
            Ok(Ok(Outcome::Failed)) => (true, Err(anyhow!("guest failed"))),
        };
        worker.served = worker.served.saturating_add(1);
        let shared = match isolation {
            Isolation::Shared(key) => {
                worker.isolation = Some(key);
                true
            }
            Isolation::Single => false,
        };
        if reusable && shared && worker.served < self.retire_after {
            self.park(worker);
        } else {
            // A broken exchange leaves the worker in an unknown state; a retired or
            // single-use one has seen as many requests as it may.
            self.discard(worker);
        }
        Attempt {
            result: match used.failure.take() {
                Some(failure) => Err(failure),
                None => result,
            },
            effects,
            fuel_left: used.fuel_left,
            calls_left: used.calls_left,
        }
    }
}

struct Used {
    fuel_left: u64,
    calls_left: u32,
    failure: Option<anyhow::Error>,
}

/// One request's exchange. Its socket is moved onto this runtime and back, because
/// workers start before the serving runtime exists.
async fn exchange<H: HostCalls>(
    worker: &mut Worker,
    request: &RequestView,
    effects: &mut Option<H>,
    used: &mut Used,
    deadline: Instant,
) -> Result<Outcome> {
    let request = serde_json::to_vec(request)?;
    ensure!(request.len() <= MAX_REQUEST_BYTES, "request limit");
    let std_stream = worker.stream.take().context("worker socket missing")?;
    std_stream.set_nonblocking(true)?;
    let mut stream = UnixStream::from_std(std_stream)?;
    let wall_millis = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    let run = ToWorker::Run {
        fuel: used.fuel_left,
        calls: used.calls_left,
        wall_millis,
        request,
    };
    wire::send(&mut stream, &run.encode()?).await?;
    let granted_fuel = used.fuel_left;
    let granted_calls = used.calls_left;
    loop {
        let frame = wire::receive(&mut stream).await?;
        let reply = match FromWorker::decode(&frame)? {
            FromWorker::Done {
                fuel_left,
                calls_left,
                outcome,
            } => {
                // A worker cannot grant itself budget, or undo calls the server counted.
                used.fuel_left = fuel_left.min(granted_fuel);
                used.calls_left = calls_left.min(used.calls_left).min(granted_calls);
                let std_stream = stream.into_std()?;
                std_stream.set_nonblocking(false)?;
                worker.stream = Some(std_stream);
                return Ok(outcome);
            }
            FromWorker::Invoke { operation, target } => match granted(effects, used)? {
                Some(host) => {
                    let result = host.invoke(operation, target).await;
                    settle(result, used)
                }
                None => None,
            },
            FromWorker::Follow { operation } => match granted(effects, used)? {
                Some(host) => {
                    let result = host.follow(operation).await;
                    settle(result, used)
                }
                None => None,
            },
            FromWorker::FollowSource { resource, id } => match granted(effects, used)? {
                Some(host) => settle(host.follow_source(resource, id).map(|()| Vec::new()), used),
                None => None,
            },
        };
        wire::send(&mut stream, &ToWorker::Reply(reply).encode()?).await?;
    }
}

/// The server's checks for one storage call. A refused call keeps its error here,
/// and the attempt fails with it however the guest responds. Going over the budget
/// is a protocol violation: an honest worker stops before it.
fn granted<'a, H: HostCalls>(
    effects: &'a mut Option<H>,
    used: &mut Used,
) -> Result<Option<&'a mut H>> {
    used.calls_left = used
        .calls_left
        .checked_sub(1)
        .context("worker exceeded its host calls")?;
    let Some(host) = effects.as_mut() else {
        used.failure
            .get_or_insert_with(|| anyhow!("no repository grant"));
        return Ok(None);
    };
    if !host.storage_allowed() {
        used.failure
            .get_or_insert_with(|| anyhow!("storage import during action"));
        return Ok(None);
    }
    Ok(Some(host))
}

fn settle(result: Result<Vec<u8>>, used: &mut Used) -> Option<Vec<u8>> {
    match result {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            used.failure.get_or_insert(error);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxide_protocol::{RequestKind, VERSION};
    use std::time::Duration;

    fn request() -> RequestView {
        RequestView {
            params: Default::default(),
            available_forms: Vec::new(),
            version: VERSION,
            kind: RequestKind::Route(1),
            target: None,
            input: Default::default(),
            inspection: Default::default(),
        }
    }

    const PAGE: &[u8] = br#"{"page":{"title":"Fresh","nodes":[{"text":"Hello"}]}}"#;

    struct Storage {
        allowed: bool,
        invoked: u32,
        refuse: bool,
    }
    impl HostCalls for Storage {
        fn isolation(&self) -> Isolation {
            Isolation::Shared("test".into())
        }
        fn storage_allowed(&self) -> bool {
            self.allowed
        }
        async fn invoke(&mut self, _: u32, _: u64) -> Result<Vec<u8>> {
            self.invoked += 1;
            if self.refuse {
                anyhow::bail!("policy refused");
            }
            Ok(b"row".to_vec())
        }
        fn follow_source(&mut self, _: u32, _: u64) -> Result<()> {
            Ok(())
        }
        async fn follow(&mut self, _: u32) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }
    fn storage() -> Storage {
        Storage {
            allowed: true,
            invoked: 0,
            refuse: false,
        }
    }

    /// A pool with one worker whose socket a test script answers, as a guest that
    /// escaped Wasmtime could.
    fn hostile() -> (Arc<GuestPool>, UnixStream) {
        let (ours, theirs) = StdStream::pair().unwrap();
        theirs.set_nonblocking(true).unwrap();
        let pool = GuestPool {
            idle: Mutex::new(vec![Worker {
                id: 1,
                served: 0,
                isolation: None,
                stream: Some(ours),
                broker: None,
            }]),
            changed: watch::Sender::new(0),
            closed: AtomicBool::new(false),
            live: AtomicUsize::new(1),
            starting: AtomicUsize::new(0),
            waiting: AtomicUsize::new(0),
            started: AtomicUsize::new(1),
            retire_after: 256,
            limits: Limits::default(),
            broker: None,
        };
        (Arc::new(pool), UnixStream::from_std(theirs).unwrap())
    }

    async fn message(script: &mut UnixStream, message: FromWorker) {
        wire::send(script, &message.encode().unwrap())
            .await
            .unwrap();
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[tokio::test]
    async fn a_worker_cannot_grant_itself_budget() {
        let (pool, mut script) = hostile();
        let server = tokio::spawn(async move {
            wire::receive(&mut script).await.unwrap();
            message(
                &mut script,
                FromWorker::Invoke {
                    operation: 1,
                    target: 0,
                },
            )
            .await;
            wire::receive(&mut script).await.unwrap();
            message(
                &mut script,
                FromWorker::Done {
                    fuel_left: u64::MAX,
                    calls_left: u32::MAX,
                    outcome: Outcome::Output(PAGE.to_vec()),
                },
            )
            .await;
            script
        });
        let attempt = pool
            .run(request(), Some(storage()), 100, 8, deadline())
            .await;
        assert!(attempt.result.is_ok());
        assert_eq!(attempt.fuel_left, 100);
        assert_eq!(attempt.calls_left, 7);
        assert_eq!(attempt.effects.unwrap().invoked, 1);
        assert_eq!(pool.idle_workers(), 1);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn exceeding_host_calls_kills_the_worker_before_storage_runs() {
        let (pool, mut script) = hostile();
        let server = tokio::spawn(async move {
            wire::receive(&mut script).await.unwrap();
            message(
                &mut script,
                FromWorker::Invoke {
                    operation: 1,
                    target: 0,
                },
            )
            .await;
            script
        });
        let attempt = pool
            .run(request(), Some(storage()), 100, 0, deadline())
            .await;
        assert!(attempt.result.is_err());
        assert_eq!(attempt.effects.unwrap().invoked, 0);
        assert_eq!(pool.idle_workers(), 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn forged_output_cannot_hide_a_refused_call() {
        let (pool, mut script) = hostile();
        let server = tokio::spawn(async move {
            wire::receive(&mut script).await.unwrap();
            message(
                &mut script,
                FromWorker::Invoke {
                    operation: 1,
                    target: 0,
                },
            )
            .await;
            let reply = wire::receive(&mut script).await.unwrap();
            assert_eq!(ToWorker::decode(&reply).unwrap(), ToWorker::Reply(None));
            message(
                &mut script,
                FromWorker::Done {
                    fuel_left: 1,
                    calls_left: 1,
                    outcome: Outcome::Output(PAGE.to_vec()),
                },
            )
            .await;
            script
        });
        let mut refusing = storage();
        refusing.refuse = true;
        let attempt = pool
            .run(request(), Some(refusing), 100, 8, deadline())
            .await;
        assert_eq!(attempt.result.unwrap_err().to_string(), "policy refused");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn storage_stays_closed_when_the_server_says_so() {
        let (pool, mut script) = hostile();
        let server = tokio::spawn(async move {
            wire::receive(&mut script).await.unwrap();
            message(
                &mut script,
                FromWorker::Invoke {
                    operation: 1,
                    target: 0,
                },
            )
            .await;
            let reply = wire::receive(&mut script).await.unwrap();
            assert_eq!(ToWorker::decode(&reply).unwrap(), ToWorker::Reply(None));
            message(
                &mut script,
                FromWorker::Done {
                    fuel_left: 1,
                    calls_left: 1,
                    outcome: Outcome::Failed,
                },
            )
            .await;
            script
        });
        let mut closed = storage();
        closed.allowed = false;
        let attempt = pool.run(request(), Some(closed), 100, 8, deadline()).await;
        assert!(attempt.result.is_err());
        assert_eq!(attempt.effects.unwrap().invoked, 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_output_is_rejected_by_the_server() {
        let (pool, mut script) = hostile();
        let server = tokio::spawn(async move {
            wire::receive(&mut script).await.unwrap();
            message(
                &mut script,
                FromWorker::Done {
                    fuel_left: 1,
                    calls_left: 1,
                    outcome: Outcome::Output(
                        br#"{"page":{"title":"x","nodes":[{"raw":"<script>"}]}}"#.to_vec(),
                    ),
                },
            )
            .await;
            script
        });
        let attempt = pool
            .run(request(), Some(storage()), 100, 8, deadline())
            .await;
        assert!(attempt.result.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_frames_and_silence_end_the_worker() {
        let (pool, mut script) = hostile();
        let server = tokio::spawn(async move {
            wire::receive(&mut script).await.unwrap();
            wire::send(&mut script, &[99]).await.unwrap();
            script
        });
        let attempt = pool
            .run(request(), Some(storage()), 100, 8, deadline())
            .await;
        assert!(attempt.result.is_err());
        assert_eq!(pool.idle_workers(), 0);
        let _script = server.await.unwrap();

        let (pool, _silent) = hostile();
        let attempt = pool
            .run(
                request(),
                Some(storage()),
                100,
                8,
                Instant::now() + Duration::from_millis(50),
            )
            .await;
        assert!(attempt.result.unwrap_err().is::<GuestBusy>());
        assert_eq!(pool.idle_workers(), 0);
    }

    struct Keyed(Isolation);
    impl HostCalls for Keyed {
        fn isolation(&self) -> Isolation {
            self.0.clone()
        }
        fn storage_allowed(&self) -> bool {
            true
        }
        async fn invoke(&mut self, _: u32, _: u64) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn follow_source(&mut self, _: u32, _: u64) -> Result<()> {
            Ok(())
        }
        async fn follow(&mut self, _: u32) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    async fn answered(pool: &Arc<GuestPool>, isolation: Isolation, script: &mut UnixStream) {
        let (attempt, ()) = tokio::join!(
            pool.run(request(), Some(Keyed(isolation)), 100, 8, deadline()),
            async {
                wire::receive(script).await.unwrap();
                message(
                    script,
                    FromWorker::Done {
                        fuel_left: 1,
                        calls_left: 1,
                        outcome: Outcome::Output(PAGE.to_vec()),
                    },
                )
                .await;
            }
        );
        attempt.result.unwrap();
    }

    #[tokio::test]
    async fn a_worker_never_serves_another_account() {
        let (pool, mut script) = hostile();
        let alice = Isolation::Shared("alice".into());
        answered(&pool, alice.clone(), &mut script).await;
        assert_eq!(pool.idle_workers(), 1);
        answered(&pool, alice, &mut script).await;
        let bob = pool
            .run(
                request(),
                Some(Keyed(Isolation::Shared("bob".into()))),
                100,
                8,
                deadline(),
            )
            .await;
        assert!(matches!(
            bob.result.unwrap_err().downcast_ref(),
            Some(GuestBusy::Capacity)
        ));
        assert_eq!(pool.idle_workers(), 1, "alice's worker stayed hers");
        let single = pool
            .run(
                request(),
                Some(Keyed(Isolation::Single)),
                100,
                8,
                deadline(),
            )
            .await;
        assert!(single.result.is_err(), "a used worker is not single-use");
    }

    #[tokio::test]
    async fn a_single_use_worker_is_discarded() {
        let (pool, mut script) = hostile();
        answered(&pool, Isolation::Single, &mut script).await;
        assert_eq!(pool.idle_workers(), 0);
    }

    #[tokio::test]
    async fn no_idle_worker_reports_capacity() {
        let (pool, _script) = hostile();
        pool.close();
        let attempt = pool
            .run(request(), Some(storage()), 100, 8, deadline())
            .await;
        assert!(matches!(
            attempt.result.unwrap_err().downcast_ref(),
            Some(GuestBusy::Capacity)
        ));
    }
}
