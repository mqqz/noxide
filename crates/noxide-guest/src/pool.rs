//! The server's side of worker processes. The server stays the authority: it checks
//! storage access on every call, counts calls, bounds the deadline, and decodes the
//! output itself. A worker that breaks the protocol is killed and never reused.
use crate::{
    Attempt, GuestBusy, Limits,
    wire::{self, FromWorker, Outcome, ToWorker},
};
use anyhow::{Context, Result, anyhow, ensure};
use noxide_host_calls::HostCalls;
use noxide_protocol::{MAX_REQUEST_BYTES, RequestView, ResponseIntent, decode_response};
use std::{
    io::Write,
    os::{fd::OwnedFd, unix::net::UnixStream as StdStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
};
use tokio::{net::UnixStream, time::Instant};

/// Largest component a worker accepts during startup.
pub const MAX_COMPONENT_BYTES: usize = 64 * 1024 * 1024;

/// Write what a new worker needs on its stdin socket.
fn write_init(stream: &mut StdStream, component: &[u8], limits: &Limits) -> Result<()> {
    ensure!(component.len() <= MAX_COMPONENT_BYTES, "component limit");
    stream.write_all(&(limits.memory_bytes as u64).to_le_bytes())?;
    stream.write_all(&limits.fuel.to_le_bytes())?;
    stream.write_all(&limits.host_calls.to_le_bytes())?;
    stream.write_all(&(limits.wall_time.as_millis() as u64).to_le_bytes())?;
    stream.write_all(&(component.len() as u64).to_le_bytes())?;
    stream.write_all(component)?;
    Ok(())
}

/// Read the startup message in a worker. Its limits come from the trusted server.
pub fn read_init(stream: &mut impl std::io::Read) -> Result<(Limits, Vec<u8>)> {
    fn u64(stream: &mut impl std::io::Read) -> Result<u64> {
        let mut bytes = [0; 8];
        stream.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    let memory_bytes = usize::try_from(u64(stream)?)?;
    let fuel = u64(stream)?;
    let mut calls = [0; 4];
    stream.read_exact(&mut calls)?;
    let wall_time = std::time::Duration::from_millis(u64(stream)?);
    let length = usize::try_from(u64(stream)?)?;
    ensure!(length <= MAX_COMPONENT_BYTES, "component limit");
    let mut component = vec![0; length];
    stream.read_exact(&mut component)?;
    let limits = Limits {
        memory_bytes,
        fuel,
        host_calls: u32::from_le_bytes(calls),
        wall_time,
        concurrency: 1,
    };
    Ok((limits, component))
}

struct Worker {
    child: Child,
    stream: Option<StdStream>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Closing the socket also ends an idle worker if the kill is refused.
        drop(self.stream.take());
        if self.child.kill().is_ok() {
            let _ = self.child.wait();
        }
    }
}

pub struct GuestPool {
    idle: Mutex<Vec<Worker>>,
    limits: Limits,
    spawner: Option<Spawner>,
}

struct Spawner {
    program: PathBuf,
    arguments: Vec<String>,
    component: Arc<[u8]>,
}

impl Spawner {
    fn spawn(&self, limits: &Limits) -> Result<Worker> {
        let (mut ours, theirs) = StdStream::pair()?;
        let child = Command::new(&self.program)
            .args(&self.arguments)
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear()
            .spawn()
            .with_context(|| format!("cannot start {}", self.program.display()))?;
        let mut worker = Worker {
            child,
            stream: None,
        };
        write_init(&mut ours, &self.component, limits)?;
        let mut ready = [0];
        std::io::Read::read_exact(&mut ours, &mut ready).context("worker did not start")?;
        ensure!(&ready == b"R", "worker did not start");
        worker.stream = Some(ours);
        Ok(worker)
    }
}

impl GuestPool {
    /// Start `limits.concurrency` workers, each compiling the component. A confined
    /// server cannot start processes, so call this before confining.
    pub fn start(
        program: &Path,
        arguments: &[&str],
        component: &[u8],
        limits: Limits,
    ) -> Result<Self> {
        let spawner = Spawner {
            program: program.to_owned(),
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            component: component.into(),
        };
        let idle = (0..limits.concurrency)
            .map(|_| spawner.spawn(&limits))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            idle: Mutex::new(idle),
            limits,
            spawner: Some(spawner),
        })
    }

    /// Stop replacing workers that fail, once this process can no longer start them.
    pub fn stop_replacing(&mut self) {
        self.spawner = None;
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn idle_workers(&self) -> usize {
        self.idle.lock().unwrap().len()
    }

    fn checkout(&self) -> Option<Worker> {
        self.idle.lock().unwrap().pop()
    }

    /// A replacement is compiled off the async executor and added when ready.
    fn replace(self: &Arc<Self>) {
        if self.spawner.is_none() {
            return;
        }
        let pool = self.clone();
        tokio::task::spawn_blocking(move || {
            let spawner = pool.spawner.as_ref().expect("checked above");
            if let Ok(worker) = spawner.spawn(&pool.limits) {
                pool.idle.lock().unwrap().push(worker);
            }
        });
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
        let Some(mut worker) = self.checkout() else {
            return Attempt {
                result: Err(GuestBusy::Capacity.into()),
                effects,
                fuel_left: fuel,
                calls_left: calls,
            };
        };
        let exchange = tokio::time::timeout_at(
            deadline,
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
        if reusable {
            self.idle.lock().unwrap().push(worker);
        } else {
            // A broken exchange leaves the worker in an unknown state.
            drop(worker);
            self.replace();
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
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let pool = GuestPool {
            idle: Mutex::new(vec![Worker {
                child,
                stream: Some(ours),
            }]),
            limits: Limits::default(),
            spawner: None,
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

    #[tokio::test]
    async fn no_idle_worker_reports_capacity() {
        let (pool, _script) = hostile();
        pool.idle.lock().unwrap().clear();
        let attempt = pool
            .run(request(), Some(storage()), 100, 8, deadline())
            .await;
        assert!(matches!(
            attempt.result.unwrap_err().downcast_ref(),
            Some(GuestBusy::Capacity)
        ));
    }
}
