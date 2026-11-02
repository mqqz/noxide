//! The guest process: compile one component, then run requests from the socket
//! the server passed as stdin. It holds nothing but that socket, and treats every
//! storage call as a question for the server.
use crate::{Limits, Runtime};
use anyhow::{Context, Result, bail, ensure};
use noxide_guest::wire::{self, FromWorker, Outcome, ToWorker};
use noxide_host_calls::HostCalls;
use std::sync::Arc;
use tokio::{net::UnixStream, sync::Mutex, time::Instant};

/// Sources a guest may follow before its next storage call.
const MAX_PENDING_SOURCES: usize = 4096;

struct Remote {
    stream: Arc<Mutex<UnixStream>>,
    /// `follow_source` cannot wait, so these travel with the next message.
    pending: Vec<(u32, u64)>,
}

impl Remote {
    async fn flush(&mut self) -> Result<()> {
        let mut stream = self.stream.lock().await;
        for (resource, id) in std::mem::take(&mut self.pending) {
            let message = FromWorker::FollowSource { resource, id };
            wire::send(&mut *stream, &message.encode()?).await?;
            match ToWorker::decode(&wire::receive(&mut *stream).await?)? {
                ToWorker::Reply(Some(_)) => {}
                ToWorker::Reply(None) => bail!("storage call refused"),
                ToWorker::Run { .. } => bail!("unexpected server message"),
            }
        }
        Ok(())
    }

    async fn ask(&mut self, message: FromWorker) -> Result<Vec<u8>> {
        self.flush().await?;
        let mut stream = self.stream.lock().await;
        wire::send(&mut *stream, &message.encode()?).await?;
        match ToWorker::decode(&wire::receive(&mut *stream).await?)? {
            ToWorker::Reply(Some(bytes)) => Ok(bytes),
            ToWorker::Reply(None) => bail!("storage call refused"),
            ToWorker::Run { .. } => bail!("unexpected server message"),
        }
    }
}

impl HostCalls for Remote {
    /// The server chooses a worker's requests; a worker only runs them.
    fn isolation(&self) -> noxide_host_calls::Isolation {
        noxide_host_calls::Isolation::Single
    }
    /// The server checks this on every call; it never trusts the worker's answer.
    fn storage_allowed(&self) -> bool {
        true
    }
    async fn invoke(&mut self, operation: u32, target: u64) -> Result<Vec<u8>> {
        self.ask(FromWorker::Invoke { operation, target }).await
    }
    fn follow_source(&mut self, resource: u32, id: u64) -> Result<()> {
        ensure!(
            self.pending.len() < MAX_PENDING_SOURCES,
            "follow source limit"
        );
        self.pending.push((resource, id));
        Ok(())
    }
    async fn follow(&mut self, operation: u32) -> Result<Vec<u8>> {
        self.ask(FromWorker::Follow { operation }).await
    }
}

pub struct Worker {
    runtime: Runtime<Remote>,
}

impl Worker {
    /// Load code the compile process made, and only that: see `Runtime::load`. Confine
    /// the process first, so hostile code would hold nothing. Only `noxide-guest` may
    /// call this, which `tools/check_layers.py` enforces.
    pub fn load_from_broker(artifact: &[u8], limits: Limits) -> Result<Self> {
        // A worker runs one request at a time, whatever the server's total is.
        let limits = Limits {
            concurrency: 1,
            ..limits
        };
        Ok(Self {
            runtime: Runtime::load(artifact, limits)?,
        })
    }

    /// Serve until the server closes the socket.
    pub async fn serve(self, stream: UnixStream) -> Result<()> {
        let stream = Arc::new(Mutex::new(stream));
        loop {
            let frame = {
                let mut stream = stream.lock().await;
                match wire::receive(&mut *stream).await {
                    Ok(frame) => frame,
                    Err(_) => return Ok(()),
                }
            };
            let ToWorker::Run {
                fuel,
                calls,
                wall_millis,
                request,
            } = ToWorker::decode(&frame).context("server message")?
            else {
                bail!("unexpected server message");
            };
            let deadline = Instant::now() + std::time::Duration::from_millis(wall_millis);
            let remote = Remote {
                stream: stream.clone(),
                pending: Vec::new(),
            };
            let output = self
                .runtime
                .run_output(request, remote, fuel, calls, deadline)
                .await;
            // Sources not yet sent still need the server's check.
            let flushed = match output.effects {
                Some(mut remote) => remote.flush().await,
                None => Ok(()),
            };
            let (fuel_left, calls_left) = (output.fuel_left, output.calls_left);
            let outcome = match (output.bytes, flushed) {
                (Ok(bytes), Ok(())) => Outcome::Output(bytes),
                (Err(error), _) if error.is::<crate::GuestBusy>() => Outcome::Deadline,
                _ => Outcome::Failed,
            };
            let done = FromWorker::Done {
                fuel_left,
                calls_left,
                outcome,
            };
            wire::send(&mut *stream.lock().await, &done.encode()?).await?;
        }
    }
}

/// Admit and compile a component, for the compile process. Its contract is checked by
/// loading the result, as a worker will.
pub fn compile_artifact(component: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    let artifact = crate::precompile(component, limits)?;
    Worker::load_from_broker(&artifact, limits.clone())?;
    Ok(artifact)
}
