//! Bounded native I/O ownership. A timed-out/dropped request cancels cooperative
//! work, but its permit remains inside the actual worker until that worker exits.
//! Kernel I/O may block beyond a deadline: capacity then stays quarantined.
use crate::{
    state::Generation,
    store::{IoGuard, ObjectKey},
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::blobs::{MAX_CONCURRENT_DOWNLOADS, MAX_CONCURRENT_UPLOADS};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Instant,
};
use tokio::{sync::Semaphore, task::JoinHandle};

const RUNNING: u8 = 0;
const SUCCEEDED: u8 = 1;
const FAILED: u8 = 2;

mod sealed {
    pub trait Sealed {}
}
/// A completed upload worker cannot return a writable descriptor or partial
/// upload to be resumed after its stopped witness has been published.
pub trait IoOutput: sealed::Sealed + Send + 'static {}
impl sealed::Sealed for crate::store::DurableObject {}
impl IoOutput for crate::store::DurableObject {}
impl sealed::Sealed for () {}
impl IoOutput for () {}
impl sealed::Sealed for crate::inspect::InventoryBatch {}
impl IoOutput for crate::inspect::InventoryBatch {}
impl sealed::Sealed for crate::inspect::Snapshot {}
impl IoOutput for crate::inspect::Snapshot {}
impl sealed::Sealed for crate::store::OpenedObject {}
impl IoOutput for crate::store::OpenedObject {}
impl sealed::Sealed for crate::store::PairObservation {}
impl IoOutput for crate::store::PairObservation {}
impl sealed::Sealed for crate::store::DurablePairMarker {}
impl IoOutput for crate::store::DurablePairMarker {}

pub struct IoPool {
    permits: Arc<Semaphore>,
}
impl IoPool {
    pub fn uploads(count: u8) -> Result<Self> {
        Self::new(count, MAX_CONCURRENT_UPLOADS)
    }
    pub fn downloads(count: u8) -> Result<Self> {
        Self::new(count, MAX_CONCURRENT_DOWNLOADS)
    }
    fn new(count: u8, ceiling: u8) -> Result<Self> {
        ensure!(count > 0 && count <= ceiling, "invalid blob worker limit");
        Ok(Self {
            permits: Arc::new(Semaphore::new(usize::from(count))),
        })
    }
    /// No waiting admission queue. Acquire before submitting to Tokio's native
    /// worker pool, bounding even work queued behind unrelated blocking tasks.
    pub fn try_start<T: IoOutput>(
        &self,
        key: ObjectKey,
        generation: Generation,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
        operation: impl FnOnce(IoGuard) -> Result<T> + Send + 'static,
    ) -> Result<IoJob<T>> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .context("blob I/O busy")?;
        let guard = IoGuard::new(deadline, cancelled.clone());
        guard.check()?;
        let witness = IoWitness(Arc::new(Completion {
            key,
            generation,
            cancelled: cancelled.clone(),
            stopped: AtomicBool::new(false),
            outcome: AtomicU8::new(RUNNING),
            changed: tokio::sync::Notify::new(),
        }));
        let worker = witness.clone();
        let handle = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let stopped = StopGuard(worker);
            let result = (|| {
                guard.check()?;
                let result = operation(guard.clone())?;
                guard.check()?;
                Ok(result)
            })();
            stopped.0.0.outcome.store(
                if result.is_ok() { SUCCEEDED } else { FAILED },
                Ordering::Release,
            );
            result
        });
        Ok(IoJob {
            handle,
            witness,
            cancelled,
            deadline,
            finished: false,
        })
    }
}

struct Completion {
    key: ObjectKey,
    generation: Generation,
    cancelled: Arc<AtomicBool>,
    stopped: AtomicBool,
    outcome: AtomicU8,
    changed: tokio::sync::Notify,
}
#[derive(Clone)]
pub struct IoWitness(Arc<Completion>);
pub struct StoppedIo(Arc<Completion>);
impl IoWitness {
    /// Absence of a database row is insufficient. This proof is minted only
    /// after the worker (including unwind) has released all owned file objects.
    pub fn stopped(&self) -> Option<StoppedIo> {
        self.0
            .stopped
            .load(Ordering::Acquire)
            .then(|| StoppedIo(self.0.clone()))
    }
}
impl StoppedIo {
    pub fn key(&self) -> &ObjectKey {
        &self.0.key
    }
    pub fn generation(&self) -> Generation {
        self.0.generation
    }
    pub fn failed_or_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
            || self.0.outcome.load(Ordering::Acquire) != SUCCEEDED
    }
}
struct StopGuard(IoWitness);
impl Drop for StopGuard {
    fn drop(&mut self) {
        self.0.0.stopped.store(true, Ordering::Release);
        self.0.0.changed.notify_waiters();
    }
}

pub struct IoJob<T> {
    handle: JoinHandle<Result<T>>,
    witness: IoWitness,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    finished: bool,
}
impl<T> IoJob<T> {
    pub fn witness(&self) -> IoWitness {
        self.witness.clone()
    }
    pub async fn finish(mut self) -> Result<T> {
        let result = tokio::time::timeout_at(self.deadline.into(), &mut self.handle)
            .await
            .context("blob I/O deadline")?
            .context("blob I/O worker failed")??;
        IoGuard::new(self.deadline, self.cancelled.clone()).check()?;
        self.finished = true;
        Ok(result)
    }
}
impl<T> Drop for IoJob<T> {
    fn drop(&mut self) {
        if !self.finished {
            self.cancelled.store(true, Ordering::Release);
        }
        // A JoinHandle drop detaches; it cannot cancel a running native syscall.
        // The actual worker owns its permit and completion witness to the end.
    }
}

#[cfg(test)]
#[path = "io_tests.rs"]
mod tests;

impl IoWitness {
    /// A host reservation exists but its owner has not dispatched native I/O.
    /// The reservation lease must remain live until dispatch or mark this stopped.
    pub fn pending(key: ObjectKey, generation: Generation) -> Self {
        Self(Arc::new(Completion {
            key,
            generation,
            cancelled: Arc::new(AtomicBool::new(false)),
            stopped: AtomicBool::new(false),
            outcome: AtomicU8::new(FAILED),
            changed: tokio::sync::Notify::new(),
        }))
    }
    pub fn stop_unstarted(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.stopped.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
    #[cfg(any(test, feature = "test-support"))]
    pub async fn wait_stopped(&self) {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.stopped().is_some() {
                return;
            }
            changed.await;
        }
    }
}
