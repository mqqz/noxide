//! One DB-bound delivery owner. Wall leases never release physical capacity.
use crate::transport::{BearerSecret, Transport};
use anyhow::{Context, Result, ensure};
use noxide_effects::{
    directory::{OwnerDirectory, WALK, check, walk_directory},
    types::opaque,
};
use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, FlockOperation, Mode, OFlags},
};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const FILE: OFlags = OFlags::NOFOLLOW
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);
type Active = BTreeMap<u64, (Option<String>, tokio::time::Instant)>;
pub struct DeliveryOwner {
    lease: Arc<OwnerLease>,
    pub transport: Transport,
    slots: Arc<Semaphore>,
    concurrency: u8,
    active: Mutex<Active>,
    next: AtomicU64,
    changed: tokio::sync::Notify,
    pub claim_lock: tokio::sync::Mutex<()>,
}
pub struct OwnerLease {
    _directory: Arc<OwnerDirectory>,
    file: OwnedFd,
}
impl OwnerLease {
    pub fn open(directory: Arc<OwnerDirectory>, store_id: &str, deadline: Instant) -> Result<Self> {
        check(deadline)?;
        ensure!(
            opaque(store_id)
                && store_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
            "invalid effect owner binding"
        );
        let name = format!("noxide-effects-{store_id}.lock");
        let file = fs::openat(
            &directory.fd,
            name.as_str(),
            FILE | OFlags::RDWR | OFlags::CREATE,
            Mode::RUSR | Mode::WUSR,
        )
        .context("open effect delivery owner")?;
        regular(&file, 0)?;
        check(deadline)?;
        Ok(Self {
            _directory: directory,
            file,
        })
    }
}
impl Drop for DeliveryOwner {
    fn drop(&mut self) {
        let _ = fs::flock(&self.lease.file, FlockOperation::Unlock);
    }
}
impl DeliveryOwner {
    pub fn claim(
        lease: Arc<OwnerLease>,
        concurrency: u8,
        transport: Transport,
    ) -> Result<Arc<Self>> {
        ensure!((1..=2).contains(&concurrency), "invalid effect concurrency");
        fs::flock(&lease.file, FlockOperation::NonBlockingLockExclusive)
            .context("effect delivery already owned")?;
        Ok(Arc::new(Self {
            lease,
            transport,
            slots: Arc::new(Semaphore::new(usize::from(concurrency))),
            concurrency,
            active: Mutex::new(BTreeMap::new()),
            next: AtomicU64::new(1),
            changed: tokio::sync::Notify::new(),
            claim_lock: tokio::sync::Mutex::new(()),
        }))
    }
    pub fn try_attempt(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
    ) -> Result<PhysicalAttempt> {
        let physical = self
            .slots
            .clone()
            .try_acquire_owned()
            .context("effect delivery busy")?;
        let gate = Arc::new(Semaphore::new(1));
        let request = Arc::new(gate.clone().try_acquire_owned()?);
        let serial = self.next.fetch_add(1, Ordering::AcqRel);
        ensure!(serial < u64::MAX, "effect physical serial exhausted");
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(serial, (None, deadline));
        let state = Arc::new(PhysicalState {
            owner: self.clone(),
            _physical: Some(physical),
            serial,
            cancelled: AtomicBool::new(false),
        });
        Ok(PhysicalAttempt {
            state: Some(state),
            request: Some(request),
            gate,
            deadline,
            executor: tokio::runtime::Handle::current(),
        })
    }
    pub fn active_claims(&self) -> Vec<String> {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter_map(|(id, _)| id.clone())
            .collect()
    }
    pub async fn drain(&self) -> Result<()> {
        loop {
            let changed = self.changed.notified();
            let deadline = {
                let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
                if active.is_empty() {
                    ensure!(
                        self.slots.available_permits() == usize::from(self.concurrency),
                        "effect physical capacity unconfirmed"
                    );
                    return Ok(());
                }
                active
                    .values()
                    .map(|(_, d)| *d)
                    .max()
                    .context("effect drain deadline missing")?
            };
            tokio::time::timeout_at(deadline, changed)
                .await
                .context("effect physical stop unconfirmed")?;
        }
    }
}
struct PhysicalState {
    owner: Arc<DeliveryOwner>,
    _physical: Option<OwnedSemaphorePermit>,
    serial: u64,
    cancelled: AtomicBool,
}
impl Drop for PhysicalState {
    fn drop(&mut self) {
        drop(self._physical.take());
        self.owner
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.serial);
        self.owner.changed.notify_waiters();
    }
}
/// The private request token is also retained by ordinary provider cleanup.
/// Only reacquiring its unique gate proves that provider/file holders stopped.
pub struct PhysicalAttempt {
    state: Option<Arc<PhysicalState>>,
    request: Option<Arc<OwnedSemaphorePermit>>,
    gate: Arc<Semaphore>,
    deadline: tokio::time::Instant,
    executor: tokio::runtime::Handle,
}
impl PhysicalAttempt {
    pub fn request(&self) -> Arc<OwnedSemaphorePermit> {
        self.request.as_ref().expect("live effect attempt").clone()
    }
    pub fn mark_claim(&self, id: &str) {
        let state = self.state.as_ref().expect("live effect attempt");
        if let Some((claim, _)) = state
            .owner
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&state.serial)
        {
            *claim = Some(id.to_owned());
        }
    }
    pub fn native_hold(&self) -> NativeHold {
        NativeHold {
            state: self.state.as_ref().expect("live effect attempt").clone(),
            _request: self.request(),
        }
    }
    pub async fn finish(mut self) -> Result<()> {
        drop(self.request.take());
        let state = self.state.take().expect("live effect attempt");
        if tokio::time::timeout_at(self.deadline, self.gate.clone().acquire_owned())
            .await
            .is_err()
        {
            std::mem::forget(state);
            anyhow::bail!("effect physical stop unconfirmed; ownership retained")
        }
        drop(state);
        Ok(())
    }
}
impl Drop for PhysicalAttempt {
    fn drop(&mut self) {
        drop(self.request.take());
        if let Some(state) = self.state.take() {
            state.cancelled.store(true, Ordering::Release);
            let gate = self.gate.clone();
            let deadline = self.deadline;
            // At most two such cleanup tasks exist: each retains its physical
            // slot and exclusive owner. No replacement deadline is introduced.
            self.executor.spawn(async move {
                if tokio::time::timeout_at(deadline, gate.acquire_owned())
                    .await
                    .is_err()
                {
                    std::mem::forget(state);
                }
            });
        }
    }
}
pub struct NativeHold {
    state: Arc<PhysicalState>,
    _request: Arc<OwnedSemaphorePermit>,
}
impl NativeHold {
    fn check(&self, deadline: Instant) -> Result<()> {
        ensure!(
            !self.state.cancelled.load(Ordering::Acquire),
            "effect file work cancelled"
        );
        check(deadline)
    }
}
/// Runs only on an admitted blocking worker, retaining the physical owner and
/// request token until every file descriptor has actually closed.
pub fn read_secret(path: &Path, deadline: Instant, hold: NativeHold) -> Result<BearerSecret> {
    hold.check(deadline)?;
    let parent = path.parent().context("effect secret parent missing")?;
    let name = path.file_name().context("effect secret filename missing")?;
    let directory = walk_directory(parent, WALK, deadline)?;
    let fd = fs::openat(&directory, name, FILE | OFlags::RDONLY, Mode::empty())
        .context("open effect secret")?;
    let stat = fs::fstat(&fd)?;
    ensure!(
        (1..=2048).contains(&stat.st_size),
        "effect secret byte limit"
    );
    regular(&fd, stat.st_size as u64)?;
    hold.check(deadline)?;
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    let mut file = File::from(fd);
    std::io::Read::by_ref(&mut file)
        .take(2049)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() == stat.st_size as usize,
        "effect secret changed during read"
    );
    drop(file);
    hold.check(deadline)?;
    BearerSecret::from_host(String::from_utf8(bytes).context("invalid effect secret encoding")?)
        .map_err(|_| anyhow::anyhow!("invalid effect bearer secret"))
}
fn regular(fd: &OwnedFd, size: u64) -> Result<()> {
    let stat = fs::fstat(fd)?;
    ensure!(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
            && stat.st_mode & 0o7777 == 0o600
            && stat.st_uid == rustix::process::geteuid().as_raw()
            && stat.st_nlink == 1
            && stat.st_size >= 0
            && stat.st_size as u64 == size,
        "effect file must be private owned regular metadata"
    );
    Ok(())
}
#[cfg(test)]
mod tests;
