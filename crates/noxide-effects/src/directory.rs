//! The private directory that binds an effect queue to one host. Opening it grants
//! no delivery ownership.
use crate::types::digest;
use anyhow::{Context, Result, ensure};
use rustix::{
    fd::OwnedFd,
    fs::{self, Mode, OFlags},
};
use std::{
    path::{Component, Path},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);
/// Walks without read access, so a confined worker needs a rule for the secret only.
pub const WALK: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
pub struct OwnerDirectory {
    pub fd: OwnedFd,
    digest: String,
}
impl OwnerDirectory {
    pub fn open(path: &Path, deadline: Instant) -> Result<Self> {
        let fd = open_directory(path, deadline)?;
        let stat = fs::fstat(&fd)?;
        ensure!(
            stat.st_uid == rustix::process::geteuid().as_raw() && stat.st_mode & 0o7777 == 0o700,
            "effect owner directory must be private and owned"
        );
        let digest = digest(&(
            "effect-owner-directory-v1",
            path.to_str().context("invalid effect owner path")?,
            stat.st_dev,
            stat.st_ino,
        ))?;
        check(deadline)?;
        Ok(Self { fd, digest })
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
fn open_directory(path: &Path, deadline: Instant) -> Result<OwnedFd> {
    walk_directory(path, DIRECTORY, deadline)
}
pub fn walk_directory(path: &Path, flags: OFlags, deadline: Instant) -> Result<OwnedFd> {
    ensure!(
        path.is_absolute() && path.as_os_str().len() <= 4096,
        "effect host path must be absolute and bounded"
    );
    let mut parts = path.components();
    ensure!(
        parts.next() == Some(Component::RootDir),
        "invalid effect host path"
    );
    let mut fd = fs::open("/", flags, Mode::empty())?;
    let mut count = 0;
    for part in parts {
        check(deadline)?;
        count += 1;
        ensure!(count <= 64, "effect host path depth");
        let Component::Normal(name) = part else {
            anyhow::bail!("noncanonical effect host path")
        };
        fd = fs::openat(&fd, name, flags, Mode::empty()).context("open effect host directory")?;
    }
    check(deadline)?;
    Ok(fd)
}
pub fn check(deadline: Instant) -> Result<()> {
    ensure!(Instant::now() < deadline, "effect host I/O deadline");
    Ok(())
}

pub struct DirectoryPreparation {
    started: AtomicBool,
    result: OnceLock<std::result::Result<Arc<OwnerDirectory>, ()>>,
    changed: tokio::sync::Notify,
}
impl DirectoryPreparation {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: AtomicBool::new(false),
            result: OnceLock::new(),
            changed: tokio::sync::Notify::new(),
        })
    }
    pub fn prepared(&self) -> Result<&Arc<OwnerDirectory>> {
        self.result
            .get()
            .context("effect directory not prepared")?
            .as_ref()
            .map_err(|_| anyhow::anyhow!("effect directory preparation failed"))
    }
    pub fn digest(&self) -> Result<&str> {
        Ok(self.prepared()?.digest())
    }
    /// At most one bounded native preparation. The blocking task owns its state
    /// through actual completion even if the caller is cancelled.
    pub async fn prepare(
        state: &Arc<Self>,
        effective: &crate::effect_deployment::EffectiveEffectDeployment,
        deadline: std::time::Instant,
    ) -> Result<()> {
        let path = effective
            .runtime_directory
            .clone()
            .context("effect runtime directory missing")?;
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
            tokio::time::timeout_at(deadline.into(), changed)
                .await
                .context("effect directory preparation deadline")?;
        }
    }
}
