//! Private immutable object files. This module does not grant upload/download
//! authority and is not a substitute for transactional metadata or quotas.
//!
//! Run I/O on bounded workers retaining their admission permit until completion.
//! Dropping a request must set its cancellation flag; dropping these objects
//! closes descriptors but deliberately performs no potentially blocking cleanup.
use anyhow::{Context, Result, ensure};
use noxide_protocol::blobs::{MAX_UPLOAD_BYTES, TRANSFER_BUFFER_BYTES};
use rand::{RngCore, rngs::OsRng};
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags},
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::NOFOLLOW
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);
pub(crate) const SCAN_BATCH: usize = 64;

/// Host-generated storage identity, never a guest filename or public BlobRef.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ObjectKey(String);
impl ObjectKey {
    pub(crate) fn random() -> Result<Self> {
        let mut bytes = [0; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .context("blob randomness unavailable")?;
        Self::parse(hex(&bytes))
    }
    pub(crate) fn parse(value: String) -> Result<Self> {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid object identity"
        );
        Ok(Self(value))
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObjectKey([redacted])")
    }
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

/// A request's monotonic bound. Never used for lifecycle expiry or GC grace.
#[derive(Clone)]
pub(crate) struct IoGuard {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
impl IoGuard {
    pub(crate) fn new(deadline: Instant, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            deadline,
            cancelled,
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        ensure!(
            !self.cancelled.load(Ordering::Acquire) && Instant::now() < self.deadline,
            "blob transfer cancelled or expired"
        );
        Ok(())
    }
}

struct Inner {
    _root: OwnedFd,
    _lease: OwnedFd,
    partial: OwnedFd,
    objects: OwnedFd,
    identity: ObjectKey,
}
#[derive(Clone)]
pub(crate) struct BlobStore(Arc<Inner>);

impl BlobStore {
    /// Requires an absolute operator path with no symlink components. Only its
    /// final directory may be created; existing directories must be private and
    /// owned by this process's effective user. One process owns a store at once.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let (parent, name) = parent(path)?;
        let root = private_dir(&parent, &name)?;
        let lease = fs::openat(
            &root,
            "lock",
            FILE_FLAGS | OFlags::RDWR | OFlags::CREATE,
            Mode::RUSR | Mode::WUSR,
        )
        .context("open blob store lease")?;
        regular(&lease, 0o600, Some(0))?;
        fs::flock(&lease, FlockOperation::NonBlockingLockExclusive)
            .context("blob store already owned")?;
        // A configured private directory is not automatically an object store.
        // Refuse unrelated root entries rather than adopt/clean an operator's
        // existing data. The six fixed layout names plus dots bound this scan.
        let mut entries = fs::Dir::read_from(&root)?;
        let mut count = 0;
        for entry in &mut entries {
            count += 1;
            ensure!(count <= 8, "unexpected blob store root layout");
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            ensure!(
                matches!(
                    name,
                    b"." | b".."
                        | b"identity"
                        | b"lock"
                        | b"partial"
                        | b"objects"
                        | b"pair"
                        | b"pair.pending"
                ),
                "unexpected blob store root entry"
            );
        }
        let identity = identity(&root)?;
        let partial = private_dir(&root, "partial")?;
        let objects = private_dir(&root, "objects")?;
        ensure!(
            fs::fstat(&partial)?.st_dev == fs::fstat(&objects)?.st_dev,
            "blob directories must share a filesystem"
        );
        Ok(Self(Arc::new(Inner {
            _root: root,
            _lease: lease,
            partial,
            objects,
            identity,
        })))
    }
    pub(crate) fn identity(&self) -> &ObjectKey {
        &self.0.identity
    }

    /// The caller must commit quota reservation and Uploading metadata first.
    /// Create-new prevents replacing even another failed upload's partial file.
    pub(crate) fn begin(
        &self,
        key: ObjectKey,
        limit: u64,
        guard: IoGuard,
    ) -> Result<PendingObject> {
        guard.check()?;
        ensure!(
            (1..=MAX_UPLOAD_BYTES).contains(&limit),
            "invalid upload byte limit"
        );
        let fd = fs::openat(
            &self.0.partial,
            key.as_str(),
            FILE_FLAGS | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        )
        .context("create private upload")?;
        regular(&fd, 0o600, Some(0))?;
        guard.check()?;
        Ok(PendingObject {
            store: self.clone(),
            key,
            file: fd.into(),
            limit,
            written: 0,
            digest: Sha256::new(),
            guard,
        })
    }

    /// Caller holds current resource/field authority in its short transaction.
    /// Capture this descriptor before releasing that transaction. A missing,
    /// replaced, linked, writable or wrong-size object is an error, never a 200.
    pub(crate) fn open_object(
        &self,
        key: &ObjectKey,
        expected: u64,
        guard: IoGuard,
    ) -> Result<OpenedObject> {
        guard.check()?;
        ensure!(expected <= MAX_UPLOAD_BYTES, "invalid object byte count");
        let fd = fs::openat(
            &self.0.objects,
            key.as_str(),
            FILE_FLAGS | OFlags::RDONLY,
            Mode::empty(),
        )
        .context("blob object unavailable")?;
        regular(&fd, 0o400, Some(expected))?;
        guard.check()?;
        Ok(OpenedObject {
            file: fd.into(),
            remaining: expected,
            guard,
            _store: self.clone(),
        })
    }

    /// Only a fenced metadata GC claimant calls this. Idempotent across crash
    /// after unlink. The transaction has been released before these syscalls.
    pub(crate) fn remove(&self, key: &ObjectKey, guard: &IoGuard) -> Result<()> {
        for directory in [&self.0.partial, &self.0.objects] {
            guard.check()?;
            match fs::unlinkat(directory, key.as_str(), AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error).context("remove claimed blob object"),
            }
            fs::fsync(directory).context("persist blob removal")?;
            guard.check()?;
        }
        Ok(())
    }

    pub(crate) fn scan(&self, location: ObjectLocation) -> Result<ObjectScan> {
        let directory = match location {
            ObjectLocation::Partial => &self.0.partial,
            ObjectLocation::Final => &self.0.objects,
        };
        Ok(ObjectScan {
            directory: fs::Dir::read_from(directory)?,
            location,
            _store: self.clone(),
        })
    }
}

pub(crate) struct PendingObject {
    store: BlobStore,
    key: ObjectKey,
    file: File,
    limit: u64,
    written: u64,
    digest: Sha256,
    guard: IoGuard,
}
impl PendingObject {
    pub(crate) fn write_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        self.guard.check()?;
        ensure!(bytes.len() <= TRANSFER_BUFFER_BYTES, "upload buffer limit");
        let total = self
            .written
            .checked_add(bytes.len() as u64)
            .context("upload size overflow")?;
        ensure!(total <= self.limit, "upload byte limit");
        let mut remaining = bytes;
        while !remaining.is_empty() {
            self.guard.check()?;
            let written = match self.file.write(remaining) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result.context("write private upload")?,
            };
            ensure!(written != 0, "incomplete upload write");
            remaining = &remaining[written..];
        }
        self.written = total;
        self.digest.update(bytes);
        self.guard.check()
    }
    /// A DurableObject is constructible only after data and both rename
    /// directories have been synced. A deadline/error leaves an unclaimable
    /// partial or finalized orphan for metadata-driven bounded reconciliation.
    pub(crate) fn finalize(self) -> Result<DurableObject> {
        self.finalize_observed(|_| Ok(()))
    }
    fn finalize_observed(
        self,
        mut observe: impl FnMut(FinalizePoint) -> Result<()>,
    ) -> Result<DurableObject> {
        self.guard.check()?;
        regular(&self.file, 0o600, Some(self.written))?;
        fs::fchmod(&self.file, Mode::RUSR).context("seal uploaded object")?;
        fs::fsync(&self.file).context("persist uploaded data")?;
        observe(FinalizePoint::DataSynced)?;
        self.guard.check()?;
        fs::renameat_with(
            &self.store.0.partial,
            self.key.as_str(),
            &self.store.0.objects,
            self.key.as_str(),
            RenameFlags::NOREPLACE,
        )
        .context("finalize uploaded object")?;
        observe(FinalizePoint::Renamed)?;
        self.guard.check()?;
        fs::fsync(&self.store.0.objects).context("persist finalized object")?;
        observe(FinalizePoint::DestinationSynced)?;
        self.guard.check()?;
        fs::fsync(&self.store.0.partial).context("persist staging removal")?;
        observe(FinalizePoint::SourceSynced)?;
        self.guard.check()?;
        Ok(DurableObject {
            key: self.key,
            bytes: self.written,
            sha256: self.digest.finalize().into(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalizePoint {
    DataSynced,
    Renamed,
    DestinationSynced,
    SourceSynced,
}

/// Evidence for the metadata transition to Staged; never serialized to a guest.
pub(crate) struct DurableObject {
    key: ObjectKey,
    bytes: u64,
    sha256: [u8; 32],
}
impl DurableObject {
    pub(crate) fn key(&self) -> &ObjectKey {
        &self.key
    }
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }
    pub(crate) fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

pub(crate) struct OpenedObject {
    file: File,
    remaining: u64,
    guard: IoGuard,
    _store: BlobStore,
}
impl OpenedObject {
    /// The caller uses one reusable <=64KiB buffer. A captured descriptor stays
    /// valid through later GC unlink; this grants no authority to a new stream.
    pub(crate) fn read_chunk(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.guard.check()?;
        ensure!(
            !buffer.is_empty() && buffer.len() <= TRANSFER_BUFFER_BYTES,
            "download buffer limit"
        );
        if self.remaining == 0 {
            return Ok(0);
        }
        let len = buffer.len().min(self.remaining as usize);
        let read = loop {
            self.guard.check()?;
            match self.file.read(&mut buffer[..len]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => break result.context("read immutable object")?,
            }
        };
        ensure!(read != 0, "blob object truncated");
        self.remaining -= read as u64;
        self.guard.check()?;
        Ok(read)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectLocation {
    Partial,
    Final,
}
pub(crate) struct ObjectScan {
    directory: fs::Dir,
    location: ObjectLocation,
    _store: BlobStore,
}
impl ObjectScan {
    /// Reads at most 64 directory entries, including dot entries. Retain this
    /// scanner between worker batches; restarting it per batch can starve GC.
    pub(crate) fn next_batch(
        &mut self,
        guard: &IoGuard,
    ) -> Result<Vec<(ObjectLocation, ObjectKey)>> {
        let mut out = Vec::new();
        for _ in 0..SCAN_BATCH {
            guard.check()?;
            let Some(entry) = self.directory.next() else {
                break;
            };
            let entry = entry.context("scan blob objects")?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            ensure!(
                entry.file_type() == FileType::RegularFile,
                "unexpected blob directory entry"
            );
            let name = std::str::from_utf8(name).context("invalid object identity")?;
            out.push((self.location, ObjectKey::parse(name.to_owned())?));
        }
        Ok(out)
    }
}

fn parent(path: &Path) -> Result<(OwnedFd, String)> {
    ensure!(path.is_absolute(), "blob store path must be absolute");
    let mut components = path.components();
    ensure!(
        components.next() == Some(Component::RootDir),
        "invalid blob store path"
    );
    let parts = components
        .map(|component| match component {
            Component::Normal(name) => name
                .to_str()
                .map(str::to_owned)
                .context("invalid blob store path"),
            _ => anyhow::bail!("noncanonical blob store path"),
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(!parts.is_empty(), "blob store cannot be filesystem root");
    let mut fd = fs::open("/", DIR_FLAGS, Mode::empty())?;
    for part in &parts[..parts.len() - 1] {
        fd = fs::openat(&fd, part.as_str(), DIR_FLAGS, Mode::empty())
            .context("open blob store parent")?;
    }
    Ok((fd, parts.last().unwrap().clone()))
}
fn private_dir(parent: &OwnedFd, name: &str) -> Result<OwnedFd> {
    match fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => fs::fsync(parent).context("persist private blob directory")?,
        Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error).context("create private blob directory"),
    }
    let fd = fs::openat(parent, name, DIR_FLAGS, Mode::empty())
        .context("open private blob directory")?;
    let stat = fs::fstat(&fd)?;
    ensure!(
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            && stat.st_mode & 0o7777 == 0o700
            && stat.st_uid == rustix::process::geteuid().as_raw(),
        "blob directory is not private and owned"
    );
    Ok(fd)
}
fn regular(fd: &impl std::os::fd::AsFd, mode: u32, bytes: Option<u64>) -> Result<()> {
    let stat = fs::fstat(fd)?;
    ensure!(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
            && stat.st_mode & 0o7777 == mode
            && stat.st_uid == rustix::process::geteuid().as_raw()
            && stat.st_nlink == 1
            && stat.st_size >= 0
            && bytes.is_none_or(|n| stat.st_size as u64 == n),
        "invalid immutable object metadata"
    );
    Ok(())
}
fn identity(root: &OwnedFd) -> Result<ObjectKey> {
    match fs::openat(
        root,
        "identity",
        FILE_FLAGS | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => {
            regular(&fd, 0o600, Some(0))?;
            let key = ObjectKey::random()?;
            let mut file = File::from(fd);
            file.write_all(key.as_str().as_bytes())
                .context("write blob store identity")?;
            fs::fchmod(&file, Mode::RUSR)?;
            fs::fsync(&file)?;
            fs::fsync(root)?;
            Ok(key)
        }
        Err(rustix::io::Errno::EXIST) => {
            let fd = fs::openat(root, "identity", FILE_FLAGS | OFlags::RDONLY, Mode::empty())?;
            regular(&fd, 0o400, Some(64))?;
            let mut bytes = [0; 64];
            File::from(fd).read_exact(&mut bytes)?;
            ObjectKey::parse(std::str::from_utf8(&bytes)?.to_owned())
        }
        Err(error) => Err(error).context("create blob store identity"),
    }
}

#[path = "blob_pairing.rs"]
mod pairing;
pub(crate) use pairing::{
    DurablePairMarker, PairId, PairObservation, PairPhase, PairRecord, PairStep,
};

#[cfg(test)]
#[path = "blob_store_tests.rs"]
mod tests;
