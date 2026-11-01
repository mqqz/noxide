//! Pairing data is not a DB commit acknowledgement. The coordinator must use
//! the shared commit guard before following a pending record with FS writes.
use super::*;

#[derive(Clone, PartialEq, Eq)]
pub struct PairId(ObjectKey);
impl PairId {
    pub fn random() -> Result<Self> {
        Ok(Self(ObjectKey::random()?))
    }
    pub fn parse(value: String) -> Result<Self> {
        Ok(Self(ObjectKey::parse(value)?))
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl fmt::Debug for PairId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairId([redacted])")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairPhase {
    Pending,
    Paired,
}
#[derive(Clone, Debug)]
pub struct PairRecord {
    pub store: ObjectKey,
    pub pair: PairId,
    pub phase: PairPhase,
    pub empty_metadata: bool,
}
pub struct PairObservation {
    store: BlobStore,
    marker: Option<PairId>,
    pending: Option<Vec<u8>>,
    empty: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub enum PairStep {
    CreatePending,
    InstallMarker(PairId),
    Acknowledge(PairId),
    Ready(PairId),
}
impl PairObservation {
    pub fn store_identity(&self) -> &ObjectKey {
        self.store.identity()
    }
    pub fn decide(&self, record: Option<&PairRecord>) -> Result<PairStep> {
        match record {
            None => {
                ensure!(
                    self.marker.is_none() && self.pending.is_none() && self.empty,
                    "unpaired database cannot adopt an existing store"
                );
                Ok(PairStep::CreatePending)
            }
            Some(record) => {
                ensure!(
                    record.store == *self.store.identity(),
                    "pair store identity mismatch"
                );
                match record.phase {
                    PairPhase::Paired => {
                        ensure!(
                            self.pending.is_none() && self.marker.as_ref() == Some(&record.pair),
                            "paired database lacks matching durable marker"
                        );
                        Ok(PairStep::Ready(record.pair.clone()))
                    }
                    PairPhase::Pending => {
                        ensure!(
                            record.empty_metadata && self.empty,
                            "pending database cannot adopt populated store or metadata"
                        );
                        if let Some(marker) = &self.marker {
                            ensure!(
                                marker == &record.pair && self.pending.is_none(),
                                "pending pair marker mismatch"
                            );
                            Ok(PairStep::Acknowledge(record.pair.clone()))
                        } else {
                            if let Some(bytes) = &self.pending {
                                ensure!(
                                    record.pair.as_str().as_bytes().starts_with(bytes),
                                    "partial pairing marker disagrees with pending database"
                                );
                            }
                            Ok(PairStep::InstallMarker(record.pair.clone()))
                        }
                    }
                }
            }
        }
    }
}
/// File and root directory have both been fsynced. Matching DB paired
/// acknowledgement and healthy lifecycle activation are still required.
pub struct DurablePairMarker {
    store: BlobStore,
    pair: PairId,
}
impl DurablePairMarker {
    pub fn store(&self) -> &ObjectKey {
        self.store.identity()
    }
    pub fn pair(&self) -> &PairId {
        &self.pair
    }
}
impl BlobStore {
    /// One bounded entry batch per directory proves empty/nonempty. Unknown
    /// name/type errors refuse pairing; no object is removed or adopted.
    pub fn observe_pair(&self, guard: &IoGuard) -> Result<PairObservation> {
        guard.check()?;
        let marker = read_marker(&self.0._root, "pair", false)?
            .map(|bytes| PairId::parse(String::from_utf8(bytes)?))
            .transpose()?;
        guard.check()?;
        let pending = read_marker(&self.0._root, "pair.pending", true)?;
        ensure!(
            marker.is_none() || pending.is_none(),
            "ambiguous pairing markers"
        );
        let mut partial = self.scan(ObjectLocation::Partial)?;
        let mut objects = self.scan(ObjectLocation::Final)?;
        let empty = partial.next_batch(guard)?.is_empty() && objects.next_batch(guard)?.is_empty();
        guard.check()?;
        Ok(PairObservation {
            store: self.clone(),
            marker,
            pending,
            empty,
        })
    }
    /// ONLY after authoritative durable pending DB acknowledgement/recovery.
    /// This low-level helper does not prove that commit or delete unknown data.
    pub fn install_pair(&self, record: &PairRecord, guard: &IoGuard) -> Result<DurablePairMarker> {
        self.install_pair_observed(record, guard, |_| Ok(()))
    }
    fn install_pair_observed(
        &self,
        record: &PairRecord,
        guard: &IoGuard,
        mut observe: impl FnMut(PairPoint) -> Result<()>,
    ) -> Result<DurablePairMarker> {
        let observation = self.observe_pair(guard)?;
        let step = observation.decide(Some(record))?;
        ensure!(
            matches!(step, PairStep::InstallMarker(_) | PairStep::Acknowledge(_)),
            "pair installation requires pending database"
        );
        if matches!(step, PairStep::InstallMarker(_)) {
            if observation.pending.is_some() {
                // Only this fixed private partial marker, validated as the SAME
                // committed pending ID prefix, is removed. No recursive cleanup.
                guard.check()?;
                fs::unlinkat(&self.0._root, "pair.pending", AtFlags::empty())?;
                fs::fsync(&self.0._root)?;
                guard.check()?;
            }
            let fd = fs::openat(
                &self.0._root,
                "pair.pending",
                FILE_FLAGS | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            )?;
            regular(&fd, 0o600, Some(0))?;
            let mut file = File::from(fd);
            guard.check()?;
            file.write_all(record.pair.as_str().as_bytes())
                .context("write pending pair marker")?;
            fs::fchmod(&file, Mode::RUSR)?;
            fs::fsync(&file)?;
            observe(PairPoint::FileSynced)?;
            guard.check()?;
            fs::renameat_with(
                &self.0._root,
                "pair.pending",
                &self.0._root,
                "pair",
                RenameFlags::NOREPLACE,
            )?;
            observe(PairPoint::Renamed)?;
            guard.check()?;
        }
        // A marker recovered between rename and directory fsync is synced
        // again. Its name alone is not evidence of filesystem durability.
        let fd = fs::openat(
            &self.0._root,
            "pair",
            FILE_FLAGS | OFlags::RDONLY,
            Mode::empty(),
        )?;
        regular(&fd, 0o400, Some(64))?;
        fs::fsync(&fd)?;
        guard.check()?;
        fs::fsync(&self.0._root)?;
        observe(PairPoint::DirectorySynced)?;
        guard.check()?;
        let marker =
            read_marker(&self.0._root, "pair", false)?.context("pair marker unavailable")?;
        ensure!(
            marker == record.pair.as_str().as_bytes(),
            "pair marker changed"
        );
        Ok(DurablePairMarker {
            store: self.clone(),
            pair: record.pair.clone(),
        })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PairPoint {
    FileSynced,
    Renamed,
    DirectorySynced,
}
fn read_marker(root: &OwnedFd, name: &str, partial: bool) -> Result<Option<Vec<u8>>> {
    let fd = match fs::openat(root, name, FILE_FLAGS | OFlags::RDONLY, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error).context("open pairing marker"),
    };
    let stat = fs::fstat(&fd)?;
    ensure!((0..=64).contains(&stat.st_size), "pair marker length");
    let mode = stat.st_mode & 0o7777;
    ensure!(
        mode == 0o400 || partial && mode == 0o600,
        "pair marker mode"
    );
    regular(&fd, mode, None)?;
    let mut bytes = Vec::with_capacity(64);
    File::from(fd).take(65).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 64 && (partial || bytes.len() == 64),
        "pair marker length"
    );
    ensure!(
        bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
        "invalid pair marker encoding"
    );
    Ok(Some(bytes))
}

#[cfg(test)]
#[path = "pairing_tests.rs"]
mod tests;
