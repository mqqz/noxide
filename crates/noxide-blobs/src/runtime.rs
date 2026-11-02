//! The blob directory's process state, its pairing with the database and bounded
//! maintenance. The host keeps request admission and authorization; each maintenance
//! transaction here passes the host's fence first.
#[cfg(any(test, feature = "test-support"))]
use crate::upload::Barrier;
use crate::{
    blob_deployment::BlobDeployment,
    inspect::{InventoryBatch, Snapshot},
    io::{IoPool, IoWitness},
    metadata::{BlobRow, MetadataContext},
    state::Commitment,
    store::{BlobStore, IoGuard, ObjectKey, PairStep},
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{blobs::BlobPolicy, time::Timestamp};
use noxide_store::database::{Database, RequestError, Transaction};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::time::Instant;

/// What maintenance needs from the host. Every transaction calls `fence` first.
pub trait ReconcileHost: Sync {
    fn database(&self) -> &Database;
    /// Check this deployment's schema and generation inside `tx`.
    fn fence<'a>(&'a self, tx: &'a mut Transaction)
    -> impl Future<Output = Result<()>> + Send + 'a;
    /// Record that time passed and return the time this transaction observes.
    fn observed_now<'a>(
        &'a self,
        tx: &'a mut Transaction,
    ) -> impl Future<Output = Result<Timestamp>> + Send + 'a;
}

pub struct BlobRuntime {
    store: BlobStore,
    policy: BlobPolicy,
    process: ObjectKey,
    fence: crate::store::ProcessFence,
    uploads: Arc<IoPool>,
    downloads: Arc<IoPool>,
    streams: Arc<tokio::sync::Semaphore>,
    ready: AtomicBool,
    inventory: Arc<Mutex<Option<Inventory>>>,
    inventory_complete: AtomicBool,
    metadata_cursor: Mutex<String>,
    quarantined: AtomicBool,
    workers: Mutex<BTreeMap<String, IoWitness>>,
    undispatched: Mutex<BTreeMap<String, IoWitness>>,
    #[cfg(any(test, feature = "test-support"))]
    verification: Mutex<Option<Arc<Barrier>>>,
    #[cfg(any(test, feature = "test-support"))]
    gc_after_commit: Mutex<Option<Arc<Barrier>>>,
}
impl BlobRuntime {
    pub fn open(deployment: BlobDeployment, policy: BlobPolicy) -> Result<Self> {
        let store = BlobStore::open(&deployment.directory)?;
        let fence = store.claim_process()?;
        Ok(Self {
            process: fence.process().clone(),
            fence,
            store,
            uploads: Arc::new(IoPool::uploads(policy.limits.uploads)?),
            downloads: Arc::new(IoPool::downloads(policy.limits.downloads)?),
            streams: Arc::new(tokio::sync::Semaphore::new(usize::from(
                policy.limits.downloads,
            ))),
            policy,
            ready: AtomicBool::new(false),
            inventory: Arc::new(Mutex::new(None)),
            inventory_complete: AtomicBool::new(false),
            metadata_cursor: Mutex::new(String::new()),
            quarantined: AtomicBool::new(false),
            workers: Mutex::new(BTreeMap::new()),
            undispatched: Mutex::new(BTreeMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            verification: Mutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            gc_after_commit: Mutex::new(None),
        })
    }
    /// Whether new uploads may start.
    pub fn available(&self) -> Result<()> {
        ensure!(self.ready.load(Ordering::Acquire), RequestError::Busy);
        ensure!(
            self.inventory_complete.load(Ordering::Acquire),
            RequestError::Busy
        );
        ensure!(
            !self.quarantined.load(Ordering::Acquire),
            RequestError::Busy
        );
        Ok(())
    }
    pub fn store(&self) -> &BlobStore {
        &self.store
    }
    pub fn policy(&self) -> &BlobPolicy {
        &self.policy
    }
    pub fn process(&self) -> &ObjectKey {
        &self.process
    }
    pub fn uploads(&self) -> &Arc<IoPool> {
        &self.uploads
    }
    pub fn downloads(&self) -> &Arc<IoPool> {
        &self.downloads
    }
    pub fn streams(&self) -> &Arc<tokio::sync::Semaphore> {
        &self.streams
    }
    /// Whether the directory has been paired with the database.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    /// Stop new uploads until an operator intervenes. There is no way to undo this here.
    pub fn quarantine(&self) {
        self.quarantined.store(true, Ordering::Release);
    }
    /// Reserve a worker slot for a new object. The lease stops it if never dispatched.
    pub fn reserve(&self, row: &BlobRow) -> Result<ReservationLease> {
        let witness = IoWitness::pending(row.metadata.key.clone(), row.metadata.generation);
        let mut workers = self.workers.lock().unwrap();
        ensure!(
            workers.len() < self.policy.limits.objects as usize,
            "blob reservation registry full"
        );
        workers.insert(row.metadata.key.as_str().into(), witness.clone());
        Ok(ReservationLease {
            witness,
            armed: true,
        })
    }
    /// Track running work so reconciliation can prove when it stopped.
    pub fn record_worker(&self, row: &BlobRow, witness: IoWitness) {
        self.workers
            .lock()
            .unwrap()
            .insert(row.metadata.key.as_str().into(), witness);
    }
}

/// Test access to internal state. Deployed binaries never enable this feature.
#[cfg(any(test, feature = "test-support"))]
impl BlobRuntime {
    pub fn quarantined(&self) -> &AtomicBool {
        &self.quarantined
    }
    pub fn workers(&self) -> &Mutex<BTreeMap<String, IoWitness>> {
        &self.workers
    }
    pub fn undispatched(&self) -> &Mutex<BTreeMap<String, IoWitness>> {
        &self.undispatched
    }
    pub fn verification(&self) -> &Mutex<Option<Arc<Barrier>>> {
        &self.verification
    }
    pub fn gc_after_commit(&self) -> &Mutex<Option<Arc<Barrier>>> {
        &self.gc_after_commit
    }
}

pub fn commitment(domain: &str, values: &[&str]) -> Result<Commitment> {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    for value in values {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    Commitment::parse(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Commit, reporting an unacknowledged commit that may have succeeded as unknown.
pub async fn commit(tx: &mut Transaction) -> Result<()> {
    let result = tx.commit().await;
    if tx.commit_acknowledged() {
        return Ok(());
    }
    if tx.commit_may_have_succeeded() {
        return Err(RequestError::OutcomeUnknown.into());
    }
    result?;
    anyhow::bail!("blob metadata commit lacks acknowledgment")
}

impl BlobRuntime {
    /// Pair this directory with the database. Runs once, before any request.
    pub async fn activate(&self, database: &Database, deadline: Instant) -> Result<()> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let store = self.store.clone();
        let observation = self
            .uploads
            .try_start(
                self.process.clone(),
                crate::state::Generation::parse(1)?,
                deadline.into_std(),
                cancelled.clone(),
                move |guard| store.observe_pair(&guard),
            )?
            .finish()
            .await?;
        let mut tx = database.begin(deadline.into_std()).await?;
        tx.check_storage().await?;
        let prepared = MetadataContext { tx: &mut tx }
            .prepare_pair(&observation)
            .await?;
        ensure!(
            !prepared.pending_inserted || matches!(prepared.step, PairStep::InstallMarker(_)),
            "new pairing must install its pending marker"
        );
        // Unknown acknowledgment cannot authorize a filesystem marker. Restart
        // recovers the authoritative pending record through the same protocol.
        commit(&mut tx).await?;
        ensure!(
            tx.commit_acknowledged(),
            "blob pairing commit is unconfirmed"
        );
        if !matches!(prepared.step, PairStep::Ready(_)) {
            let store = self.store.clone();
            let marker = self
                .uploads
                .try_start(
                    self.process.clone(),
                    crate::state::Generation::parse(1)?,
                    deadline.into_std(),
                    cancelled,
                    move |guard| store.install_pair(&prepared.record, &guard),
                )?
                .finish()
                .await?;
            let mut tx = database.begin(deadline.into_std()).await?;
            MetadataContext { tx: &mut tx }
                .acknowledge_pair(&marker)
                .await?;
            commit(&mut tx).await?;
            ensure!(
                tx.commit_acknowledged(),
                "blob pairing acknowledgment is unconfirmed"
            );
        }
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    /// One bounded maintenance page. Unknown objects are charged and retained;
    /// only authoritative known metadata can produce a fenced deletion claim.
    pub async fn reconcile_page(&self, host: &impl ReconcileHost, deadline: Instant) -> Result<()> {
        let result = self.reconcile_page_inner(host, deadline).await;
        if result
            .as_ref()
            .err()
            .is_some_and(|error| error.is::<crate::store::PhysicalMismatch>())
        {
            self.quarantined.store(true, Ordering::Release);
        }
        result
    }

    async fn reconcile_page_inner(
        &self,
        host: &impl ReconcileHost,
        deadline: Instant,
    ) -> Result<()> {
        let inventory = self.inventory.clone();
        let store = self.store.clone();
        let batch = self
            .uploads
            .try_start(
                self.process.clone(),
                crate::state::Generation::parse(1)?,
                deadline.into_std(),
                Arc::new(AtomicBool::new(false)),
                move |guard| {
                    let mut inventory = inventory.lock().unwrap();
                    if inventory.is_none() {
                        *inventory = Some(Inventory::new(&store)?);
                    }
                    let batch = inventory.as_mut().unwrap().batch(&store, &guard)?;
                    if batch.complete {
                        *inventory = None;
                    }
                    Ok(batch)
                },
            )?
            .finish()
            .await?;
        let mut tx = host.database().begin(deadline.into_std()).await?;
        host.fence(&mut tx).await?;
        let now = host.observed_now(&mut tx).await?;
        for (key, physical) in batch.items {
            let row = MetadataContext { tx: &mut tx }.object(&key).await?;
            if row.is_none()
                && let Some(physical) = physical
            {
                self.quarantined.store(true, Ordering::Release);
                let bytes = physical
                    .partial
                    .unwrap_or(0)
                    .checked_add(physical.finalized.unwrap_or(0))
                    .context("unknown blob length overflow")?;
                let paths =
                    u8::from(physical.partial.is_some()) + u8::from(physical.finalized.is_some());
                MetadataContext { tx: &mut tx }
                    .quarantine_unknown(
                        &key,
                        bytes,
                        paths,
                        self.store.identity(),
                        &self.process,
                        now,
                    )
                    .await?;
            }
        }
        let after = self.metadata_cursor.lock().unwrap().clone();
        let rows = MetadataContext { tx: &mut tx }.page(&after).await?;
        commit(&mut tx).await?;
        ensure!(
            tx.commit_acknowledged(),
            "blob inventory commit unconfirmed"
        );
        if batch.complete {
            self.inventory_complete.store(true, Ordering::Release);
        }
        *self.metadata_cursor.lock().unwrap() = rows
            .last()
            .filter(|_| rows.len() == crate::inspect::INSPECTION_PAGE)
            .map(|r| r.metadata.binding.slot.as_str().into())
            .unwrap_or_default();
        // At most four deletions per page, always with committed CAS
        // claims and physical-stop witnesses for this process's work.
        let mut deleted = 0;
        for row in rows {
            if deleted == 4 {
                break;
            }
            if self.reconcile_row(host, &row, now, deadline).await? {
                deleted += 1;
            }
        }
        Ok(())
    }

    /// Plan one known row from its physical state. Returns whether it removed an object.
    async fn reconcile_row(
        &self,
        host: &impl ReconcileHost,
        row: &BlobRow,
        now: Timestamp,
        deadline: Instant,
    ) -> Result<bool> {
        use crate::inspect::{FindingKind, InspectionPage, SnapshotItem};
        let physical = self.row_snapshot(row, deadline).await?;
        let witness = self.stopped_witness(row);
        let stopped = witness.as_ref().and_then(IoWitness::stopped);
        let stopped_refs: Vec<_> = stopped.iter().collect();
        let page = InspectionPage::plan(
            self.store.identity(),
            &self.process,
            &[SnapshotItem {
                key: row.metadata.key.clone(),
                physical,
                metadata: Some(row.clone()),
            }],
            &stopped_refs,
            now,
        )?;
        let _digest = page.digest()?;
        let kind = page.findings[0].kind;
        ensure!(row.claimed <= now, "blob claim is ahead of observed clock");
        if kind.requires_operator() {
            self.quarantined.store(true, Ordering::Release);
            return Ok(false);
        }
        if kind == FindingKind::RetainTombstone {
            self.workers
                .lock()
                .unwrap()
                .remove(row.metadata.key.as_str());
            self.undispatched
                .lock()
                .unwrap()
                .remove(row.metadata.key.as_str());
        }
        if !kind.recoverable_hint() {
            return Ok(false);
        }
        if kind == FindingKind::CleanKnownDeletedObject {
            // Tombstones name only their original opaque key. A
            // current transaction rechecks them before native I/O.
            self.clean_tombstone(host, row, deadline).await?;
            return Ok(true);
        }
        let mut tx = host.database().begin(deadline.into_std()).await?;
        host.fence(&mut tx).await?;
        let current = MetadataContext { tx: &mut tx }
            .slot(&row.metadata.binding.slot)
            .await?
            .context("blob recovery row missing")?;
        if current.metadata.generation != row.metadata.generation
            || current.metadata.state != row.metadata.state
        {
            tx.rollback().await?;
            return Ok(false);
        }
        let (claimed, claim) = match kind {
            FindingKind::ClaimExpiredStage | FindingKind::ClaimUnreferenced => {
                MetadataContext { tx: &mut tx }
                    .claim_collectable(&current, &self.process, now)
                    .await?
            }
            FindingKind::ClaimStoppedUpload => {
                MetadataContext { tx: &mut tx }
                    .claim_stopped_upload(
                        &current,
                        &self.process,
                        now,
                        stopped.as_ref().context("stopped upload proof missing")?,
                    )
                    .await?
            }
            FindingKind::RecoverPriorProcessUpload => {
                MetadataContext { tx: &mut tx }
                    .recover_prior_upload(&current, &self.fence, now)
                    .await?
            }
            FindingKind::ResumeStoppedDeletion | FindingKind::RecoverPriorProcessDeletion => {
                MetadataContext { tx: &mut tx }
                    .resume_deletion(&current, &self.fence, now, stopped.as_ref())
                    .await?
            }
            _ => {
                tx.rollback().await?;
                return Ok(false);
            }
        };
        let dispatch = self.arm_deletion(row, witness, &claim);
        commit(&mut tx).await?;
        ensure!(tx.commit_acknowledged(), "blob deletion claim unconfirmed");
        self.delete_claimed(host, row, &claimed, &claim, dispatch, now, deadline)
            .await
    }

    async fn row_snapshot(
        &self,
        row: &BlobRow,
        deadline: Instant,
    ) -> Result<Option<crate::inspect::PhysicalSnapshot>> {
        let store = self.store.clone();
        let key = row.metadata.key.clone();
        Ok(self
            .uploads
            .try_start(
                key.clone(),
                row.metadata.generation,
                deadline.into_std(),
                Arc::new(AtomicBool::new(false)),
                move |guard| Ok(Snapshot(store.snapshot(&key, &guard)?)),
            )?
            .finish()
            .await?
            .0)
    }

    /// A stop proof for this row's generation, from its worker or its undispatched claim.
    fn stopped_witness(&self, row: &BlobRow) -> Option<IoWitness> {
        let matching = |witness: &IoWitness| {
            witness
                .stopped()
                .is_some_and(|proof| proof.generation() == row.metadata.generation)
        };
        self.workers
            .lock()
            .unwrap()
            .get(row.metadata.key.as_str())
            .filter(|w| matching(w))
            .cloned()
            .or_else(|| {
                self.undispatched
                    .lock()
                    .unwrap()
                    .get(row.metadata.key.as_str())
                    .filter(|w| matching(w))
                    .cloned()
            })
    }

    /// Keep stop proof and arm the claim's witness before the claim commits.
    fn arm_deletion(
        &self,
        row: &BlobRow,
        witness: Option<IoWitness>,
        claim: &crate::state::GcClaim,
    ) -> ReservationLease {
        // Retain stopped proof for both possible commit
        // generations until native dispatch is authoritative.
        if let Some(witness) = witness {
            self.workers
                .lock()
                .unwrap()
                .insert(row.metadata.key.as_str().into(), witness);
        }
        let pending = IoWitness::pending(claim.key().clone(), claim.generation());
        self.undispatched
            .lock()
            .unwrap()
            .insert(row.metadata.key.as_str().into(), pending.clone());
        ReservationLease {
            witness: pending,
            armed: true,
        }
    }

    /// With the claim committed, remove the object and record that under a new fence.
    #[allow(clippy::too_many_arguments)]
    async fn delete_claimed(
        &self,
        host: &impl ReconcileHost,
        row: &BlobRow,
        claimed: &BlobRow,
        claim: &crate::state::GcClaim,
        dispatch: ReservationLease,
        now: Timestamp,
        deadline: Instant,
    ) -> Result<bool> {
        #[cfg(any(test, feature = "test-support"))]
        {
            let barrier = { self.gc_after_commit.lock().unwrap().clone() };
            if let Some(barrier) = barrier {
                barrier.wait().await;
            }
        }
        let store = self.store.clone();
        let key = claim.key().clone();
        let job = self.uploads.try_start(
            key.clone(),
            claim.generation(),
            deadline.into_std(),
            Arc::new(AtomicBool::new(false)),
            move |guard| store.remove(&key, &guard),
        )?;
        self.workers
            .lock()
            .unwrap()
            .insert(row.metadata.key.as_str().into(), job.witness());
        self.undispatched
            .lock()
            .unwrap()
            .remove(row.metadata.key.as_str());
        dispatch.dispatched();
        job.finish().await?;
        let mut tx = host.database().begin(deadline.into_std()).await?;
        host.fence(&mut tx).await?;
        MetadataContext { tx: &mut tx }
            .deleted(claimed, claim, self.store.identity(), now)
            .await?;
        commit(&mut tx).await?;
        ensure!(
            tx.commit_acknowledged(),
            "blob deletion completion unconfirmed"
        );
        self.workers
            .lock()
            .unwrap()
            .remove(row.metadata.key.as_str());
        Ok(true)
    }

    async fn clean_tombstone(
        &self,
        host: &impl ReconcileHost,
        row: &crate::metadata::BlobRow,
        deadline: Instant,
    ) -> Result<()> {
        let mut tx = host.database().begin(deadline.into_std()).await?;
        host.fence(&mut tx).await?;
        let current = MetadataContext { tx: &mut tx }
            .slot(&row.metadata.binding.slot)
            .await?
            .context("blob tombstone missing")?;
        ensure!(
            current.metadata.generation == row.metadata.generation
                && current.metadata.state == crate::state::State::Deleted,
            "blob tombstone changed"
        );
        commit(&mut tx).await?;
        ensure!(tx.commit_acknowledged(), "blob tombstone read unconfirmed");
        let key = row.metadata.key.clone();
        let store = self.store.clone();
        self.uploads
            .try_start(
                key.clone(),
                row.metadata.generation,
                deadline.into_std(),
                Arc::new(AtomicBool::new(false)),
                move |guard| store.remove(&key, &guard),
            )?
            .finish()
            .await
    }
}

pub struct ReservationLease {
    witness: IoWitness,
    armed: bool,
}
impl ReservationLease {
    pub fn dispatched(mut self) {
        self.armed = false;
    }
}
impl Drop for ReservationLease {
    fn drop(&mut self) {
        if self.armed {
            self.witness.stop_unstarted();
        }
    }
}

struct Inventory {
    scans: [crate::store::ObjectScan; 2],
    directory: usize,
    pending: std::collections::VecDeque<ObjectKey>,
}
impl Inventory {
    fn new(store: &BlobStore) -> Result<Self> {
        use crate::store::ObjectLocation;
        Ok(Self {
            scans: [
                store.scan(ObjectLocation::Partial)?,
                store.scan(ObjectLocation::Final)?,
            ],
            directory: 0,
            pending: Default::default(),
        })
    }
    fn batch(&mut self, store: &BlobStore, guard: &IoGuard) -> Result<InventoryBatch> {
        let mut items = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        while items.len() < crate::inspect::INSPECTION_PAGE {
            guard.check()?;
            if let Some(key) = self.pending.pop_front() {
                if seen.insert(key.clone()) {
                    items.push((key.clone(), store.snapshot(&key, guard)?));
                }
                continue;
            }
            if self.directory == 2 {
                break;
            }
            let batch = self.scans[self.directory].next_batch(guard)?;
            if batch.is_empty() {
                self.directory += 1;
            }
            self.pending.extend(batch.into_iter().map(|(_, key)| key));
        }
        Ok(InventoryBatch {
            items,
            complete: self.directory == 2 && self.pending.is_empty(),
        })
    }
}
