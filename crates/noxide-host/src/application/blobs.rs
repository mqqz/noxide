//! Host-owned blob authority and transport integration. All metadata statements
//! share the enclosing request's actual SQL meter and original deadline.
use super::*;
#[cfg(test)]
use crate::blob_upload::Barrier;
pub(crate) use crate::blob_upload::UploadScope;
use crate::{
    blob_inspect::{InventoryBatch, Snapshot},
    blob_io::{IoPool, IoWitness},
    blob_metadata::{MetadataContext, Reservation, ReservationOutcome},
    blob_state::{Commitment, UploadBinding},
    blob_store::{BlobStore, IoGuard, ObjectKey, PairStep},
};
use anyhow::Context;
use noxide_protocol::blobs::*;
use std::sync::{Mutex, atomic::AtomicBool};

pub(crate) struct BlobRuntime {
    pub(crate) store: BlobStore,
    pub(crate) policy: BlobPolicy,
    pub(crate) process: ObjectKey,
    fence: crate::blob_store::ProcessFence,
    pub(crate) uploads: Arc<IoPool>,
    pub(crate) downloads: Arc<IoPool>,
    streams: Arc<tokio::sync::Semaphore>,
    pub(crate) ready: AtomicBool,
    inventory: Arc<Mutex<Option<Inventory>>>,
    inventory_complete: AtomicBool,
    metadata_cursor: Mutex<String>,
    pub(crate) quarantined: AtomicBool,
    pub(crate) workers: Mutex<BTreeMap<String, IoWitness>>,
    undispatched: Mutex<BTreeMap<String, IoWitness>>,
    #[cfg(test)]
    verification: Mutex<Option<Arc<Barrier>>>,
    #[cfg(test)]
    gc_after_commit: Mutex<Option<Arc<Barrier>>>,
}
impl BlobRuntime {
    pub(super) fn open(deployment: crate::BlobDeployment, policy: BlobPolicy) -> Result<Self> {
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
            #[cfg(test)]
            verification: Mutex::new(None),
            #[cfg(test)]
            gc_after_commit: Mutex::new(None),
        })
    }
    pub(crate) fn available(&self) -> Result<()> {
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
}

fn commitment(domain: &str, values: &[&str]) -> Result<Commitment> {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    for value in values {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    Commitment::parse(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
impl Application {
    pub(super) async fn activate_blobs(&self, deadline: Instant) -> Result<()> {
        let Some(blobs) = &self.blobs else {
            return Ok(());
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let store = blobs.store.clone();
        let observation = blobs
            .uploads
            .try_start(
                blobs.process.clone(),
                crate::blob_state::Generation::parse(1)?,
                deadline.into_std(),
                cancelled.clone(),
                move |guard| store.observe_pair(&guard),
            )?
            .finish()
            .await?;
        let mut tx = self.database.begin(deadline.into_std()).await?;
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
        Self::blob_commit(&mut tx).await?;
        ensure!(
            tx.commit_acknowledged(),
            "blob pairing commit is unconfirmed"
        );
        if !matches!(prepared.step, PairStep::Ready(_)) {
            let store = blobs.store.clone();
            let marker = blobs
                .uploads
                .try_start(
                    blobs.process.clone(),
                    crate::blob_state::Generation::parse(1)?,
                    deadline.into_std(),
                    cancelled,
                    move |guard| store.install_pair(&prepared.record, &guard),
                )?
                .finish()
                .await?;
            let mut tx = self.database.begin(deadline.into_std()).await?;
            MetadataContext { tx: &mut tx }
                .acknowledge_pair(&marker)
                .await?;
            Self::blob_commit(&mut tx).await?;
            ensure!(
                tx.commit_acknowledged(),
                "blob pairing acknowledgment is unconfirmed"
            );
        }
        blobs.ready.store(true, Ordering::Release);
        Ok(())
    }
    pub(super) fn upload_scope(
        &self,
        binding: u32,
        nonce: &str,
        session: &Token,
        principal: &auth::Principal,
    ) -> Result<Option<UploadScope>> {
        let Some(blobs) = &self.blobs else {
            return Ok(None);
        };
        let Some(upload) = blobs
            .policy
            .uploads
            .iter()
            .find(|u| u.web_binding == binding)
        else {
            return Ok(None);
        };
        let subject = match principal {
            auth::Principal::Service(_) => anyhow::bail!(RequestError::InvalidRequest),
            auth::Principal::User(user) => {
                commitment("noxide/upload-account/v1", &[&self.deployment, &user.id])?
            }
            auth::Principal::Anonymous => commitment(
                "noxide/upload-capability/v1",
                &[&self.deployment, &session.nonce],
            )?,
        };
        let binding_id = binding.to_string();
        Ok(Some(UploadScope::new(
            blobs.store.clone(),
            blobs.uploads.clone(),
            #[cfg(test)]
            blobs.verification.lock().unwrap().clone(),
            UploadBinding {
                slot: commitment("noxide/upload-slot/v1", &[&self.deployment, nonce])?,
                subject,
                context: commitment(
                    "noxide/upload-context/v1",
                    &[&self.submission_contract(), &binding_id, &session.nonce],
                )?,
                input: commitment("noxide/upload-input/v1", &[&upload.input])?,
            },
        )))
    }
    pub(crate) fn upload_ticket(&self, binding: u32, submission: &str) -> Result<String> {
        self.keys.csrf(&format!(
            "noxide/upload-ticket/v1:{}:{binding}:{submission}",
            self.submission_contract()
        ))
    }
}

pub(crate) enum PreparedUpload {
    Existing { input: String, replay: bool },
    Created(Box<crate::blob_metadata::BlobRow>, ReservationLease),
    Absent,
}
impl Application {
    pub(crate) fn multipart_spec(&self, binding: u32) -> Result<crate::blob_multipart::PrefixSpec> {
        use crate::blob_multipart::{PrefixSpec, ScalarPart};
        let action = manifest::web_action(&self.manifest, binding)?;
        let blobs = self.blobs.as_ref().context("blob deployment missing")?;
        let upload = blobs
            .policy
            .uploads
            .iter()
            .find(|u| u.web_binding == binding)
            .context("upload not declared")?;
        let input = action
            .inputs
            .iter()
            .find(|i| i.name == upload.input)
            .context("upload input missing")?;
        let FieldKind::UploadHandle { max_bytes } = input.kind else {
            anyhow::bail!("invalid upload input");
        };
        let mut fields = vec![
            ScalarPart {
                name: self.presentation.csrf_field.clone(),
                max_bytes: 128,
                required: true,
            },
            ScalarPart {
                name: self.presentation.submission_field.clone(),
                max_bytes: 8192,
                required: true,
            },
            ScalarPart {
                name: "_upload".into(),
                max_bytes: 128,
                required: true,
            },
        ];
        for target in action
            .targets
            .iter()
            .filter(|t| matches!(t.source, TargetSource::Selected { .. }))
        {
            fields.push(ScalarPart {
                name: format!("_target_{}", target.name),
                max_bytes: 2048,
                required: true,
            });
        }
        // Rendered DOM determines native browser multipart scalar order.
        let order: Vec<_> = if action.layout.is_empty() {
            action.inputs.iter().map(|i| i.name.as_str()).collect()
        } else {
            action
                .layout
                .iter()
                .filter_map(|n| {
                    if let FormInstruction::Field { name, .. } = n {
                        Some(name.as_str())
                    } else {
                        None
                    }
                })
                .collect()
        };
        for name in order {
            let field = action
                .inputs
                .iter()
                .find(|i| i.name == name)
                .context("unknown layout input")?;
            if name == upload.input {
                continue;
            }
            fields.push(ScalarPart {
                name: name.into(),
                max_bytes: field.max_bytes as usize,
                required: !field.optional && field.kind != FieldKind::Boolean,
            });
        }
        // Empty filename is accepted syntactically for retry; only a verified
        // existing stage or an optional input+destination can authorize absence.
        PrefixSpec::new(
            fields,
            upload.input.clone(),
            true,
            max_bytes.min(blobs.policy.limits.file_bytes),
        )
    }
    pub(crate) async fn prepare_upload(
        &self,
        cookie: &str,
        binding: u32,
        values: &Fields,
        filename: Option<crate::blob_transport::AttachmentName>,
    ) -> Result<PreparedUpload> {
        let blobs = self.blobs.as_ref().context("blobs unavailable")?;
        let action = manifest::web_action(&self.manifest, binding)?;
        let upload = blobs
            .policy
            .uploads
            .iter()
            .find(|u| u.web_binding == binding)
            .context("unknown upload binding")?;
        let input = action
            .inputs
            .iter()
            .find(|i| i.name == upload.input)
            .context("upload input missing")?;
        let submission = values
            .get(&self.presentation.submission_field)
            .context("missing submission")?;
        let csrf = values
            .get(&self.presentation.csrf_field)
            .context("missing CSRF")?;
        let ticket = values.get("_upload").context("missing upload ticket")?;
        self.keys.verify_csrf(
            &format!(
                "noxide/upload-ticket/v1:{}:{binding}:{submission}",
                self.submission_contract()
            ),
            ticket,
        )?;
        let admission = self.admit_invocation(false).await?;
        let owner = admission.owner;
        owner
            .run(async {
                let deadline = owner.work_deadline();
                let mut tx = self.database.begin(deadline.into_std()).await?;
                self.admission(&mut tx, false).await?;
                let now = self.observe_clock_write(&mut tx, security::now()?).await?;
                let core = ActionCore::of(action.core)?;
                let (token, session, principal) = self
                    .submission_identity(&mut tx, core, cookie, submission, csrf, now)
                    .await?;
                let scalar: Fields = values
                    .iter()
                    .filter(|(name, _)| {
                        !matches!(name.as_str(), "_upload")
                            && *name != &self.presentation.csrf_field
                            && *name != &self.presentation.submission_field
                    })
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let (scalar, selections) = self.action_input(action.core, &scalar)?;
                ensure!(
                    scalar.keys().all(|name| action
                        .inputs
                        .iter()
                        .any(|i| &i.name == name && i.name != upload.input)),
                    "unexpected upload prefix field"
                );
                for field in action.inputs.iter().filter(|i| i.name != upload.input) {
                    let raw = scalar.get(&field.name).map(String::as_str).unwrap_or(
                        if field.kind == FieldKind::Boolean {
                            "false"
                        } else {
                            ""
                        },
                    );
                    field.canonical(raw).map_err(anyhow::Error::msg)?;
                }
                self.web_target_grants(
                    &token,
                    core,
                    manifest::web_binding(&self.manifest, binding)?,
                    &selections,
                    &session,
                    &principal,
                    now,
                )?;
                let context = self
                    .upload_scope(binding, &token.nonce, &session, &principal)?
                    .context("upload context missing")?;
                MetadataContext { tx: &mut tx }
                    .lock_form(blobs.store.identity())
                    .await?;
                // This is the authoritative prior-commit check before accepting any
                // file bytes. Existing nonce rows serialize the eventual core claim.
                let receipt = self
                    .load_receipt(&mut tx, &token.nonce, &session.nonce)
                    .await?;
                if let Some([_, outcome]) = &receipt {
                    ensure!(!outcome.is_empty(), RequestError::OutcomeUnknown);
                }
                let time = if receipt.is_none() {
                    blobs.available()?;
                    Some(self.temporal_after_admission(&mut tx).await?.timestamp())
                } else {
                    None
                };
                let existing = MetadataContext { tx: &mut tx }
                    .slot(&context.binding.slot)
                    .await?;
                let prepared = if let Some(row) = existing {
                    ensure!(
                        row.metadata.binding == context.binding,
                        "foreign upload stage"
                    );
                    let replay = receipt.is_some();
                    ensure!(
                        replay
                            || (row.metadata.state == crate::blob_state::State::Staged
                                && time.context("upload lifecycle time missing")?
                                    < row.metadata.expires),
                        "upload is not reusable"
                    );
                    ensure!(
                        replay || filename.is_none(),
                        "a finalized upload cannot be replaced"
                    );
                    PreparedUpload::Existing {
                        input: row.metadata.handle.as_str().into(),
                        replay,
                    }
                } else if receipt.is_some() {
                    if input.optional && filename.is_none() {
                        PreparedUpload::Existing {
                            input: String::new(),
                            replay: true,
                        }
                    } else if filename.is_some() {
                        anyhow::bail!(RequestError::InvalidRequest)
                    } else {
                        anyhow::bail!(RequestError::OutcomeUnknown)
                    }
                } else if let Some(filename) = filename {
                    let FieldKind::UploadHandle { max_bytes } = input.kind else {
                        anyhow::bail!("invalid upload input");
                    };
                    let result = MetadataContext { tx: &mut tx }
                        .reserve(Reservation {
                            binding: context.binding.clone(),
                            filename,
                            limit: max_bytes.min(blobs.policy.limits.file_bytes),
                            now: time.context("upload lifecycle time missing")?,
                            policy: &blobs.policy,
                            capability: upload.anonymous,
                            store: blobs.store.identity(),
                            process: &blobs.process,
                        })
                        .await?;
                    match result {
                        ReservationOutcome::Created(row) => {
                            let witness = IoWitness::pending(
                                row.metadata.key.clone(),
                                row.metadata.generation,
                            );
                            let mut workers = blobs.workers.lock().unwrap();
                            ensure!(
                                workers.len() < blobs.policy.limits.objects as usize,
                                "blob reservation registry full"
                            );
                            workers.insert(row.metadata.key.as_str().into(), witness.clone());
                            PreparedUpload::Created(
                                Box::new(row),
                                ReservationLease {
                                    witness,
                                    armed: true,
                                },
                            )
                        }
                        ReservationOutcome::Existing(row) => {
                            ensure!(
                                row.metadata.binding == context.binding,
                                "foreign upload reservation race"
                            );
                            anyhow::bail!(RequestError::Busy)
                        }
                    }
                } else {
                    ensure!(input.optional, "required upload missing");
                    PreparedUpload::Absent
                };
                Self::blob_commit(&mut tx).await?;
                ensure!(tx.commit_acknowledged(), RequestError::OutcomeUnknown);
                Ok(prepared)
            })
            .await
    }
    pub(crate) async fn publish_upload(
        &self,
        row: &crate::blob_metadata::BlobRow,
        object: crate::blob_store::DurableObject,
    ) -> Result<String> {
        let blobs = self.blobs.as_ref().context("blobs unavailable")?;
        let admission = self.admit_invocation(false).await?;
        let owner = admission.owner;
        owner
            .run(async {
                let deadline = owner.work_deadline();
                let mut tx = self.database.begin(deadline.into_std()).await?;
                self.admission(&mut tx, false).await?;
                self.observe_clock_write(&mut tx, security::now()?).await?;
                let now = self.temporal_after_admission(&mut tx).await?.timestamp();
                let guard = IoGuard::new(deadline.into_std(), Arc::new(AtomicBool::new(false)));
                let staged = MetadataContext { tx: &mut tx }
                    .publish(row, object, now, blobs.store.identity(), &guard)
                    .await?;
                Self::blob_commit(&mut tx).await?;
                ensure!(tx.commit_acknowledged(), RequestError::OutcomeUnknown);
                Ok(staged.metadata.handle.as_str().into())
            })
            .await
    }
}

impl Application {
    pub(crate) fn blob_phase(&self, cap: std::time::Duration) -> RequestScope {
        self.request_scope(self.runtime.limits().wall_time)
            .phase(cap)
    }
    pub(crate) fn blob_action_limit(&self) -> std::time::Duration {
        self.runtime.limits().wall_time
    }
}

pub(crate) struct Download {
    pub(crate) opened: crate::blob_store::OpenedObject,
    pub(crate) permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    pub(crate) key: ObjectKey,
    pub(crate) generation: crate::blob_state::Generation,
    pub(crate) bytes: u64,
    pub(crate) filename: crate::blob_transport::AttachmentName,
    pub(crate) cancelled: Arc<AtomicBool>,
    pub(crate) deadline: Instant,
}
impl Application {
    pub(super) fn download_links(
        &self,
        effects: &Effects,
        session: Option<&Token>,
        now: i64,
    ) -> Result<BTreeMap<(u32, u64, String), String>> {
        let RequestKind::Route(route) = effects.request.kind else {
            return Ok(BTreeMap::new());
        };
        effects
            .blob_reads
            .iter()
            .map(|((read, id, field), (incarnation, blob))| {
                let operation = manifest::operation(&self.manifest, *read)?;
                ensure!(
                    operation.kind == OperationKind::Read && operation.via.is_none(),
                    "download requires direct Read"
                );
                let (_, ticket) = self.keys.issue(
                    TokenKind::Download {
                        contract: self.submission_contract(),
                        read: *read,
                        target: RecordTarget {
                            resource: operation.resource,
                            id: *id,
                            incarnation: incarnation.clone(),
                            revision: 1,
                            route: Some(route),
                        },
                        field: field.clone(),
                        blob: blob.clone(),
                    },
                    session.map(|s| s.nonce.as_str()).unwrap_or(""),
                    now,
                    900,
                )?;
                Ok((
                    (*read, *id, field.clone()),
                    format!("/_noxide/download?ticket={ticket}"),
                ))
            })
            .collect()
    }
    pub(crate) async fn open_download(
        &self,
        cookie: Option<&str>,
        ticket: &str,
    ) -> Result<Download> {
        let blobs = self.blobs.as_ref().context("blobs unavailable")?;
        ensure!(blobs.ready.load(Ordering::Acquire), "blobs unavailable");
        let permit = Arc::new(
            blobs
                .streams
                .clone()
                .try_acquire_owned()
                .context("download concurrency limit")?,
        );
        let transfer = self.blob_phase(std::time::Duration::from_millis(TRANSFER_TOTAL_MILLIS));
        let admission = self.admit_invocation(false).await?;
        let owner = admission.owner;
        let result = owner
            .run(async {
                let deadline = owner.work_deadline();
                let mut tx = self.database.begin_read(deadline.into_std()).await?;
                self.admission(&mut tx, false).await?;
                let now =
                    security::observe_clock_read(&mut tx, security::now()?, &self.clock).await?;
                let token = self.keys.verify(ticket, now)?;
                let TokenKind::Download {
                    contract,
                    read,
                    target,
                    field,
                    blob,
                } = token.kind
                else {
                    anyhow::bail!("invalid download ticket");
                };
                ensure!(
                    contract == self.submission_contract(),
                    "retired download ticket"
                );
                let route = manifest::route(
                    &self.manifest,
                    target.route.context("download source route missing")?,
                )?;
                let op = manifest::operation(&self.manifest, read)?;
                ensure!(
                    route.operations.contains(&read)
                        && op.kind == OperationKind::Read
                        && op.via.is_none()
                        && op.resource == target.resource,
                    "invalid direct Read provenance"
                );
                let identity = self
                    .route_identity(&mut tx, &route.access, cookie, now)
                    .await?;
                let (session, principal) = match identity {
                    Some((s, p)) => (Some(s), p),
                    None => (None, auth::Principal::Anonymous),
                };
                ensure!(
                    token.subject == session.as_ref().map(|s| s.nonce.as_str()).unwrap_or(""),
                    "foreign download session"
                );
                let mut calls = repository::MAX_LIST_DATABASE_CALLS;
                let time = if crate::authority::uses_time(&self.manifest) {
                    calls -= 1;
                    Some(self.temporal_after_admission(&mut tx).await?)
                } else {
                    None
                };
                let mut authority = self.authority_context(time)?;
                let mut context = repository::ReadContext {
                    tx: &mut tx,
                    manifest: &self.manifest,
                    principal: &principal,
                    authority: &mut authority,
                    budget: repository::ReadBudget::Query(&mut calls),
                };
                let stored = context
                    .load(op.resource, target.id)
                    .await?
                    .context("download unavailable")?;
                ensure!(
                    stored.incarnation == target.incarnation
                        && repository::authorize_stored_read(&mut context, op, &stored).await?,
                    "download unavailable"
                );
                ensure!(
                    op.fields
                        .as_ref()
                        .is_none_or(|fields| fields.contains(&field)),
                    "blob outside Read projection"
                );
                ensure!(
                    manifest::resource(&self.manifest, op.resource)?
                        .fields
                        .iter()
                        .any(|f| f.name == field && matches!(f.kind, FieldKind::Blob { .. })),
                    "invalid blob field"
                );
                ensure!(
                    stored.record.fields.get(&field).map(String::as_str) == Some(blob.as_str()),
                    "download association changed"
                );
                let row = MetadataContext { tx: &mut tx }
                    .reference(&blob)
                    .await?
                    .context("download unavailable")?;
                let storage_resource = tx.storage_resource(&self.manifest, op.resource).await?;
                ensure!(
                    row.metadata.state == crate::blob_state::State::Attached
                        && row.metadata.association.as_ref()
                            == Some(&crate::blob_state::Association {
                                resource: storage_resource,
                                id: i64::try_from(target.id)?,
                                incarnation: target.incarnation,
                                field
                            }),
                    "download association mismatch"
                );
                let cancelled = Arc::new(AtomicBool::new(false));
                let cancel = cancelled.clone();
                let store = blobs.store.clone();
                let key = row.metadata.key.clone();
                let bytes = row.metadata.bytes;
                let digest = row.metadata.digest.context("download digest missing")?;
                let transfer_deadline = transfer.work_deadline();
                let native_permit = permit.clone();
                let opened = blobs
                    .downloads
                    .try_start(
                        key.clone(),
                        row.metadata.generation,
                        deadline.into_std(),
                        cancelled.clone(),
                        move |_guard| {
                            let _permit = native_permit;
                            let mut opened = store.open_object(
                                &key,
                                bytes,
                                IoGuard::new(transfer_deadline.into_std(), cancel),
                            )?;
                            opened.verify_digest(digest)?;
                            Ok(opened)
                        },
                    )?
                    .finish()
                    .await?;
                // The immutable descriptor is captured while current authority and
                // association share this read transaction. No transaction streams.
                Self::blob_commit(&mut tx).await?;
                ensure!(
                    tx.commit_acknowledged(),
                    "download read transaction unconfirmed"
                );
                Ok(Download {
                    opened,
                    permit,
                    key: row.metadata.key,
                    generation: row.metadata.generation,
                    bytes,
                    filename: row.filename,
                    cancelled,
                    deadline: transfer_deadline,
                })
            })
            .await;
        if result
            .as_ref()
            .err()
            .is_some_and(|error: &anyhow::Error| error.is::<crate::blob_store::PhysicalMismatch>())
        {
            blobs.quarantined.store(true, Ordering::Release);
        }
        result
    }
}

impl Application {
    pub(super) fn bound_upload_ticket(&self, binding: u32, submission: &str) -> Option<String> {
        self.blobs
            .as_ref()
            .filter(|blobs| {
                blobs
                    .policy
                    .uploads
                    .iter()
                    .any(|u| u.web_binding == binding)
            })
            .and_then(|_| self.upload_ticket(binding, submission).ok())
    }
}

#[cfg(test)]
mod tests;

pub(crate) struct ReservationLease {
    witness: IoWitness,
    armed: bool,
}
impl ReservationLease {
    pub(crate) fn dispatched(mut self) {
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
    scans: [crate::blob_store::ObjectScan; 2],
    directory: usize,
    pending: std::collections::VecDeque<ObjectKey>,
}
impl Inventory {
    fn new(store: &BlobStore) -> Result<Self> {
        use crate::blob_store::ObjectLocation;
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
        while items.len() < crate::blob_inspect::INSPECTION_PAGE {
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
impl Application {
    /// One bounded maintenance page. Unknown objects are charged and retained;
    /// only authoritative known metadata can produce a fenced deletion claim.
    pub(crate) async fn reconcile_blobs(&self, deadline: Instant) -> Result<()> {
        use crate::blob_inspect::{FindingKind, InspectionPage, SnapshotItem};
        let Some(blobs) = &self.blobs else {
            return Ok(());
        };
        let scope = RequestScope::new(
            self.request_lifecycle.clone(),
            deadline,
            self.runtime.limits().wall_time,
            self.database_statement_limit,
        );
        let result = scope
            .run(async {
                let admission = self.admit_invocation(false).await?;
                let owner = admission.owner;
                owner
                    .run(async {
                        let deadline = owner.work_deadline();
                        let inventory = blobs.inventory.clone();
                        let store = blobs.store.clone();
                        let batch = blobs
                            .uploads
                            .try_start(
                                blobs.process.clone(),
                                crate::blob_state::Generation::parse(1)?,
                                deadline.into_std(),
                                Arc::new(AtomicBool::new(false)),
                                move |guard| {
                                    let mut inventory = inventory.lock().unwrap();
                                    if inventory.is_none() {
                                        *inventory = Some(Inventory::new(&store)?);
                                    }
                                    let batch =
                                        inventory.as_mut().unwrap().batch(&store, &guard)?;
                                    if batch.complete {
                                        *inventory = None;
                                    }
                                    Ok(batch)
                                },
                            )?
                            .finish()
                            .await?;
                        let mut tx = self.database.begin(deadline.into_std()).await?;
                        self.admission(&mut tx, false).await?;
                        self.observe_clock_write(&mut tx, security::now()?).await?;
                        let now = self.temporal_after_admission(&mut tx).await?.timestamp();
                        for (key, physical) in batch.items {
                            let row = MetadataContext { tx: &mut tx }.object(&key).await?;
                            if row.is_none()
                                && let Some(physical) = physical
                            {
                                blobs.quarantined.store(true, Ordering::Release);
                                let bytes = physical
                                    .partial
                                    .unwrap_or(0)
                                    .checked_add(physical.finalized.unwrap_or(0))
                                    .context("unknown blob length overflow")?;
                                let paths = u8::from(physical.partial.is_some())
                                    + u8::from(physical.finalized.is_some());
                                MetadataContext { tx: &mut tx }
                                    .quarantine_unknown(
                                        &key,
                                        bytes,
                                        paths,
                                        blobs.store.identity(),
                                        &blobs.process,
                                        now,
                                    )
                                    .await?;
                            }
                        }
                        let after = blobs.metadata_cursor.lock().unwrap().clone();
                        let rows = MetadataContext { tx: &mut tx }.page(&after).await?;
                        Self::blob_commit(&mut tx).await?;
                        ensure!(
                            tx.commit_acknowledged(),
                            "blob inventory commit unconfirmed"
                        );
                        if batch.complete {
                            blobs.inventory_complete.store(true, Ordering::Release);
                        }
                        *blobs.metadata_cursor.lock().unwrap() = rows
                            .last()
                            .filter(|_| rows.len() == crate::blob_inspect::INSPECTION_PAGE)
                            .map(|r| r.metadata.binding.slot.as_str().into())
                            .unwrap_or_default();
                        // At most four deletions per page, always with committed CAS
                        // claims and physical-stop witnesses for this process's work.
                        let mut deleted = 0;
                        for row in rows {
                            if deleted == 4 {
                                break;
                            }
                            let store = blobs.store.clone();
                            let key = row.metadata.key.clone();
                            let physical = blobs
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
                                .0;
                            let matching = |witness: &IoWitness| {
                                witness.stopped().is_some_and(|proof| {
                                    proof.generation() == row.metadata.generation
                                })
                            };
                            let witness = blobs
                                .workers
                                .lock()
                                .unwrap()
                                .get(row.metadata.key.as_str())
                                .filter(|w| matching(w))
                                .cloned()
                                .or_else(|| {
                                    blobs
                                        .undispatched
                                        .lock()
                                        .unwrap()
                                        .get(row.metadata.key.as_str())
                                        .filter(|w| matching(w))
                                        .cloned()
                                });
                            let stopped = witness.as_ref().and_then(IoWitness::stopped);
                            let stopped_refs: Vec<_> = stopped.iter().collect();
                            let page = InspectionPage::plan(
                                blobs.store.identity(),
                                &blobs.process,
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
                                blobs.quarantined.store(true, Ordering::Release);
                                continue;
                            }
                            if kind == FindingKind::RetainTombstone {
                                blobs
                                    .workers
                                    .lock()
                                    .unwrap()
                                    .remove(row.metadata.key.as_str());
                                blobs
                                    .undispatched
                                    .lock()
                                    .unwrap()
                                    .remove(row.metadata.key.as_str());
                            }
                            if !kind.recoverable_hint() {
                                continue;
                            }
                            if kind == FindingKind::CleanKnownDeletedObject {
                                // Tombstones name only their original opaque key. A
                                // current transaction rechecks them before native I/O.
                                self.clean_tombstone(blobs, &row, deadline).await?;
                                deleted += 1;
                                continue;
                            }
                            let mut tx = self.database.begin(deadline.into_std()).await?;
                            self.admission(&mut tx, false).await?;
                            let current = MetadataContext { tx: &mut tx }
                                .slot(&row.metadata.binding.slot)
                                .await?
                                .context("blob recovery row missing")?;
                            if current.metadata.generation != row.metadata.generation
                                || current.metadata.state != row.metadata.state
                            {
                                tx.rollback().await?;
                                continue;
                            }
                            let (claimed, claim) = match kind {
                                FindingKind::ClaimExpiredStage | FindingKind::ClaimUnreferenced => {
                                    MetadataContext { tx: &mut tx }
                                        .claim_collectable(&current, &blobs.process, now)
                                        .await?
                                }
                                FindingKind::ClaimStoppedUpload => {
                                    MetadataContext { tx: &mut tx }
                                        .claim_stopped_upload(
                                            &current,
                                            &blobs.process,
                                            now,
                                            stopped
                                                .as_ref()
                                                .context("stopped upload proof missing")?,
                                        )
                                        .await?
                                }
                                FindingKind::RecoverPriorProcessUpload => {
                                    MetadataContext { tx: &mut tx }
                                        .recover_prior_upload(&current, &blobs.fence, now)
                                        .await?
                                }
                                FindingKind::ResumeStoppedDeletion
                                | FindingKind::RecoverPriorProcessDeletion => {
                                    MetadataContext { tx: &mut tx }
                                        .resume_deletion(
                                            &current,
                                            &blobs.fence,
                                            now,
                                            stopped.as_ref(),
                                        )
                                        .await?
                                }
                                _ => {
                                    tx.rollback().await?;
                                    continue;
                                }
                            };
                            // Retain stopped proof for both possible commit
                            // generations until native dispatch is authoritative.
                            if let Some(witness) = witness {
                                blobs
                                    .workers
                                    .lock()
                                    .unwrap()
                                    .insert(row.metadata.key.as_str().into(), witness);
                            }
                            let pending =
                                IoWitness::pending(claim.key().clone(), claim.generation());
                            blobs
                                .undispatched
                                .lock()
                                .unwrap()
                                .insert(row.metadata.key.as_str().into(), pending.clone());
                            let dispatch = ReservationLease {
                                witness: pending,
                                armed: true,
                            };
                            Self::blob_commit(&mut tx).await?;
                            ensure!(tx.commit_acknowledged(), "blob deletion claim unconfirmed");
                            #[cfg(test)]
                            {
                                let barrier = { blobs.gc_after_commit.lock().unwrap().clone() };
                                if let Some(barrier) = barrier {
                                    barrier.wait().await;
                                }
                            }
                            let store = blobs.store.clone();
                            let key = claim.key().clone();
                            let job = blobs.uploads.try_start(
                                key.clone(),
                                claim.generation(),
                                deadline.into_std(),
                                Arc::new(AtomicBool::new(false)),
                                move |guard| store.remove(&key, &guard),
                            )?;
                            blobs
                                .workers
                                .lock()
                                .unwrap()
                                .insert(row.metadata.key.as_str().into(), job.witness());
                            blobs
                                .undispatched
                                .lock()
                                .unwrap()
                                .remove(row.metadata.key.as_str());
                            dispatch.dispatched();
                            job.finish().await?;
                            let mut tx = self.database.begin(deadline.into_std()).await?;
                            self.admission(&mut tx, false).await?;
                            MetadataContext { tx: &mut tx }
                                .deleted(&claimed, &claim, blobs.store.identity(), now)
                                .await?;
                            Self::blob_commit(&mut tx).await?;
                            ensure!(
                                tx.commit_acknowledged(),
                                "blob deletion completion unconfirmed"
                            );
                            blobs
                                .workers
                                .lock()
                                .unwrap()
                                .remove(row.metadata.key.as_str());
                            deleted += 1;
                        }
                        Ok(())
                    })
                    .await
            })
            .await;
        if result
            .as_ref()
            .err()
            .is_some_and(|error: &anyhow::Error| error.is::<crate::blob_store::PhysicalMismatch>())
        {
            blobs.quarantined.store(true, Ordering::Release);
        }
        result
    }
    async fn clean_tombstone(
        &self,
        blobs: &BlobRuntime,
        row: &crate::blob_metadata::BlobRow,
        deadline: Instant,
    ) -> Result<()> {
        let mut tx = self.database.begin(deadline.into_std()).await?;
        self.admission(&mut tx, false).await?;
        let current = MetadataContext { tx: &mut tx }
            .slot(&row.metadata.binding.slot)
            .await?
            .context("blob tombstone missing")?;
        ensure!(
            current.metadata.generation == row.metadata.generation
                && current.metadata.state == crate::blob_state::State::Deleted,
            "blob tombstone changed"
        );
        Self::blob_commit(&mut tx).await?;
        ensure!(tx.commit_acknowledged(), "blob tombstone read unconfirmed");
        let key = row.metadata.key.clone();
        let store = blobs.store.clone();
        blobs
            .uploads
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

impl Application {
    async fn blob_commit(tx: &mut Transaction) -> Result<()> {
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
}
