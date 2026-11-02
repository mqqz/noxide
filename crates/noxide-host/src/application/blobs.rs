//! Host-owned blob authority and transport integration. All metadata statements
//! share the enclosing request's actual SQL meter and original deadline.
use super::*;
use anyhow::Context;
pub use noxide_blobs::runtime::{BlobRuntime, ReservationLease};
pub use noxide_blobs::upload::UploadScope;
use noxide_blobs::{
    metadata::{MetadataContext, Reservation, ReservationOutcome},
    runtime::{ReconcileHost, commit as blob_commit, commitment},
    state::UploadBinding,
    store::{IoGuard, ObjectKey},
};
use noxide_protocol::{blobs::*, time::Timestamp};
use std::sync::atomic::AtomicBool;

impl Application {
    pub(super) async fn activate_blobs(&self, deadline: Instant) -> Result<()> {
        match &self.blobs {
            Some(blobs) => blobs.activate(&self.database, deadline).await,
            None => Ok(()),
        }
    }
    /// One maintenance page under its own request scope and admission.
    pub async fn reconcile_blobs(&self, deadline: Instant) -> Result<()> {
        self.reconcile_blobs_through(self, deadline).await
    }
    /// The same page through a wrapped host, so a test can count its fence calls.
    #[cfg(feature = "test-support")]
    pub async fn test_reconcile_blobs_through(
        &self,
        host: &impl ReconcileHost,
        deadline: Instant,
    ) -> Result<()> {
        self.reconcile_blobs_through(host, deadline).await
    }
    async fn reconcile_blobs_through(
        &self,
        host: &impl ReconcileHost,
        deadline: Instant,
    ) -> Result<()> {
        let Some(blobs) = &self.blobs else {
            return Ok(());
        };
        let scope = RequestScope::new(
            self.request_lifecycle.clone(),
            deadline,
            self.runtime.limits().wall_time,
            self.database_statement_limit,
        );
        scope
            .run(async {
                let admission = self.admit_invocation(false).await?;
                let owner = admission.owner;
                owner
                    .run(async { blobs.reconcile_page(host, owner.work_deadline()).await })
                    .await
            })
            .await
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
            .policy()
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
        let scope = UploadScope::new(
            blobs.store().clone(),
            blobs.uploads().clone(),
            UploadBinding {
                slot: commitment("noxide/upload-slot/v1", &[&self.deployment, nonce])?,
                subject,
                context: commitment(
                    "noxide/upload-context/v1",
                    &[&self.submission_contract(), &binding_id, &session.nonce],
                )?,
                input: commitment("noxide/upload-input/v1", &[&upload.input])?,
            },
        );
        #[cfg(any(test, feature = "test-support"))]
        let scope = scope.with_barrier(blobs.verification().lock().unwrap().clone());
        Ok(Some(scope))
    }
    pub fn upload_ticket(&self, binding: u32, submission: &str) -> Result<String> {
        self.keys.csrf(&format!(
            "noxide/upload-ticket/v1:{}:{binding}:{submission}",
            self.submission_contract()
        ))
    }
}

pub enum PreparedUpload {
    Existing { input: String, replay: bool },
    Created(Box<noxide_blobs::metadata::BlobRow>, ReservationLease),
    Absent,
}
impl Application {
    pub fn multipart_spec(&self, binding: u32) -> Result<noxide_blobs::multipart::PrefixSpec> {
        use noxide_blobs::multipart::{PrefixSpec, ScalarPart};
        let action = manifest::web_action(&self.manifest, binding)?;
        let blobs = self.blobs.as_ref().context("blob deployment missing")?;
        let upload = blobs
            .policy()
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
            max_bytes.min(blobs.policy().limits.file_bytes),
        )
    }
    pub async fn prepare_upload(
        &self,
        cookie: &str,
        binding: u32,
        values: &Fields,
        filename: Option<noxide_blobs::transport::AttachmentName>,
    ) -> Result<PreparedUpload> {
        let blobs = self.blobs.as_ref().context("blobs unavailable")?;
        let action = manifest::web_action(&self.manifest, binding)?;
        let upload = blobs
            .policy()
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
                    .lock_form(blobs.store().identity())
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
                            || (row.metadata.state == noxide_blobs::state::State::Staged
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
                            limit: max_bytes.min(blobs.policy().limits.file_bytes),
                            now: time.context("upload lifecycle time missing")?,
                            policy: blobs.policy(),
                            capability: upload.anonymous,
                            store: blobs.store().identity(),
                            process: blobs.process(),
                        })
                        .await?;
                    match result {
                        ReservationOutcome::Created(row) => {
                            let lease = blobs.reserve(&row)?;
                            PreparedUpload::Created(Box::new(row), lease)
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
                blob_commit(&mut tx).await?;
                ensure!(tx.commit_acknowledged(), RequestError::OutcomeUnknown);
                Ok(prepared)
            })
            .await
    }
    pub async fn publish_upload(
        &self,
        row: &noxide_blobs::metadata::BlobRow,
        object: noxide_blobs::store::DurableObject,
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
                    .publish(row, object, now, blobs.store().identity(), &guard)
                    .await?;
                blob_commit(&mut tx).await?;
                ensure!(tx.commit_acknowledged(), RequestError::OutcomeUnknown);
                Ok(staged.metadata.handle.as_str().into())
            })
            .await
    }
}

impl Application {
    pub fn blob_phase(&self, cap: std::time::Duration) -> RequestScope {
        self.request_scope(self.runtime.limits().wall_time)
            .phase(cap)
    }
    pub fn blob_action_limit(&self) -> std::time::Duration {
        self.runtime.limits().wall_time
    }
}

pub struct Download {
    pub opened: noxide_blobs::store::OpenedObject,
    pub permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    pub key: ObjectKey,
    pub generation: noxide_blobs::state::Generation,
    pub bytes: u64,
    pub filename: noxide_blobs::transport::AttachmentName,
    pub cancelled: Arc<AtomicBool>,
    pub deadline: Instant,
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
    pub async fn open_download(&self, cookie: Option<&str>, ticket: &str) -> Result<Download> {
        let blobs = self.blobs.as_ref().context("blobs unavailable")?;
        ensure!(blobs.is_ready(), "blobs unavailable");
        let permit = Arc::new(
            blobs
                .streams()
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
                    row.metadata.state == noxide_blobs::state::State::Attached
                        && row.metadata.association.as_ref()
                            == Some(&noxide_blobs::state::Association {
                                resource: storage_resource,
                                id: i64::try_from(target.id)?,
                                incarnation: target.incarnation,
                                field
                            }),
                    "download association mismatch"
                );
                let cancelled = Arc::new(AtomicBool::new(false));
                let cancel = cancelled.clone();
                let store = blobs.store().clone();
                let key = row.metadata.key.clone();
                let bytes = row.metadata.bytes;
                let digest = row.metadata.digest.context("download digest missing")?;
                let transfer_deadline = transfer.work_deadline();
                let native_permit = permit.clone();
                let opened = blobs
                    .downloads()
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
                blob_commit(&mut tx).await?;
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
        if result.as_ref().err().is_some_and(|error: &anyhow::Error| {
            error.is::<noxide_blobs::store::PhysicalMismatch>()
        }) {
            blobs.quarantine();
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
                    .policy()
                    .uploads
                    .iter()
                    .any(|u| u.web_binding == binding)
            })
            .and_then(|_| self.upload_ticket(binding, submission).ok())
    }
}

impl ReconcileHost for Application {
    fn database(&self) -> &Database {
        &self.database
    }
    async fn fence<'a>(&'a self, tx: &'a mut Transaction) -> Result<()> {
        self.admission(tx, false).await
    }
    async fn observed_now<'a>(&'a self, tx: &'a mut Transaction) -> Result<Timestamp> {
        self.observe_clock_write(tx, security::now()?).await?;
        Ok(self.temporal_after_admission(tx).await?.timestamp())
    }
}
