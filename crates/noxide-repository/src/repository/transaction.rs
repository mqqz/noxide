//! One action's transaction: authorize each step, then create, update or delete.
use super::*;

pub(super) fn adjust(
    current: i64,
    amount: i64,
    min: i64,
    max: i64,
    increase: bool,
    rejection: &GuardRejection,
) -> Result<i64> {
    let value = if increase {
        current.checked_add(amount)
    } else {
        current.checked_sub(amount)
    };
    value
        .filter(|value| (min..=max).contains(value))
        .ok_or_else(|| {
            GuardFailure {
                input: rejection.input.clone(),
                message: rejection.message.clone(),
            }
            .into()
        })
}

impl Effects {
    #[allow(clippy::too_many_lines)]
    pub async fn execute_transaction(
        &mut self,
        action: crate::action_contract::ActionCore<'_>,
        time: Option<crate::lifecycle_clock::AttemptTime>,
    ) -> Result<Vec<MutationOutcome>> {
        ensure!(
            self.request.kind == RequestKind::Action(action.id),
            "transaction outside action"
        );
        manifest::validate_inputs(action.inputs, &self.request.input)?;
        let context = computation::Context {
            snapshots: self.target_rows.clone(),
            time,
        };
        let mut outcomes = Vec::with_capacity(action.steps.len());
        for step in action.steps {
            ensure!(self.calls > 0, "database call budget");
            self.calls -= 1;
            let op = manifest::operation(&self.manifest, step.operation)?.clone();
            let stored = match &step.target {
                Target::None => None,
                Target::Named(name) => {
                    let grant = self.grants.get(name).ok_or(ReferenceUnavailable)?;
                    ensure!(grant.resource == op.resource, ReferenceUnavailable);
                    let stored = load(&mut self.tx, &self.manifest, op.resource, grant.id)
                        .await?
                        .ok_or(ReferenceUnavailable)?;
                    ensure!(
                        stored.incarnation == grant.incarnation,
                        ReferenceUnavailable
                    );
                    Some(stored)
                }
            };
            self.authorize_step(&op, stored.as_ref()).await?;
            if op.kind != OperationKind::Create {
                self.current_guard_authority(action, step, stored.as_ref())
                    .await?;
                self.computation_values(&context, &outcomes, step, stored.as_ref())
                    .guards(step, action)?;
            }
            let mut values = Fields::new();
            let mut attachments = Vec::new();
            let mut assignments: Vec<_> = step.assign.iter().collect();
            assignments.sort_by(|a, b| a.field.cmp(&b.field));
            for assignment in assignments {
                let destination = manifest::resource(&self.manifest, op.resource)?
                    .fields
                    .iter()
                    .find(|f| f.name == assignment.field)
                    .ok_or(ReferenceUnavailable)?;
                if let FieldKind::Blob { max_bytes } = destination.kind {
                    ensure!(op.kind == OperationKind::Create, ReferenceUnavailable);
                    let Change::Set(Value::Input(name)) = &assignment.change else {
                        anyhow::bail!(ReferenceUnavailable);
                    };
                    let raw = self.request.input.get(name).ok_or(ReferenceUnavailable)?;
                    if raw.is_empty() && destination.optional {
                        self.upload
                            .as_ref()
                            .ok_or(ReferenceUnavailable)?
                            .absent(&mut self.tx)
                            .await?;
                        values.insert(assignment.field.clone(), String::new());
                        continue;
                    }
                    let handle = noxide_protocol::blobs::UploadHandle::parse(raw.clone())
                        .map_err(anyhow::Error::msg)?;
                    let upload = self.upload.as_ref().ok_or(ReferenceUnavailable)?;
                    let locked = noxide_blobs::metadata::MetadataContext { tx: &mut self.tx }
                        .lock_stage(&handle, &upload.binding, upload.now)
                        .await?;
                    ensure!(
                        locked.row().metadata.bytes <= max_bytes,
                        ReferenceUnavailable
                    );
                    let row = locked.row();
                    // The stage lock excludes GC. Only a checked immutable descriptor
                    // proves bytes exist before canonical proposed-row authorization.
                    upload.verify(row).await?;
                    values.insert(assignment.field.clone(), locked.blob().as_str().to_owned());
                    attachments.push((assignment.field.clone(), locked));
                    continue;
                }
                let value = match &assignment.change {
                    Change::Set(value) => self
                        .computation_values(&context, &outcomes, step, stored.as_ref())
                        .value(value, action)?
                        .encode(),
                    Change::Decrease { by, rejection } | Change::Increase { by, rejection } => {
                        let record = stored
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("adjustment requires target"))?;
                        let resource = manifest::resource(&self.manifest, op.resource)?;
                        let field = resource
                            .fields
                            .iter()
                            .find(|f| f.name == assignment.field)
                            .ok_or_else(|| anyhow::anyhow!("unknown adjustment field"))?;
                        let FieldKind::Integer {
                            min: Some(min),
                            max: Some(max),
                        } = field.kind
                        else {
                            anyhow::bail!("unbounded adjustment")
                        };
                        let current: i64 = record
                            .record
                            .fields
                            .get(&assignment.field)
                            .ok_or_else(|| anyhow::anyhow!("missing adjustment field"))?
                            .parse()?;
                        let computation::Scalar::Integer(amount) = self
                            .computation_values(&context, &outcomes, step, Some(record))
                            .value(by, action)?
                        else {
                            anyhow::bail!(CalculationUnavailable)
                        };
                        ensure!(amount > 0, CalculationUnavailable);
                        adjust(
                            current,
                            amount,
                            min,
                            max,
                            matches!(assignment.change, Change::Increase { .. }),
                            rejection,
                        )?
                        .to_string()
                    }
                };
                ensure!(
                    values.insert(assignment.field.clone(), value).is_none(),
                    "duplicate assignment"
                );
            }
            let (outcome, written) = match op.kind {
                OperationKind::Create => {
                    let (outcome, row) = self
                        .create_step(&op, step, values, &outcomes, action, &context)
                        .await?;
                    (outcome, Some(row))
                }
                OperationKind::Update => {
                    let (outcome, row) = self
                        .update_step(&op, stored.as_ref().ok_or(ReferenceUnavailable)?, values)
                        .await?;
                    (outcome, Some(row))
                }
                OperationKind::Delete => (
                    self.delete_step(&op, stored.as_ref().ok_or(ReferenceUnavailable)?)
                        .await?,
                    None,
                ),
                _ => anyhow::bail!("transaction requires mutation"),
            };
            for (field, locked) in attachments {
                let now = self.upload.as_ref().ok_or(ReferenceUnavailable)?.now;
                let storage_resource = self
                    .tx
                    .storage_resource(&self.manifest, outcome.resource)
                    .await?;
                noxide_blobs::metadata::MetadataContext { tx: &mut self.tx }
                    .associate(
                        locked,
                        noxide_blobs::state::Association {
                            resource: storage_resource,
                            id: i64::try_from(outcome.id)?,
                            incarnation: outcome.incarnation.clone(),
                            field,
                        },
                        now,
                    )
                    .await?;
            }
            self.authority.invalidate();
            self.target_rows.remove(&(outcome.resource, outcome.id));
            match written {
                Some(row) => self
                    .written_rows
                    .insert((outcome.resource, outcome.id), row),
                None => self.written_rows.remove(&(outcome.resource, outcome.id)),
            };
            outcomes.push(outcome);
            #[cfg(any(test, feature = "test-support"))]
            crate::database::fault::after_effect(&mut self.tx).await?;
        }
        Ok(outcomes)
    }
    /// Every reused final row must equal what a fresh load would return.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn assert_written_rows_current(&mut self) {
        let written = self.written_rows.clone();
        assert!(!written.is_empty(), "no written row to compare");
        for ((resource, id), row) in written {
            let loaded = load(&mut self.tx, &self.manifest, resource, id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(loaded, row, "written row diverged from stored row");
        }
    }
    pub(super) async fn authorize_step(
        &mut self,
        op: &Operation,
        stored: Option<&StoredRecord>,
    ) -> Result<()> {
        if op.kind == OperationKind::Create {
            ensure!(
                create_prerequisites(op, &self.principal),
                ReferenceUnavailable
            );
        } else {
            let stored = stored.ok_or(ReferenceUnavailable)?;
            if manifest::is_capability(op) {
                ensure!(self.row_unexpired(stored)?, ReferenceUnavailable);
                ensure!(
                    self.capability_grant
                        .as_ref()
                        .is_some_and(|grant| grant.resource == stored.record.resource
                            && grant.id == stored.record.id
                            && grant.incarnation == stored.incarnation)
                        && stored.cap_version.is_some(),
                    ReferenceUnavailable
                );
            } else {
                ensure!(
                    self.authorize_existing(op, stored).await?,
                    ReferenceUnavailable
                );
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    pub(super) async fn create_step(
        &mut self,
        op: &Operation,
        step: &Step,
        mut fields: Fields,
        outcomes: &[MutationOutcome],
        action: crate::action_contract::ActionCore<'_>,
        context: &computation::Context,
    ) -> Result<(MutationOutcome, StoredRecord)> {
        let m = self.manifest.clone();
        let resource = manifest::resource(&m, op.resource)?;
        for reference in manifest::reference_fields(resource) {
            let parent = manifest::reference_resource(&m, op.resource, &reference.name)?
                .expect("admitted reference");
            let id: u64 = fields
                .get(&reference.name)
                .ok_or(ReferenceUnavailable)?
                .parse()?;
            let cached = self
                .written_rows
                .get(&(parent.id, id))
                .or_else(|| self.target_rows.get(&(parent.id, id)));
            let stored = if let Some(stored) = cached {
                #[cfg(any(test, feature = "test-support"))]
                if self.written_rows.contains_key(&(parent.id, id)) {
                    let loaded = load(&mut self.tx, &m, parent.id, id).await?;
                    assert_eq!(
                        loaded.as_ref(),
                        Some(stored),
                        "reused reference row diverged"
                    );
                }
                stored.clone()
            } else {
                ensure!(self.calls >= 2, "database call budget");
                self.calls -= 2;
                let stored = load(&mut self.tx, &m, parent.id, id)
                    .await?
                    .ok_or(ReferenceUnavailable)?;
                self.target_rows.insert((parent.id, id), stored.clone());
                stored
            };
            let assignment = step
                .assign
                .iter()
                .find(|a| a.field == reference.name)
                .ok_or_else(|| anyhow::anyhow!("missing reference assignment"))?;
            let expected_incarnation = match &assignment.change {
                Change::Set(Value::Target(name)) => {
                    let grant = self.grants.get(name).ok_or(ReferenceUnavailable)?;
                    ensure!(
                        grant.resource == parent.id && grant.id == id,
                        ReferenceUnavailable
                    );
                    &grant.incarnation
                }
                Change::Set(Value::Created(index)) => {
                    let outcome = outcomes
                        .get(usize::from(*index))
                        .ok_or(ReferenceUnavailable)?;
                    ensure!(
                        outcome.kind == MutationKind::Created
                            && outcome.resource == parent.id
                            && outcome.id == id,
                        ReferenceUnavailable
                    );
                    &outcome.incarnation
                }
                _ => anyhow::bail!("invalid reference assignment"),
            };
            ensure!(
                &stored.incarnation == expected_incarnation,
                ReferenceUnavailable
            );
            let eligible = manifest::operation(
                &m,
                *op.bind
                    .get(&reference.name)
                    .ok_or_else(|| anyhow::anyhow!("missing binding eligibility"))?,
            )?;
            ensure!(
                authorize_stored_read(&mut self.read_context(), eligible, &stored).await?
                    && (resource
                        .gate
                        .as_ref()
                        .is_none_or(|gate| gate.field != reference.name)
                        || manifest::gate_permits(resource, &stored.record.fields, true)),
                ReferenceUnavailable
            );
        }
        for field in &resource.fields {
            if let Some(value) = &field.initial {
                ensure!(
                    fields.insert(field.name.clone(), value.clone()).is_none(),
                    "initial value cannot be assigned"
                );
            }
        }
        for field in &resource.fields {
            if matches!(field.kind, FieldKind::Blob { .. })
                && field.optional
                && !fields.contains_key(&field.name)
            {
                fields.insert(field.name.clone(), String::new());
            }
        }
        manifest::validate_fields(resource, &fields)?;
        for unique in &resource.unique {
            crate::membership::canonical_tuple(resource, unique, &fields)?;
        }
        let public = manifest::is_public(op);
        let user = if public {
            None
        } else {
            Some(self.principal.user()?.clone())
        };
        if resource
            .fields
            .iter()
            .any(|f| matches!(f.kind, FieldKind::Account { .. }))
        {
            let creator = self.principal.user().map_err(|_| ReferenceUnavailable)?;
            let rows = self
                .tx
                .rows(&stmt::ACTIVE_ACCOUNT_TENANT, &[creator.id.as_str().into()])
                .await?;
            let tenant = rows.first().ok_or(ReferenceUnavailable)?;
            ensure!(tenant[0] == creator.tenant, ReferenceUnavailable);
            for field in resource
                .fields
                .iter()
                .filter(|f| matches!(f.kind, FieldKind::Account { .. }))
            {
                let id = fields.get(&field.name).ok_or(ReferenceUnavailable)?;
                ensure!(
                    !self
                        .tx
                        .rows(
                            &stmt::ACTIVE_ACCOUNT_IN_TENANT,
                            &[id.as_str().into(), tenant[0].as_str().into()]
                        )
                        .await?
                        .is_empty(),
                    ReferenceUnavailable
                );
            }
        }
        self.authorize_create_row(op, &fields).await?;
        self.computation_values(context, outcomes, step, None)
            .guards(step, action)?;
        let storage_resource = self.tx.storage_resource(&m, op.resource).await?;
        if let Some(user) = &user {
            let used = self
                .tx
                .rows(
                    &stmt::OWNER_RECORD_QUOTA,
                    &[storage_resource.into(), user.id.as_str().into()],
                )
                .await?;
            ensure!(used[0][0].parse::<usize>()? < 10_000, "record quota");
        }
        let id = crate::security::record_id()?;
        let incarnation = crate::security::random_id()?;
        let created_seq = self.tx.allocate_creation().await?;
        if public {
            self.tx
                .run(
                    &stmt::INSERT_UNOWNED_RECORD,
                    &[
                        storage_resource.into(),
                        (id as i64).into(),
                        serde_json::to_string(&fields)?.into(),
                        incarnation.as_str().into(),
                        created_seq.into(),
                    ],
                )
                .await?;
        } else {
            let user = user.as_ref().expect("authorized private creation");
            self.tx
                .run(
                    &stmt::INSERT_OWNED_RECORD,
                    &[
                        storage_resource.into(),
                        (id as i64).into(),
                        user.id.as_str().into(),
                        user.tenant.as_str().into(),
                        serde_json::to_string(&fields)?.into(),
                        incarnation.as_str().into(),
                        created_seq.into(),
                    ],
                )
                .await?;
        }
        self.update_search(op.resource, storage_resource, id, &incarnation, 1, &fields)
            .await?;
        let (owner, tenant) = user.map_or_else(Default::default, |user| (user.id, user.tenant));
        let row = StoredRecord {
            record: Record {
                resource: op.resource,
                id,
                fields,
            },
            owner,
            tenant,
            incarnation: incarnation.clone(),
            revision: 1,
            cap_version: public.then_some(1),
        };
        let outcome = MutationOutcome {
            kind: MutationKind::Created,
            resource: op.resource,
            id,
            incarnation,
        };
        Ok((outcome, row))
    }
    pub(super) async fn update_step(
        &mut self,
        op: &Operation,
        stored: &StoredRecord,
        assignments: Fields,
    ) -> Result<(MutationOutcome, StoredRecord)> {
        let schema = manifest::resource(&self.manifest, op.resource)?;
        for name in assignments.keys() {
            let field = schema
                .fields
                .iter()
                .find(|field| &field.name == name)
                .ok_or(ReferenceUnavailable)?;
            ensure!(!field.is_immutable(), "immutable field cannot be updated");
        }
        let mut fields = stored.record.fields.clone();
        fields.extend(assignments);
        manifest::validate_fields(manifest::resource(&self.manifest, op.resource)?, &fields)?;
        self.check_expiry_update(op, &stored.record.fields, &fields)?;
        let next = stored
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("record revision exhausted"))?;
        let storage_resource = self
            .tx
            .storage_resource(&self.manifest, op.resource)
            .await?;
        let changed = self
            .tx
            .run(
                &stmt::UPDATE_RECORD,
                &[
                    storage_resource.into(),
                    (stored.record.id as i64).into(),
                    stored.incarnation.as_str().into(),
                    stored.revision.into(),
                    serde_json::to_string(&fields)?.into(),
                    next.into(),
                ],
            )
            .await?;
        ensure!(changed == 1, ConditionalConflict);
        self.update_search(
            op.resource,
            storage_resource,
            stored.record.id,
            &stored.incarnation,
            next,
            &fields,
        )
        .await?;
        let outcome = MutationOutcome {
            kind: MutationKind::Updated,
            resource: op.resource,
            id: stored.record.id,
            incarnation: stored.incarnation.clone(),
        };
        let row = StoredRecord {
            record: Record {
                fields,
                ..stored.record.clone()
            },
            revision: next,
            ..stored.clone()
        };
        Ok((outcome, row))
    }
    pub(super) async fn delete_step(
        &mut self,
        op: &Operation,
        stored: &StoredRecord,
    ) -> Result<MutationOutcome> {
        for child in &self.manifest.resources {
            for field in manifest::reference_fields(child) {
                if manifest::reference_resource(&self.manifest, child.id, &field.name)?
                    .is_some_and(|parent| parent.id == op.resource)
                {
                    let storage = self.tx.storage_resource(&self.manifest, child.id).await?;
                    let expression = self.tx.field_expression(&field.name)?;
                    let query = stmt::child_referencing(storage, &expression);
                    let rows = self
                        .tx
                        .rows(&query, &[stored.record.id.to_string().into()])
                        .await?;
                    ensure!(rows.is_empty(), "parent has children");
                }
            }
        }
        let storage_resource = self
            .tx
            .storage_resource(&self.manifest, op.resource)
            .await?;
        let mut expected = std::collections::BTreeMap::new();
        for field in &manifest::resource(&self.manifest, op.resource)?.fields {
            if matches!(field.kind, FieldKind::Blob { .. })
                && let Some(value) = stored
                    .record
                    .fields
                    .get(&field.name)
                    .filter(|v| !v.is_empty())
            {
                expected.insert(
                    field.name.clone(),
                    noxide_protocol::blobs::BlobRef::parse(value.clone())
                        .map_err(anyhow::Error::msg)?,
                );
            }
        }
        if self.manifest.blobs.is_some() {
            noxide_blobs::metadata::MetadataContext { tx: &mut self.tx }
                .detach_resource(
                    storage_resource,
                    i64::try_from(stored.record.id)?,
                    &stored.incarnation,
                    &expected,
                )
                .await?;
        }
        let changed = self
            .tx
            .run(
                &stmt::DELETE_RECORD,
                &[
                    storage_resource.into(),
                    (stored.record.id as i64).into(),
                    stored.incarnation.as_str().into(),
                    stored.revision.into(),
                ],
            )
            .await?;
        ensure!(changed == 1, ConditionalConflict);
        Ok(MutationOutcome {
            kind: MutationKind::Deleted,
            resource: op.resource,
            id: stored.record.id,
            incarnation: stored.incarnation.clone(),
        })
    }
}
