mod authority;
mod computation;
mod queries;
pub(crate) mod search;
use crate::{
    auth::Principal,
    database::{Param, Transaction},
    manifest,
    security::RecordTarget,
};
use anyhow::{Result, ensure};
pub(crate) use authority::{ReadBudget, ReadContext};
#[cfg(test)]
pub(crate) use authority::{test_authorize_page_resource, test_read_resource};
pub(crate) use computation::{
    CalculationUnavailable, Scalar as ScheduleScalar, Values as ScheduleValues,
};
use noxide_protocol::query::CursorKey;
use noxide_protocol::*;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct ReferenceUnavailable;
impl std::fmt::Display for ReferenceUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("reference unavailable")
    }
}
impl std::error::Error for ReferenceUnavailable {}

#[derive(Debug)]
pub(crate) struct GuardFailure {
    pub input: Option<String>,
    pub message: String,
}
impl std::fmt::Display for GuardFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("transaction guard rejected")
    }
}
impl std::error::Error for GuardFailure {}

#[derive(Debug)]
pub(crate) struct ConditionalConflict;
impl std::fmt::Display for ConditionalConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("conditional write conflict")
    }
}
impl std::error::Error for ConditionalConflict {}

fn adjust(
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

/// Candidate-dependent predicates are unknown until the proposed row resolves.
/// Every other prerequisite remains checked before guest execution and guards.
pub(crate) fn create_prerequisites(operation: &Operation, principal: &Principal) -> bool {
    if manifest::is_public(operation) {
        return true;
    }
    let Ok(user) = principal.user() else {
        return false;
    };
    operation.policy.any.iter().any(|rule| {
        !rule.is_empty()
            && rule.iter().all(|predicate| match predicate {
                Predicate::PrincipalIs { .. } | Predicate::ExistsRelated(_) => true,
                Predicate::Public
                | Predicate::Service { .. }
                | Predicate::Capability
                | Predicate::Owner
                | Predicate::SameTenant
                | Predicate::Role { .. } => allowed(
                    &Policy {
                        any: vec![vec![predicate.clone()]],
                    },
                    principal,
                    crate::policy::Row {
                        owner: &user.id,
                        tenant: &user.tenant,
                        fields: &Fields::new(),
                    },
                ),
            })
    })
}

pub(crate) const MAX_LIST_DATABASE_CALLS: usize = 4096;

pub(crate) struct Effects {
    pub authority: crate::authority::Authority,
    pub upload: Option<crate::application::blobs::UploadContext>,
    pub blob_reads:
        std::collections::BTreeMap<(u32, u64, String), (String, noxide_protocol::blobs::BlobRef)>,
    pub provenance:
        std::collections::BTreeMap<(u32, u32, u64), std::collections::BTreeMap<String, u64>>,
    pub follow_sources: Vec<(u32, u64)>,
    pub invoked: std::collections::BTreeSet<u32>,
    pub list_bytes: usize,
    pub list_calls: usize,
    pub result_limit: usize,
    pub truncated: bool,
    pub see_all: Vec<RouteRef>,
    pub tx: Transaction,
    pub manifest: Arc<Manifest>,
    pub plans: std::collections::BTreeMap<u32, Arc<crate::query_plan::ListPlan>>,
    pub principal: Principal,
    pub request: RequestView,
    pub grants: std::collections::BTreeMap<String, RecordTarget>,
    pub target_rows: std::collections::BTreeMap<(u32, u64), StoredRecord>,
    pub capability_grant: Option<RecordTarget>,
    pub calls: u32,
    pub cursor: Option<CursorKey>,
    pub more: Option<CursorKey>,
}

// Measure the exact cross-boundary representation, including array framing.
fn append_prefix(
    records: &mut Vec<Record>,
    record: Record,
    limit: usize,
    empty: bool,
) -> Result<bool> {
    records.push(record);
    if serde_json::to_vec(records)?.len() <= limit {
        return Ok(true);
    }
    records.pop();
    ensure!(
        empty || !records.is_empty(),
        "record exceeds repository result budget"
    );
    Ok(false)
}

#[derive(Clone)]
pub(crate) struct StoredRecord {
    pub record: Record,
    pub owner: String,
    pub tenant: String,
    pub incarnation: String,
    pub revision: i64,
    pub cap_version: Option<i64>,
}

pub(crate) async fn load(
    tx: &mut Transaction,
    m: &Manifest,
    resource: u32,
    id: u64,
) -> Result<Option<StoredRecord>> {
    ensure!(id > 0 && id <= i64::MAX as u64, "invalid resource target");
    let storage_resource = tx.storage_resource(m, resource).await?;
    let sql = format!(
        "SELECT COALESCE(owner,''),tenant,{}, {},CAST(revision AS TEXT),COALESCE(CAST(cap_version AS TEXT),'') FROM nx_records WHERE resource=$1 AND id=$2",
        tx.bounded_text("fields", 20_000),
        tx.bounded_text("incarnation", 64)
    );
    let rows = tx
        .fetch::<6>(
            &sql,
            &[Param::Number(storage_resource), Param::Number(id as i64)],
        )
        .await?;
    rows.into_iter()
        .next()
        .map(
            |[owner, tenant, fields, incarnation, revision, cap_version]| {
                let fields = serde_json::from_str(&fields)?;
                manifest::validate_fields(manifest::resource(m, resource)?, &fields)?;
                let revision = revision.parse()?;
                ensure!(
                    revision > 0 && !incarnation.is_empty(),
                    "invalid record metadata"
                );
                Ok(StoredRecord {
                    record: Record {
                        resource,
                        id,
                        fields,
                    },
                    owner,
                    tenant,
                    incarnation,
                    revision,
                    cap_version: if cap_version.is_empty() {
                        None
                    } else {
                        Some(cap_version.parse()?)
                    },
                })
            },
        )
        .transpose()
}

pub(crate) use crate::policy::allowed;

/// Common host read authorization and projection; no guest code is executed.
async fn read_projected_resource(
    context: &mut ReadContext<'_>,
    op: &Operation,
    target: u64,
) -> Result<Option<(Record, String)>> {
    let Some(stored) = context.load(op.resource, target).await? else {
        return Ok(None);
    };
    if !authorize_stored_read(context, op, &stored).await? {
        return Ok(None);
    }
    let mut record = stored.record;
    if manifest::is_public(op) {
        let projection = op
            .fields
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing read projection"))?;
        record.fields.retain(|name, _| projection.contains(name));
    }
    Ok(Some((record, stored.incarnation)))
}

#[cfg(test)]
pub(crate) async fn read_resource(
    context: &mut ReadContext<'_>,
    op: &Operation,
    target: u64,
) -> Result<Option<Record>> {
    Ok(read_projected_resource(context, op, target)
        .await?
        .map(|(record, _)| record))
}

pub(crate) async fn authorize_stored_read(
    context: &mut ReadContext<'_>,
    op: &Operation,
    stored: &StoredRecord,
) -> Result<bool> {
    ensure!(
        matches!(op.kind, OperationKind::Read | OperationKind::List),
        "invalid row read authority"
    );
    if !read_allowed(context, op, stored).await? {
        return Ok(false);
    }
    let source = manifest::resource(context.manifest, op.resource)?;
    if manifest::is_public(op)
        && let Some(gate) = &source.gate
    {
        let parent = manifest::reference_resource(context.manifest, op.resource, &gate.field)?
            .expect("admitted gate reference");
        let id = stored.record.fields[&gate.field].parse()?;
        let Some(parent) = context.load(parent.id, id).await? else {
            return Ok(false);
        };
        if !context.unexpired(&parent)?
            || !manifest::gate_permits(source, &parent.record.fields, false)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) async fn read_allowed(
    context: &mut ReadContext<'_>,
    op: &Operation,
    stored: &StoredRecord,
) -> Result<bool> {
    ensure!(
        matches!(op.kind, OperationKind::Read | OperationKind::List)
            && op.resource == stored.record.resource,
        "invalid read binding"
    );
    if !context.authorize(op, stored).await? {
        return Ok(false);
    }
    if manifest::is_public(op) {
        let visibility = op
            .visibility
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing visibility"))?;
        ensure!(op.fields.is_some(), "missing read projection");
        if stored.record.fields.get(&visibility.field) != Some(&visibility.equals) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) async fn authorize_page_resource(
    context: &mut ReadContext<'_>,
    route: &Route,
    resource: u32,
    id: u64,
    incarnation: Option<&str>,
) -> Result<Option<StoredRecord>> {
    ensure!(route.resource == Some(resource), "route resource differs");
    let Some(stored) = context.load(resource, id).await? else {
        return Ok(None);
    };
    if incarnation.is_some_and(|value| value != stored.incarnation) {
        return Ok(None);
    }
    let mut reads = 0;
    let mut public_read = false;
    let mut private_read = false;
    for operation in &route.operations {
        let op = manifest::operation(context.manifest, *operation)?;
        if op.kind == OperationKind::Read && op.via.is_none() && op.resource == resource {
            reads += 1;
            if read_allowed(context, op, &stored).await? {
                if manifest::is_public(op) {
                    public_read = true;
                } else {
                    private_read = true;
                }
            }
        }
    }
    ensure!(reads > 0, "missing resource read");
    if !public_read && !private_read {
        return Ok(None);
    }
    if !private_read && let Some(gate) = &manifest::resource(context.manifest, resource)?.gate {
        let parent = manifest::reference_resource(context.manifest, resource, &gate.field)?
            .expect("admitted gate reference");
        let id = stored.record.fields[&gate.field].parse()?;
        let Some(parent) = context.load(parent.id, id).await? else {
            return Ok(None);
        };
        if !context.unexpired(&parent)?
            || !manifest::gate_permits(
                manifest::resource(context.manifest, resource)?,
                &parent.record.fields,
                false,
            )
        {
            return Ok(None);
        }
    }
    Ok(Some(stored))
}

impl Effects {
    pub(crate) async fn execute_transaction(
        &mut self,
        action: crate::application::ActionCore<'_>,
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
                    let locked = crate::blob_metadata::MetadataContext { tx: &mut self.tx }
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
            let outcome = match op.kind {
                OperationKind::Create => {
                    self.create_step(&op, step, values, &outcomes, action, &context)
                        .await?
                }
                OperationKind::Update => {
                    self.update_step(&op, stored.as_ref().ok_or(ReferenceUnavailable)?, values)
                        .await?
                }
                OperationKind::Delete => {
                    self.delete_step(&op, stored.as_ref().ok_or(ReferenceUnavailable)?)
                        .await?
                }
                _ => anyhow::bail!("transaction requires mutation"),
            };
            for (field, locked) in attachments {
                let now = self.upload.as_ref().ok_or(ReferenceUnavailable)?.now;
                let storage_resource = self
                    .tx
                    .storage_resource(&self.manifest, outcome.resource)
                    .await?;
                crate::blob_metadata::MetadataContext { tx: &mut self.tx }
                    .associate(
                        locked,
                        crate::blob_state::Association {
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
            outcomes.push(outcome);
            #[cfg(test)]
            crate::failure_tests::after_effect(&mut self.tx).await?;
        }
        Ok(outcomes)
    }

    async fn authorize_step(
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

    async fn create_step(
        &mut self,
        op: &Operation,
        step: &Step,
        mut fields: Fields,
        outcomes: &[MutationOutcome],
        action: crate::application::ActionCore<'_>,
        context: &computation::Context,
    ) -> Result<MutationOutcome> {
        let m = self.manifest.clone();
        let resource = manifest::resource(&m, op.resource)?;
        for reference in manifest::reference_fields(resource) {
            let parent = manifest::reference_resource(&m, op.resource, &reference.name)?
                .expect("admitted reference");
            let id: u64 = fields
                .get(&reference.name)
                .ok_or(ReferenceUnavailable)?
                .parse()?;
            let stored = if let Some(stored) = self.target_rows.get(&(parent.id, id)) {
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
                .fetch::<1>(
                    "SELECT tenant FROM nx_accounts WHERE id=$1 AND state='active' AND tenant<>''",
                    &[creator.id.as_str().into()],
                )
                .await?;
            let tenant = rows.first().ok_or(ReferenceUnavailable)?;
            ensure!(tenant[0] == creator.tenant, ReferenceUnavailable);
            for field in resource
                .fields
                .iter()
                .filter(|f| matches!(f.kind, FieldKind::Account { .. }))
            {
                let id = fields.get(&field.name).ok_or(ReferenceUnavailable)?;
                ensure!(!self.tx.fetch::<1>("SELECT id FROM nx_accounts WHERE id=$1 AND state='active' AND tenant=$2", &[id.as_str().into(), tenant[0].as_str().into()]).await?.is_empty(), ReferenceUnavailable);
            }
        }
        self.authorize_create_row(op, &fields).await?;
        self.computation_values(context, outcomes, step, None)
            .guards(step, action)?;
        let storage_resource = self.tx.storage_resource(&m, op.resource).await?;
        if let Some(user) = &user {
            let used = self.tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM (SELECT id FROM nx_records WHERE resource=$1 AND owner=$2 LIMIT 10000) AS quota", &[storage_resource.into(), user.id.as_str().into()]).await?;
            ensure!(used[0][0].parse::<usize>()? < 10_000, "record quota");
        }
        let id = crate::security::record_id()?;
        let incarnation = crate::security::random_id()?;
        let created_seq = self.tx.allocate_creation().await?;
        if public {
            self.tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES($1,$2,NULL,'',$3,$4,1,1,$5)", &[storage_resource.into(), (id as i64).into(), serde_json::to_string(&fields)?.into(), incarnation.as_str().into(), created_seq.into()]).await?;
        } else {
            let user = user.expect("authorized private creation");
            self.tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,$4,$5,$6,1,$7)", &[storage_resource.into(), (id as i64).into(), user.id.as_str().into(), user.tenant.as_str().into(), serde_json::to_string(&fields)?.into(), incarnation.as_str().into(), created_seq.into()]).await?;
        }
        self.update_search(op.resource, storage_resource, id, &incarnation, 1, &fields)
            .await?;
        Ok(MutationOutcome {
            kind: MutationKind::Created,
            resource: op.resource,
            id,
            incarnation,
        })
    }

    async fn update_step(
        &mut self,
        op: &Operation,
        stored: &StoredRecord,
        assignments: Fields,
    ) -> Result<MutationOutcome> {
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
        let changed = self.tx.execute("UPDATE nx_records SET fields=$5,revision=$6 WHERE resource=$1 AND id=$2 AND incarnation=$3 AND revision=$4", &[storage_resource.into(), (stored.record.id as i64).into(), stored.incarnation.as_str().into(), stored.revision.into(), serde_json::to_string(&fields)?.into(), next.into()]).await?;
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
        Ok(MutationOutcome {
            kind: MutationKind::Updated,
            resource: op.resource,
            id: stored.record.id,
            incarnation: stored.incarnation.clone(),
        })
    }

    async fn delete_step(
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
                    let rows = self.tx.fetch::<1>(&format!("SELECT CAST(id AS TEXT) FROM nx_records WHERE resource={storage} AND {expression}=$1 LIMIT 1"), &[stored.record.id.to_string().into()]).await?;
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
            crate::blob_metadata::MetadataContext { tx: &mut self.tx }
                .detach_resource(
                    storage_resource,
                    i64::try_from(stored.record.id)?,
                    &stored.incarnation,
                    &expected,
                )
                .await?;
        }
        let changed = self.tx.execute("DELETE FROM nx_records WHERE resource=$1 AND id=$2 AND incarnation=$3 AND revision=$4", &[storage_resource.into(), (stored.record.id as i64).into(), stored.incarnation.as_str().into(), stored.revision.into()]).await?;
        ensure!(changed == 1, ConditionalConflict);
        Ok(MutationOutcome {
            kind: MutationKind::Deleted,
            resource: op.resource,
            id: stored.record.id,
            incarnation: stored.incarnation.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn next_request(&mut self) {
        self.invoked.clear();
        self.provenance.clear();
        self.blob_reads.clear();
        self.follow_sources.clear();
        self.list_bytes = 0;
        self.list_calls = MAX_LIST_DATABASE_CALLS;
        self.see_all.clear();
    }
    pub(crate) fn charge_list_calls(&mut self, count: usize) -> Result<()> {
        ensure!(self.list_calls >= count, "list database call budget");
        self.list_calls -= count;
        Ok(())
    }
    fn list_result_limit(&self, op: &Operation) -> Result<usize> {
        let RequestKind::Route(route) = self.request.kind else {
            anyhow::bail!("list outside route")
        };
        let reserve: usize = manifest::route(&self.manifest, route)?
            .operations
            .iter()
            .filter(|id| !self.invoked.contains(id))
            .filter_map(|id| manifest::operation(&self.manifest, *id).ok())
            .filter(|op| op.kind == OperationKind::List || op.via.is_some())
            .map(|op| {
                if op.via.is_some() {
                    128 // Complete twenty-slot unavailable result plus framing.
                } else if manifest::is_preview(op) {
                    64
                } else {
                    MAX_RESULT_BYTES
                }
            })
            .sum();
        let available = MAX_LIST_RESULT_BYTES
            .checked_sub(self.list_bytes + reserve)
            .ok_or_else(|| anyhow::anyhow!("list result budget"))?
            .min(MAX_RESULT_BYTES);
        let envelope = if manifest::is_preview(op) { 64 } else { 0 };
        ensure!(
            available >= if envelope == 0 { 2 } else { envelope },
            "list result budget"
        );
        Ok(available - envelope)
    }

    async fn list_single(
        &mut self,
        op: &Operation,
        storage_resource: i64,
        plan: &crate::query_plan::ListPlan,
    ) -> Result<Vec<u8>> {
        let size = plan.limit as usize;
        let direction = plan.direction();
        let cursor = if plan.preview {
            None
        } else {
            self.cursor.clone()
        };
        let mut params = vec![Param::Number(storage_resource)];
        let clauses = self.authority_sql(op, &mut params).await?;
        let visibility = self.visibility_clause(op, &mut params)?;
        let mut parent_clause = String::new();
        if let Some(scope) = &plan.scope {
            let id = self
                .request
                .target
                .ok_or_else(|| anyhow::anyhow!("missing parent target"))?;
            params.push(id.to_string().into());
            // A catalog-derived constant lets PostgreSQL's generic plans
            // prove the partial-index predicate despite resource=$1.
            parent_clause = format!(
                " AND resource={storage_resource} AND {}=${}",
                self.tx.field_expression(scope)?,
                params.len()
            );
        }
        let selection = plan.selection_sql(&self.tx, &mut params, &self.request.params)?;
        let mut records = Vec::new();
        let mut last = cursor.clone();
        self.more = None;
        // At most three bounded stored rows per database transfer. The
        // approved page size bounds both iterations and total row work.
        'page: while records.len() < size {
            let batch = (size - records.len()).min(3);
            let mut page_params = params.clone();
            let keyset = plan.keyset(last.as_ref(), &mut page_params)?;
            let sql = format!(
                "SELECT CAST(created_seq AS TEXT),CAST(id AS TEXT),COALESCE(owner,''),tenant,{} FROM nx_records WHERE resource=$1 AND resource={storage_resource} AND ({}){visibility}{parent_clause}{selection}{keyset} ORDER BY nx_records.created_seq {direction} LIMIT {batch}",
                self.tx.bounded_text("fields", 20_000),
                clauses.join(" OR ")
            );
            self.charge_list_calls(1)?;
            let rows = self.tx.fetch::<5>(&sql, &page_params).await?;
            let count = rows.len();
            let parsed: Vec<Fields> = rows
                .iter()
                .map(|row| serde_json::from_str(&row[4]))
                .collect::<std::result::Result<_, _>>()?;
            let policy_rows: Vec<_> = rows
                .iter()
                .zip(&parsed)
                .map(|(row, fields)| {
                    Ok(crate::authority::Row {
                        id: row[1].parse()?,
                        owner: &row[2],
                        tenant: &row[3],
                        fields,
                    })
                })
                .collect::<Result<_>>()?;
            let decisions = self.authorize_rows(op, &policy_rows).await?;
            for ([seq, id, _owner, _tenant, fields], permitted) in rows.into_iter().zip(decisions) {
                plan.check_selection(&serde_json::from_str(&fields)?, &self.request.params)?;
                ensure!(permitted, "policy invariant");
                let record = Record {
                    resource: op.resource,
                    id: id.parse()?,
                    fields: self.visible_fields(op, serde_json::from_str(&fields)?)?,
                };
                if !append_prefix(&mut records, record, self.result_limit, plan.preview)? {
                    self.truncated = true;
                    self.more = last.clone();
                    break 'page;
                }
                last = Some(CursorKey::Created {
                    sequence: seq.parse()?,
                    record: id.parse()?,
                });
            }
            if count < batch {
                break;
            }
        }
        if self.more.is_none() && records.len() == size {
            let mut page_params = params.clone();
            let keyset = plan.keyset(last.as_ref(), &mut page_params)?;
            self.charge_list_calls(1)?;
            let next=self.tx.fetch::<1>(&format!("SELECT CAST(created_seq AS TEXT) FROM nx_records WHERE resource=$1 AND resource={storage_resource} AND ({}){visibility}{parent_clause}{selection}{keyset} ORDER BY nx_records.created_seq {direction} LIMIT 1",clauses.join(" OR ")),&page_params).await?;
            if !next.is_empty() {
                self.truncated = true;
                self.more = last.clone();
            }
        }
        Ok(serde_json::to_vec(&records)?)
    }
    async fn list_merge(
        &mut self,
        op: &Operation,
        storage_resource: i64,
        plan: &crate::query_plan::ListPlan,
        scans: &[crate::policy::ScanRule],
    ) -> Result<Vec<u8>> {
        let size = plan.limit as usize;
        let direction = plan.direction();
        let cursor = if plan.preview {
            None
        } else {
            self.cursor.clone()
        };
        let mut candidates = std::collections::BTreeMap::new();
        let mut boundary = if plan.descending() { 0 } else { u64::MAX };
        let mut bounded_more = false;
        for scan in scans {
            let exact = scan.exact;
            let scan_policy = crate::policy::scan_policy(&op.policy, scan);
            let mut scan_params = vec![Param::Number(storage_resource)];
            let clause =
                crate::policy::sql(&self.tx, &scan_policy, &self.principal, &mut scan_params)
                    .join(" OR ");
            let selection = plan.selection_sql(&self.tx, &mut scan_params, &self.request.params)?;
            let mut parent_clause = String::new();
            if let Some(parent) = &plan.scope {
                let target = self
                    .request
                    .target
                    .ok_or_else(|| anyhow::anyhow!("missing parent target"))?;
                scan_params.push(target.to_string().into());
                parent_clause = format!(
                    " AND {}=${}",
                    self.tx.field_expression(parent)?,
                    scan_params.len()
                );
            }
            let visibility = self.visibility_clause(op, &mut scan_params)?;
            let keyset = plan.keyset(cursor.as_ref(), &mut scan_params)?;
            let limit = if exact {
                size + 1
            } else {
                (256 / op.policy.any.len()).min(64)
            };
            let sql = format!(
                "SELECT CAST(created_seq AS TEXT),CAST(id AS TEXT) FROM nx_records WHERE resource=$1 AND resource={storage_resource} AND ({clause}){visibility}{parent_clause}{selection}{keyset} ORDER BY nx_records.created_seq {direction} LIMIT {limit}"
            );
            self.charge_list_calls(1)?;
            let rows = self.tx.fetch::<2>(&sql, &scan_params).await?;
            if !exact && rows.len() == limit {
                let last = rows.last().expect("nonempty")[0].parse()?;
                boundary = if plan.descending() {
                    boundary.max(last)
                } else {
                    boundary.min(last)
                };
                bounded_more = true;
            }
            for [seq, id] in rows {
                candidates.insert(seq.parse::<u64>()?, id.parse::<u64>()?);
            }
        }
        let mut records = Vec::new();
        let mut last = cursor.clone();
        self.more = None;
        let ordered: Vec<_> = if plan.descending() {
            candidates.into_iter().rev().collect()
        } else {
            candidates.into_iter().collect()
        };
        let ordered: Vec<_> = ordered
            .into_iter()
            .take_while(|(seq, _)| {
                if plan.descending() {
                    *seq >= boundary
                } else {
                    *seq <= boundary
                }
            })
            .collect();
        'page: for group in ordered.chunks(crate::membership::MAX_BATCH) {
            let ids: Vec<_> = group.iter().map(|(_, id)| *id).collect();
            let loaded = authority::load_batch(
                &mut self.tx,
                &self.manifest,
                op.resource,
                storage_resource,
                &ids,
                &mut self.list_calls,
            )
            .await?;
            let stored: Vec<_> = group
                .iter()
                .map(|(_, id)| {
                    loaded
                        .get(id)
                        .ok_or_else(|| anyhow::anyhow!("record disappeared"))
                })
                .collect::<Result<_>>()?;
            let policy_rows: Vec<_> = stored.iter().map(|stored| stored.authority_row()).collect();
            let allowed = self.authorize_rows(op, &policy_rows).await?;
            for (((seq, _), stored), allowed) in group.iter().zip(stored).zip(allowed) {
                if !allowed {
                    last = Some(CursorKey::Created {
                        sequence: *seq,
                        record: stored.record.id,
                    });
                    continue;
                }
                if let Some(field) = &plan.scope
                    && stored
                        .record
                        .fields
                        .get(field)
                        .and_then(|value| value.parse::<u64>().ok())
                        != self.request.target
                {
                    last = Some(CursorKey::Created {
                        sequence: *seq,
                        record: stored.record.id,
                    });
                    continue;
                }
                plan.check_selection(&stored.record.fields, &self.request.params)?;
                let mut record = stored.record.clone();
                record.fields = self.visible_fields(op, record.fields)?;
                if records.len() == size
                    || !append_prefix(&mut records, record, self.result_limit, plan.preview)?
                {
                    self.truncated = true;
                    self.more = last.clone();
                    break 'page;
                }
                last = Some(CursorKey::Created {
                    sequence: *seq,
                    record: stored.record.id,
                });
            }
        }
        if self.more.is_none() && bounded_more {
            self.truncated = true;
            self.more = ordered
                .iter()
                .find(|(seq, _)| *seq == boundary)
                .map(|(seq, id)| CursorKey::Created {
                    sequence: *seq,
                    record: *id,
                });
        }
        Ok(serde_json::to_vec(&records)?)
    }

    fn visibility_clause(&self, op: &Operation, params: &mut Vec<Param>) -> Result<String> {
        if !manifest::is_public(op) {
            return Ok(String::new());
        }
        let visibility = op
            .visibility
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing public visibility"))?;
        let expression = self.tx.field_expression(&visibility.field)?;
        params.push(visibility.equals.as_str().into());
        Ok(format!(" AND ({expression} = ${})", params.len()))
    }

    fn visible_fields(&self, op: &Operation, mut fields: Fields) -> Result<Fields> {
        if manifest::is_public(op) {
            let visibility = op
                .visibility
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing public visibility"))?;
            ensure!(
                fields.get(&visibility.field) == Some(&visibility.equals),
                "public visibility invariant"
            );
        }
        manifest::validate_fields(manifest::resource(&self.manifest, op.resource)?, &fields)?;
        if manifest::is_public(op) {
            let names = op
                .fields
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing public fields"))?;
            fields.retain(|name, _| names.contains(name));
        }
        Ok(fields)
    }

    pub(crate) fn follow_source(&mut self, resource: u32, id: u64) -> Result<()> {
        ensure!(
            matches!(self.request.kind, RequestKind::Route(_)),
            "storage import during action"
        );
        ensure!(self.follow_sources.len() < 20, "follow source budget");
        self.follow_sources.push((resource, id));
        Ok(())
    }
    pub(crate) async fn follow(&mut self, operation: u32) -> Result<Vec<u8>> {
        ensure!(
            matches!(self.request.kind, RequestKind::Route(_)),
            "storage import during action"
        );
        ensure!(self.calls > 0, "database call budget");
        self.calls -= 1;
        let op = manifest::operation(&self.manifest, operation)?.clone();
        let via = op
            .via
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("follow declaration required"))?;
        let RequestKind::Route(route) = self.request.kind else {
            anyhow::bail!("follow outside route")
        };
        ensure!(
            manifest::route(&self.manifest, route)?
                .operations
                .contains(&operation),
            "follow outside request grant"
        );
        ensure!(self.invoked.insert(operation), "operation already invoked");
        let sources = std::mem::take(&mut self.follow_sources);
        let targets: Vec<u64> = sources
            .iter()
            .map(|(resource, id)| {
                self.provenance
                    .get(&(via.source, *resource, *id))
                    .and_then(|fields| fields.get(&via.field))
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("follow source was not returned"))
            })
            .collect::<Result<_>>()?;
        let unique: std::collections::BTreeSet<_> = targets.iter().copied().collect();
        let mut records = std::collections::BTreeMap::new();
        if !unique.is_empty() {
            self.charge_list_calls(2)?;
            let storage = self
                .tx
                .storage_resource(&self.manifest, op.resource)
                .await?;
            let mut params = vec![Param::Number(storage)];
            let mut slots = Vec::new();
            for id in unique {
                params.push(Param::Number(id as i64));
                slots.push(format!("${}", params.len()));
            }
            let sql = format!(
                "SELECT CAST(id AS TEXT),COALESCE(owner,''),tenant,{} FROM nx_records WHERE resource=$1 AND id IN ({})",
                self.tx.bounded_text("fields", 20_000),
                slots.join(",")
            );
            let rows = self.tx.fetch::<4>(&sql, &params).await?;
            // Gate target reads are batched separately below; no per-record round trips.
            let mut loaded = Vec::new();
            for [id, owner, tenant, fields] in rows {
                let fields = serde_json::from_str(&fields)?;
                manifest::validate_fields(
                    manifest::resource(&self.manifest, op.resource)?,
                    &fields,
                )?;
                let stored = StoredRecord {
                    record: Record {
                        resource: op.resource,
                        id: id.parse()?,
                        fields,
                    },
                    owner,
                    tenant,
                    incarnation: String::new(),
                    revision: 1,
                    cap_version: None,
                };
                loaded.push(stored);
            }
            let policy_rows: Vec<_> = loaded.iter().map(StoredRecord::authority_row).collect();
            let permitted = self.authorize_rows(&op, &policy_rows).await?;
            let mut candidates = Vec::new();
            for (stored, allowed) in loaded.into_iter().zip(permitted) {
                if !allowed {
                    continue;
                }
                if manifest::is_public(&op) {
                    let visibility = op
                        .visibility
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing public visibility"))?;
                    if stored.record.fields.get(&visibility.field) != Some(&visibility.equals) {
                        continue;
                    }
                }
                candidates.push(stored.record);
            }
            if manifest::is_public(&op)
                && let Some(gate) = manifest::resource(&self.manifest, op.resource)?
                    .gate
                    .clone()
            {
                let target_resource =
                    manifest::reference_resource(&self.manifest, op.resource, &gate.field)?
                        .expect("gate target")
                        .id;
                self.charge_list_calls(2)?;
                let storage = self
                    .tx
                    .storage_resource(&self.manifest, target_resource)
                    .await?;
                let mut params = vec![Param::Number(storage)];
                let mut slots = Vec::new();
                for record in &candidates {
                    params.push(Param::Number(record.fields[&gate.field].parse()?));
                    slots.push(format!("${}", params.len()));
                }
                let mut visible = std::collections::BTreeSet::new();
                if !slots.is_empty() {
                    let sql = format!(
                        "SELECT CAST(id AS TEXT),{} FROM nx_records WHERE resource=$1 AND id IN ({})",
                        self.tx.bounded_text("fields", 20_000),
                        slots.join(",")
                    );
                    for [id, fields] in self.tx.fetch::<2>(&sql, &params).await? {
                        let fields = serde_json::from_str(&fields)?;
                        manifest::validate_fields(
                            manifest::resource(&self.manifest, target_resource)?,
                            &fields,
                        )?;
                        if crate::expiry::available(
                            manifest::resource(&self.manifest, target_resource)?,
                            &fields,
                            self.authority.time(),
                        )? && manifest::gate_permits(
                            manifest::resource(&self.manifest, op.resource)?,
                            &fields,
                            false,
                        ) {
                            visible.insert(id);
                        }
                    }
                }
                candidates.retain(|record| visible.contains(&record.fields[&gate.field]));
            }
            for mut record in candidates {
                if let Some(fields) = &op.fields {
                    record.fields.retain(|name, _| fields.contains(name));
                }
                records.insert(record.id, record);
            }
        }
        let result: Vec<_> = targets.iter().map(|id| records.get(id)).collect();
        let bytes = serde_json::to_vec(&result)?;
        ensure!(
            bytes.len() <= self.list_result_limit(&op)?,
            "follow result budget"
        );
        self.list_bytes += bytes.len();
        ensure!(
            self.list_bytes <= MAX_LIST_RESULT_BYTES,
            "list result budget"
        );
        Ok(bytes)
    }
    pub(crate) async fn picker_records(&mut self, binding: u32, name: &str) -> Result<Vec<Record>> {
        let RequestKind::Route(route) = self.request.kind else {
            anyhow::bail!("picker outside web route")
        };
        ensure!(
            manifest::route(&self.manifest, route)?
                .forms
                .contains(&binding),
            "picker outside binding grant"
        );
        let action = manifest::web_action(&self.manifest, binding)?;
        let declaration = manifest::action_target(&action.targets, name)?;
        let TargetSource::Selected { query, .. } = declaration.source else {
            anyhow::bail!("not a picker target")
        };
        let op = manifest::operation(&self.manifest, query)?.clone();
        let previous = (
            self.cursor.clone(),
            self.more.clone(),
            self.result_limit,
            self.truncated,
        );
        // Route pagination is scoped to its own query; it cannot select a
        // different window of the host-owned picker query.
        self.cursor = None;
        let result = self.invoke_internal(query, 0, true).await;
        (self.cursor, self.more, self.result_limit, self.truncated) = previous;
        let bytes = result?;
        if manifest::is_preview(&op) {
            Ok(serde_json::from_slice::<PreviewResult>(&bytes)?.items)
        } else {
            Ok(serde_json::from_slice(&bytes)?)
        }
    }
    pub(crate) async fn invoke(&mut self, operation: u32, target: u64) -> Result<Vec<u8>> {
        self.invoke_internal(operation, target, false).await
    }
    async fn invoke_internal(
        &mut self,
        operation: u32,
        target: u64,
        picker: bool,
    ) -> Result<Vec<u8>> {
        ensure!(self.calls > 0, "database call budget");
        self.calls -= 1;
        let op = manifest::operation(&self.manifest, operation)?.clone();
        ensure!(op.via.is_none(), "follow cannot be invoked by ID");
        if picker {
            ensure!(
                op.kind == OperationKind::List && op.scope.is_none() && target == 0,
                "invalid picker query grant"
            );
        } else {
            match &self.request.kind {
                RequestKind::Route(id) => {
                    let route = manifest::route(&self.manifest, *id)?;
                    ensure!(
                        route.operations.contains(&operation)
                            && target
                                == if matches!(
                                    op.kind,
                                    OperationKind::List | OperationKind::Aggregate
                                ) {
                                    0
                                } else {
                                    self.request.target.unwrap_or(0)
                                },
                        "operation outside request grant"
                    );
                    ensure!(
                        matches!(
                            op.kind,
                            OperationKind::List | OperationKind::Read | OperationKind::Aggregate
                        ),
                        "read route mutation"
                    );
                    ensure!(self.invoked.insert(operation), "operation already invoked");
                }
                RequestKind::Action(_) => anyhow::bail!("storage import during action"),
            }
        }
        if matches!(op.kind, OperationKind::List | OperationKind::Aggregate) {
            self.charge_list_calls(1)?;
        }
        let storage_resource = self
            .tx
            .storage_resource(&self.manifest, op.resource)
            .await?;
        let value = match op.kind {
            OperationKind::Aggregate => self.aggregate_query(&op, storage_resource).await?,
            OperationKind::Create | OperationKind::Update | OperationKind::Delete => {
                anyhow::bail!("mutation outside declared transaction")
            }
            OperationKind::Read => {
                let found = read_projected_resource(&mut self.read_context(), &op, target).await?;
                if let Some((record, incarnation)) = &found {
                    for field in &manifest::resource(&self.manifest, op.resource)?.fields {
                        if matches!(field.kind, FieldKind::Blob { .. })
                            && op
                                .fields
                                .as_ref()
                                .is_none_or(|fields| fields.contains(&field.name))
                            && let Some(raw) =
                                record.fields.get(&field.name).filter(|v| !v.is_empty())
                        {
                            let blob = noxide_protocol::blobs::BlobRef::parse(raw.clone())
                                .map_err(anyhow::Error::msg)?;
                            self.blob_reads.insert(
                                (op.id, record.id, field.name.clone()),
                                (incarnation.clone(), blob),
                            );
                        }
                    }
                }
                serde_json::to_vec(&found.map(|(record, _)| record))?
            }
            OperationKind::List => {
                self.result_limit = self.list_result_limit(&op)?;
                self.truncated = false;
                let previous_more = self.more.clone();
                let plan = self
                    .plans
                    .get(&op.id)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing list plan"))?;
                ensure!(plan.operation == op.id, "invalid list plan");
                let source_resource = manifest::resource(&self.manifest, op.resource)?.clone();
                if manifest::is_public(&op)
                    && source_resource.gate.is_some()
                    && let Some(parent) = manifest::reference_resource(
                        &self.manifest,
                        op.resource,
                        &source_resource.gate.as_ref().expect("gate").field,
                    )?
                    .map(|p| p.id)
                {
                    self.charge_list_calls(2)?;
                    let id = self
                        .request
                        .target
                        .ok_or_else(|| anyhow::anyhow!("missing parent target"))?;
                    let field = manifest::reference_field(
                        &source_resource,
                        &source_resource.gate.as_ref().expect("gate").field,
                    )
                    .expect("parent");
                    ensure!(
                        plan.scope.as_deref() == Some(field.name.as_str()),
                        "invalid list parent"
                    );
                    let record = load(&mut self.tx, &self.manifest, parent, id).await?;
                    let gate_visible = match &record {
                        Some(record) => {
                            self.row_unexpired(record)?
                                && manifest::gate_permits(
                                    &source_resource,
                                    &record.record.fields,
                                    false,
                                )
                        }
                        None => false,
                    };
                    if !gate_visible {
                        let bytes = if plan.preview {
                            self.more = previous_more;
                            serde_json::to_vec(&PreviewResult {
                                items: Vec::new(),
                                truncated: false,
                            })?
                        } else {
                            self.more = None;
                            serde_json::to_vec(&Vec::<Record>::new())?
                        };
                        self.list_bytes += bytes.len();
                        ensure!(
                            self.list_bytes <= MAX_LIST_RESULT_BYTES,
                            "list result budget"
                        );
                        return Ok(bytes);
                    }
                }
                let bytes = if op
                    .query
                    .as_ref()
                    .is_some_and(|query| query.search.is_some() || query.range.is_some())
                    || matches!(plan.order, ListOrder::Field { .. })
                {
                    self.list_extended(&op, storage_resource, &plan).await?
                } else {
                    match &plan.strategy {
                        crate::policy::ListStrategy::Single => {
                            self.list_single(&op, storage_resource, &plan).await?
                        }
                        crate::policy::ListStrategy::Merge(scans) => {
                            self.list_merge(&op, storage_resource, &plan, scans).await?
                        }
                    }
                };
                let bytes = if plan.preview {
                    let truncated = self.truncated || self.more.is_some();
                    self.more = previous_more;
                    if truncated
                        && let Some(route) = op
                            .list
                            .as_ref()
                            .and_then(|s| s.preview.as_ref())
                            .and_then(|p| p.see_all)
                    {
                        let target = manifest::route(&self.manifest, route)?;
                        let reference = RouteRef {
                            route,
                            target: target.resource.and(self.request.target),
                            params: target
                                .params
                                .iter()
                                .map(|name| {
                                    Ok((
                                        name.clone(),
                                        self.request
                                            .params
                                            .get(name)
                                            .ok_or_else(|| {
                                                anyhow::anyhow!("missing preview parameter")
                                            })?
                                            .clone(),
                                    ))
                                })
                                .collect::<Result<_>>()?,
                        };
                        crate::routing::resolve(&self.manifest, &reference)?;
                        self.see_all.push(reference);
                    }
                    serde_json::to_vec(&PreviewResult {
                        items: serde_json::from_slice(&bytes)?,
                        truncated,
                    })?
                } else {
                    bytes
                };
                self.list_bytes += bytes.len();
                ensure!(
                    self.list_bytes <= MAX_LIST_RESULT_BYTES,
                    "list result budget"
                );
                bytes
            }
        };
        if matches!(op.kind, OperationKind::Read | OperationKind::List) {
            let records: Vec<Record> = if op.kind == OperationKind::Read {
                serde_json::from_slice::<Option<Record>>(&value)?
                    .into_iter()
                    .collect()
            } else if manifest::is_preview(&op) {
                serde_json::from_slice::<PreviewResult>(&value)?.items
            } else {
                serde_json::from_slice(&value)?
            };
            for record in records {
                let references =
                    manifest::reference_fields(manifest::resource(&self.manifest, op.resource)?)
                        .filter_map(|field| {
                            record
                                .fields
                                .get(&field.name)
                                .map(|value| (field.name.clone(), value))
                        })
                        .map(|(field, value)| Ok((field, value.parse::<u64>()?)))
                        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
                if !references.is_empty() {
                    self.provenance
                        .insert((op.id, op.resource, record.id), references);
                    ensure!(self.provenance.len() <= 56, "follow provenance budget");
                }
            }
        }
        ensure!(value.len() <= MAX_RESULT_BYTES, "repository output budget");
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transaction_adjustments_guard_overflow_and_both_bounds() {
        let rejection = GuardRejection {
            input: Some("quantity".into()),
            message: "Not enough stock".into(),
        };
        for (current, amount, min, max, increase) in [
            (i64::MAX, 1, i64::MIN, i64::MAX, true),
            (i64::MIN, 1, i64::MIN, i64::MAX, false),
            (5, 6, 0, 10, false),
            (5, 6, 0, 10, true),
        ] {
            let error = adjust(current, amount, min, max, increase, &rejection).unwrap_err();
            let guard = error
                .downcast_ref::<GuardFailure>()
                .expect("declared rejection");
            assert_eq!(guard.input, rejection.input);
            assert_eq!(guard.message, rejection.message);
        }
        assert_eq!(adjust(5, 5, 0, 10, false, &rejection).unwrap(), 0);
        assert_eq!(adjust(5, 5, 0, 10, true, &rejection).unwrap(), 10);
        assert_eq!(
            adjust(i64::MIN, i64::MAX, i64::MIN, i64::MAX, true, &rejection).unwrap(),
            -1
        );
        assert_eq!(
            adjust(i64::MAX, i64::MAX, i64::MIN, i64::MAX, false, &rejection).unwrap(),
            0
        );
    }

    #[test]
    fn byte_prefix_counts_protocol_framing_and_fails_on_first_row_overflow() {
        let mut record = Record {
            resource: 1,
            id: 42,
            fields: Fields::from([("body".into(), String::new())]),
        };
        let overhead = serde_json::to_vec(&vec![record.clone()]).unwrap().len();
        record
            .fields
            .insert("body".into(), "x".repeat(MAX_RESULT_BYTES - overhead));
        let mut rows = Vec::new();
        assert!(append_prefix(&mut rows, record.clone(), MAX_RESULT_BYTES, false).unwrap());
        assert_eq!(serde_json::to_vec(&rows).unwrap().len(), MAX_RESULT_BYTES);
        assert!(!append_prefix(&mut rows, record.clone(), MAX_RESULT_BYTES, false).unwrap());
        assert_eq!(rows.len(), 1);
        record
            .fields
            .insert("body".into(), "\\".repeat(MAX_RESULT_BYTES));
        let mut empty = Vec::new();
        assert!(append_prefix(&mut empty, record, MAX_RESULT_BYTES, false).is_err());
        assert!(empty.is_empty());
    }

    #[test]
    fn policy_is_scoped_and_empty_rules_deny() {
        let alice = Principal::User(crate::auth::User {
            id: "alice".into(),
            tenant: "one".into(),
            roles: vec![("admin".into(), "one".into())],
        });
        assert!(!allowed(
            &Policy { any: vec![] },
            &alice,
            crate::policy::Row {
                owner: "alice",
                tenant: "one",
                fields: &Default::default()
            }
        ));
        assert!(!allowed(
            &Policy { any: vec![vec![]] },
            &alice,
            crate::policy::Row {
                owner: "alice",
                tenant: "one",
                fields: &Default::default()
            }
        ));
        let owner = Policy {
            any: vec![vec![Predicate::Owner]],
        };
        assert!(allowed(
            &owner,
            &alice,
            crate::policy::Row {
                owner: "alice",
                tenant: "one",
                fields: &Default::default()
            }
        ));
        assert!(!allowed(
            &owner,
            &alice,
            crate::policy::Row {
                owner: "bob",
                tenant: "one",
                fields: &Default::default()
            }
        ));
        let role = Policy {
            any: vec![vec![Predicate::Role {
                name: "admin".into(),
                tenant_scoped: true,
            }]],
        };
        assert!(allowed(
            &role,
            &alice,
            crate::policy::Row {
                owner: "bob",
                tenant: "one",
                fields: &Default::default()
            }
        ));
        assert!(!allowed(
            &role,
            &alice,
            crate::policy::Row {
                owner: "bob",
                tenant: "two",
                fields: &Default::default()
            }
        ));
    }
}
