use crate::{
    auth::Principal,
    database::{Param, Transaction},
    manifest,
    security::RecordTarget,
};
use anyhow::{Result, ensure};
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
    pub input: String,
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

pub(crate) const MAX_LIST_DATABASE_CALLS: usize = 4096;

pub(crate) struct Effects {
    pub provenance: std::collections::BTreeMap<(u32, u32, u64), u64>,
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
    pub grant: Option<RecordTarget>,
    pub capability_grant: Option<RecordTarget>,
    pub calls: u32,
    pub cursor: Option<u64>,
    pub more: Option<u64>,
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
pub(crate) async fn read_resource(
    tx: &mut Transaction,
    m: &Manifest,
    principal: &Principal,
    op: &Operation,
    target: u64,
) -> Result<Option<Record>> {
    let Some(stored) = load(tx, m, op.resource, target).await? else {
        return Ok(None);
    };
    if !read_allowed(m, principal, op, &stored)? {
        return Ok(None);
    }
    if manifest::is_public(op)
        && manifest::resource(m, op.resource)?.gate.is_some()
        && let Some(parent) = manifest::reference_resource(m, op.resource)?
    {
        let source_resource = manifest::resource(m, op.resource)?;
        let field = manifest::reference_field(source_resource).expect("reference");
        let id = stored
            .record
            .fields
            .get(&field.name)
            .ok_or_else(|| anyhow::anyhow!("missing parent"))?
            .parse()?;
        let parent = load(tx, m, parent.id, id).await?;
        if !parent.is_some_and(|p| manifest::gate_permits(source_resource, &p.record.fields, false))
        {
            return Ok(None);
        }
    }
    let mut record = stored.record;
    if manifest::is_public(op) {
        let projection = op
            .fields
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing read projection"))?;
        record.fields.retain(|name, _| projection.contains(name));
    }
    Ok(Some(record))
}
pub(crate) fn read_allowed(
    m: &Manifest,
    principal: &Principal,
    op: &Operation,
    stored: &StoredRecord,
) -> Result<bool> {
    ensure!(
        op.kind == OperationKind::Read && op.resource == stored.record.resource,
        "invalid read binding"
    );
    manifest::validate_fields(manifest::resource(m, op.resource)?, &stored.record.fields)?;
    if !allowed(
        &op.policy,
        principal,
        crate::policy::Row {
            owner: &stored.owner,
            tenant: &stored.tenant,
            fields: &stored.record.fields,
        },
    ) {
        return Ok(false);
    }
    if manifest::is_public(op) {
        let visible = op
            .visibility
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing visibility"))?;
        ensure!(op.fields.is_some(), "missing read projection");
        if stored.record.fields.get(&visible.field) != Some(&visible.equals) {
            return Ok(false);
        }
    }
    Ok(true)
}
pub(crate) async fn authorize_page_resource(
    tx: &mut Transaction,
    m: &Manifest,
    principal: &Principal,
    route: &Route,
    resource: u32,
    id: u64,
    incarnation: Option<&str>,
) -> Result<Option<StoredRecord>> {
    ensure!(route.resource == Some(resource), "route resource differs");
    let Some(stored) = load(tx, m, resource, id).await? else {
        return Ok(None);
    };
    if incarnation.is_some_and(|i| i != stored.incarnation) {
        return Ok(None);
    }
    let mut reads = 0;
    for operation in &route.operations {
        let op = manifest::operation(m, *operation)?;
        if op.kind == OperationKind::Read && op.via.is_none() && op.resource == resource {
            reads += 1;
            if !read_allowed(m, principal, op, &stored)? {
                return Ok(None);
            }
        }
    }
    ensure!(reads > 0, "missing resource read");
    if let Some(gate) = &manifest::resource(m, resource)?.gate
        && route.operations.iter().any(|id| {
            manifest::operation(m, *id).is_ok_and(|op| {
                op.kind == OperationKind::Read
                    && op.via.is_none()
                    && op.resource == resource
                    && manifest::is_public(op)
            })
        })
    {
        let target = manifest::reference_resource(m, resource)?.expect("gate target");
        let id = stored.record.fields[&gate.field].parse()?;
        let target = load(tx, m, target.id, id).await?;
        if target.is_none_or(|target| {
            !manifest::gate_permits(
                manifest::resource(m, resource).expect("admitted resource"),
                &target.record.fields,
                false,
            )
        }) {
            return Ok(None);
        }
    }
    Ok(Some(stored))
}

impl Effects {
    pub(crate) async fn execute_transaction(
        &mut self,
        action: crate::application::ActionCore<'_>,
    ) -> Result<Vec<MutationOutcome>> {
        ensure!(
            self.request.kind == RequestKind::Action(action.id),
            "transaction outside action"
        );
        manifest::validate_inputs(action.inputs, &self.request.input)?;
        let mut outcomes = Vec::with_capacity(action.steps.len());
        for step in action.steps {
            ensure!(self.calls > 0, "database call budget");
            self.calls -= 1;
            let op = manifest::operation(&self.manifest, step.operation)?.clone();
            let stored = match step.target {
                Target::None => None,
                Target::Signed => {
                    let grant = self.grant.as_ref().ok_or(ReferenceUnavailable)?;
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
            self.authorize_step(&op, stored.as_ref())?;
            let mut values = Fields::new();
            for assignment in &step.assign {
                let value = match &assignment.change {
                    Change::Set(value) => match value {
                        Value::Input(name) => self
                            .request
                            .input
                            .get(name)
                            .ok_or_else(|| anyhow::anyhow!("missing transaction input"))?
                            .clone(),
                        Value::Constant(value) => value.clone(),
                        Value::SignedTarget => self
                            .grant
                            .as_ref()
                            .ok_or(ReferenceUnavailable)?
                            .id
                            .to_string(),
                        Value::Created(index) => {
                            let created = outcomes
                                .get(usize::from(*index))
                                .ok_or_else(|| anyhow::anyhow!("missing created result"))?;
                            let created: &MutationOutcome = created;
                            ensure!(
                                created.kind == MutationKind::Created,
                                "result is not a create"
                            );
                            created.id.to_string()
                        }
                    },
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
                        let amount: i64 = self
                            .request
                            .input
                            .get(by)
                            .ok_or_else(|| anyhow::anyhow!("missing adjustment amount"))?
                            .parse()?;
                        ensure!(amount > 0, "invalid adjustment amount");
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
                OperationKind::Create => self.create_step(&op, step, values, &outcomes).await?,
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
            outcomes.push(outcome);
            #[cfg(test)]
            crate::failure_tests::after_effect(&mut self.tx).await?;
        }
        Ok(outcomes)
    }

    fn authorize_step(&self, op: &Operation, stored: Option<&StoredRecord>) -> Result<()> {
        if op.kind == OperationKind::Create {
            if manifest::is_public(op) {
                return Ok(());
            }
            let user = self.principal.user().map_err(|_| ReferenceUnavailable)?;
            ensure!(
                allowed(
                    &op.policy,
                    &self.principal,
                    crate::policy::Row {
                        owner: &user.id,
                        tenant: &user.tenant,
                        fields: &Fields::new(),
                    }
                ),
                ReferenceUnavailable
            );
        } else {
            let stored = stored.ok_or(ReferenceUnavailable)?;
            if manifest::is_capability(op) {
                let grant = self.grant.as_ref().ok_or(ReferenceUnavailable)?;
                ensure!(
                    self.capability_grant.as_ref() == Some(grant) && stored.cap_version.is_some(),
                    ReferenceUnavailable
                );
            } else {
                ensure!(
                    allowed(
                        &op.policy,
                        &self.principal,
                        crate::policy::Row {
                            owner: &stored.owner,
                            tenant: &stored.tenant,
                            fields: &stored.record.fields,
                        }
                    ),
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
    ) -> Result<MutationOutcome> {
        let m = self.manifest.clone();
        let resource = manifest::resource(&m, op.resource)?;
        if let Some(parent) = manifest::reference_resource(&m, op.resource)? {
            let reference = manifest::reference_field(resource).expect("admitted reference");
            let id: u64 = fields
                .get(&reference.name)
                .ok_or(ReferenceUnavailable)?
                .parse()?;
            let stored = load(&mut self.tx, &m, parent.id, id)
                .await?
                .ok_or(ReferenceUnavailable)?;
            let assignment = step
                .assign
                .iter()
                .find(|a| a.field == reference.name)
                .ok_or_else(|| anyhow::anyhow!("missing reference assignment"))?;
            let expected_incarnation = match &assignment.change {
                Change::Set(Value::SignedTarget) => {
                    let grant = self.grant.as_ref().ok_or(ReferenceUnavailable)?;
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
            let bind = op
                .bind
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing binding eligibility"))?;
            let eligible = manifest::operation(&m, bind.eligible)?;
            ensure!(
                read_resource(&mut self.tx, &m, &self.principal, eligible, id)
                    .await?
                    .is_some()
                    && manifest::gate_permits(resource, &stored.record.fields, true),
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
        manifest::validate_fields(resource, &fields)?;
        let public = manifest::is_public(op);
        let user = if public {
            None
        } else {
            Some(self.principal.user()?)
        };
        if resource
            .fields
            .iter()
            .any(|f| matches!(f.kind, FieldKind::Account { .. }))
        {
            let creator = self.principal.user()?;
            let rows = self
                .tx
                .fetch::<1>(
                    "SELECT tenant FROM nx_accounts WHERE id=$1 AND state='active' AND tenant<>''",
                    &[creator.id.as_str().into()],
                )
                .await?;
            let tenant = rows
                .first()
                .ok_or_else(|| anyhow::anyhow!("account binding unavailable"))?;
            ensure!(tenant[0] == creator.tenant, "account binding unavailable");
            for field in resource
                .fields
                .iter()
                .filter(|f| matches!(f.kind, FieldKind::Account { .. }))
            {
                let id = fields
                    .get(&field.name)
                    .ok_or_else(|| anyhow::anyhow!("account binding unavailable"))?;
                ensure!(!self.tx.fetch::<1>("SELECT id FROM nx_accounts WHERE id=$1 AND state='active' AND tenant=$2", &[id.as_str().into(), tenant[0].as_str().into()]).await?.is_empty(), "account binding unavailable");
            }
        }
        let storage_resource = self.tx.storage_resource(&m, op.resource).await?;
        if let Some(user) = user {
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
        let mut fields = stored.record.fields.clone();
        fields.extend(assignments);
        manifest::validate_fields(manifest::resource(&self.manifest, op.resource)?, &fields)?;
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
            if manifest::reference_resource(&self.manifest, child.id)?
                .is_some_and(|p| p.id == op.resource)
            {
                let field = manifest::reference_field(child).expect("admitted reference");
                let storage = self.tx.storage_resource(&self.manifest, child.id).await?;
                let expression = self.tx.field_expression(&field.name)?;
                let rows = self.tx.fetch::<1>(&format!("SELECT CAST(id AS TEXT) FROM nx_records WHERE resource={storage} AND {expression}=$1 LIMIT 1"), &[stored.record.id.to_string().into()]).await?;
                ensure!(rows.is_empty(), "parent has children");
            }
        }
        let storage_resource = self
            .tx
            .storage_resource(&self.manifest, op.resource)
            .await?;
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
        self.follow_sources.clear();
        self.list_bytes = 0;
        self.list_calls = MAX_LIST_DATABASE_CALLS;
        self.see_all.clear();
    }
    fn charge_list_calls(&mut self, count: usize) -> Result<()> {
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
        let cursor = if plan.preview { None } else { self.cursor };
        let mut params = vec![Param::Number(storage_resource)];
        let clauses = crate::policy::sql(&self.tx, &op.policy, &self.principal, &mut params);
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
        let mut last = cursor;
        self.more = None;
        // At most three bounded stored rows per database transfer. The
        // approved page size bounds both iterations and total row work.
        'page: while records.len() < size {
            let batch = (size - records.len()).min(3);
            let mut page_params = params.clone();
            let keyset = plan.keyset(last, &mut page_params);
            let sql = format!(
                "SELECT CAST(created_seq AS TEXT),CAST(id AS TEXT),COALESCE(owner,''),tenant,{} FROM nx_records WHERE resource=$1 AND resource={storage_resource} AND ({}){visibility}{parent_clause}{selection}{keyset} ORDER BY nx_records.created_seq {direction} LIMIT {batch}",
                self.tx.bounded_text("fields", 20_000),
                clauses.join(" OR ")
            );
            self.charge_list_calls(1)?;
            let rows = self.tx.fetch::<5>(&sql, &page_params).await?;
            let count = rows.len();
            for [seq, id, owner, tenant, fields] in rows {
                plan.check_selection(&serde_json::from_str(&fields)?, &self.request.params)?;
                ensure!(
                    allowed(
                        &op.policy,
                        &self.principal,
                        crate::policy::Row {
                            owner: &owner,
                            tenant: &tenant,
                            fields: &serde_json::from_str(&fields)?
                        }
                    ),
                    "policy invariant"
                );
                let record = Record {
                    resource: op.resource,
                    id: id.parse()?,
                    fields: self.visible_fields(op, serde_json::from_str(&fields)?)?,
                };
                if !append_prefix(&mut records, record, self.result_limit, plan.preview)? {
                    self.truncated = true;
                    self.more = last;
                    break 'page;
                }
                last = Some(seq.parse()?);
            }
            if count < batch {
                break;
            }
        }
        if self.more.is_none() && records.len() == size {
            let mut page_params = params.clone();
            let keyset = plan.keyset(last, &mut page_params);
            self.charge_list_calls(1)?;
            let next=self.tx.fetch::<1>(&format!("SELECT CAST(created_seq AS TEXT) FROM nx_records WHERE resource=$1 AND resource={storage_resource} AND ({}){visibility}{parent_clause}{selection}{keyset} ORDER BY nx_records.created_seq {direction} LIMIT 1",clauses.join(" OR ")),&page_params).await?;
            if !next.is_empty() {
                self.truncated = true;
                self.more = last;
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
        let cursor = if plan.preview { None } else { self.cursor };
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
            let keyset = plan.keyset(cursor, &mut scan_params);
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
        let mut last = cursor;
        self.more = None;
        let ordered: Box<dyn Iterator<Item = (u64, u64)> + Send> = if plan.descending() {
            Box::new(candidates.into_iter().rev())
        } else {
            Box::new(candidates.into_iter())
        };
        for (seq, id) in ordered {
            if if plan.descending() {
                seq < boundary
            } else {
                seq > boundary
            } {
                break;
            }
            self.charge_list_calls(2)?;
            let stored = load(&mut self.tx, &self.manifest, op.resource, id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("record disappeared"))?;
            if !allowed(
                &op.policy,
                &self.principal,
                crate::policy::Row {
                    owner: &stored.owner,
                    tenant: &stored.tenant,
                    fields: &stored.record.fields,
                },
            ) {
                last = Some(seq);
                continue;
            }
            if let Some(field) = &plan.scope
                && stored
                    .record
                    .fields
                    .get(field)
                    .and_then(|v| v.parse::<u64>().ok())
                    != self.request.target
            {
                last = Some(seq);
                continue;
            }
            plan.check_selection(&stored.record.fields, &self.request.params)?;
            let mut record = stored.record;
            record.fields = self.visible_fields(op, record.fields)?;
            if records.len() == size
                || !append_prefix(&mut records, record, self.result_limit, plan.preview)?
            {
                self.truncated = true;
                self.more = last;
                break;
            }
            last = Some(seq);
        }
        if self.more.is_none() && bounded_more {
            self.truncated = true;
            self.more = Some(boundary);
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
            let mut candidates = Vec::new();
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
                if read_allowed(&self.manifest, &self.principal, &op, &stored)? {
                    candidates.push(stored.record);
                }
            }
            if manifest::is_public(&op)
                && let Some(gate) = manifest::resource(&self.manifest, op.resource)?
                    .gate
                    .clone()
            {
                let target_resource = manifest::reference_resource(&self.manifest, op.resource)?
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
                        if manifest::gate_permits(
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
    pub(crate) async fn invoke(&mut self, operation: u32, target: u64) -> Result<Vec<u8>> {
        ensure!(self.calls > 0, "database call budget");
        self.calls -= 1;
        let op = manifest::operation(&self.manifest, operation)?.clone();
        ensure!(op.via.is_none(), "follow cannot be invoked by ID");
        match &self.request.kind {
            RequestKind::Route(id) => {
                let route = manifest::route(&self.manifest, *id)?;
                ensure!(
                    route.operations.contains(&operation)
                        && target
                            == if op.kind == OperationKind::List {
                                0
                            } else {
                                self.request.target.unwrap_or(0)
                            },
                    "operation outside request grant"
                );
                ensure!(
                    matches!(op.kind, OperationKind::List | OperationKind::Read),
                    "read route mutation"
                );
                ensure!(self.invoked.insert(operation), "operation already invoked");
            }
            RequestKind::Action(_) => anyhow::bail!("storage import during action"),
        }
        if op.kind == OperationKind::List {
            self.charge_list_calls(1)?;
        }
        let storage_resource = self
            .tx
            .storage_resource(&self.manifest, op.resource)
            .await?;
        let value = match op.kind {
            OperationKind::Create | OperationKind::Update | OperationKind::Delete => {
                anyhow::bail!("mutation outside declared transaction")
            }
            OperationKind::Read => serde_json::to_vec(
                &read_resource(&mut self.tx, &self.manifest, &self.principal, &op, target).await?,
            )?,
            OperationKind::List => {
                self.result_limit = self.list_result_limit(&op)?;
                self.truncated = false;
                let previous_more = self.more;
                let plan = self
                    .plans
                    .get(&op.id)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing list plan"))?;
                ensure!(plan.operation == op.id, "invalid list plan");
                let source_resource = manifest::resource(&self.manifest, op.resource)?.clone();
                if manifest::is_public(&op)
                    && source_resource.gate.is_some()
                    && let Some(parent) =
                        manifest::reference_resource(&self.manifest, op.resource)?.map(|p| p.id)
                {
                    self.charge_list_calls(2)?;
                    let id = self
                        .request
                        .target
                        .ok_or_else(|| anyhow::anyhow!("missing parent target"))?;
                    let field =
                        manifest::reference_field(manifest::resource(&self.manifest, op.resource)?)
                            .expect("parent");
                    ensure!(
                        plan.scope.as_deref() == Some(field.name.as_str()),
                        "invalid list parent"
                    );
                    let record = load(&mut self.tx, &self.manifest, parent, id).await?;
                    if record.as_ref().is_none_or(|r| {
                        manifest::is_public(&op)
                            && !manifest::gate_permits(&source_resource, &r.record.fields, false)
                    }) {
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
                let bytes = match &plan.strategy {
                    crate::policy::ListStrategy::Single => {
                        self.list_single(&op, storage_resource, &plan).await?
                    }
                    crate::policy::ListStrategy::Merge(scans) => {
                        self.list_merge(&op, storage_resource, &plan, scans).await?
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
            if let Some(field) =
                manifest::reference_field(manifest::resource(&self.manifest, op.resource)?)
            {
                for record in records {
                    // Projections may omit the reference; such operations cannot be follow sources.
                    if let Some(target) = record.fields.get(&field.name) {
                        self.provenance
                            .insert((op.id, op.resource, record.id), target.parse()?);
                        ensure!(self.provenance.len() <= 56, "follow provenance budget");
                    }
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
            input: "quantity".into(),
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
