use crate::{
    auth::Principal,
    database::{Param, Transaction},
    manifest,
    security::RecordTarget,
};
use anyhow::{Result, ensure};
use noxide_protocol::*;
use std::sync::Arc;

pub(crate) struct Effects {
    pub tx: Transaction,
    pub manifest: Arc<Manifest>,
    pub plans: std::collections::BTreeMap<u32, Arc<crate::query_plan::ListPlan>>,
    pub principal: Principal,
    pub request: RequestView,
    pub outcome: Option<ResponseIntent>,
    pub grant: Option<RecordTarget>,
    pub capability_grant: Option<RecordTarget>,
    pub record: Option<StoredRecord>,
    pub calls: u32,
    pub cursor: Option<u64>,
    pub more: Option<u64>,
}

// Measure the exact cross-boundary representation, including array framing.
fn append_prefix(records: &mut Vec<Record>, record: Record) -> Result<bool> {
    records.push(record);
    if serde_json::to_vec(records)?.len() <= MAX_RESULT_BYTES {
        return Ok(true);
    }
    records.pop();
    ensure!(
        !records.is_empty(),
        "record exceeds repository result budget"
    );
    Ok(false)
}

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
        && let Some(parent) = manifest::parent_resource(m, op.resource)?
    {
        let field = manifest::parent_field(manifest::resource(m, op.resource)?).expect("parent");
        let id = stored
            .record
            .fields
            .get(&field.name)
            .ok_or_else(|| anyhow::anyhow!("missing parent"))?
            .parse()?;
        let parent = load(tx, m, parent.id, id).await?;
        if !parent.is_some_and(|p| manifest::parent_permits(field, &p.record.fields, false)) {
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
fn read_allowed(
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
        if op.kind == OperationKind::Read && op.resource == resource {
            reads += 1;
            if !read_allowed(m, principal, op, &stored)? {
                return Ok(None);
            }
        }
    }
    ensure!(reads > 0, "missing resource read");
    // Parent resources have no parent themselves in the admitted one-level model.
    Ok(Some(stored))
}

impl Effects {
    async fn list_single(
        &mut self,
        op: &Operation,
        storage_resource: i64,
        plan: &crate::query_plan::ListPlan,
    ) -> Result<Vec<u8>> {
        let size = plan.limit as usize;
        let direction = plan.direction();
        let mut params = vec![Param::Number(storage_resource)];
        let mut clauses = crate::policy::sql(&self.tx, &op.policy, &self.principal, &mut params);
        if manifest::is_public(op) {
            clauses = vec![
                self.visibility_clause(op, &mut params)?
                    .trim_start_matches(" AND ")
                    .to_owned(),
            ];
        }
        let mut parent_clause = String::new();
        if manifest::parent_resource(&self.manifest, op.resource)?.is_some() {
            let id = self
                .request
                .target
                .ok_or_else(|| anyhow::anyhow!("missing parent target"))?;
            let field = manifest::parent_field(manifest::resource(&self.manifest, op.resource)?)
                .expect("parent");
            params.push(id.to_string().into());
            // A catalog-derived constant lets PostgreSQL's generic plans
            // prove the partial-index predicate despite resource=$1.
            parent_clause = format!(
                " AND resource={storage_resource} AND {}=${}",
                self.tx.field_expression(&field.name)?,
                params.len()
            );
        }
        let selection = plan.selection_sql(&self.tx, &mut params)?;
        let mut records = Vec::new();
        let mut last = self.cursor;
        self.more = None;
        // At most three bounded stored rows per database transfer. The
        // approved page size bounds both iterations and total row work.
        'page: while records.len() < size {
            let batch = (size - records.len()).min(3);
            let mut page_params = params.clone();
            let keyset = plan.keyset(last, &mut page_params);
            let sql = format!(
                "SELECT CAST(created_seq AS TEXT),CAST(id AS TEXT),COALESCE(owner,''),tenant,{} FROM nx_records WHERE resource=$1 AND ({}){parent_clause}{selection}{keyset} ORDER BY nx_records.created_seq {direction} LIMIT {batch}",
                self.tx.bounded_text("fields", 20_000),
                clauses.join(" OR ")
            );
            let rows = self.tx.fetch::<5>(&sql, &page_params).await?;
            let count = rows.len();
            for [seq, id, owner, tenant, fields] in rows {
                plan.check_selection(&serde_json::from_str(&fields)?)?;
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
                if !append_prefix(&mut records, record)? {
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
            let next=self.tx.fetch::<1>(&format!("SELECT CAST(created_seq AS TEXT) FROM nx_records WHERE resource=$1 AND ({}){parent_clause}{selection}{keyset} ORDER BY nx_records.created_seq {direction} LIMIT 1",clauses.join(" OR ")),&page_params).await?;
            if !next.is_empty() {
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
            let selection = plan.selection_sql(&self.tx, &mut scan_params)?;
            let mut parent_clause = String::new();
            if let Some(parent) = &plan.parent {
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
            let keyset = plan.keyset(self.cursor, &mut scan_params);
            let limit = if exact {
                size + 1
            } else {
                (256 / op.policy.any.len()).min(64)
            };
            let sql = format!(
                "SELECT CAST(created_seq AS TEXT),CAST(id AS TEXT) FROM nx_records WHERE resource=$1 AND resource={storage_resource} AND ({clause}){visibility}{parent_clause}{selection}{keyset} ORDER BY nx_records.created_seq {direction} LIMIT {limit}"
            );
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
        let mut last = self.cursor;
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
            if let Some(field) =
                manifest::parent_field(manifest::resource(&self.manifest, op.resource)?)
                && stored
                    .record
                    .fields
                    .get(&field.name)
                    .and_then(|v| v.parse::<u64>().ok())
                    != self.request.target
            {
                last = Some(seq);
                continue;
            }
            plan.check_selection(&stored.record.fields)?;
            let mut record = stored.record;
            record.fields = self.visible_fields(op, record.fields)?;
            if records.len() == size || !append_prefix(&mut records, record)? {
                self.more = last;
                break;
            }
            last = Some(seq);
        }
        if self.more.is_none() && bounded_more {
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
        let (expression, path) = self.tx.field_text(&visibility.field, params.len() + 1);
        params.push(path);
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

    pub(crate) async fn invoke(&mut self, operation: u32, target: u64) -> Result<Vec<u8>> {
        ensure!(self.calls > 0, "database call budget");
        self.calls -= 1;
        let op = manifest::operation(&self.manifest, operation)?.clone();
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
            }
            RequestKind::Action(id) => {
                let action = manifest::action(&self.manifest, *id)?;
                ensure!(
                    action.operation == operation
                        && matches!(
                            op.kind,
                            OperationKind::Create | OperationKind::Update | OperationKind::Delete
                        )
                        && target == 0
                        && self.outcome.is_none(),
                    "operation outside action grant"
                );
            }
        }
        let storage_resource = self
            .tx
            .storage_resource(&self.manifest, op.resource)
            .await?;
        let value = match op.kind {
            OperationKind::Create => {
                let mut input = self.request.input.clone();
                if let Some(parent) = manifest::parent_resource(&self.manifest, op.resource)? {
                    let field =
                        manifest::parent_field(manifest::resource(&self.manifest, op.resource)?)
                            .expect("parent field");
                    let grant = self
                        .grant
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing parent grant"))?;
                    ensure!(
                        grant.resource == parent.id && self.request.target == Some(grant.id),
                        "invalid parent grant"
                    );
                    let stored = load(&mut self.tx, &self.manifest, parent.id, grant.id)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("missing parent"))?;
                    ensure!(
                        stored.incarnation == grant.incarnation
                            && stored.revision == grant.revision
                            && manifest::parent_permits(field, &stored.record.fields, true),
                        "parent unavailable or locked"
                    );
                    ensure!(
                        input
                            .insert(field.name.clone(), grant.id.to_string())
                            .is_none(),
                        "parent cannot be submitted"
                    );
                } else {
                    ensure!(self.grant.is_none(), "creation has no existing target");
                }
                for field in &manifest::resource(&self.manifest, op.resource)?.fields {
                    if let Some(value) = &field.initial {
                        ensure!(
                            input.insert(field.name.clone(), value.clone()).is_none(),
                            "initial value cannot be submitted"
                        );
                    }
                }
                let public = manifest::is_public(&op);
                let user = if public {
                    None
                } else {
                    Some(self.principal.user()?)
                };
                if let Some(user) = user {
                    ensure!(
                        allowed(
                            &op.policy,
                            &self.principal,
                            crate::policy::Row {
                                owner: &user.id,
                                tenant: &user.tenant,
                                fields: &Default::default()
                            }
                        ),
                        "policy denied"
                    );
                }
                let resource = manifest::resource(&self.manifest, op.resource)?;
                manifest::validate_fields(resource, &input)?;
                if resource
                    .fields
                    .iter()
                    .any(|f| matches!(f.kind, FieldKind::Account { .. }))
                {
                    let creator = self.principal.user()?;
                    let rows = self.tx.fetch::<1>("SELECT tenant FROM nx_accounts WHERE id=$1 AND state='active' AND tenant<>''", &[creator.id.as_str().into()]).await?;
                    let tenant = rows
                        .first()
                        .ok_or_else(|| anyhow::anyhow!("account binding unavailable"))?;
                    ensure!(tenant[0] == creator.tenant, "account binding unavailable");
                    for field in resource
                        .fields
                        .iter()
                        .filter(|f| matches!(f.kind, FieldKind::Account { .. }))
                    {
                        let id = input
                            .get(&field.name)
                            .ok_or_else(|| anyhow::anyhow!("account binding unavailable"))?;
                        ensure!(!self.tx.fetch::<1>("SELECT id FROM nx_accounts WHERE id=$1 AND state='active' AND tenant=$2", &[id.as_str().into(), tenant[0].as_str().into()]).await?.is_empty(), "account binding unavailable");
                    }
                }

                if let Some(user) = user {
                    let used=self.tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM (SELECT id FROM nx_records WHERE resource=$1 AND owner=$2 LIMIT 10000) AS quota",&[Param::Number(storage_resource),user.id.as_str().into()]).await?;
                    ensure!(used[0][0].parse::<usize>()? < 10_000, "record quota");
                }
                let id = crate::security::record_id()?;
                let record = Record {
                    resource: op.resource,
                    id,
                    fields: input,
                };
                let created_seq = self.tx.allocate_creation().await?;
                if public {
                    self.tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES($1,$2,NULL,'',$3,$4,1,1,$5)", &[storage_resource.into(), (id as i64).into(), serde_json::to_string(&record.fields)?.into(), crate::security::random_id()?.into(),created_seq.into()]).await?;
                } else {
                    let user = user.expect("private creation requires user");
                    self.tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,$4,$5,$6,1,$7)",&[
                    Param::Number(storage_resource),Param::Number(id as i64),user.id.clone().into(),user.tenant.clone().into(),serde_json::to_string(&record.fields)?.into(), crate::security::random_id()?.into(),created_seq.into()
                ]).await?;
                }
                #[cfg(test)]
                crate::failure_tests::after_effect(&mut self.tx).await?;
                let RequestKind::Action(action) = self.request.kind else {
                    anyhow::bail!("missing action")
                };
                self.outcome = Some(ResponseIntent::Created {
                    resource: op.resource,
                    id,
                    destination: RouteRef {
                        route: manifest::action(&self.manifest, action)?.redirect.route(),
                        target: Some(id),
                    },
                });
                serde_json::to_vec(&record)?
            }
            OperationKind::Update | OperationKind::Delete => {
                if !manifest::is_capability(&op) {
                    self.principal.user()?;
                }
                let RequestKind::Action(action) = self.request.kind else {
                    anyhow::bail!("missing action")
                };
                let a = manifest::action(&self.manifest, action)?;
                let grant = self
                    .grant
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing target grant"))?;
                let stored = self
                    .record
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing target snapshot"))?;
                ensure!(
                    grant.resource == op.resource
                        && self.request.target == Some(grant.id)
                        && stored.record.resource == grant.resource
                        && stored.record.id == grant.id
                        && stored.incarnation == grant.incarnation
                        && stored.revision == grant.revision,
                    "target outside grant"
                );
                if manifest::is_capability(&op) {
                    ensure!(
                        self.capability_grant.as_ref() == Some(grant)
                            && stored.cap_version.is_some(),
                        "missing verified capability grant"
                    );
                } else {
                    ensure!(
                        allowed(
                            &op.policy,
                            &self.principal,
                            crate::policy::Row {
                                owner: &stored.owner,
                                tenant: &stored.tenant,
                                fields: &stored.record.fields
                            }
                        ),
                        "policy denied"
                    );
                }
                manifest::validate_input(&self.manifest, a, &self.request.input)?;
                let mut params = vec![
                    Param::Number(storage_resource),
                    Param::Number(grant.id as i64),
                    grant.incarnation.as_str().into(),
                    grant.revision.into(),
                ];
                let outcome = if op.kind == OperationKind::Update {
                    let next = grant
                        .revision
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("record revision exhausted"))?;
                    let mut fields = stored.record.fields.clone();
                    fields.extend(self.request.input.clone());
                    for field in manifest::resource(&self.manifest, op.resource)?
                        .fields
                        .iter()
                        .filter(|f| matches!(f.kind, FieldKind::Account { .. }))
                    {
                        fields.insert(
                            field.name.clone(),
                            stored.record.fields[&field.name].clone(),
                        );
                    }
                    manifest::validate_fields(
                        manifest::resource(&self.manifest, op.resource)?,
                        &fields,
                    )?;
                    params.push(serde_json::to_string(&fields)?.into());
                    params.push(next.into());
                    ensure!(self.tx.execute("UPDATE nx_records SET fields=$5,revision=$6 WHERE resource=$1 AND id=$2 AND incarnation=$3 AND revision=$4", &params).await? == 1, "record changed");
                    ResponseIntent::Updated {
                        resource: op.resource,
                        id: grant.id,
                        destination: RouteRef {
                            route: a.redirect.route(),
                            target: Some(grant.id),
                        },
                    }
                } else {
                    for child in &self.manifest.resources {
                        if manifest::parent_resource(&self.manifest, child.id)?
                            .is_some_and(|p| p.id == op.resource)
                        {
                            let field = manifest::parent_field(child).expect("parent");
                            let child_storage =
                                self.tx.storage_resource(&self.manifest, child.id).await?;
                            let expression = self.tx.field_expression(&field.name)?;
                            let rows = self.tx.fetch::<1>(&format!("SELECT CAST(id AS TEXT) FROM nx_records WHERE resource={child_storage} AND {expression}=$1 LIMIT 1"), &[grant.id.to_string().into()]).await?;
                            ensure!(rows.is_empty(), "parent has children");
                        }
                    }
                    ensure!(self.tx.execute("DELETE FROM nx_records WHERE resource=$1 AND id=$2 AND incarnation=$3 AND revision=$4", &params).await? == 1, "record changed");
                    ResponseIntent::Deleted {
                        resource: op.resource,
                        id: grant.id,
                        destination: RouteRef {
                            route: a.redirect.route(),
                            target: None,
                        },
                    }
                };
                #[cfg(test)]
                crate::failure_tests::after_effect(&mut self.tx).await?;
                self.outcome = Some(outcome.clone());
                serde_json::to_vec(&outcome)?
            }
            OperationKind::Read => serde_json::to_vec(
                &read_resource(&mut self.tx, &self.manifest, &self.principal, &op, target).await?,
            )?,
            OperationKind::List => {
                let plan = self
                    .plans
                    .get(&op.id)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing list plan"))?;
                ensure!(plan.operation == op.id, "invalid list plan");
                if let Some(parent) = manifest::parent_resource(&self.manifest, op.resource)? {
                    let id = self
                        .request
                        .target
                        .ok_or_else(|| anyhow::anyhow!("missing parent target"))?;
                    let field =
                        manifest::parent_field(manifest::resource(&self.manifest, op.resource)?)
                            .expect("parent");
                    ensure!(
                        plan.parent.as_deref() == Some(field.name.as_str()),
                        "invalid list parent"
                    );
                    let record = load(&mut self.tx, &self.manifest, parent.id, id).await?;
                    if record.as_ref().is_none_or(|r| {
                        manifest::is_public(&op)
                            && !manifest::parent_permits(field, &r.record.fields, false)
                    }) {
                        return Ok(serde_json::to_vec(&Vec::<Record>::new())?);
                    }
                }
                match &plan.strategy {
                    crate::policy::ListStrategy::Single => {
                        self.list_single(&op, storage_resource, &plan).await?
                    }
                    crate::policy::ListStrategy::Merge(scans) => {
                        self.list_merge(&op, storage_resource, &plan, scans).await?
                    }
                }
            }
        };
        ensure!(value.len() <= MAX_RESULT_BYTES, "repository output budget");
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(append_prefix(&mut rows, record.clone()).unwrap());
        assert_eq!(serde_json::to_vec(&rows).unwrap().len(), MAX_RESULT_BYTES);
        assert!(!append_prefix(&mut rows, record.clone()).unwrap());
        assert_eq!(rows.len(), 1);
        record
            .fields
            .insert("body".into(), "\\".repeat(MAX_RESULT_BYTES));
        let mut empty = Vec::new();
        assert!(append_prefix(&mut empty, record).is_err());
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
