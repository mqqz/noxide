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

impl Effects {
    async fn parent_visible(&mut self, child: u32, fields: &Fields) -> Result<bool> {
        let Some(parent) = manifest::parent_resource(&self.manifest, child)? else {
            return Ok(true);
        };
        let field =
            manifest::parent_field(manifest::resource(&self.manifest, child)?).expect("parent");
        let id = fields
            .get(&field.name)
            .ok_or_else(|| anyhow::anyhow!("missing parent"))?
            .parse()?;
        let record = load(&mut self.tx, &self.manifest, parent.id, id).await?;
        Ok(record.is_some_and(|r| manifest::parent_permits(field, &r.record.fields, false)))
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
                let public = manifest::is_public(&op);
                let user = if public {
                    None
                } else {
                    Some(self.principal.user()?)
                };
                if let Some(user) = user {
                    ensure!(
                        allowed(&op.policy, &self.principal, &user.id, &user.tenant),
                        "policy denied"
                    );
                }
                let resource = manifest::resource(&self.manifest, op.resource)?;
                manifest::validate_fields(resource, &input)?;
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
                        route: manifest::action(&self.manifest, action)?.redirect,
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
                        allowed(&op.policy, &self.principal, &stored.owner, &stored.tenant),
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
                            route: a.redirect,
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
                            let expression = self.tx.parent_expression(&field.name)?;
                            let rows = self.tx.fetch::<1>(&format!("SELECT CAST(id AS TEXT) FROM nx_records WHERE resource={child_storage} AND {expression}=$1 LIMIT 1"), &[grant.id.to_string().into()]).await?;
                            ensure!(rows.is_empty(), "parent has children");
                        }
                    }
                    ensure!(self.tx.execute("DELETE FROM nx_records WHERE resource=$1 AND id=$2 AND incarnation=$3 AND revision=$4", &params).await? == 1, "record changed");
                    ResponseIntent::Deleted {
                        resource: op.resource,
                        id: grant.id,
                        destination: RouteRef {
                            route: a.redirect,
                            target: None,
                        },
                    }
                };
                #[cfg(test)]
                crate::failure_tests::after_effect(&mut self.tx).await?;
                self.outcome = Some(outcome.clone());
                serde_json::to_vec(&outcome)?
            }
            OperationKind::Read => {
                ensure!(
                    target > 0 && target <= i64::MAX as u64,
                    "invalid resource target"
                );
                let mut params = vec![
                    Param::Number(storage_resource),
                    Param::Number(target as i64),
                ];
                let visibility = self.visibility_clause(&op, &mut params)?;
                let sql = format!(
                    "SELECT COALESCE(owner,''),tenant,{} FROM nx_records WHERE resource=$1 AND id=$2{visibility}",
                    self.tx.bounded_text("fields", 20_000)
                );
                let rows = self.tx.fetch::<3>(&sql, &params).await?;
                let record = match rows.first() {
                    Some([owner, tenant, fields])
                        if allowed(&op.policy, &self.principal, owner, tenant) =>
                    {
                        let fields: Fields = serde_json::from_str(fields)?;
                        if manifest::is_public(&op)
                            && !self.parent_visible(op.resource, &fields).await?
                        {
                            return Ok(serde_json::to_vec(&Option::<Record>::None)?);
                        }
                        let fields = self.visible_fields(&op, fields)?;
                        Some(Record {
                            resource: op.resource,
                            id: target,
                            fields,
                        })
                    }
                    _ => None,
                };
                serde_json::to_vec(&record)?
            }
            OperationKind::List => {
                let mut params = vec![Param::Number(storage_resource)];
                let mut clauses = crate::policy::sql(&op.policy, &self.principal, &mut params);
                if manifest::is_public(&op) {
                    clauses = vec![
                        self.visibility_clause(&op, &mut params)?
                            .trim_start_matches(" AND ")
                            .to_owned(),
                    ];
                }
                let mut parent_clause = String::new();
                if let Some(parent) = manifest::parent_resource(&self.manifest, op.resource)? {
                    let id = self
                        .request
                        .target
                        .ok_or_else(|| anyhow::anyhow!("missing parent target"))?;
                    let field =
                        manifest::parent_field(manifest::resource(&self.manifest, op.resource)?)
                            .expect("parent");
                    let record = load(&mut self.tx, &self.manifest, parent.id, id).await?;
                    if record.as_ref().is_none_or(|r| {
                        manifest::is_public(&op)
                            && !manifest::parent_permits(field, &r.record.fields, false)
                    }) {
                        return Ok(serde_json::to_vec(&Vec::<Record>::new())?);
                    }
                    params.push(id.to_string().into());
                    // A catalog-derived constant lets PostgreSQL's generic plans
                    // prove the partial-index predicate despite resource=$1.
                    parent_clause = format!(
                        " AND resource={storage_resource} AND {}=${}",
                        self.tx.parent_expression(&field.name)?,
                        params.len()
                    );
                }
                let size = op.list.as_ref().map_or(3, |s| s.page_size) as usize;
                params.push(Param::Number(self.cursor.unwrap_or(0) as i64));
                let mut records = Vec::new();
                let mut last = self.cursor.unwrap_or(0);
                self.more = None;
                // At most three bounded stored rows per database transfer. The
                // approved page size bounds both iterations and total row work.
                'page: while records.len() < size {
                    let batch = (size - records.len()).min(3);
                    *params.last_mut().expect("cursor") = Param::Number(last as i64);
                    let sql = format!(
                        "SELECT CAST(created_seq AS TEXT),CAST(id AS TEXT),COALESCE(owner,''),tenant,{} FROM nx_records WHERE resource=$1 AND ({}){parent_clause} AND created_seq>${} ORDER BY nx_records.created_seq ASC LIMIT {batch}",
                        self.tx.bounded_text("fields", 20_000),
                        clauses.join(" OR "),
                        params.len()
                    );
                    let rows = self.tx.fetch::<5>(&sql, &params).await?;
                    let count = rows.len();
                    for [seq, id, owner, tenant, fields] in rows {
                        ensure!(
                            allowed(&op.policy, &self.principal, &owner, &tenant),
                            "policy invariant"
                        );
                        let record = Record {
                            resource: op.resource,
                            id: id.parse()?,
                            fields: self.visible_fields(&op, serde_json::from_str(&fields)?)?,
                        };
                        if !append_prefix(&mut records, record)? {
                            self.more = Some(last);
                            break 'page;
                        }
                        last = seq.parse()?;
                    }
                    if count < batch {
                        break;
                    }
                }
                if self.more.is_none() && records.len() == size {
                    *params.last_mut().expect("cursor") = Param::Number(last as i64);
                    let next=self.tx.fetch::<1>(&format!("SELECT CAST(created_seq AS TEXT) FROM nx_records WHERE resource=$1 AND ({}){parent_clause} AND created_seq>${} ORDER BY nx_records.created_seq ASC LIMIT 1",clauses.join(" OR "),params.len()),&params).await?;
                    if !next.is_empty() {
                        self.more = Some(last);
                    }
                }
                serde_json::to_vec(&records)?
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
        assert!(!allowed(&Policy { any: vec![] }, &alice, "alice", "one"));
        assert!(!allowed(
            &Policy { any: vec![vec![]] },
            &alice,
            "alice",
            "one"
        ));
        let owner = Policy {
            any: vec![vec![Predicate::Owner]],
        };
        assert!(allowed(&owner, &alice, "alice", "one"));
        assert!(!allowed(&owner, &alice, "bob", "one"));
        let role = Policy {
            any: vec![vec![Predicate::Role {
                name: "admin".into(),
                tenant_scoped: true,
            }]],
        };
        assert!(allowed(&role, &alice, "bob", "one"));
        assert!(!allowed(&role, &alice, "bob", "two"));
    }
}
