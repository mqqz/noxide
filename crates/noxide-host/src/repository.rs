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

pub(crate) fn allowed(policy: &Policy, principal: &Principal, owner: &str, tenant: &str) -> bool {
    policy.any.iter().any(|rule| {
        !rule.is_empty()
            && rule.iter().all(|p| match (principal, p) {
                (_, Predicate::Public) => true,
                (_, Predicate::Capability) => false,
                (Principal::Anonymous, _) => false,
                (Principal::User(user), Predicate::Owner) => user.id == owner,
                (Principal::User(user), Predicate::SameTenant) => {
                    !user.tenant.is_empty() && user.tenant == tenant
                }
                (
                    Principal::User(user),
                    Predicate::Role {
                        name,
                        tenant_scoped,
                    },
                ) => user.roles.iter().any(|(r, t)| {
                    r == name
                        && if *tenant_scoped {
                            !tenant.is_empty() && t == tenant && user.tenant == tenant
                        } else {
                            t.is_empty()
                        }
                }),
            })
    })
}

impl Effects {
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
                        && target == self.request.target.unwrap_or(0),
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
                manifest::validate_fields(resource, &self.request.input)?;
                if let Some(user) = user {
                    let used=self.tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM (SELECT id FROM nx_records WHERE resource=$1 AND owner=$2 LIMIT 10000) AS quota",&[Param::Number(storage_resource),user.id.as_str().into()]).await?;
                    ensure!(used[0][0].parse::<usize>()? < 10_000, "record quota");
                }
                let id = crate::security::record_id()?;
                let record = Record {
                    resource: op.resource,
                    id,
                    fields: self.request.input.clone(),
                };
                ensure!(self.grant.is_none(), "creation has no existing target");
                if public {
                    self.tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version) VALUES($1,$2,NULL,'',$3,$4,1,1)", &[storage_resource.into(), (id as i64).into(), serde_json::to_string(&record.fields)?.into(), crate::security::random_id()?.into()]).await?;
                } else {
                    let user = user.expect("private creation requires user");
                    self.tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision) VALUES($1,$2,$3,$4,$5,$6,1)",&[
                    Param::Number(storage_resource),Param::Number(id as i64),user.id.clone().into(),user.tenant.clone().into(),serde_json::to_string(&record.fields)?.into(), crate::security::random_id()?.into()
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
                        let fields = self.visible_fields(&op, serde_json::from_str(fields)?)?;
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
                let mut clauses = Vec::new();
                for rule in &op.policy.any {
                    let mut terms = Vec::new();
                    for predicate in rule {
                        let term = match (&self.principal, predicate) {
                            (_, Predicate::Public) => "1=1".into(),
                            (_, Predicate::Capability) => "1=0".into(),
                            (Principal::Anonymous, _) => "1=0".into(),
                            (Principal::User(user), Predicate::Owner) => {
                                params.push(user.id.clone().into());
                                format!("owner=${}", params.len())
                            }
                            (Principal::User(user), Predicate::SameTenant) => {
                                if user.tenant.is_empty() {
                                    "1=0".into()
                                } else {
                                    params.push(user.tenant.clone().into());
                                    format!("tenant=${}", params.len())
                                }
                            }
                            (
                                Principal::User(user),
                                Predicate::Role {
                                    name,
                                    tenant_scoped,
                                },
                            ) => {
                                if user.roles.iter().any(|(r, t)| {
                                    r == name
                                        && if *tenant_scoped {
                                            !t.is_empty() && *t == user.tenant
                                        } else {
                                            t.is_empty()
                                        }
                                }) {
                                    if *tenant_scoped {
                                        params.push(user.tenant.clone().into());
                                        format!("tenant=${}", params.len())
                                    } else {
                                        "1=1".into()
                                    }
                                } else {
                                    "1=0".into()
                                }
                            }
                        };
                        terms.push(term);
                    }
                    clauses.push(format!("({})", terms.join(" AND ")));
                }
                if manifest::is_public(&op) {
                    clauses = vec![
                        self.visibility_clause(&op, &mut params)?
                            .trim_start_matches(" AND ")
                            .to_owned(),
                    ];
                }
                params.push(Param::Number(self.cursor.unwrap_or(i64::MAX as u64) as i64));
                let sql = format!(
                    "SELECT CAST(id AS TEXT),COALESCE(owner,''),tenant,{} FROM nx_records WHERE resource=$1 AND ({}) AND id<${} ORDER BY nx_records.id DESC LIMIT 3",
                    self.tx.bounded_text("fields", 20_000),
                    clauses.join(" OR "),
                    params.len()
                );
                let rows = self.tx.fetch::<4>(&sql, &params).await?;
                let mut records = Vec::new();
                for [id, owner, tenant, fields] in rows {
                    ensure!(
                        allowed(&op.policy, &self.principal, &owner, &tenant),
                        "policy invariant"
                    );
                    let fields = self.visible_fields(&op, serde_json::from_str(&fields)?)?;
                    records.push(Record {
                        resource: op.resource,
                        id: id.parse()?,
                        fields,
                    });
                }
                if records.len() == 3 {
                    self.more = records.last().map(|r| r.id);
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
