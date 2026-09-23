use crate::{
    auth::Principal,
    database::{Param, Transaction},
    manifest,
};
use anyhow::{Result, ensure};
use noxide_protocol::*;
use std::sync::Arc;

pub(crate) struct Effects {
    pub tx: Transaction,
    pub manifest: Arc<Manifest>,
    pub principal: Principal,
    pub request: RequestView,
    pub created: Option<Record>,
    pub calls: u32,
    pub cursor: Option<u64>,
    pub more: Option<u64>,
}

pub(crate) fn allowed(policy: &Policy, principal: &Principal, owner: &str, tenant: &str) -> bool {
    policy.any.iter().any(|rule| {
        !rule.is_empty()
            && rule.iter().all(|p| match p {
                Predicate::Owner => principal.id == owner,
                Predicate::SameTenant => !principal.tenant.is_empty() && principal.tenant == tenant,
                Predicate::Role {
                    name,
                    tenant_scoped,
                } => principal.roles.iter().any(|(r, t)| {
                    r == name
                        && if *tenant_scoped {
                            !tenant.is_empty() && t == tenant && principal.tenant == tenant
                        } else {
                            t.is_empty()
                        }
                }),
            })
    })
}

impl Effects {
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
                ensure!(op.kind != OperationKind::Create, "read route mutation");
            }
            RequestKind::Action(id) => {
                let action = manifest::action(&self.manifest, *id)?;
                ensure!(
                    action.operation == operation
                        && op.kind == OperationKind::Create
                        && target == 0
                        && self.created.is_none(),
                    "operation outside action grant"
                );
            }
        }
        let value = match op.kind {
            OperationKind::Create => {
                ensure!(
                    allowed(
                        &op.policy,
                        &self.principal,
                        &self.principal.id,
                        &self.principal.tenant
                    ),
                    "policy denied"
                );
                let resource = manifest::resource(&self.manifest, op.resource)?;
                manifest::validate_fields(resource, &self.request.input)?;
                let used=self.tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM (SELECT id FROM nx_records WHERE resource=$1 AND owner=$2 LIMIT 10000) AS quota",&[Param::Number(op.resource.into()),self.principal.id.as_str().into()]).await?;
                ensure!(used[0][0].parse::<usize>()? < 10_000, "record quota");
                let id = crate::security::record_id()?;
                let record = Record {
                    resource: op.resource,
                    id,
                    fields: self.request.input.clone(),
                };
                self.tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields) VALUES($1,$2,$3,$4,$5)",&[
                    Param::Number(op.resource.into()),Param::Number(id as i64),self.principal.id.clone().into(),self.principal.tenant.clone().into(),serde_json::to_string(&record.fields)?.into()
                ]).await?;
                #[cfg(test)]
                crate::failure_tests::after_effect(&mut self.tx).await?;
                self.created = Some(record.clone());
                serde_json::to_vec(&record)?
            }
            OperationKind::Read => {
                ensure!(
                    target > 0 && target <= i64::MAX as u64,
                    "invalid resource target"
                );
                let sql = format!(
                    "SELECT owner,tenant,{} FROM nx_records WHERE resource=$1 AND id=$2",
                    self.tx.bounded_text("fields", 20_000)
                );
                let rows = self
                    .tx
                    .fetch::<3>(
                        &sql,
                        &[
                            Param::Number(op.resource.into()),
                            Param::Number(target as i64),
                        ],
                    )
                    .await?;
                let record = match rows.first() {
                    Some([owner, tenant, fields])
                        if allowed(&op.policy, &self.principal, owner, tenant) =>
                    {
                        let fields = serde_json::from_str(fields)?;
                        manifest::validate_fields(
                            manifest::resource(&self.manifest, op.resource)?,
                            &fields,
                        )?;
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
                let mut params = vec![Param::Number(op.resource.into())];
                let mut clauses = Vec::new();
                for rule in &op.policy.any {
                    let mut terms = Vec::new();
                    for predicate in rule {
                        let term = match predicate {
                            Predicate::Owner => {
                                params.push(self.principal.id.clone().into());
                                format!("owner=${}", params.len())
                            }
                            Predicate::SameTenant => {
                                if self.principal.tenant.is_empty() {
                                    "1=0".into()
                                } else {
                                    params.push(self.principal.tenant.clone().into());
                                    format!("tenant=${}", params.len())
                                }
                            }
                            Predicate::Role {
                                name,
                                tenant_scoped,
                            } => {
                                if self.principal.roles.iter().any(|(r, t)| {
                                    r == name
                                        && if *tenant_scoped {
                                            !t.is_empty() && *t == self.principal.tenant
                                        } else {
                                            t.is_empty()
                                        }
                                }) {
                                    if *tenant_scoped {
                                        params.push(self.principal.tenant.clone().into());
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
                params.push(Param::Number(self.cursor.unwrap_or(i64::MAX as u64) as i64));
                let sql = format!(
                    "SELECT CAST(id AS TEXT),owner,tenant,{} FROM nx_records WHERE resource=$1 AND ({}) AND id<${} ORDER BY id DESC LIMIT 3",
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
                    let fields = serde_json::from_str(&fields)?;
                    manifest::validate_fields(
                        manifest::resource(&self.manifest, op.resource)?,
                        &fields,
                    )?;
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
        let alice = Principal {
            id: "alice".into(),
            tenant: "one".into(),
            roles: vec![("admin".into(), "one".into())],
        };
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
