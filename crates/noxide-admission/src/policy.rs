//! Principal binding is shared by row checks and parameterized query filtering.
use crate::{
    principal::Principal,
    query_plan::NativeProvider,
    sql::{Param, Sql, sql},
};
use noxide_protocol::{Policy, Predicate};

#[derive(Debug)]
pub enum ListStrategy {
    Single,
    Merge(Vec<ScanRule>),
}
#[derive(Debug)]
pub struct ScanRule {
    pub rule: usize,
    pub exact: bool,
}

pub fn residual_strategy(policy: &Policy) -> ListStrategy {
    ListStrategy::Merge(
        (0..policy.any.len())
            .map(|rule| ScanRule { rule, exact: false })
            .collect(),
    )
}
pub fn list_strategy(policy: &Policy, scoped: bool) -> ListStrategy {
    if !policy.any.iter().flatten().any(|p| {
        matches!(
            p,
            Predicate::PrincipalIs { .. } | Predicate::ExistsRelated(_)
        )
    }) {
        return ListStrategy::Single;
    }
    ListStrategy::Merge(
        policy
            .any
            .iter()
            .enumerate()
            .map(|(rule, atoms)| ScanRule {
                rule,
                exact: !scoped
                    && !atoms
                        .iter()
                        .any(|p| matches!(p, Predicate::ExistsRelated(_)))
                    && atoms
                        .iter()
                        .filter(|p| matches!(p, Predicate::Owner | Predicate::PrincipalIs { .. }))
                        .count()
                        <= 1,
            })
            .collect(),
    )
}
pub fn scan_policy(policy: &Policy, scan: &ScanRule) -> Policy {
    let atoms = &policy.any[scan.rule];
    let rule = if scan.exact {
        atoms.clone()
    } else if atoms
        .iter()
        .any(|atom| matches!(atom, Predicate::Service { .. }))
    {
        atoms
            .iter()
            .filter(|atom| matches!(atom, Predicate::Service { .. } | Predicate::SameTenant))
            .cloned()
            .collect()
    } else {
        atoms
            .iter()
            .find(|p| matches!(p, Predicate::Owner | Predicate::PrincipalIs { .. }))
            .cloned()
            .into_iter()
            .collect()
    };
    Policy {
        any: vec![if rule.is_empty() {
            vec![Predicate::Public]
        } else {
            rule
        }],
    }
}

enum Condition<'a> {
    Allow,
    Deny,
    Owner(&'a str),
    Tenant(&'a str),
    Account { field: &'a str, id: &'a str },
    Related(&'a noxide_protocol::membership::ExistsRelated),
}

fn bind<'a>(predicate: &'a Predicate, principal: &'a Principal) -> Condition<'a> {
    match (principal, predicate) {
        (Principal::Service(service), Predicate::Public | Predicate::SameTenant) => {
            Condition::Tenant(service.tenant())
        }
        (_, Predicate::Public) => Condition::Allow,
        (Principal::Service(service), Predicate::Service { worker }) => {
            if service.worker() == worker {
                Condition::Tenant(service.tenant())
            } else {
                Condition::Deny
            }
        }
        (_, Predicate::Service { .. }) | (Principal::Service(_), _) => Condition::Deny,
        (_, Predicate::Capability) | (Principal::Anonymous, _) => Condition::Deny,
        (Principal::User(user), Predicate::PrincipalIs { field }) => Condition::Account {
            field,
            id: &user.id,
        },
        (Principal::User(user), Predicate::Owner) => Condition::Owner(&user.id),
        (Principal::User(user), Predicate::SameTenant) => {
            if user.tenant.is_empty() {
                Condition::Deny
            } else {
                Condition::Tenant(&user.tenant)
            }
        }
        (Principal::User(_), Predicate::ExistsRelated(related)) => Condition::Related(related),
        (
            Principal::User(user),
            Predicate::Role {
                name,
                tenant_scoped,
            },
        ) => {
            let granted = user.roles.iter().any(|(r, t)| {
                r == name
                    && if *tenant_scoped {
                        !t.is_empty() && *t == user.tenant
                    } else {
                        t.is_empty()
                    }
            });
            if !granted {
                Condition::Deny
            } else if *tenant_scoped {
                Condition::Tenant(&user.tenant)
            } else {
                Condition::Allow
            }
        }
    }
}
pub struct Row<'a> {
    pub owner: &'a str,
    pub tenant: &'a str,
    pub fields: &'a noxide_protocol::Fields,
}
pub fn allowed(policy: &Policy, principal: &Principal, row: Row<'_>) -> bool {
    allowed_with(policy, principal, row, |_| false)
}

pub fn allowed_with(
    policy: &Policy,
    principal: &Principal,
    row: Row<'_>,
    mut related: impl FnMut(&noxide_protocol::membership::ExistsRelated) -> bool,
) -> bool {
    policy.any.iter().any(|rule| {
        !rule.is_empty()
            && rule.iter().all(|p| match bind(p, principal) {
                Condition::Account { field, id } => row.fields.get(field).is_some_and(|v| v == id),
                Condition::Related(predicate) => related(predicate),
                Condition::Allow => true,
                Condition::Deny => false,
                Condition::Owner(value) => row.owner == value,
                Condition::Tenant(value) => row.tenant == value,
            })
    })
}
pub fn sql(
    provider: NativeProvider,
    policy: &Policy,
    principal: &Principal,
    params: &mut Vec<Param>,
) -> Vec<Sql> {
    sql_with(provider, policy, principal, params, |_, _| {
        Ok(Sql::statement("1=0"))
    })
    .expect("infallible base policy")
}

pub fn sql_with(
    provider: NativeProvider,
    policy: &Policy,
    principal: &Principal,
    params: &mut Vec<Param>,
    mut related: impl FnMut(
        &noxide_protocol::membership::ExistsRelated,
        &mut Vec<Param>,
    ) -> anyhow::Result<Sql>,
) -> anyhow::Result<Vec<Sql>> {
    if policy.any.is_empty() {
        return Ok(vec![Sql::statement("1=0")]);
    }
    policy
        .any
        .iter()
        .map(|rule| {
            if rule.is_empty() {
                return Ok(Sql::statement("1=0"));
            }
            let terms: Vec<_> = rule
                .iter()
                .map(|p| {
                    Ok(match bind(p, principal) {
                        Condition::Related(predicate) => return related(predicate, params),
                        Condition::Account { field, id } => {
                            params.push(id.into());
                            sql!(
                                "{}=${}",
                                provider
                                    .field_expression(field)
                                    .expect("admitted account field"),
                                params.len()
                            )
                        }
                        Condition::Allow => Sql::statement("1=1"),
                        Condition::Deny => Sql::statement("1=0"),
                        condition => {
                            let (column, value) = match condition {
                                Condition::Owner(value) => ("owner", value),
                                Condition::Tenant(value) => ("tenant", value),
                                _ => unreachable!(),
                            };
                            params.push(value.into());
                            sql!("{column}=${}", params.len())
                        }
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(sql!("({})", Sql::join(&terms, " AND ")))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum IndexColumn {
    Owner,
    Tenant,
    Field(String),
    Timestamp(String),
}
pub fn index_prefix(policy: &Policy, scan: Option<&ScanRule>) -> Vec<IndexColumn> {
    let atoms = match scan {
        Some(scan) => &policy.any[scan.rule],
        None if policy.any.len() == 1 => &policy.any[0],
        None => return Vec::new(),
    };
    let identity = atoms.iter().find_map(|atom| match atom {
        Predicate::Owner => Some(IndexColumn::Owner),
        Predicate::PrincipalIs { field } => Some(IndexColumn::Field(field.clone())),
        _ => None,
    });
    let tenant = atoms.iter().any(|atom| {
        matches!(
            atom,
            Predicate::SameTenant
                | Predicate::Service { .. }
                | Predicate::Role {
                    tenant_scoped: true,
                    ..
                }
        )
    });
    let mut columns: Vec<_> = identity.into_iter().collect();
    let service = atoms
        .iter()
        .any(|atom| matches!(atom, Predicate::Service { .. }));
    if tenant
        && (service || scan.is_none_or(|scan| scan.exact))
        && (scan.is_some() || columns.is_empty())
    {
        columns.push(IndexColumn::Tenant);
    }
    columns
}
