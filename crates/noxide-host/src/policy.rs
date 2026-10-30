//! Principal binding is shared by row checks and parameterized query filtering.
use crate::{
    auth::Principal,
    database::{Param, Transaction},
};
use noxide_protocol::{Policy, Predicate};

#[derive(Debug)]
pub(crate) enum ListStrategy {
    Single,
    Merge(Vec<ScanRule>),
}
#[derive(Debug)]
pub(crate) struct ScanRule {
    pub rule: usize,
    pub exact: bool,
}
pub(crate) fn list_strategy(policy: &Policy, scoped: bool) -> ListStrategy {
    if !policy
        .any
        .iter()
        .flatten()
        .any(|p| matches!(p, Predicate::PrincipalIs { .. }))
    {
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
                    && atoms
                        .iter()
                        .filter(|p| matches!(p, Predicate::Owner | Predicate::PrincipalIs { .. }))
                        .count()
                        <= 1,
            })
            .collect(),
    )
}
pub(crate) fn scan_policy(policy: &Policy, scan: &ScanRule) -> Policy {
    let atoms = &policy.any[scan.rule];
    let rule = if scan.exact {
        atoms.clone()
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
}

fn bind<'a>(predicate: &'a Predicate, principal: &'a Principal) -> Condition<'a> {
    match (principal, predicate) {
        (_, Predicate::Public) => Condition::Allow,
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
pub(crate) struct Row<'a> {
    pub owner: &'a str,
    pub tenant: &'a str,
    pub fields: &'a noxide_protocol::Fields,
}
pub(crate) fn allowed(policy: &Policy, principal: &Principal, row: Row<'_>) -> bool {
    policy.any.iter().any(|rule| {
        !rule.is_empty()
            && rule.iter().all(|p| match bind(p, principal) {
                Condition::Account { field, id } => row.fields.get(field).is_some_and(|v| v == id),
                Condition::Allow => true,
                Condition::Deny => false,
                Condition::Owner(value) => row.owner == value,
                Condition::Tenant(value) => row.tenant == value,
            })
    })
}
pub(crate) fn sql(
    tx: &Transaction,
    policy: &Policy,
    principal: &Principal,
    params: &mut Vec<Param>,
) -> Vec<String> {
    if policy.any.is_empty() {
        return vec!["1=0".into()];
    }
    policy
        .any
        .iter()
        .map(|rule| {
            if rule.is_empty() {
                return "1=0".into();
            }
            let terms: Vec<_> = rule
                .iter()
                .map(|p| match bind(p, principal) {
                    Condition::Account { field, id } => {
                        params.push(id.into());
                        format!(
                            "{}=${}",
                            tx.field_expression(field).expect("admitted account field"),
                            params.len()
                        )
                    }
                    Condition::Allow => "1=1".into(),
                    Condition::Deny => "1=0".into(),
                    condition => {
                        let (column, value) = match condition {
                            Condition::Owner(value) => ("owner", value),
                            Condition::Tenant(value) => ("tenant", value),
                            _ => unreachable!(),
                        };
                        params.push(value.into());
                        format!("{column}=${}", params.len())
                    }
                })
                .collect();
            format!("({})", terms.join(" AND "))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::User;
    use sqlx::{Connection, Row};

    #[test]
    fn list_strategies_preserve_existing_scan_shapes() {
        let recipient = Predicate::PrincipalIs {
            field: "recipient".into(),
        };
        let role = Predicate::Role {
            name: "moderator".into(),
            tenant_scoped: true,
        };
        for atom in [
            Predicate::Public,
            Predicate::Owner,
            Predicate::SameTenant,
            role.clone(),
        ] {
            assert!(matches!(
                list_strategy(
                    &Policy {
                        any: vec![vec![atom.clone()], vec![Predicate::Owner]]
                    },
                    false
                ),
                ListStrategy::Single
            ));
        }
        for atoms in [
            vec![recipient.clone()],
            vec![recipient.clone(), Predicate::SameTenant],
            vec![role],
            vec![Predicate::Owner],
            vec![Predicate::Owner, recipient.clone()],
            vec![recipient.clone(), recipient.clone()],
        ] {
            let policy = Policy {
                any: vec![vec![recipient.clone()], atoms.clone()],
            };
            for scoped in [false, true] {
                let ListStrategy::Merge(scans) = list_strategy(&policy, scoped) else {
                    panic!("expected merge")
                };
                assert_eq!(scans.len(), 2);
                for scan in &scans {
                    let expected = !scoped
                        && policy.any[scan.rule]
                            .iter()
                            .filter(|p| {
                                matches!(p, Predicate::Owner | Predicate::PrincipalIs { .. })
                            })
                            .count()
                            <= 1;
                    assert_eq!(scan.exact, expected);
                    let compiled = scan_policy(&policy, scan);
                    if expected {
                        assert_eq!(compiled.any[0], policy.any[scan.rule]);
                    } else {
                        assert_eq!(compiled.any[0].len(), 1);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn sql_and_row_decisions_agree_for_all_predicates_and_empty_rules() {
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let host = crate::Database::sqlite(tmp.path().join("policy.db"));
        let tx = host
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(30))
            .await
            .unwrap();
        let principals = [
            Principal::Anonymous,
            Principal::User(User {
                id: "alice".into(),
                tenant: "one".into(),
                roles: vec![("editor".into(), "one".into()), ("admin".into(), "".into())],
            }),
            Principal::User(User {
                id: "bob".into(),
                tenant: "".into(),
                roles: vec![],
            }),
        ];
        let predicates = [
            Predicate::Public,
            Predicate::Capability,
            Predicate::Owner,
            Predicate::SameTenant,
            Predicate::PrincipalIs {
                field: "recipient".into(),
            },
            Predicate::Role {
                name: "editor".into(),
                tenant_scoped: true,
            },
            Predicate::Role {
                name: "admin".into(),
                tenant_scoped: false,
            },
            Predicate::Role {
                name: "missing".into(),
                tenant_scoped: false,
            },
        ];
        let mut policies = vec![Policy { any: vec![] }, Policy { any: vec![vec![]] }];
        for left in &predicates {
            for right in &predicates {
                policies.push(Policy {
                    any: vec![vec![left.clone(), right.clone()]],
                });
                policies.push(Policy {
                    any: vec![vec![left.clone()], vec![right.clone()]],
                });
            }
        }
        for principal in &principals {
            for policy in &policies {
                for owner in ["alice", "bob", ""] {
                    for tenant in ["one", "two", ""] {
                        let mut params = vec![Param::from(owner), Param::from(tenant)];
                        let clauses = sql(&tx, policy, principal, &mut params);
                        let statement = format!(
                            "SELECT ({}) FROM (SELECT $1 AS owner, $2 AS tenant, '{{\"recipient\":\"bob\"}}' AS fields)",
                            clauses.join(" OR ")
                        );
                        let mut query = sqlx::query(&statement);
                        for param in params {
                            query = match param {
                                Param::Text(value) => query.bind(value),
                                Param::Number(value) => query.bind(value),
                            };
                        }
                        let row = query.fetch_one(&mut db).await.unwrap();
                        let actual: i64 = row.get(0);
                        assert_eq!(
                            actual != 0,
                            allowed(
                                policy,
                                principal,
                                crate::policy::Row {
                                    owner,
                                    tenant,
                                    fields: &noxide_protocol::Fields::from([(
                                        "recipient".into(),
                                        "bob".into()
                                    )])
                                }
                            )
                        );
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub(crate) enum IndexColumn {
    Owner,
    Tenant,
    Field(String),
}
pub(crate) fn index_prefix(policy: &Policy, scan: Option<&ScanRule>) -> Vec<IndexColumn> {
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
                | Predicate::Role {
                    tenant_scoped: true,
                    ..
                }
        )
    });
    let mut columns: Vec<_> = identity.into_iter().collect();
    if tenant && scan.is_none_or(|scan| scan.exact) && (scan.is_some() || columns.is_empty()) {
        columns.push(IndexColumn::Tenant);
    }
    columns
}
