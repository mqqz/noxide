//! Principal binding is shared by row checks and parameterized query filtering.
use crate::{auth::Principal, database::Param};
use noxide_protocol::{Policy, Predicate};

enum Condition<'a> {
    Allow,
    Deny,
    Owner(&'a str),
    Tenant(&'a str),
}

fn bind<'a>(predicate: &Predicate, principal: &'a Principal) -> Condition<'a> {
    match (principal, predicate) {
        (_, Predicate::Public) => Condition::Allow,
        (_, Predicate::Capability) | (Principal::Anonymous, _) => Condition::Deny,
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
pub(crate) fn allowed(policy: &Policy, principal: &Principal, owner: &str, tenant: &str) -> bool {
    policy.any.iter().any(|rule| {
        !rule.is_empty()
            && rule.iter().all(|p| match bind(p, principal) {
                Condition::Allow => true,
                Condition::Deny => false,
                Condition::Owner(value) => owner == value,
                Condition::Tenant(value) => tenant == value,
            })
    })
}
pub(crate) fn sql(policy: &Policy, principal: &Principal, params: &mut Vec<Param>) -> Vec<String> {
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

    #[tokio::test]
    async fn sql_and_row_decisions_agree_for_all_predicates_and_empty_rules() {
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
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
                        let clauses = sql(policy, principal, &mut params);
                        let statement = format!(
                            "SELECT ({}) FROM (SELECT $1 AS owner, $2 AS tenant)",
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
                        assert_eq!(actual != 0, allowed(policy, principal, owner, tenant));
                    }
                }
            }
        }
    }
}
