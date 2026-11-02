//! Row decisions and generated SQL agree against a real provider.
use crate::auth::User;
use crate::policy::*;
use crate::{auth::Principal, sql::Param};
use noxide_protocol::{Policy, Predicate};
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
                        .filter(|p| matches!(p, Predicate::Owner | Predicate::PrincipalIs { .. }))
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
                    let filter =
                        filter(tx.query_provider().unwrap(), policy, principal, &mut params);
                    let statement = format!(
                        "SELECT ({}) FROM (SELECT $1 AS owner, $2 AS tenant, '{{\"recipient\":\"bob\"}}' AS fields)",
                        filter.sql()
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
