use super::*;
use crate::{
    Database,
    auth::User,
    lifecycle_clock::{self, Freshness},
};
use noxide_protocol::{AccountScope, ChoiceVariant};
use std::{
    sync::atomic::AtomicI64,
    time::{Duration, Instant},
};

fn text(name: &str, kind: FieldKind) -> TextField {
    TextField {
        immutable: false,
        name: name.into(),
        label: name.into(),
        kind,
        optional: false,
        initial: None,
        max_bytes: 64,
    }
}

fn resources() -> Vec<Resource> {
    vec![
        Resource {
            search: None,
            expiry: None,
            unique: Vec::new(),
            id: 1,
            name: "workspace".into(),
            gate: None,
            fields: vec![text("title", FieldKind::Text)],
        },
        Resource {
            search: None,
            expiry: None,
            unique: Vec::new(),
            id: 2,
            name: "membership".into(),
            gate: None,
            fields: vec![
                text(
                    "workspace",
                    FieldKind::Reference {
                        resource: "workspace".into(),
                    },
                ),
                text(
                    "account",
                    FieldKind::Account {
                        scope: AccountScope::SameTenant,
                    },
                ),
                text(
                    "role",
                    FieldKind::Choice {
                        variants: ["admin", "member"]
                            .into_iter()
                            .map(|key| ChoiceVariant {
                                key: key.into(),
                                label: key.into(),
                            })
                            .collect(),
                    },
                ),
                text("active", FieldKind::Boolean),
                text(
                    "status",
                    FieldKind::Choice {
                        variants: ["current", "revoked", "expired"]
                            .into_iter()
                            .map(|key| ChoiceVariant {
                                key: key.into(),
                                label: key.into(),
                            })
                            .collect(),
                    },
                ),
            ],
        },
        Resource {
            search: None,
            expiry: None,
            unique: Vec::new(),
            id: 3,
            name: "document".into(),
            gate: None,
            fields: vec![text(
                "workspace",
                FieldKind::Reference {
                    resource: "workspace".into(),
                },
            )],
        },
    ]
}

fn declaration() -> ExistsRelated {
    ExistsRelated {
        resource: "membership".into(),
        reference: "workspace".into(),
        target: RelatedTarget::SelfRecord,
        account: "account".into(),
        conditions: BTreeMap::from([
            ("role".into(), MembershipLiteral::Choice("admin".into())),
            ("active".into(), MembershipLiteral::Boolean(true)),
            ("status".into(), MembershipLiteral::Choice("current".into())),
        ]),
    }
}

fn unique() -> MembershipUnique {
    MembershipUnique {
        reference: "workspace".into(),
        account: "account".into(),
    }
}

fn fields(reference: &str, account: &str, role: &str, active: &str, status: &str) -> Fields {
    Fields::from([
        ("workspace".into(), reference.into()),
        ("account".into(), account.into()),
        ("role".into(), role.into()),
        ("active".into(), active.into()),
        ("status".into(), status.into()),
    ])
}

#[test]
fn admission_rejects_forged_shapes_and_canonicalizes_conditions() {
    let resources = resources();
    let base = declaration();
    admit(&resources, &resources[0], std::slice::from_ref(&base)).unwrap();
    let mut second = base.clone();
    second
        .conditions
        .insert("role".into(), MembershipLiteral::Choice("member".into()));
    assert_eq!(
        admit(&resources, &resources[0], &[base.clone(), second])
            .unwrap()
            .len(),
        MAX_MEMBERSHIP_PREDICATES
    );
    let mut reference = base.clone();
    reference.target = RelatedTarget::Reference {
        field: "workspace".into(),
    };
    admit(&resources, &resources[2], &[reference]).unwrap();
    assert!(admit(&resources, &resources[0], &[base.clone(), base.clone()]).is_err());
    assert!(
        admit(
            &resources,
            &resources[0],
            &[base.clone(), base.clone(), base.clone()]
        )
        .is_err()
    );
    let mut too_many_conditions = base.clone();
    too_many_conditions.conditions.extend([
        ("extra_one".into(), MembershipLiteral::Boolean(true)),
        ("extra_two".into(), MembershipLiteral::Boolean(true)),
    ]);
    assert!(admit(&resources, &resources[0], &[too_many_conditions]).is_err());
    let mutations: [fn(&mut ExistsRelated); 9] = [
        |d| d.resource = "Unknown".into(),
        |d| d.reference = "role".into(),
        |d| d.reference = "workspace') OR 1=1--".into(),
        |d| d.account = "role".into(),
        |d| {
            d.target = RelatedTarget::Reference {
                field: "title".into(),
            }
        },
        |d| {
            d.conditions
                .insert("account".into(), MembershipLiteral::Choice("admin".into()));
        },
        |d| {
            d.conditions
                .insert("active".into(), MembershipLiteral::Choice("true".into()));
        },
        |d| {
            d.conditions
                .insert("role".into(), MembershipLiteral::Choice("Owner".into()));
        },
        |d| {
            d.conditions
                .insert("title".into(), MembershipLiteral::Boolean(true));
        },
    ];
    for mutation in mutations {
        let mut forged = base.clone();
        mutation(&mut forged);
        assert!(admit(&resources, &resources[0], &[forged]).is_err());
    }
    let mut bad = resources.clone();
    bad[1].fields[0].optional = true;
    assert!(admit(&bad, &bad[0], std::slice::from_ref(&base)).is_err());
    let mut bad = resources.clone();
    bad[1].fields[1].initial = Some("forged".into());
    assert!(admit(&bad, &bad[0], std::slice::from_ref(&base)).is_err());
    let mut reversed = base.clone();
    reversed.conditions = base
        .conditions
        .iter()
        .rev()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    assert_eq!(
        serde_json::to_vec(&base).unwrap(),
        serde_json::to_vec(&reversed).unwrap()
    );
    assert!(serde_json::from_str::<ExistsRelated>(r#"{"resource":"membership","reference":"workspace","target":"self_record","account":"account","conditions":{},"policy":[]}"#).is_err());
    assert!(serde_json::from_str::<ExistsRelated>(r#"{"resource":"membership","reference":"workspace","target":{"reference":{"field":"workspace","join":{}}},"account":"account","conditions":{}}"#).is_err());
}

#[test]
fn tuple_validation_rejects_alternate_reference_and_account_encodings() {
    let resources = resources();
    let account = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let good = fields("1", account, "admin", "true", "current");
    assert_eq!(
        canonical_tuple(&resources[1], &unique(), &good).unwrap(),
        ("1".into(), account.into())
    );
    for reference in ["01", "+1", " 1", "0", "-1", "9223372036854775808", "1\u{0}"] {
        assert!(
            canonical_tuple(
                &resources[1],
                &unique(),
                &fields(reference, account, "admin", "true", "current")
            )
            .is_err(),
            "{reference:?}"
        );
    }
    for account in ["", "alice", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"] {
        assert!(
            canonical_tuple(
                &resources[1],
                &unique(),
                &fields("1", account, "admin", "true", "current")
            )
            .is_err()
        );
    }
}

async fn transaction(db: &Database) -> Transaction {
    db.begin(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap()
}

async fn attempt(db: &Database) -> AttemptTime {
    let freshness = Freshness::default();
    let mut clock_tx = transaction(db).await;
    let committed = lifecycle_clock::tick(&mut clock_tx, &AtomicI64::new(0))
        .await
        .unwrap();
    freshness.committed(committed).unwrap();
    let mut tx = transaction(db).await;
    let attempt = freshness.attempt(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    attempt
}

async fn insert(tx: &mut Transaction, resource: i64, id: i64, tenant: &str, fields: &Fields) {
    let seq = tx.allocate_creation().await.unwrap();
    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,NULL,$3,$4,$5,1,$6)", &[resource.into(), id.into(), tenant.into(), serde_json::to_string(fields).unwrap().into(), format!("record-{id}").into(), seq.into()]).await.unwrap();
}

async fn contract(db: Database) {
    db.initialize().await.unwrap();
    let resources = resources();
    let plan = admit(&resources, &resources[0], &[declaration()])
        .unwrap()
        .remove(0);
    let alice = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let bob = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
    let principal = Principal::User(User {
        id: alice.into(),
        tenant: "team".into(),
        roles: vec![],
    });
    let deployment = Deployment {
        contract: "membership",
        incarnation: "key",
        generation: "one",
    };
    let mut tx = transaction(&db).await;
    tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'membership','key','one')", &[]).await.unwrap();
    for account in [alice, bob] {
        tx.execute(
            "INSERT INTO nx_accounts(id,tenant,state,epoch) VALUES($1,'team','active',1)",
            &[account.into()],
        )
        .await
        .unwrap();
    }
    let cases = [
        (1, "team", alice, "admin", "true", "current"),
        (2, "team", alice, "member", "true", "current"),
        (3, "team", alice, "admin", "false", "current"),
        (4, "team", alice, "admin", "true", "revoked"),
        (5, "team", alice, "admin", "true", "expired"),
        (6, "other", alice, "admin", "true", "current"),
        (7, "team", bob, "admin", "true", "current"),
        (8, "team", alice, "admin", "true", "current"),
    ];
    for (id, tenant, account, role, active, status) in cases {
        insert(
            &mut tx,
            10,
            id,
            tenant,
            &fields(&id.to_string(), account, role, active, status),
        )
        .await;
    }
    // Historical duplicate members cannot turn an EXISTS result into extra rows.
    insert(
        &mut tx,
        10,
        9,
        "team",
        &fields("1", alice, "admin", "true", "current"),
    )
    .await;
    tx.commit().await.unwrap();
    let time = attempt(&db).await;
    assert!(Witnesses::new(&Principal::Anonymous, time).is_err());
    assert!(
        Witnesses::new(
            &Principal::User(User {
                id: alice.into(),
                tenant: String::new(),
                roles: vec![]
            }),
            time
        )
        .is_err()
    );
    let empty = Fields::new();
    let rows: Vec<_> = (1..=9)
        .map(|id| ProtectedRow {
            id,
            tenant: "team",
            fields: &empty,
        })
        .collect();
    let mut witnesses = Witnesses::new(&principal, time).unwrap();
    let mut tx = transaction(&db).await;
    let mut calls = 1;
    let actual = witnesses
        .lookup(&mut tx, &deployment, &plan, 10, &rows, &mut calls)
        .await
        .unwrap();
    let expected: Vec<_> = (1..=9)
        .map(|id| {
            cases
                .iter()
                .any(|(reference, tenant, account, role, active, status)| {
                    *reference == id
                        && *tenant == "team"
                        && plan.matches(
                            &id.to_string(),
                            tenant,
                            &fields(&reference.to_string(), account, role, active, status),
                            alice,
                            true,
                        )
                })
        })
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(
        actual,
        vec![true, false, false, false, false, false, false, true, false]
    );
    assert_eq!(calls, 0, "one query covers the entire batch");
    assert_eq!(
        witnesses
            .lookup(&mut tx, &deployment, &plan, 10, &rows, &mut calls)
            .await
            .unwrap(),
        actual
    );
    let wrong_tenant = [ProtectedRow {
        id: 1,
        tenant: "other",
        fields: &empty,
    }];
    assert_eq!(
        witnesses
            .lookup(&mut tx, &deployment, &plan, 10, &wrong_tenant, &mut calls)
            .await
            .unwrap(),
        [false]
    );
    let mut by_ref = declaration();
    by_ref.target = RelatedTarget::Reference {
        field: "workspace".into(),
    };
    let by_ref = admit(&resources, &resources[2], &[by_ref])
        .unwrap()
        .remove(0);
    let linked = Fields::from([("workspace".into(), "1".into())]);
    let refs = [
        ProtectedRow {
            id: 200,
            tenant: "team",
            fields: &linked,
        },
        ProtectedRow {
            id: 201,
            tenant: "team",
            fields: &linked,
        },
    ];
    assert_eq!(
        witnesses
            .lookup(&mut tx, &deployment, &by_ref, 10, &refs, &mut 1)
            .await
            .unwrap(),
        [true, true]
    );
    tx.execute(
        "UPDATE nx_accounts SET state='disabled' WHERE id=$1",
        &[alice.into()],
    )
    .await
    .unwrap();
    witnesses.invalidate();
    assert_eq!(
        witnesses
            .lookup(&mut tx, &deployment, &plan, 10, &rows, &mut 1)
            .await
            .unwrap(),
        vec![false; 9]
    );
    tx.execute(
        "UPDATE nx_accounts SET state='active',tenant='other' WHERE id=$1",
        &[alice.into()],
    )
    .await
    .unwrap();
    witnesses.invalidate();
    assert_eq!(
        witnesses
            .lookup(&mut tx, &deployment, &plan, 10, &rows, &mut 1)
            .await
            .unwrap(),
        vec![false; 9]
    );
    tx.execute(
        "UPDATE nx_accounts SET tenant='team' WHERE id=$1",
        &[alice.into()],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE nx_records SET owner=$1 WHERE resource=10 AND id IN (1,9)",
        &[alice.into()],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE nx_records SET fields=$1 WHERE resource=10 AND id IN (1,9)",
        &[
            serde_json::to_string(&fields("1", alice, "member", "true", "current"))
                .unwrap()
                .into(),
        ],
    )
    .await
    .unwrap();
    witnesses.invalidate();
    assert_eq!(
        witnesses
            .lookup(&mut tx, &deployment, &plan, 10, &rows[..1], &mut 1)
            .await
            .unwrap(),
        [false],
        "membership-row owner grants nothing"
    );
    let wrong_deployment = Deployment {
        generation: "retired",
        ..deployment
    };
    // A positive witness from another deployment/storage scope cannot be reused.
    witnesses
        .lookup(&mut tx, &deployment, &plan, 10, &rows, &mut 1)
        .await
        .unwrap();
    assert_eq!(
        witnesses
            .lookup(&mut tx, &wrong_deployment, &plan, 10, &rows, &mut 1)
            .await
            .unwrap(),
        vec![false; 9]
    );
    assert_eq!(
        witnesses
            .lookup(&mut tx, &deployment, &plan, 11, &rows, &mut 1)
            .await
            .unwrap(),
        vec![false; 9]
    );
    witnesses.invalidate();
    let full: Vec<_> = (1..=128)
        .map(|id| ProtectedRow {
            id,
            tenant: "team",
            fields: &empty,
        })
        .collect();
    let mut bounded_calls = 2;
    for batch in full.chunks(MAX_BATCH) {
        assert_eq!(
            witnesses
                .lookup(&mut tx, &deployment, &plan, 10, batch, &mut bounded_calls)
                .await
                .unwrap()
                .len(),
            MAX_BATCH
        );
    }
    assert_eq!(witnesses.values.len(), MAX_WITNESSES);
    assert_eq!(bounded_calls, 0);
    assert!(
        witnesses
            .lookup(
                &mut tx,
                &deployment,
                &plan,
                10,
                &[ProtectedRow {
                    id: 129,
                    tenant: "team",
                    fields: &empty
                }],
                &mut 1
            )
            .await
            .is_err()
    );
    witnesses.invalidate();
    assert!(
        witnesses
            .lookup(&mut tx, &deployment, &plan, 10, &rows, &mut 0)
            .await
            .is_err()
    );
    let over: Vec<_> = (1..=65)
        .map(|id| ProtectedRow {
            id,
            tenant: "team",
            fields: &empty,
        })
        .collect();
    assert!(
        witnesses
            .lookup(&mut tx, &deployment, &plan, 10, &over, &mut 1)
            .await
            .is_err()
    );
    assert!(
        witnesses
            .lookup(
                &mut tx,
                &deployment,
                &plan,
                10,
                &[ProtectedRow {
                    id: 0,
                    tenant: "team",
                    fields: &empty
                }],
                &mut 1
            )
            .await
            .is_err()
    );
    tx.commit().await.unwrap();

    // The provider rejects historical duplicates when the index is introduced.
    let mut tx = transaction(&db).await;
    let ddl = unique_index_sql(&tx, &resources[1], 10, &unique()).unwrap();
    assert!(tx.execute(&ddl, &[]).await.is_err());
    tx.rollback().await.unwrap();
    let mut tx = transaction(&db).await;
    tx.execute("DELETE FROM nx_records WHERE resource=10 AND id=9", &[])
        .await
        .unwrap();
    tx.execute(&ddl, &[]).await.unwrap();
    tx.commit().await.unwrap();
    for (tenant, role, status) in [
        ("team", "admin", "current"),
        ("team", "member", "revoked"),
        ("other", "admin", "expired"),
    ] {
        let mut tx = transaction(&db).await;
        let seq = tx.allocate_creation().await.unwrap();
        let value = fields("1", alice, role, "true", status);
        canonical_tuple(&resources[1], &unique(), &value).unwrap();
        assert!(tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES(10,100,NULL,$1,$2,'duplicate',1,$3)", &[tenant.into(), serde_json::to_string(&value).unwrap().into(), seq.into()]).await.is_err());
        tx.rollback().await.unwrap();
    }
    // A distinct account or reference remains possible under the same index.
    let mut tx = transaction(&db).await;
    insert(
        &mut tx,
        10,
        100,
        "team",
        &fields("1", bob, "member", "true", "current"),
    )
    .await;
    insert(
        &mut tx,
        10,
        101,
        "team",
        &fields("20", alice, "admin", "true", "current"),
    )
    .await;
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn sqlite_membership_provider_truth_table() {
    let tmp = tempfile::tempdir().unwrap();
    contract(Database::sqlite(tmp.path().join("membership.db"))).await;
}

#[tokio::test]
async fn postgres_membership_provider_truth_table() {
    // Explicitly selected provider evidence must fail if its real provider is
    // unavailable; an absent URL is never silently counted as a pass.
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES")
        .expect("real provider test requires NOXIDE_TEST_POSTGRES");
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_p07_membership_{}", std::process::id());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let database_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    let result = tokio::spawn(contract(Database::postgres(&database_url).unwrap())).await;
    sqlx::query(&format!("DROP DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    result.unwrap();
}
