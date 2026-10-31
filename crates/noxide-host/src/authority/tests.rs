use super::*;
use crate::{
    Database,
    auth::User,
    lifecycle_clock::{self, Freshness},
};
use noxide_protocol::{
    AccountScope, ChoiceVariant, FieldKind, OperationKind, Policy, Predicate, Resource, TextField,
    expiry::ResourceExpiry,
    membership::{ExistsRelated, MembershipLiteral, RelatedTarget},
    time::Duration,
};
use std::{
    sync::atomic::AtomicI64,
    time::{Duration as StdDuration, Instant},
};

const ALICE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BOB: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";

fn field(name: &str, kind: FieldKind) -> TextField {
    TextField {
        immutable: false,
        kind,
        name: name.into(),
        label: name.into(),
        optional: false,
        initial: None,
        max_bytes: 64,
    }
}
fn choice(name: &str, values: &[&str]) -> TextField {
    field(
        name,
        FieldKind::Choice {
            variants: values
                .iter()
                .map(|key| ChoiceVariant {
                    key: (*key).into(),
                    label: (*key).into(),
                })
                .collect(),
        },
    )
}
fn resource(id: u32, name: &str, fields: Vec<TextField>) -> Resource {
    Resource {
        search: None,
        id,
        name: name.into(),
        fields,
        gate: None,
        unique: Vec::new(),
        expiry: Some(ResourceExpiry {
            field: "expires".into(),
            max_after: Duration::from_secs(3600).unwrap(),
        }),
    }
}
fn related(target: RelatedTarget) -> Predicate {
    Predicate::ExistsRelated(ExistsRelated {
        resource: "memberships".into(),
        reference: "workspace".into(),
        target,
        account: "account".into(),
        conditions: BTreeMap::from([
            ("role".into(), MembershipLiteral::Choice("admin".into())),
            ("active".into(), MembershipLiteral::Boolean(true)),
            ("status".into(), MembershipLiteral::Choice("current".into())),
        ]),
    })
}
fn operation(id: u32, resource: u32, kind: OperationKind, predicate: Predicate) -> Operation {
    Operation {
        maintenance: false,
        query: None,
        id,
        resource,
        kind,
        policy: Policy {
            any: vec![vec![predicate]],
        },
        bind: Default::default(),
        scope: None,
        via: None,
        filter: Vec::new(),
        disclose: Vec::new(),
        list: None,
        visibility: None,
        fields: None,
    }
}
fn manifest() -> Manifest {
    let mut create_membership = operation(
        5,
        2,
        OperationKind::Create,
        Predicate::PrincipalIs {
            field: "account".into(),
        },
    );
    create_membership.bind.insert("workspace".into(), 6);
    Manifest {
        effects: None,
        jobs: None,
        blobs: None,
        version: noxide_protocol::VERSION,
        assets: Vec::new(),
        resources: vec![
            resource(
                1,
                "workspaces",
                vec![
                    field("title", FieldKind::Text),
                    field("expires", FieldKind::Timestamp),
                ],
            ),
            resource(
                2,
                "memberships",
                vec![
                    field(
                        "workspace",
                        FieldKind::Reference {
                            resource: "workspaces".into(),
                        },
                    ),
                    field(
                        "account",
                        FieldKind::Account {
                            scope: AccountScope::SameTenant,
                        },
                    ),
                    choice("role", &["admin", "member"]),
                    field("active", FieldKind::Boolean),
                    choice("status", &["current", "revoked"]),
                    field("expires", FieldKind::Timestamp),
                ],
            ),
            resource(
                3,
                "documents",
                vec![
                    field(
                        "workspace",
                        FieldKind::Reference {
                            resource: "workspaces".into(),
                        },
                    ),
                    field("body", FieldKind::Text),
                    field("expires", FieldKind::Timestamp),
                ],
            ),
        ],
        operations: vec![
            operation(
                1,
                1,
                OperationKind::Read,
                related(RelatedTarget::SelfRecord),
            ),
            operation(
                2,
                3,
                OperationKind::Read,
                related(RelatedTarget::Reference {
                    field: "workspace".into(),
                }),
            ),
            operation(
                3,
                2,
                OperationKind::Update,
                related(RelatedTarget::Reference {
                    field: "workspace".into(),
                }),
            ),
            operation(4, 1, OperationKind::Create, Predicate::Owner),
            create_membership,
            operation(6, 1, OperationKind::Read, Predicate::Owner),
        ],
        routes: vec![noxide_protocol::Route {
            id: 1,
            access: noxide_protocol::Access::Authenticated,
            path: "/".into(),
            resource: None,
            params: Vec::new(),
            operations: Vec::new(),
            forms: Vec::new(),
        }],
        actions: Vec::new(),
        web_bindings: Vec::new(),
    }
}
fn workspace(expires: i64) -> Fields {
    Fields::from([
        ("title".into(), "workspace".into()),
        ("expires".into(), expires.to_string()),
    ])
}
fn member(
    workspace: u64,
    account: &str,
    role: &str,
    active: bool,
    status: &str,
    expires: i64,
) -> Fields {
    Fields::from([
        ("workspace".into(), workspace.to_string()),
        ("account".into(), account.into()),
        ("role".into(), role.into()),
        ("active".into(), active.to_string()),
        ("status".into(), status.into()),
        ("expires".into(), expires.to_string()),
    ])
}
fn user() -> Principal {
    Principal::User(User {
        id: ALICE.into(),
        tenant: "team".into(),
        roles: Vec::new(),
    })
}
fn scope() -> DeploymentScope {
    DeploymentScope {
        contract: "authority".into(),
        incarnation: "key".into(),
        generation: "active".into(),
    }
}
async fn transaction(database: &Database) -> Transaction {
    database
        .begin(Instant::now() + StdDuration::from_secs(30))
        .await
        .unwrap()
}
async fn attempt(database: &Database) -> AttemptTime {
    let freshness = Freshness::default();
    let mut tx = transaction(database).await;
    let tick = lifecycle_clock::tick(&mut tx, &AtomicI64::new(0))
        .await
        .unwrap();
    freshness.committed(tick).unwrap();
    let mut tx = transaction(database).await;
    let time = freshness.attempt(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    time
}
async fn insert(
    tx: &mut Transaction,
    storage: i64,
    id: i64,
    owner: &str,
    tenant: &str,
    fields: &Fields,
) {
    let seq = tx.allocate_creation().await.unwrap();
    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,$4,$5,$6,1,$7)", &[storage.into(), id.into(), owner.into(), tenant.into(), serde_json::to_string(fields).unwrap().into(), format!("row-{storage}-{id}").into(), seq.into()]).await.unwrap();
}

#[test]
fn forged_authority_and_horizon_declarations_fail_independent_admission() {
    let m = manifest();
    crate::manifest::validate(&m).unwrap();
    let mut bad = m.clone();
    bad.resources[0].expiry.as_mut().unwrap().max_after =
        Duration::from_millis(noxide_protocol::expiry::MAX_EXPIRY_MILLIS + 1).unwrap();
    assert!(crate::manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.resources[0].fields[1].optional = true;
    assert!(crate::manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.resources[0].expiry.as_mut().unwrap().field = "title".into();
    assert!(crate::manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.resources[1]
        .unique
        .push(noxide_protocol::membership::MembershipUnique {
            reference: "role".into(),
            account: "account".into(),
        });
    assert!(crate::manifest::validate(&bad).is_err());
    let mut reordered = m.clone();
    reordered.resources[1].unique = vec![noxide_protocol::membership::MembershipUnique {
        reference: "workspace".into(),
        account: "account".into(),
    }];
    assert_ne!(
        crate::manifest::digest(&m).unwrap(),
        crate::manifest::digest(&reordered).unwrap()
    );
    assert!(crate::query_plan::required_indexes(&m).unwrap().iter().any(|index| index.resource == "memberships" && matches!(index.columns.last(), Some(policy::IndexColumn::Timestamp(field)) if field == "expires")));
    assert!(
        m.operations
            .iter()
            .all(|op| op.resource != 2
                || !matches!(op.kind, OperationKind::Read | OperationKind::List)),
        "fixture grants no membership read/list authority"
    );
}

async fn provider(database: Database) {
    database.initialize().await.unwrap();
    let m = manifest();
    database.reconcile_query_indexes(&m).await.unwrap();
    let time = attempt(&database).await;
    let now = time.timestamp().unix_millis();
    let future = now + 10_000;
    let mut tx = transaction(&database).await;
    tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'authority','key','active')", &[]).await.unwrap();
    for id in [ALICE, BOB] {
        tx.execute(
            "INSERT INTO nx_accounts(id,tenant,state,epoch) VALUES($1,'team','active',1)",
            &[id.into()],
        )
        .await
        .unwrap();
    }
    let workspaces = tx.storage_resource(&m, 1).await.unwrap();
    let memberships = tx.storage_resource(&m, 2).await.unwrap();
    for id in 1..=11 {
        insert(
            &mut tx,
            workspaces,
            id,
            BOB,
            "team",
            &workspace(if id == 10 { now } else { future }),
        )
        .await;
    }
    let cases = [
        (1, ALICE, "admin", true, "current", future, "team"),
        (2, ALICE, "member", true, "current", future, "team"),
        (3, ALICE, "admin", false, "current", future, "team"),
        (4, ALICE, "admin", true, "revoked", future, "team"),
        (5, ALICE, "admin", true, "current", now, "team"),
        (6, ALICE, "admin", true, "current", future, "other"),
        (7, BOB, "admin", true, "current", future, "team"),
        (8, ALICE, "admin", true, "current", future, "team"),
        (9, ALICE, "admin", true, "current", future, "team"),
        (10, ALICE, "admin", true, "current", future, "team"),
        (11, ALICE, "member", true, "current", future, "team"),
    ];
    for (id, account, role, active, status, expires, tenant) in cases {
        insert(
            &mut tx,
            memberships,
            id,
            ALICE,
            tenant,
            &member(id as u64, account, role, active, status, expires),
        )
        .await;
    }
    insert(
        &mut tx,
        memberships,
        109,
        ALICE,
        "team",
        &member(9, ALICE, "admin", true, "current", future),
    )
    .await;
    tx.commit().await.unwrap();

    let fields: Vec<_> = (1..=11)
        .map(|id| workspace(if id == 10 { now } else { future }))
        .collect();
    let rows: Vec<_> = fields
        .iter()
        .enumerate()
        .map(|(i, fields)| Row {
            id: i as u64 + 1,
            owner: BOB,
            tenant: "team",
            fields,
        })
        .collect();
    let expected = vec![
        true, false, false, false, false, false, false, true, true, false, false,
    ];
    let mut tx = database
        .begin_read(Instant::now() + StdDuration::from_secs(30))
        .await
        .unwrap();
    let before = tx.fetch::<2>("SELECT CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock WHERE singleton=1", &[]).await.unwrap();
    let mut authority = Authority::new(Some(time), scope());
    let mut read_calls = 2;
    let direct = authority
        .authorize(
            &mut tx,
            &m,
            &user(),
            &m.operations[0],
            &rows,
            &mut read_calls,
        )
        .await
        .unwrap();
    assert_eq!(direct, expected);
    assert_eq!(read_calls, 0, "one catalog query and one witness batch");
    for _ in 0..3 {
        assert_eq!(
            authority
                .authorize(
                    &mut tx,
                    &m,
                    &user(),
                    &m.operations[0],
                    &rows,
                    &mut read_calls
                )
                .await
                .unwrap(),
            expected,
            "read/projection/inspection/preflight reuse unchanged facts"
        );
    }
    let mut next_attempt = Authority::new(Some(time), scope());
    assert!(
        next_attempt
            .authorize(&mut tx, &m, &user(), &m.operations[0], &rows, &mut 0)
            .await
            .is_err(),
        "new attempt cannot reuse a prior context's witnesses"
    );
    let mut params = vec![workspaces.into()];
    let sql = authority
        .sql(&mut tx, &m, &user(), &m.operations[0], &mut params, &mut 16)
        .await
        .unwrap();
    let actual = tx
        .fetch::<1>(
            &format!(
                "SELECT CAST(id AS TEXT) FROM nx_records WHERE resource=$1 AND ({}) ORDER BY id",
                sql.join(" OR ")
            ),
            &params,
        )
        .await
        .unwrap();
    assert_eq!(
        actual,
        vec![["1".to_owned()], ["8".to_owned()], ["9".to_owned()]]
    );
    assert_eq!(
        authority
            .authorize(
                &mut tx,
                &m,
                &Principal::Anonymous,
                &m.operations[0],
                &rows,
                &mut 16
            )
            .await
            .unwrap(),
        vec![false; 11],
        "anonymous picker cannot inherit authenticated membership"
    );
    let mut after_swap_calls = 1;
    assert_eq!(
        authority
            .authorize(
                &mut tx,
                &m,
                &user(),
                &m.operations[0],
                &rows,
                &mut after_swap_calls
            )
            .await
            .unwrap(),
        expected
    );
    assert_eq!(
        after_swap_calls, 0,
        "principal restoration requires a fresh witness query"
    );
    let after = tx.fetch::<2>("SELECT CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock WHERE singleton=1", &[]).await.unwrap();
    assert_eq!(
        before, after,
        "read-only authority never ticks or renews lifecycle state"
    );
    tx.commit().await.unwrap();

    let mut tx = transaction(&database).await;
    let mut authority = Authority::new(Some(time), scope());
    tx.execute(
        "UPDATE nx_accounts SET state='disabled' WHERE id=$1",
        &[ALICE.into()],
    )
    .await
    .unwrap();
    authority.invalidate();
    assert_eq!(
        authority
            .authorize(&mut tx, &m, &user(), &m.operations[0], &rows, &mut 16)
            .await
            .unwrap(),
        vec![false; 11]
    );
    tx.execute(
        "UPDATE nx_accounts SET state='active',tenant='other' WHERE id=$1",
        &[ALICE.into()],
    )
    .await
    .unwrap();
    authority.invalidate();
    assert_eq!(
        authority
            .authorize(&mut tx, &m, &user(), &m.operations[0], &rows, &mut 16)
            .await
            .unwrap(),
        vec![false; 11]
    );
    tx.execute(
        "UPDATE nx_accounts SET tenant='team' WHERE id=$1",
        &[ALICE.into()],
    )
    .await
    .unwrap();
    authority.invalidate();
    let owned_member = member(11, ALICE, "member", true, "current", future);
    assert_eq!(
        authority
            .authorize(
                &mut tx,
                &m,
                &user(),
                &m.operations[2],
                &[Row {
                    id: 11,
                    owner: ALICE,
                    tenant: "team",
                    fields: &owned_member
                }],
                &mut 16
            )
            .await
            .unwrap(),
        [false],
        "actual principal-owned membership cannot authorize admin management"
    );
    tx.execute(
        "UPDATE nx_records SET fields=$1 WHERE resource=$2 AND id=1",
        &[
            serde_json::to_string(&member(1, ALICE, "member", true, "current", future))
                .unwrap()
                .into(),
            memberships.into(),
        ],
    )
    .await
    .unwrap();
    authority.invalidate();
    assert_eq!(
        authority
            .authorize(&mut tx, &m, &user(), &m.operations[0], &rows[..1], &mut 16)
            .await
            .unwrap(),
        [false]
    );
    tx.rollback().await.unwrap();

    // Canonical candidate policy sees resolved Principal/reference/literal values.
    // Full Created(0)/receipt/executor proof is supplied after runtime integration.
    let mut tx = transaction(&database).await;
    let mut authority = Authority::new(Some(time), scope());
    let proposed = workspace(future);
    assert_eq!(
        authority
            .authorize(
                &mut tx,
                &m,
                &user(),
                &m.operations[3],
                &[Row {
                    id: 0,
                    owner: ALICE,
                    tenant: "team",
                    fields: &proposed
                }],
                &mut 16
            )
            .await
            .unwrap(),
        [true]
    );
    insert(&mut tx, workspaces, 200, ALICE, "team", &proposed).await;
    let candidate = member(200, ALICE, "admin", true, "current", future);
    assert_eq!(
        authority
            .authorize(
                &mut tx,
                &m,
                &user(),
                &m.operations[4],
                &[Row {
                    id: 0,
                    owner: ALICE,
                    tenant: "team",
                    fields: &candidate
                }],
                &mut 16
            )
            .await
            .unwrap(),
        [true]
    );
    insert(&mut tx, memberships, 200, ALICE, "team", &candidate).await;
    authority.invalidate();
    assert_eq!(
        authority
            .authorize(
                &mut tx,
                &m,
                &user(),
                &m.operations[0],
                &[Row {
                    id: 200,
                    owner: ALICE,
                    tenant: "team",
                    fields: &proposed
                }],
                &mut 16
            )
            .await
            .unwrap(),
        [true]
    );
    let immediate = workspace(now);
    assert_eq!(
        authority
            .authorize(
                &mut tx,
                &m,
                &user(),
                &m.operations[3],
                &[Row {
                    id: 0,
                    owner: ALICE,
                    tenant: "team",
                    fields: &immediate
                }],
                &mut 16
            )
            .await
            .unwrap(),
        [true]
    );
    assert_eq!(
        authority
            .authorize(
                &mut tx,
                &m,
                &user(),
                &m.operations[5],
                &[Row {
                    id: 201,
                    owner: ALICE,
                    tenant: "team",
                    fields: &immediate
                }],
                &mut 16
            )
            .await
            .unwrap(),
        [false]
    );
    let forged = workspace(now + 3_600_001);
    assert!(
        authority
            .authorize(
                &mut tx,
                &m,
                &user(),
                &m.operations[3],
                &[Row {
                    id: 0,
                    owner: ALICE,
                    tenant: "team",
                    fields: &forged
                }],
                &mut 16
            )
            .await
            .is_err()
    );
    let mut lowered = m.resources[0].clone();
    lowered.expiry.as_mut().unwrap().max_after = Duration::from_secs(1).unwrap();
    expiry::check_write(&lowered, Some(&proposed), &proposed, Some(time)).unwrap();
    assert!(expiry::check_write(&lowered, Some(&proposed), &forged, Some(time)).is_err());
    let mut unavailable = Authority::new(None, scope());
    assert!(
        unavailable
            .authorize(&mut tx, &m, &user(), &m.operations[0], &rows, &mut 16)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn sqlite_authority_sql_rows_expiry_and_mutations() {
    let tmp = tempfile::tempdir().unwrap();
    provider(Database::sqlite(tmp.path().join("authority.db"))).await;
}

#[tokio::test]
async fn postgres_authority_sql_rows_expiry_and_mutations() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES")
        .expect("real PostgreSQL authority test requires NOXIDE_TEST_POSTGRES");
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_p07_authority_{}", std::process::id());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let fixture = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    let result = tokio::spawn(provider(Database::postgres(&fixture).unwrap())).await;
    sqlx::query(&format!("DROP DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    result.unwrap();
}

mod read_paths;
#[cfg(feature = "query-metrics")]
mod work;
