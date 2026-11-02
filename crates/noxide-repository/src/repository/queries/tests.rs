use super::*;
use crate::{
    Database,
    auth::User,
    authority::{Authority, DeploymentScope},
    database::lifecycle::{AdmissionOwner, Registry},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
const ALICE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BOB: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
fn manifest() -> Manifest {
    let mut m = crate::test_support::manifest();
    m.actions.clear();
    m.web_bindings.clear();
    m.routes[0].forms.clear();
    m.resources[0].search = Some(query::SearchIndex {
        tokenizer: crate::search::TOKENIZER_ID.into(),
        fields: vec!["body".into()],
        max_bytes: 4096,
    });
    m.resources[0].fields.push(TextField {
        immutable: true,
        name: "rank".into(),
        label: "Rank".into(),
        kind: FieldKind::Integer {
            min: None,
            max: None,
        },
        optional: false,
        initial: None,
        max_bytes: 20,
    });
    m.operations[0].list = Some(ListSettings {
        order: ListOrder::CreatedAsc,
        page_size: 2,
        preview: None,
    });
    m.operations[0].query = Some(query::Query {
        search: Some(query::Search {
            fields: vec!["body".into()],
            parameter: "terms".into(),
        }),
        ..Default::default()
    });
    let mut aggregate = m.operations[0].clone();
    aggregate.id = 4;
    aggregate.kind = OperationKind::Aggregate;
    aggregate.list = None;
    aggregate.query = Some(query::Query {
        aggregate: Some(query::Aggregate {
            source: 1,
            function: AggregateFunction::Count,
        }),
        ..Default::default()
    });
    m.operations.push(aggregate);
    m.routes[0].operations = vec![1, 4];
    m.routes[0].path = "/search".into();
    m.routes[0].params = vec!["terms".into()];
    m.routes.push(Route {
        id: 3,
        path: "/".into(),
        params: vec![],
        resource: None,
        operations: vec![],
        forms: vec![],
        access: Access::Authenticated,
    });
    m
}
fn effects(tx: Transaction, m: &Manifest) -> Effects {
    Effects {
        authority: Authority::new(
            None,
            DeploymentScope {
                contract: "query-tests".into(),
                incarnation: "deployment".into(),
                generation: "active".into(),
            },
        ),
        upload: None,
        blob_reads: Default::default(),
        provenance: Default::default(),
        follow_sources: vec![],
        invoked: Default::default(),
        list_bytes: 0,
        list_calls: MAX_LIST_DATABASE_CALLS,
        result_limit: MAX_RESULT_BYTES,
        truncated: false,
        see_all: vec![],
        tx,
        manifest: Arc::new(m.clone()),
        plans: crate::query_plan::compile_all(m).unwrap(),
        principal: Principal::User(User {
            id: ALICE.into(),
            tenant: "team".into(),
            roles: vec![],
        }),
        request: RequestView {
            version: VERSION,
            kind: RequestKind::Route(1),
            target: None,
            input: Fields::new(),
            inspection: Default::default(),
            available_forms: vec![],
            params: if m.routes[0].params.iter().any(|name| name == "terms") {
                Fields::from([("terms".into(), "rust العربية".into())])
            } else {
                Fields::new()
            },
        },
        grants: Default::default(),
        target_rows: Default::default(),
        written_rows: Default::default(),
        capability_grant: None,
        calls: 16,
        cursor: None,
        more: None,
    }
}
fn scope() -> RequestScope {
    RequestScope::new(
        Arc::new(Registry::default()),
        tokio::time::Instant::now() + Duration::from_secs(10),
        Duration::from_secs(10),
        256,
    )
}
async fn owner() -> AdmissionOwner {
    let request = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();
    let database = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();
    AdmissionOwner::new(scope(), request.into(), database.into(), None)
}
async fn begin(db: &Database) -> Transaction {
    db.begin(Instant::now() + Duration::from_secs(10))
        .await
        .unwrap()
}
async fn insert(
    tx: &mut Transaction,
    storage: i64,
    id: i64,
    owner: &str,
    body: &str,
    rank: i64,
    workspace: bool,
) {
    let mut fields = Fields::from([
        ("body".into(), body.into()),
        ("rank".into(), rank.to_string()),
    ]);
    if workspace {
        fields.insert("workspace".into(), "42".into());
    }
    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,'team',$4,'row',1,$2)",&[storage.into(),id.into(),owner.into(),serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
    let checkpoint = tx.operator_checkpoint().unwrap();
    let indexed =
        crate::search::indexed_record(&[Some(body)], 4096, &mut || checkpoint.checkpoint())
            .unwrap();
    let prepared =
        crate::search::PreparedPostings::new(&indexed, || checkpoint.checkpoint()).unwrap();
    crate::database::schema::replace_postings(tx, storage, id, "row", 1, id, &prepared)
        .await
        .unwrap();
}
async fn fixture(db: &Database, m: &Manifest) -> i64 {
    manifest::validate(m).unwrap();
    db.initialize().await.unwrap();
    db.reconcile_query_indexes(m).await.unwrap();
    let mut tx = begin(db).await;
    tx.bind_schema(m).await.unwrap();
    let storage = tx.storage_resource(m, 1).await.unwrap();
    for account in [ALICE, BOB] {
        tx.execute(
            "INSERT INTO nx_accounts(id,tenant,state,epoch) VALUES($1,'team','active',1)",
            &[account.into()],
        )
        .await
        .unwrap();
    }
    if m.resources.len() == 2 {
        let parent = tx.storage_resource(m, 2).await.unwrap();
        for id in [42i64, 43] {
            tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,'team',$4,'workspace',1,$5)", &[parent.into(),id.into(),ALICE.into(),serde_json::to_string(&Fields::from([("body".into(),format!("Workspace{id}"))])).unwrap().into(),(400000+id).into()]).await.unwrap();
        }
    }
    for (id, owner, body, rank) in [
        (1, BOB, "rust العربية", 3),
        (2, ALICE, "rust only", 2),
        (3, ALICE, "rust العربية", 2),
        (4, ALICE, "العربية rust", 1),
    ] {
        insert(
            &mut tx,
            storage,
            id,
            owner,
            body,
            rank,
            m.resources[0]
                .fields
                .iter()
                .any(|field| field.name == "workspace"),
        )
        .await;
    }
    tx.execute(
        "UPDATE nx_creation_counter SET value=(SELECT MAX(created_seq) FROM nx_records)",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    storage
}
async fn runtime_case(db: Database) {
    let m = manifest();
    // Setup tokenization uses an explicit test owner; subsequent requests get fresh owners.
    let storage = fixture(&db, &m).await;
    owner()
        .await
        .run(async {
            let mut e = effects(begin(&db).await, &m);
            let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), [3, 4]);
            assert!(e.more.is_none());
            assert!(RequestScope::search_candidates_remaining().unwrap() < 256);
            // A separate operation shares this same request frontier.
            let count: AggregateResult =
                serde_json::from_slice(&e.invoke(4, 0).await.unwrap()).unwrap();
            assert_eq!(count, Ok(query::AggregateValue::Count(2)));
            e.tx.rollback().await.unwrap();
        })
        .await;
    // Replace postings and row revision atomically; rollback must preserve both.
    owner()
        .await
        .run(async {
            let mut e = effects(begin(&db).await, &m);
            let fields = Fields::from([
                ("body".into(), "unrelated".into()),
                ("rank".into(), "2".into()),
            ]);
            e.tx.execute(
                "UPDATE nx_records SET fields=$1,revision=2 WHERE resource=$2 AND id=3",
                &[
                    serde_json::to_string(&fields).unwrap().into(),
                    storage.into(),
                ],
            )
            .await
            .unwrap();
            e.update_search(1, storage, 3, "row", 2, &fields)
                .await
                .unwrap();
            e.tx.rollback().await.unwrap();
        })
        .await;
    owner()
        .await
        .run(async {
            let mut e = effects(begin(&db).await, &m);
            let result: AggregateResult =
                serde_json::from_slice(&e.invoke(4, 0).await.unwrap()).unwrap();
            assert_eq!(result, Ok(query::AggregateValue::Count(2)));
            e.tx.rollback().await.unwrap();
        })
        .await;
}
#[tokio::test]
async fn sqlite_runtime_search_count_and_posting_rollback() {
    let dir = tempfile::tempdir().unwrap().keep();
    eprintln!("retained SQLite fixture {}", dir.display());
    runtime_case(Database::sqlite(dir.join("p09.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES"]
async fn postgres_runtime_search_count_and_posting_rollback() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_query_{}", crate::security::record_id().unwrap());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    eprintln!("retained fixture database {name}");
    runtime_case(Database::postgres(case.as_str()).unwrap()).await;
}

async fn scalar_case(db: Database) {
    let mut m = manifest();
    m.operations[0].query = None;
    m.routes[0].params.clear();
    m.operations[0].list.as_mut().unwrap().order = ListOrder::Field {
        field: "rank".into(),
        direction: query::Direction::Ascending,
        mode: query::SortMode::Immutable,
    };
    fixture(&db, &m).await;
    let cursor = owner()
        .await
        .run(async {
            let mut e = effects(begin(&db).await, &m);
            let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), [4, 2]);
            let cursor = e.more.clone().unwrap();
            assert_eq!(
                cursor,
                CursorKey::Scalar {
                    value: CursorValue::Integer(2),
                    record: 2
                }
            );
            e.tx.rollback().await.unwrap();
            cursor
        })
        .await;
    owner()
        .await
        .run(async {
            let mut e = effects(begin(&db).await, &m);
            e.cursor = Some(cursor);
            let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), [3]);
            assert!(e.more.is_none());
            e.tx.rollback().await.unwrap();
        })
        .await;
    m.operations[0].query = Some(query::Query {
        range: Some(query::Range {
            field: "rank".into(),
            lower: Some(query::Bound {
                value: Operand::Literal("2".into()),
                inclusive: true,
            }),
            upper: Some(query::Bound {
                value: Operand::Literal("3".into()),
                inclusive: false,
            }),
        }),
        ..Default::default()
    });
    m.operations[3]
        .query
        .as_mut()
        .unwrap()
        .aggregate
        .as_mut()
        .unwrap()
        .function = AggregateFunction::Sum {
        field: "rank".into(),
    };
    owner()
        .await
        .run(async {
            let mut e = effects(begin(&db).await, &m);
            let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), [2, 3]);
            let sum: AggregateResult =
                serde_json::from_slice(&e.invoke(4, 0).await.unwrap()).unwrap();
            assert_eq!(sum, Ok(query::AggregateValue::Sum(4)));
            e.tx.rollback().await.unwrap();
        })
        .await;
}
#[tokio::test]
async fn sqlite_scalar_cursor_range_and_sum() {
    let dir = tempfile::tempdir().unwrap().keep();
    eprintln!("retained scalar fixture {}", dir.display());
    scalar_case(Database::sqlite(dir.join("p09.db"))).await;
}

async fn aggregate_limit_case(db: Database) {
    let mut m = manifest();
    m.operations[0].query = None;
    m.routes[0].params.clear();
    let storage = fixture(&db, &m).await;
    let mut tx = begin(&db).await;
    let fields = serde_json::to_string(&Fields::from([
        ("body".into(), "unrelated".into()),
        ("rank".into(), "1".into()),
    ]))
    .unwrap();
    tx.execute("WITH RECURSIVE numbers(n) AS (SELECT 5 UNION ALL SELECT n+1 FROM numbers WHERE n<1002) INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) SELECT $1,n,$2,'team',$3,'limit',1,n FROM numbers",&[storage.into(),ALICE.into(),fields.into()]).await.unwrap();
    tx.execute("UPDATE nx_creation_counter SET value=1002", &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    owner()
        .await
        .run(async {
            let mut e = effects(begin(&db).await, &m);
            let count: AggregateResult =
                serde_json::from_slice(&e.invoke(4, 0).await.unwrap()).unwrap();
            assert_eq!(count, Err(query::QueryError::LimitExceeded));
            e.tx.rollback().await.unwrap();
        })
        .await;
}
#[tokio::test]
async fn sqlite_aggregate_1001_candidates_returns_limit_without_partial() {
    let dir = tempfile::tempdir().unwrap().keep();
    eprintln!("retained limit fixture {}", dir.display());
    aggregate_limit_case(Database::sqlite(dir.join("p09.db"))).await;
}

async fn hundred_thousand_case(db: Database) {
    let mut m = manifest();
    m.resources.push(Resource {
        id: 2,
        name: "workspaces".into(),
        fields: vec![m.resources[0].fields[0].clone()],
        search: None,
        expiry: None,
        unique: vec![],
        gate: None,
    });
    m.resources[0].fields.push(TextField {
        immutable: true,
        name: "workspace".into(),
        label: "Workspace".into(),
        kind: FieldKind::Reference {
            resource: "workspaces".into(),
        },
        optional: false,
        initial: None,
        max_bytes: 20,
    });
    let mut read = m.operations[1].clone();
    read.id = 5;
    read.resource = 2;
    read.policy = Policy {
        any: vec![vec![Predicate::SameTenant]],
    };
    m.operations.push(read);
    m.operations[2].bind.insert("workspace".into(), 5);
    m.routes.push(Route {
        id: 4,
        path: "/workspaces/{workspace}".into(),
        resource: Some(2),
        params: vec![],
        operations: vec![5],
        forms: vec![],
        access: Access::Authenticated,
    });
    let storage = fixture(&db, &m).await;
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
    // Bulk seeding is fixture work, not a request: lift the request statement
    // limit for this transaction only so slow disks can load 100,000 rows.
    if matches!(
        tx.query_provider().unwrap(),
        crate::query_plan::NativeProvider::Postgres
    ) {
        tx.execute("SET LOCAL statement_timeout = '30s'", &[])
            .await
            .unwrap();
    }
    tx.execute(
        "UPDATE nx_records SET created_seq=created_seq+200000 WHERE resource=$1",
        &[storage.into()],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE nx_search_postings SET created_seq=created_seq+200000 WHERE resource=$1",
        &[storage.into()],
    )
    .await
    .unwrap();
    let fields = serde_json::to_string(&Fields::from([
        ("body".into(), "rust العربية".into()),
        ("rank".into(), "5".into()),
        ("workspace".into(), "43".into()),
    ]))
    .unwrap();
    for batch in 0..10 {
        let start = batch * 10000 + 1;
        let end = (batch + 1) * 10000;
        tx.execute(&format!("WITH RECURSIVE numbers(n) AS (SELECT {start} UNION ALL SELECT n+1 FROM numbers WHERE n<{end}) INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) SELECT $1,1000000+n,$2,'team',$3,'unrelated',1,n FROM numbers"),&[storage.into(),BOB.into(),fields.as_str().into()]).await.unwrap();
    }
    for token in ["rust", "العربية"] {
        tx.execute("INSERT INTO nx_search_postings(resource,record_id,field,token,incarnation,revision,created_seq) SELECT resource,id,0,$2,incarnation,revision,created_seq FROM nx_records WHERE resource=$1 AND incarnation='unrelated'",&[storage.into(),token.into()]).await.unwrap();
    }
    tx.execute(
        "UPDATE nx_creation_counter SET value=(SELECT MAX(created_seq) FROM nx_records)",
        &[],
    )
    .await
    .unwrap();
    tx.execute("ANALYZE nx_records", &[]).await.unwrap();
    tx.execute("ANALYZE nx_search_postings", &[]).await.unwrap();
    tx.commit().await.unwrap();
    owner().await.run(async {
        let mut e=effects(begin(&db).await,&m);let rows:Vec<Record>=serde_json::from_slice(&e.invoke(1,0).await.unwrap()).unwrap();
        assert!(rows.is_empty());assert_eq!(e.more,Some(CursorKey::Created{sequence:64,record:1000064}));assert_eq!(RequestScope::search_candidates_remaining().unwrap(),192);
        eprintln!("100k actual runtime sealed64 hidden candidates, returned0, continuation64");
        #[cfg(feature="query-metrics")]
        {
            let frontier=format!("SELECT record_id FROM nx_search_postings WHERE resource={storage} AND field=0 AND token='rust' ORDER BY created_seq ASC,record_id ASC LIMIT 64");
            let frontier_visits=e.tx.examined_rows(&frontier).await.unwrap();
            assert!(frontier_visits<=128,"posting frontier visited {frontier_visits}");
            let ids=(1000001..=1000064).map(|id|id.to_string()).collect::<Vec<_>>().join(",");
            let and=format!("SELECT record_id,incarnation,revision FROM nx_search_postings WHERE resource={storage} AND record_id IN ({ids}) AND field IN (0) AND token IN ('rust','العربية') GROUP BY record_id,incarnation,revision HAVING COUNT(DISTINCT token)=2 LIMIT 64");
            let and_visits=e.tx.examined_rows(&and).await.unwrap();assert!(and_visits<=2048,"bounded AND visited {and_visits}");
            eprintln!("100k real provider postingfrontier={frontier_visits} visits finiteAND={and_visits} visits");
        }
        e.tx.rollback().await.unwrap();
    }).await;
    owner()
        .await
        .run(async {
            let mut e = effects(begin(&db).await, &m);
            e.cursor = Some(CursorKey::Created {
                sequence: 99999,
                record: 1099999,
            });
            let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), [3, 4]);
            assert!(e.more.is_none());
            e.tx.rollback().await.unwrap();
        })
        .await;
    // Exact scalar/owner prefixes must avoid the same100k unrelated rows.
    let mut scalar = m.clone();
    scalar.operations[0].query = None;
    scalar.routes[0].params.clear();
    scalar.operations[0].list.as_mut().unwrap().order = ListOrder::Field {
        field: "rank".into(),
        direction: query::Direction::Ascending,
        mode: query::SortMode::Immutable,
    };
    db.reconcile_query_indexes(&scalar).await.unwrap();
    owner().await.run(async {
        let mut e=effects(begin(&db).await,&scalar);let rows:Vec<Record>=serde_json::from_slice(&e.invoke(1,0).await.unwrap()).unwrap();assert_eq!(rows.iter().map(|r|r.id).collect::<Vec<_>>(),[4,2]);
        #[cfg(feature="query-metrics")]
        {
            let expression=crate::query_plan::scalar::Scalar::new(&scalar.resources[0].fields[1],query::Direction::Ascending).unwrap().expression(e.tx.query_provider().unwrap()).unwrap();
            let sql=format!("SELECT id FROM nx_records WHERE resource={storage} AND owner='{ALICE}' ORDER BY {expression} ASC,id ASC LIMIT 64");let visits=e.tx.examined_rows(&sql).await.unwrap();assert!(visits<=64,"scalar prefix visited {visits}");eprintln!("100k real provider scalarowner={visits} visits");
        }
        e.tx.rollback().await.unwrap();
    }).await;
    // A policy OR must seal independent indexed streams before current policy.
    // In descending order the100k hidden rank5 records precede every owned row.
    let mut multi = scalar.clone();
    multi.operations[0].policy.any.push(vec![Predicate::Role {
        name: "moderator".into(),
        tenant_scoped: false,
    }]);
    multi.operations[3].policy = multi.operations[0].policy.clone();
    multi.operations[0].list.as_mut().unwrap().order = ListOrder::Field {
        field: "rank".into(),
        direction: query::Direction::Descending,
        mode: query::SortMode::Immutable,
    };
    db.reconcile_query_indexes(&multi).await.unwrap();
    owner().await.run(async {
        let mut e=effects(begin(&db).await,&multi);
        let rows:Vec<Record>=serde_json::from_slice(&e.invoke(1,0).await.unwrap()).unwrap();assert!(rows.is_empty());
        assert_eq!(e.more,Some(CursorKey::Scalar{value:CursorValue::Integer(5),record:1099937}),"policy OR cannot scan until the later owned rows");
        #[cfg(feature="query-metrics")]
        {
            let expression=crate::query_plan::scalar::Scalar::new(&multi.resources[0].fields[1],query::Direction::Descending).unwrap().expression(e.tx.query_provider().unwrap()).unwrap();
            let global=format!("SELECT id FROM nx_records WHERE resource={storage} ORDER BY {expression} DESC,id DESC LIMIT 64");
            let owned=format!("SELECT id FROM nx_records WHERE resource={storage} AND owner='{ALICE}' ORDER BY {expression} DESC,id DESC LIMIT 64");
            let global_visits=e.tx.examined_rows(&global).await.unwrap();let owner_visits=e.tx.examined_rows(&owned).await.unwrap();assert!(global_visits<=64 && owner_visits<=64);eprintln!("100k policy OR fixed streams:global={global_visits} owned={owner_visits} actual visits; hidden empty continuation preserved");
        }
        e.tx.rollback().await.unwrap();
    }).await;
    owner()
        .await
        .run(async {
            let mut e = effects(begin(&db).await, &multi);
            e.cursor = Some(CursorKey::Scalar {
                value: CursorValue::Integer(5),
                record: 1000001,
            });
            let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            assert_eq!(
                rows.iter().map(|row| row.id).collect::<Vec<_>>(),
                [3, 2],
                "deferred owned heads are preserved"
            );
            e.tx.rollback().await.unwrap();
        })
        .await;
    // The same100k Bob-owned rows belong to another exact scope. Ordinary
    // aggregate metadata requires its own protected/scope/created index shape.
    let mut scoped = m.clone();
    scoped.operations[0].query = None;
    scoped.operations[0].scope = Some("workspace".into());
    scoped.operations[3].scope = Some("workspace".into());
    scoped.routes[0].params.clear();
    scoped.routes[0].resource = Some(2);
    scoped.routes[0].operations.push(5);
    scoped.routes[0].path = "/workspaces/{workspace}/search".into();
    db.reconcile_query_indexes(&scoped).await.unwrap();
    owner().await.run(async {
        let mut e=effects(begin(&db).await,&scoped);e.request.target=Some(42);e.principal=Principal::User(User{id:BOB.into(),tenant:"team".into(),roles:vec![]});
        let count:AggregateResult=serde_json::from_slice(&e.invoke(4,0).await.unwrap()).unwrap();assert_eq!(count,Ok(query::AggregateValue::Count(1)));
        #[cfg(feature="query-metrics")]
        {
            let field=e.tx.field_expression("workspace").unwrap();let sql=format!("SELECT id FROM nx_records WHERE resource={storage} AND owner='{BOB}' AND {field}='42' ORDER BY created_seq ASC,id ASC LIMIT 64");let visits=e.tx.examined_rows(&sql).await.unwrap();assert!(visits<=64,"scoped aggregate scanned {visits}");eprintln!("100k ordinary aggregate exact owner/scope={visits} actual visits");
        }
        e.tx.rollback().await.unwrap();
    }).await;
}
#[tokio::test]
async fn sqlite_hundred_thousand_hidden_rows_keep_finite_frontier() {
    let dir = tempfile::tempdir().unwrap().keep();
    eprintln!("retained 100k SQLite fixture {}", dir.display());
    hundred_thousand_case(Database::sqlite(dir.join("p09.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES"]
async fn postgres_hundred_thousand_hidden_rows_keep_finite_frontier() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_query_100k_{}", crate::security::record_id().unwrap());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    eprintln!("retained 100k fixture database {name}");
    hundred_thousand_case(Database::postgres(case.as_str()).unwrap()).await;
}

#[tokio::test]
async fn sqlite_principal_selection_aggregates_recheck_each_principal() {
    let dir = tempfile::tempdir().unwrap().keep();
    eprintln!("retained principal fixture {}", dir.display());
    let db = Database::sqlite(dir.join("principal.db"));
    let mut m = manifest();
    m.resources[0].fields.push(TextField {
        immutable: true,
        name: "recipient".into(),
        label: "Recipient".into(),
        kind: FieldKind::Account {
            scope: AccountScope::SameTenant,
        },
        optional: false,
        initial: None,
        max_bytes: 43,
    });
    let policy = Policy {
        any: vec![vec![Predicate::PrincipalIs {
            field: "recipient".into(),
        }]],
    };
    m.operations[0].policy = policy.clone();
    m.operations[3].policy = policy;
    let storage = fixture(&db, &m).await;
    let mut tx = begin(&db).await;
    let rows = tx
        .fetch::<2>(
            "SELECT CAST(id AS TEXT),fields FROM nx_records WHERE resource=$1 ORDER BY id LIMIT 4",
            &[storage.into()],
        )
        .await
        .unwrap();
    for [id, raw] in rows {
        let mut fields: Fields = serde_json::from_str(&raw).unwrap();
        fields.insert("recipient".into(), ALICE.into());
        tx.execute(
            "UPDATE nx_records SET fields=$1 WHERE resource=$2 AND id=$3",
            &[
                serde_json::to_string(&fields).unwrap().into(),
                storage.into(),
                id.parse::<i64>().unwrap().into(),
            ],
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    for (principal, expected) in [(ALICE, 3), (BOB, 0)] {
        owner()
            .await
            .run(async {
                let mut e = effects(begin(&db).await, &m);
                e.principal = Principal::User(User {
                    id: principal.into(),
                    tenant: "team".into(),
                    roles: vec![],
                });
                let count: AggregateResult =
                    serde_json::from_slice(&e.invoke(4, 0).await.unwrap()).unwrap();
                assert_eq!(
                    count,
                    Ok(query::AggregateValue::Count(expected)),
                    "count checks current recipient policy independently of ownership"
                );
                assert!(
                    e.invoke(2, 1).await.is_err(),
                    "metadata/source does not issue an unlisted Read grant"
                );
                e.tx.rollback().await.unwrap();
            })
            .await;
    }
}
