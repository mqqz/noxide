use super::*;
use crate::schema::{Migration, MigrationOp};
use noxide_protocol::{
    FieldKind, Manifest, TextField, expiry::ResourceExpiry, membership::MembershipUnique,
};
use std::time::{Duration, Instant};

const ALICE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn field(name: &str, kind: FieldKind) -> TextField {
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

fn declarations() -> Manifest {
    let mut m = crate::test_support::manifest();
    // This fixture tests the schema API independently of guest execution.
    m.operations.clear();
    m.actions.clear();
    m.web_bindings.clear();
    m.routes.truncate(1);
    m.routes[0].operations.clear();
    m.routes[0].forms.clear();
    let mut parent = m.resources[0].clone();
    parent.id = 2;
    parent.name = "workspace".into();
    parent.fields.push(field("active", FieldKind::Boolean));
    m.resources.push(parent);
    m.resources[0].fields.extend([
        field(
            "workspace",
            FieldKind::Reference {
                resource: "workspace".into(),
            },
        ),
        field(
            "other_workspace",
            FieldKind::Reference {
                resource: "workspace".into(),
            },
        ),
        field(
            "account",
            FieldKind::Account {
                scope: noxide_protocol::AccountScope::SameTenant,
            },
        ),
        field("expires", FieldKind::Timestamp),
    ]);
    m.operations.push(noxide_protocol::Operation {
        maintenance: false,
        query: None,
        id: 1,
        resource: 2,
        kind: noxide_protocol::OperationKind::List,
        bind: Default::default(),
        scope: None,
        via: None,
        filter: vec![noxide_protocol::Condition {
            field: "active".into(),
            equals: noxide_protocol::Operand::Literal("true".into()),
        }],
        disclose: Vec::new(),
        list: None,
        visibility: None,
        fields: None,
        policy: noxide_protocol::Policy {
            any: vec![vec![noxide_protocol::Predicate::Owner]],
        },
    });
    m.routes[0].operations.push(1);
    crate::manifest::validate(&m).unwrap();
    m
}

fn unique_target(source: &Manifest) -> Manifest {
    let mut target = source.clone();
    target.resources[0].gate = Some(noxide_protocol::Gate {
        field: "workspace".into(),
        visible: noxide_protocol::Visibility {
            field: "active".into(),
            equals: "true".into(),
        },
        create_when: noxide_protocol::Visibility {
            field: "active".into(),
            equals: "true".into(),
        },
    });
    target.resources[0].unique = vec![MembershipUnique {
        reference: "workspace".into(),
        account: "account".into(),
    }];
    target.resources[0].expiry = Some(ResourceExpiry {
        field: "expires".into(),
        max_after: noxide_protocol::time::Duration::from_secs(1).unwrap(),
    });
    crate::manifest::validate(&target).unwrap();
    target
}

fn migration(source: &Manifest, target: &Manifest) -> Migration {
    Migration {
        version: 1,
        from: crate::schema::digest(&source.resources).unwrap(),
        to: crate::schema::digest(&target.resources).unwrap(),
        operations: vec![MigrationOp::ChangeResourceAuthority {
            resource: "notes".into(),
        }],
    }
}

async fn tx(db: &Database) -> Transaction {
    db.begin(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap()
}

fn fields() -> Fields {
    Fields::from([
        ("body".into(), "membership".into()),
        ("workspace".into(), "1".into()),
        ("other_workspace".into(), "1".into()),
        ("account".into(), ALICE.into()),
        ("expires".into(), "999999999".into()),
    ])
}

async fn insert(tx: &mut Transaction, storage: i64, id: i64, fields: &str) -> Result<()> {
    insert_scoped(tx, storage, id, fields, "", "team").await
}

async fn insert_scoped(
    tx: &mut Transaction,
    storage: i64,
    id: i64,
    fields: &str,
    owner: &str,
    tenant: &str,
) -> Result<()> {
    let seq = tx.allocate_creation().await?;
    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,NULLIF($6,''),$7,$3,$4,1,$5)", &[storage.into(), id.into(), fields.into(), format!("record-{storage}-{id}").into(), seq.into(), owner.into(), tenant.into()]).await?;
    Ok(())
}

async fn snapshot(db: &Database) -> Vec<Vec<[String; 2]>> {
    let mut t = tx(db).await;
    let result = vec![
        t.fetch::<2>("SELECT definition,history FROM nx_schema_definition ORDER BY singleton", &[]).await.unwrap(),
        t.fetch::<2>("SELECT CAST(id AS TEXT),fields FROM nx_records ORDER BY resource,id", &[]).await.unwrap(),
        t.fetch::<2>("SELECT resource_key,CAST(storage_id AS TEXT) FROM nx_resource_catalog ORDER BY storage_id", &[]).await.unwrap(),
        t.fetch::<2>("SELECT contract,generation FROM nx_deployment", &[]).await.unwrap(),
        match db.is_sqlite() {
            true => t.fetch::<2>("SELECT name,sql FROM sqlite_schema WHERE type='index' AND tbl_name='nx_records' ORDER BY name", &[]).await.unwrap(),
            false => t.fetch::<2>("SELECT indexname,indexdef FROM pg_catalog.pg_indexes WHERE schemaname=current_schema() AND tablename='nx_records' ORDER BY indexname", &[]).await.unwrap(),
        },
        t.fetch::<2>("SELECT CAST(resource AS TEXT)||':'||CAST(id AS TEXT),COALESCE(owner,'')||'|'||tenant||'|'||incarnation||'|'||CAST(revision AS TEXT)||'|'||CAST(created_seq AS TEXT) FROM nx_records ORDER BY resource,id", &[]).await.unwrap(),
        t.fetch::<2>("SELECT CAST(singleton AS TEXT),CAST(value AS TEXT) FROM nx_creation_counter", &[]).await.unwrap(),
        t.fetch::<2>("SELECT nonce,outcome FROM nx_receipts ORDER BY nonce", &[]).await.unwrap(),
    ];
    t.rollback().await.unwrap();
    result
}

#[test]
fn raw_json_has_one_unambiguous_string_value_per_field() {
    for raw in [
        r#"{"a":"1","a":"2"}"#,
        r#"{"a":"1","\u0061":"2"}"#,
        r#"{"a":1}"#,
        r#"{"a":null}"#,
        r#"{"a":true}"#,
        r#"{"a":{}}"#,
        r#"{}{}"#,
        r#"[]"#,
    ] {
        assert!(parse_fields(raw).is_err(), "{raw}");
    }
    assert_eq!(
        parse_fields(" { \"b\" : \"2\", \"a\" : \"1\" } ").unwrap(),
        Fields::from([("a".into(), "1".into()), ("b".into(), "2".into())])
    );
}

#[test]
fn ddl_comparison_preserves_authority_bearing_tokens() {
    assert_eq!(
        ddl_key("(fields::jsonb ->> 'workspace'::text)"),
        ddl_key("((fields)::jsonb ->> 'workspace')")
    );
    for bad in [
        "resource,tenant,fields",
        "resource,fields COLLATE nocase",
        "resource=1 OR resource=2",
        "resource=2",
        "resource=1 AND tenant='team'",
    ] {
        assert_ne!(ddl_key(bad), ddl_key("resource=1"));
    }
}

async fn contract(db: Database) {
    db.initialize().await.unwrap();
    let source = declarations();
    let target = unique_target(&source);
    let change = migration(&source, &target);
    let empty = snapshot(&db).await;
    let mut t = tx(&db).await;
    t.bind_schema_catalog(&target).await.unwrap();
    t.reconcile_query_indexes(&target).await.unwrap();
    t.bind_schema(&target).await.unwrap();
    t.rollback().await.unwrap();
    assert_eq!(
        snapshot(&db).await,
        empty,
        "initial native index DDL rolls back"
    );
    db.reconcile_query_indexes(&source).await.unwrap();
    let mut t = tx(&db).await;
    t.bind_schema(&source).await.unwrap();
    t.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'schema','key','original')", &[]).await.unwrap();
    t.execute(
        "INSERT INTO nx_accounts(id,tenant,state,epoch) VALUES($1,'team','active',1)",
        &[ALICE.into()],
    )
    .await
    .unwrap();
    insert(&mut t, 2, 1, r#"{"body":"workspace","active":"true"}"#)
        .await
        .unwrap();
    let raw = serde_json::to_string(&fields()).unwrap();
    insert(&mut t, 1, 1, &raw).await.unwrap();
    insert(&mut t, 1, 2, &raw).await.unwrap();
    t.commit().await.unwrap();

    // Historical duplicates remain legal without an explicit declaration.
    let baseline = snapshot(&db).await;
    let mut t = tx(&db).await;
    t.bind_schema(&source).await.unwrap();
    assert!(t.bind_schema(&target).await.is_err());
    t.rollback().await.unwrap();
    let mut undeclared = change.clone();
    undeclared.operations = vec![MigrationOp::ChangeField {
        resource: "notes".into(),
        field: "body".into(),
    }];
    assert!(db.schema_apply(&target, &undeclared).await.is_err());
    assert_eq!(snapshot(&db).await, baseline);
    assert!(db.schema_check(&target, &change).await.is_err());
    assert_eq!(snapshot(&db).await, baseline);
    assert!(db.schema_apply(&target, &change).await.is_err());
    assert_eq!(snapshot(&db).await, baseline);

    // A deliberate operator data change resolves the duplicate; schema code
    // never chooses a row to delete. Here keep both rows by using another parent.
    let mut t = tx(&db).await;
    insert(
        &mut t,
        2,
        2,
        r#"{"body":"second workspace","active":"true"}"#,
    )
    .await
    .unwrap();
    let mut distinct = fields();
    distinct.insert("workspace".into(), "2".into());
    t.execute(
        "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=2",
        &[serde_json::to_string(&distinct).unwrap().into()],
    )
    .await
    .unwrap();
    t.commit().await.unwrap();

    // Raw provider extraction cannot bypass canonical tuple admission. Every
    // failed activation preserves malformed bytes as well as all DDL/history.
    for bad in [
        raw.replace("\"workspace\":\"1\"", "\"workspace\":\"01\""),
        raw.replace("\"workspace\":\"1\"", "\"workspace\":1"),
        raw.replace(
            "\"workspace\":\"1\"",
            "\"workspace\":\"2\",\"workspace\":\"1\"",
        ),
        raw.replace("\"account\":", "\"extra\":\"x\",\"account\":"),
    ] {
        let mut t = tx(&db).await;
        t.execute(
            "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=1",
            &[bad.into()],
        )
        .await
        .unwrap();
        t.commit().await.unwrap();
        let before = snapshot(&db).await;
        assert!(db.schema_apply(&target, &change).await.is_err());
        assert_eq!(snapshot(&db).await, before);
    }
    let mut t = tx(&db).await;
    t.execute(
        "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=1",
        &[raw.clone().into()],
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let before = snapshot(&db).await;
    let rehearsal_started = Instant::now();
    db.schema_check(&target, &change).await.unwrap();
    println!(
        "metadata rehearsal: 2 membership + 2 parent rows, {}ms",
        rehearsal_started.elapsed().as_millis()
    );
    assert_eq!(
        snapshot(&db).await,
        before,
        "rehearsal rolls back DDL and generation"
    );
    let migration_started = Instant::now();
    db.schema_apply(&target, &change).await.unwrap();
    println!(
        "metadata apply: 2 membership + 2 parent rows, {}ms",
        migration_started.elapsed().as_millis()
    );
    let committed = snapshot(&db).await;
    assert_ne!(committed[0], before[0]);
    assert_ne!(committed[3], before[3]);
    assert_eq!(committed[1], before[1]);
    assert_eq!(committed[5..], before[5..], "protected state is unchanged");
    db.schema_apply(&target, &change).await.unwrap();
    assert_eq!(
        snapshot(&db).await,
        committed,
        "same migration is idempotent"
    );
    assert!(db.reconcile_query_indexes(&source).await.is_err());
    assert_eq!(
        snapshot(&db).await,
        committed,
        "reconcile cannot weaken the approved authority"
    );

    for bad in [
        raw.replace("\"workspace\":\"1\"", "\"workspace\":\"01\""),
        raw.replace("\"workspace\":\"1\"", "\"workspace\":1"),
    ] {
        let mut t = tx(&db).await;
        t.execute(
            "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=1",
            &[bad.into()],
        )
        .await
        .unwrap();
        t.commit().await.unwrap();
        let malformed = snapshot(&db).await;
        let mut t = tx(&db).await;
        assert!(t.bind_schema(&target).await.is_err());
        t.rollback().await.unwrap();
        assert!(db.reconcile_query_indexes(&target).await.is_err());
        assert_eq!(snapshot(&db).await, malformed);
    }
    let mut t = tx(&db).await;
    t.execute(
        "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=1",
        &[raw.clone().into()],
    )
    .await
    .unwrap();
    t.commit().await.unwrap();

    // Object formatting is irrelevant, and startup validation never rewrites it.
    let pretty = serde_json::to_string_pretty(&fields()).unwrap();
    let mut t = tx(&db).await;
    t.execute(
        "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=1",
        &[pretty.into()],
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let before = snapshot(&db).await;
    let mut t = db
        .begin_read(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
    t.bind_schema(&target).await.unwrap();
    t.rollback().await.unwrap();
    assert_eq!(snapshot(&db).await, before);

    let tuple = &target.resources[0].unique[0];
    let name = crate::membership::unique_index_name(1, tuple).unwrap();
    let mut t = tx(&db).await;
    let native = crate::membership::unique_index_sql(&t, &target.resources[0], 1, tuple).unwrap();
    t.rollback().await.unwrap();
    for spoof in [
        native.replacen("CREATE UNIQUE INDEX", "CREATE INDEX", 1),
        native.replace("WHERE resource=1", "WHERE resource=2"),
        native.replace("WHERE resource=1", "WHERE resource=1 AND tenant='team'"),
        native.replace(" WHERE resource=1", ""),
        native.replace("ON nx_records(resource,", "ON nx_records(resource,tenant,"),
        format!("CREATE INDEX {name} ON nx_records(resource,id)"),
        format!("CREATE UNIQUE INDEX {name} ON nx_records(resource,id)"),
        format!("CREATE UNIQUE INDEX {name} ON nx_records(resource,id) WHERE resource=2"),
    ] {
        let mut t = tx(&db).await;
        t.execute(&format!("DROP INDEX {name}"), &[]).await.unwrap();
        t.execute(&spoof, &[]).await.unwrap();
        t.commit().await.unwrap();
        let mut t = tx(&db).await;
        assert!(t.bind_schema(&target).await.is_err(), "{spoof}");
        t.rollback().await.unwrap();
        db.reconcile_query_indexes(&target).await.unwrap();
        let mut t = tx(&db).await;
        t.bind_schema(&target).await.unwrap();
        t.rollback().await.unwrap();
    }

    // The native key ignores body/status, owner and tenant. Concurrent writers
    // start together; the provider's constraint permits exactly one new tuple.
    let mut t = tx(&db).await;
    insert(
        &mut t,
        2,
        3,
        r#"{"body":"third workspace","active":"true"}"#,
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    let mut tasks = Vec::new();
    for id in [3, 4] {
        let db = db.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut f = fields();
            f.insert("workspace".into(), "3".into());
            f.insert("body".into(), format!("role-{id}"));
            for attempt in 0..2 {
                let mut t = db.begin(deadline).await.unwrap();
                let result = insert_scoped(
                    &mut t,
                    1,
                    id,
                    &serde_json::to_string(&f).unwrap(),
                    if id == 3 { ALICE } else { "" },
                    if id == 3 { "team" } else { "other" },
                )
                .await;
                match result {
                    Ok(()) => {
                        t.commit().await.unwrap();
                        return true;
                    }
                    Err(error) => {
                        t.rollback().await.unwrap();
                        let provider = error
                            .downcast_ref::<sqlx::Error>()
                            .and_then(sqlx::Error::as_database_error);
                        if provider.is_some_and(|e| e.is_unique_violation()) {
                            return false;
                        }
                        let code = provider.and_then(|e| e.code());
                        assert!(
                            attempt == 0 && code.as_deref() == Some("40001"),
                            "unexpected concurrent insert error: {error:#}"
                        );
                        // Production transactions are serializable. Only the
                        // counter's one stale snapshot is retried, with the same
                        // deadline; the final loser must hit native uniqueness.
                        println!(
                            "concurrent creation counter: SQLSTATE40001, one fixed-deadline retry"
                        );
                    }
                }
            }
            unreachable!("bounded native uniqueness retry")
        }));
    }
    barrier.wait().await;
    let mut successes = 0;
    for task in tasks {
        successes += usize::from(task.await.unwrap());
    }
    assert_eq!(successes, 1);
    let mut t = tx(&db).await;
    assert_eq!(
        t.fetch::<1>(
            "SELECT CAST(COUNT(*) AS TEXT) FROM nx_records WHERE resource=1",
            &[]
        )
        .await
        .unwrap()[0][0],
        "3"
    );
    t.validate_references(&target.resources).await.unwrap();
    t.bind_schema(&target).await.unwrap();
    t.rollback().await.unwrap();

    let mut renamed = target.clone();
    let renames = [
        ("workspace", "project"),
        ("account", "member"),
        ("expires", "until"),
    ];
    for (from, to) in renames {
        renamed.resources[0]
            .fields
            .iter_mut()
            .find(|f| f.name == from)
            .unwrap()
            .name = to.into();
    }
    renamed.resources[0].gate.as_mut().unwrap().field = "project".into();
    renamed.resources[0].expiry.as_mut().unwrap().field = "until".into();
    renamed.resources[0].unique[0].reference = "project".into();
    renamed.resources[0].unique[0].account = "member".into();
    let mut rename = migration(&target, &renamed);
    rename.operations = renames
        .into_iter()
        .map(|(from, to)| MigrationOp::RenameField {
            resource: "notes".into(),
            from: from.into(),
            to: to.into(),
        })
        .collect();
    let before = snapshot(&db).await;
    db.schema_check(&renamed, &rename).await.unwrap();
    assert_eq!(snapshot(&db).await, before);
    db.schema_apply(&renamed, &rename).await.unwrap();
    let mut t = tx(&db).await;
    t.bind_schema(&renamed).await.unwrap();
    t.validate_references(&renamed.resources).await.unwrap();
    let derived = crate::query_plan::required_indexes(&renamed).unwrap();
    assert!(!derived.is_empty());
    let actual = t.query_indexes().await.unwrap();
    assert!(derived.iter().all(|index| actual.contains(&index.name(2))));
    let indexes = match db.is_sqlite() {
        true => t.fetch::<1>("SELECT name FROM sqlite_schema WHERE type='index' AND tbl_name='nx_records'", &[]).await.unwrap(),
        false => t.fetch::<1>("SELECT indexname FROM pg_catalog.pg_indexes WHERE schemaname=current_schema() AND tablename='nx_records'", &[]).await.unwrap(),
    };
    for name in [
        "nx_r_1_project",
        "nx_r_1_project_owner",
        "nx_r_1_project_tenant",
        "nx_r_1_other_workspace",
        "nx_a_1_member_i",
        "nx_a_1_member_t",
    ] {
        assert!(
            indexes.iter().any(|[actual]| actual == name),
            "missing retained reference/account index {name}"
        );
    }
    let fields = t.row_fields(1, 1).await.unwrap();
    assert_eq!(fields.get("project").unwrap(), "1");
    assert_eq!(fields.get("member").unwrap(), ALICE);
    assert_eq!(fields.get("until").unwrap(), "999999999");
    assert!(!fields.contains_key("workspace"));
    t.rollback().await.unwrap();

    // Exercise multiple identity windows and several 60 KiB byte prefixes.
    // Late malformed/oversized rows must never appear to end the scan early.
    let mut t = tx(&db).await;
    for number in 10..90 {
        insert(
            &mut t,
            2,
            number,
            r#"{"body":"paged workspace","active":"true"}"#,
        )
        .await
        .unwrap();
        let mut page_fields = fields.clone();
        page_fields.insert("project".into(), number.to_string());
        page_fields.insert("body".into(), "😀".repeat(1_000));
        insert(
            &mut t,
            1,
            number,
            &serde_json::to_string(&page_fields).unwrap(),
        )
        .await
        .unwrap();
    }
    t.commit().await.unwrap();
    let started = Instant::now();
    let mut t = db
        .begin_read(started + Duration::from_secs(2))
        .await
        .unwrap();
    t.bind_schema(&renamed).await.unwrap();
    t.rollback().await.unwrap();
    println!(
        "bounded canonical preflight: 83 rows, {}ms",
        started.elapsed().as_millis()
    );
    let mut t = tx(&db).await;
    let valid = t.row_fields(1, 89).await.unwrap();
    let mut malformed = valid.clone();
    malformed.insert("until".into(), "01".into());
    t.execute(
        "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=89",
        &[serde_json::to_string(&malformed).unwrap().into()],
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let mut t = tx(&db).await;
    assert!(t.bind_schema(&renamed).await.is_err());
    t.rollback().await.unwrap();
    let mut oversized = valid.clone();
    oversized.insert("body".into(), "x".repeat(70_000));
    let mut t = tx(&db).await;
    t.execute(
        "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=89",
        &[serde_json::to_string(&oversized).unwrap().into()],
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let mut t = tx(&db).await;
    assert!(t.bind_schema(&renamed).await.is_err());
    t.rollback().await.unwrap();
    let mut t = tx(&db).await;
    t.execute(
        "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=89",
        &[serde_json::to_string(&valid).unwrap().into()],
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let mut t = tx(&db).await;
    t.bind_schema(&renamed).await.unwrap();
    let lookup = format!(
        "SELECT id FROM nx_records WHERE resource=1 AND {}=$1 AND {}=$2 LIMIT 1",
        t.field_expression("project").unwrap(),
        t.field_expression("member").unwrap()
    );
    let plan: Vec<String> = match &mut t.backend {
        Backend::Sqlite(connection) => sqlx::query(&format!("EXPLAIN QUERY PLAN {lookup}"))
            .bind("1")
            .bind(ALICE)
            .fetch_all(connection)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.try_get("detail").unwrap())
            .collect(),
        Backend::Postgres(connection) => {
            sqlx::query(&format!("EXPLAIN (ANALYZE,BUFFERS) {lookup}"))
                .bind("1")
                .bind(ALICE)
                .fetch_all(connection)
                .await
                .unwrap()
                .into_iter()
                .map(|r| r.try_get(0).unwrap())
                .collect()
        }
        Backend::Closed => unreachable!(),
    };
    let native = crate::membership::unique_index_name(1, &renamed.resources[0].unique[0]).unwrap();
    if db.is_sqlite() {
        assert!(
            plan.iter().any(|line| line.contains(&native)),
            "native tuple lookup plan: {plan:?}"
        );
    }
    // PostgreSQL may prefer a sequential scan on this tiny fixture. Preserve
    // that default plan as evidence, rather than forcing a planner preference.
    assert_eq!(
        t.fetch::<1>(
            &format!("SELECT CAST(id AS TEXT) FROM ({lookup}) matched"),
            &["1".into(), ALICE.into()]
        )
        .await
        .unwrap(),
        [["1".to_owned()]]
    );
    println!("native tuple lookup plan: {}", plan.join(" | "));
    t.rollback().await.unwrap();

    let application = crate::Application::new(
        &crate::test_support::component(None),
        &serde_json::to_vec(&renamed).unwrap(),
        crate::manifest::digest(&renamed).unwrap(),
        db.clone(),
        crate::HostKeys::generate().unwrap(),
        crate::runtime::Limits::default(),
        crate::DeploymentResources {
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap();
    let started = Instant::now();
    application.activate().await.unwrap();
    println!(
        "production Application::activate: 83 unique rows + 83 parent rows, {}ms (unchanged2s budget)",
        started.elapsed().as_millis()
    );
}

#[tokio::test]
async fn sqlite_schema_membership_activation() {
    let tmp = tempfile::tempdir().unwrap();
    contract(Database::sqlite(tmp.path().join("membership-schema.db"))).await;
}

#[tokio::test]
async fn postgres_schema_membership_activation() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES")
        .expect("NOXIDE_TEST_POSTGRES required for provider proof");
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_p07_schema_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let database_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    let result = tokio::spawn(contract(Database::postgres(&database_url).unwrap())).await;
    if result.is_ok() {
        sqlx::query(&format!("DROP DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
    } else {
        eprintln!("failed fixture retained: {name}");
    }
    result.unwrap();
}
