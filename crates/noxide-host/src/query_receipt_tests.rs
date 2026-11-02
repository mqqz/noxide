//! Search postings and receipts stay atomic across a multi-step action.
use crate::auth::AccountAdmin as _;
use crate::{Database, database::Transaction, manifest};
use noxide_protocol::*;
use std::time::{Duration, Instant};

async fn begin(db: &Database) -> Transaction {
    db.begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap()
}

async fn four_step_receipts_case(db: Database) {
    use crate::{Application, HostKeys, runtime::Limits};
    let mut m = crate::test_support::manifest();
    for name in ["detail", "summary", "title"] {
        let mut field = m.resources[0].fields[0].clone();
        field.name = name.into();
        field.label = name.into();
        m.resources[0].fields.push(field);
    }
    for field in &mut m.resources[0].fields {
        field.max_bytes = 2048;
    }
    m.resources[0].search = Some(query::SearchIndex {
        tokenizer: crate::search::TOKENIZER_ID.into(),
        fields: vec![
            "body".into(),
            "detail".into(),
            "summary".into(),
            "title".into(),
        ],
        max_bytes: 8192,
    });
    let mut update = m.operations[2].clone();
    update.id = 4;
    update.kind = OperationKind::Update;
    m.operations.push(update);
    m.actions[0].inputs[0].max_bytes = 2048;
    m.actions[0].targets = vec![crate::test_support::page_target(
        1,
        vec![2],
        Revision::Exact,
    )];
    let step = Step {
        operation: 4,
        target: Target::Named("target".into()),
        guards: vec![],
        assign: ["body", "detail", "summary", "title"]
            .into_iter()
            .map(|field| Assignment {
                field: field.into(),
                change: Change::Set(Value::Input("body".into())),
            })
            .collect(),
    };
    m.actions[0].steps = vec![step; 4];
    m.routes[0].forms.clear();
    m.routes[1].forms = vec![1];
    m.web_bindings[0].redirect = Redirect {
        route: 2,
        source: RedirectSource::Target("target".into()),
    };
    manifest::validate(&m).unwrap();
    db.initialize().await.unwrap();
    let alice = db
        .create_account("alice", "synthetic p09 receipt password", "team")
        .await
        .unwrap();
    db.reconcile_query_indexes(&m).await.unwrap();
    let mut tx = begin(&db).await;
    let storage = tx.storage_resource(&m, 1).await.unwrap();
    let seed = Fields::from(
        ["body", "detail", "summary", "title"].map(|field| (field.into(), "seed".into())),
    );
    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,42,$2,'team',$3,'seed',1,1)",&[storage.into(),alice.as_str().into(),serde_json::to_string(&seed).unwrap().into()]).await.unwrap();
    tx.execute("UPDATE nx_creation_counter SET value=1", &[])
        .await
        .unwrap();
    let checkpoint = tx.operator_checkpoint().unwrap();
    let indexed =
        crate::search::indexed_record(&[Some("seed"); 4], 8192, &mut || checkpoint.checkpoint())
            .unwrap();
    let prepared =
        crate::search::PreparedPostings::new(&indexed, || checkpoint.checkpoint()).unwrap();
    crate::database::schema::replace_postings(&mut tx, storage, 42, "seed", 1, 1, &prepared)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let app = Application::new(
        &crate::test_support::component(None),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
        crate::DeploymentResources {
            effects: None,
            jobs: None,
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap();
    app.activate().await.unwrap();
    let challenge = app.login_challenge().await.unwrap();
    let session = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "synthetic p09 receipt password",
        )
        .await
        .unwrap();
    let page = String::from_utf8(app.view(&session, 2, Some(42)).await.unwrap().body).unwrap();
    let submission = crate::test_support::hidden(&page, "_submission");
    let csrf = crate::test_support::hidden(&page, "_csrf");
    let alphabet = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let excess = (0..513)
        .map(|n| {
            format!(
                "{}{}",
                char::from(alphabet[n / 36]),
                char::from(alphabet[n % 36])
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    assert!(excess.len() < 2048);
    assert!(
        app.submit(
            &session,
            1,
            &submission,
            &csrf,
            Fields::from([("body".into(), excess)])
        )
        .await
        .is_err(),
        "513 distinct tokens reject instead of truncating"
    );
    app.request_lifecycle().drain().await.unwrap();
    let mut tx = begin(&db).await;
    let before=tx.fetch::<3>("SELECT CAST((SELECT revision FROM nx_records WHERE id=42) AS TEXT),CAST((SELECT COUNT(*) FROM nx_search_postings) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts) AS TEXT)",&[]).await.unwrap();
    assert_eq!(
        before[0],
        ["1", "4", "0"],
        "failed index construction rolls back row and receipt claim"
    );
    tx.rollback().await.unwrap();
    let text = (0..512)
        .map(|n| char::from_u32(0x4e00 + n).unwrap().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let input = Fields::from([("body".into(), text)]);
    let before_wal = if db.is_sqlite() {
        None
    } else {
        let mut tx = begin(&db).await;
        let rows = tx
            .fetch::<1>("SELECT CAST(pg_current_wal_insert_lsn() AS TEXT)", &[])
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        Some(rows[0][0].clone())
    };
    let (result, roots) =
        crate::database::lifecycle::observe_roots(crate::failure_tests::known_conflict_once(
            app.submit(&session, 1, &submission, &csrf, input.clone()),
        ))
        .await;
    result.unwrap();
    app.request_lifecycle().drain().await.unwrap();
    assert_eq!(roots.len(), 1, "four-step abort/retry retains one root");
    let (free, reserved, spent) = roots[0].statement_snapshot();
    assert_eq!(reserved, 0);
    assert_eq!(free + spent, 256);
    eprintln!(
        "four-step actual SQL:spent={spent} free={free} reserved={reserved}, includes abort/retry/receipt/navigation"
    );
    app.submit(&session, 1, &submission, &csrf, input)
        .await
        .unwrap();
    let mut tx = begin(&db).await;
    let rows=tx.fetch::<3>("SELECT CAST((SELECT COUNT(*) FROM nx_records) AS TEXT),CAST((SELECT COUNT(*) FROM nx_search_postings) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts WHERE outcome<>'') AS TEXT)",&[]).await.unwrap();
    assert_eq!(
        rows[0],
        ["1", "2048", "1"],
        "aborted first-step postings roll back and receipt replay creates no duplicate mutation"
    );
    let receipts = tx
        .fetch::<1>(
            "SELECT outcome FROM nx_receipts WHERE outcome<>'' LIMIT 2",
            &[],
        )
        .await
        .unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&receipts[0][0]).unwrap();
    let outcomes: Vec<MutationOutcome> =
        serde_json::from_value(receipt["outcomes"].clone()).unwrap();
    assert_eq!(outcomes.len(), 4);
    let revisions=tx.fetch::<3>("SELECT CAST((SELECT revision FROM nx_records WHERE id=42) AS TEXT),CAST(MIN(revision) AS TEXT),CAST(MAX(revision) AS TEXT) FROM nx_search_postings WHERE resource=$1 AND record_id=42 AND incarnation='seed'",&[storage.into()]).await.unwrap();
    assert_eq!(revisions[0], ["5", "5", "5"]);
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.kind == MutationKind::Updated
                && outcome.id == 42
                && outcome.incarnation == "seed")
    );
    if db.is_sqlite() {
        let bytes=tx.fetch::<1>("SELECT CAST((SELECT page_count FROM pragma_page_count)*(SELECT page_size FROM pragma_page_size) AS TEXT)",&[]).await.unwrap();
        eprintln!(
            "retained SQLite database allocated bytes={} (whole fixture footprint, not physical write bound)",
            bytes[0][0]
        );
    } else {
        let bytes=tx.fetch::<2>("SELECT CAST(pg_relation_size('nx_search_postings') AS TEXT),CAST(pg_indexes_size('nx_search_postings') AS TEXT)",&[]).await.unwrap();
        let wal=tx.fetch::<1>("SELECT CAST(pg_wal_lsn_diff(pg_current_wal_insert_lsn(),CAST($1 AS pg_lsn)) AS TEXT)",&[before_wal.as_ref().unwrap().as_str().into()]).await.unwrap();
        eprintln!(
            "PostgreSQL postings relation bytes={} indexes bytes={} observed global WAL delta bytes={} (application/replay window, may include background work, not physical write bound)",
            bytes[0][0], bytes[0][1], wal[0][0]
        );
    }
    eprintln!(
        "real four-update receipt:2048 postings per step,final2048 postings/revision5,1 receipt/four outcomes;513-token rejection, first-step abort and replay atomic"
    );
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn sqlite_four_mutation_steps_keep_postings_and_receipt_atomic() {
    let dir = tempfile::tempdir().unwrap().keep();
    eprintln!("retained receipt fixture {}", dir.display());
    four_step_receipts_case(Database::sqlite(dir.join("receipts.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES"]
async fn postgres_four_mutation_steps_keep_postings_and_receipt_atomic() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_query_receipt_{}", crate::security::record_id().unwrap());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    eprintln!("retained receipt database {name}");
    four_step_receipts_case(Database::postgres(case.as_str()).unwrap()).await;
}
