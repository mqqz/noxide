use super::*;
use crate::{
    database::Database,
    schema::{self, Migration, MigrationOp},
};
use sqlx::Connection;
use std::time::{Duration, Instant};

fn declarations() -> Manifest {
    let mut manifest = crate::test_support::manifest();
    manifest.resources[0].fields[0].max_bytes = 4096;
    manifest
}

fn indexed(source: &Manifest, max_bytes: u32) -> Manifest {
    let mut manifest = source.clone();
    manifest.resources[0].search = Some(SearchIndex {
        tokenizer: noxide_protocol::query::TOKENIZER_ID.into(),
        fields: vec![manifest.resources[0].fields[0].name.clone()],
        max_bytes,
    });
    manifest
}

fn migration(source: &Manifest, target: &Manifest, op: MigrationOp) -> Migration {
    Migration {
        version: 1,
        from: schema::digest(&source.resources).unwrap(),
        to: schema::digest(&target.resources).unwrap(),
        operations: vec![op],
    }
}

async fn seed(db: &Database, manifest: &Manifest, value: &str) {
    let mut tx = db.begin_schema().await.unwrap();
    let storage = tx.storage_key(&manifest.resources[0].name).await.unwrap();
    let fields = noxide_protocol::Fields::from([(
        manifest.resources[0].fields[0].name.clone(),
        value.into(),
    )]);
    tx.execute(
        "UPDATE nx_creation_counter SET value=value+1 WHERE singleton=1",
        &[],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES($1,1,NULL,'',$2,'search-schema-record',1,NULL,(SELECT value FROM nx_creation_counter WHERE singleton=1))", &[storage.into(), serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
    tx.commit().await.unwrap();
}

async fn counts(db: &Database) -> [String; 4] {
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let rows = tx.fetch::<4>("SELECT CAST((SELECT COUNT(*) FROM nx_records) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts) AS TEXT),CAST((SELECT COUNT(*) FROM nx_search_state) AS TEXT),CAST((SELECT COUNT(*) FROM nx_search_postings) AS TEXT)", &[]).await.unwrap();
    tx.commit().await.unwrap();
    rows.into_iter().next().unwrap()
}

async fn contract(db: Database) {
    let source = declarations();
    db.initialize().await.unwrap();
    db.reconcile_query_indexes(&source).await.unwrap();
    seed(&db, &source, "Rust العربية").await;
    let target = indexed(&source, 16_384);
    // Index reconciliation cannot adopt populated data or the new schema.
    assert!(db.reconcile_query_indexes(&target).await.is_err());
    assert_eq!(counts(&db).await, ["1", "0", "0", "0"]);
    let add = migration(
        &source,
        &target,
        MigrationOp::AddSearchIndex {
            resource: source.resources[0].name.clone(),
        },
    );
    db.schema_check(&target, &add).await.unwrap();
    assert_eq!(counts(&db).await, ["1", "0", "0", "0"]);
    db.schema_apply(&target, &add).await.unwrap();
    db.schema_apply(&target, &add).await.unwrap();
    assert_eq!(counts(&db).await, ["1", "0", "1", "2"]);
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT token FROM nx_search_postings ORDER BY token", &[])
            .await
            .unwrap(),
        [["rust".to_owned()], ["العربية".to_owned()]]
    );
    assert_eq!(
        tx.fetch::<1>("SELECT state FROM nx_search_state", &[])
            .await
            .unwrap(),
        [["ready".to_owned()]]
    );
    tx.commit().await.unwrap();
    let next = indexed(&source, 8192);
    let rebuild = migration(
        &target,
        &next,
        MigrationOp::RebuildSearchIndex {
            resource: source.resources[0].name.clone(),
        },
    );
    db.schema_apply(&next, &rebuild).await.unwrap();
    assert_eq!(counts(&db).await, ["1", "0", "1", "2"]);
    let remove = migration(
        &next,
        &source,
        MigrationOp::RemoveSearchIndex {
            resource: source.resources[0].name.clone(),
        },
    );
    db.schema_apply(&source, &remove).await.unwrap();
    assert_eq!(counts(&db).await, ["1", "0", "0", "0"]);

    // A rejected rebuild must preserve canonical records and the previous schema.
    let oversized = (0..513)
        .map(|index| format!("a{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut tx = db.begin_schema().await.unwrap();
    let fields =
        noxide_protocol::Fields::from([(source.resources[0].fields[0].name.clone(), oversized)]);
    tx.execute(
        "UPDATE nx_records SET fields=$1 WHERE id=1",
        &[serde_json::to_string(&fields).unwrap().into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(db.schema_apply(&target, &add).await.is_err());
    assert_eq!(counts(&db).await, ["1", "0", "0", "0"]);
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let (stored, _) = tx.schema_definition().await.unwrap().unwrap();
    assert_eq!(
        schema::digest(&stored).unwrap(),
        schema::digest(&source.resources).unwrap()
    );
    let storage = tx.storage_key(&source.resources[0].name).await.unwrap();
    assert_eq!(tx.row_fields(storage, 1).await.unwrap(), fields);
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn sqlite_explicit_search_migrations_are_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep().join("search-migrations.db");
    eprintln!(
        "REVIEWER retained SQLite operator baseline fixture: {}",
        path.display()
    );
    contract(Database::sqlite(path)).await;
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_explicit_search_migrations_are_atomic() {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let name = format!(
        "nx_search_migration_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    eprintln!("retained migration fixture: {name}");
    let fixture = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    contract(Database::postgres(&fixture).unwrap()).await;
}

// Reviewer scratch regression for appending to database/schema/search_indexes/tests.rs.
// Reviewer native lane granted by C for exact be796f0.
async fn indexed_field_replacement_contract(db: Database) {
    let plain = declarations();
    db.initialize().await.unwrap();
    db.reconcile_query_indexes(&plain).await.unwrap();
    seed(&db, &plain, "before").await;
    let source = indexed(&plain, 16_384);
    db.schema_apply(
        &source,
        &migration(
            &plain,
            &source,
            MigrationOp::AddSearchIndex {
                resource: "notes".into(),
            },
        ),
    )
    .await
    .unwrap();

    let mut before_tx = db
        .begin_read(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let storage = before_tx.storage_key("notes").await.unwrap();
    let before_fields = before_tx.row_fields(storage, 1).await.unwrap();
    let before_state = before_tx
        .fetch::<3>(
            "SELECT tokenizer,declaration,state FROM nx_search_state",
            &[],
        )
        .await
        .unwrap();
    let before_postings = before_tx
        .fetch::<1>("SELECT token FROM nx_search_postings ORDER BY token", &[])
        .await
        .unwrap();
    eprintln!(
        "REVIEWER before canonical={before_fields:?}; state={before_state:?}; postings={before_postings:?}"
    );
    before_tx.commit().await.unwrap();
    let mut target = source.clone();
    target.resources[0].fields[0].max_bytes = 2048;
    target.actions[0].inputs[0].max_bytes = 2048;
    let rewrite = Migration {
        version: 1,
        from: schema::digest(&source.resources).unwrap(),
        to: schema::digest(&target.resources).unwrap(),
        operations: vec![
            MigrationOp::DropField {
                resource: "notes".into(),
                field: "body".into(),
            },
            MigrationOp::AddField {
                resource: "notes".into(),
                field: "body".into(),
                value: "after".into(),
            },
        ],
    };
    db.schema_apply(&target, &rewrite).await.unwrap();
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let storage = tx.storage_key("notes").await.unwrap();
    assert_eq!(
        tx.row_fields(storage, 1)
            .await
            .unwrap()
            .get("body")
            .unwrap(),
        "after"
    );
    let postings = tx
        .fetch::<1>("SELECT token FROM nx_search_postings ORDER BY token", &[])
        .await
        .unwrap();
    let canonical = tx.row_fields(storage, 1).await.unwrap();
    let state = tx
        .fetch::<3>(
            "SELECT tokenizer,declaration,state FROM nx_search_state",
            &[],
        )
        .await
        .unwrap();
    eprintln!("REVIEWER persisted canonical={canonical:?}; state={state:?}; postings={postings:?}");
    // A migration that commits the rewritten canonical record must update its index.
    assert_eq!(postings, [["after".to_owned()]]);
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn reviewer_sqlite_indexed_field_replacement_stays_searchable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep().join("indexed-rewrite.db");
    eprintln!(
        "REVIEWER retained SQLite indexed rewrite fixture: {}",
        path.display()
    );
    indexed_field_replacement_contract(Database::sqlite(path)).await;
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn reviewer_postgres_indexed_field_replacement_stays_searchable() {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let name = format!(
        "nx_search_index_rewrite_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    eprintln!("REVIEWER retained PostgreSQL indexed rewrite fixture: {name}");
    let fixture = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    indexed_field_replacement_contract(Database::postgres(&fixture).unwrap()).await;
}
