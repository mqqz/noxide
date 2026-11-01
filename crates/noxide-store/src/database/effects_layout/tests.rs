//! Native startup/constraint fixtures, independent of capture and delivery.
use super::*;
use crate::database::Database;
use sqlx::Connection;
use std::{
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
struct Sqlite {
    db: Database,
    _anchor: sqlx::SqliteConnection,
}
async fn sqlite(label: &str) -> Sqlite {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-fixtures/effects-layout-fixtures");
    std::fs::create_dir_all(&root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(root)
        .unwrap()
        .keep();
    let path = directory.join("layout.db");
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
        .foreign_keys(true);
    let anchor = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let db = Database::sqlite(&path);
    db.initialize().await.unwrap();
    eprintln!("retained SQLite native fixture: {}", path.display());
    Sqlite {
        db,
        _anchor: anchor,
    }
}
async fn postgres(label: &str) -> Database {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_effects_layout_{label}_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    assert!(name.len() <= 63);
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut url = url::Url::parse(&url).unwrap();
    url.set_path(&format!("/{name}"));
    let db = Database::postgres(url.as_str()).unwrap();
    db.initialize().await.unwrap();
    eprintln!("retained PostgreSQL native fixture: {name}");
    db
}
async fn valid(db: &Database) {
    // A second startup must accept the native NOT NULL singleton as well.
    db.initialize().await.unwrap();
    let mut tx = db.begin(deadline()).await.unwrap();
    tx.check_effect_layout().await.unwrap();
    tx.execute("INSERT INTO nx_effect_queue(singleton,claim_seq,store_id,owner_directory,pending_limit,tenant_limit,concurrency) VALUES(1,0,'store','directory',1000,1000,2)",&[]).await.unwrap();
    tx.execute(
        "INSERT INTO nx_effect_tenants(deployment,tenant,claim_seq) VALUES('generation','alpha',0)",
        &[],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO nx_outbox(id,deployment,tenant,origin,ordinal,endpoint,contract,epoch,grant_version,secret_version,payload,payload_digest,eligible_ms,first_eligible_ms,attempts,fence,lease_until_ms,round,state,reason) VALUES('effect','generation','alpha','origin',0,'events','contract','epoch',1,0,'{}','digest',0,0,0,0,0,0,'pending','')",&[]).await.unwrap();
    tx.commit().await.unwrap();
    for sql in [
        "UPDATE nx_effect_queue SET concurrency=3",
        "UPDATE nx_effect_queue SET tenant_limit=0",
        "UPDATE nx_effect_queue SET pending_limit=1,tenant_limit=2",
        "UPDATE nx_effect_queue SET singleton=NULL",
        "UPDATE nx_outbox SET payload='[]'",
        "UPDATE nx_outbox SET attempts=6",
        "UPDATE nx_outbox SET ordinal=2",
        "UPDATE nx_outbox SET eligible_ms=-1",
        "UPDATE nx_outbox SET state='succeeded'",
        "UPDATE nx_outbox SET tenant='missing'",
        "DELETE FROM nx_effect_tenants",
    ] {
        let mut tx = db.begin(deadline()).await.unwrap();
        assert!(
            tx.execute(sql, &[]).await.is_err(),
            "native schema accepted {sql}"
        );
        tx.rollback().await.unwrap();
    }
    for (column, value) in [
        ("reason", "€".repeat(22)),
        (
            "payload",
            format!("{{\"large\":\"{}\"}}", "x".repeat(196608)),
        ),
    ] {
        let mut tx = db.begin(deadline()).await.unwrap();
        assert!(
            tx.execute(
                &format!("UPDATE nx_outbox SET {column}=$1"),
                &[value.into()]
            )
            .await
            .is_err()
        );
        tx.rollback().await.unwrap();
    }
    db.initialize().await.unwrap();
    let mut tx = db.begin_read(deadline()).await.unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT id FROM nx_outbox", &[])
            .await
            .unwrap(),
        [[String::from("effect")]]
    );
    tx.commit().await.unwrap();
}
async fn forged(db: &Database, sql: &[&str]) {
    let mut tx = db.begin(deadline()).await.unwrap();
    for s in sql {
        tx.execute(s.to_string(), &[]).await.unwrap();
    }
    tx.commit().await.unwrap();
    assert!(
        db.initialize().await.is_err(),
        "forged native layout accepted: {sql:?}"
    );
}
#[tokio::test]
async fn sqlite_valid_outbox_native_layout_survives_restart() {
    let case = sqlite("valid-").await;
    valid(&case.db).await;
    let mut tx = case.db.begin(deadline()).await.unwrap();
    assert!(
        tx.execute("UPDATE nx_effect_queue SET pending_limit=1.5", &[])
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn sqlite_rejects_missing_checks_keys_nullability_and_wrong_indexes() {
    for (label, from, to) in [
        ("check-", "CHECK(tenant_limit<=pending_limit)", "CHECK(1)"),
        ("key-", "PRIMARY KEY(singleton)", "CHECK(singleton=1)"),
        ("null-", "store_id TEXT NOT NULL", "store_id TEXT"),
    ] {
        let case = sqlite(label).await;
        let replacement = SQLITE[0].replacen(from, to, 1);
        assert_ne!(replacement, SQLITE[0]);
        forged(&case.db, &["DROP TABLE nx_effect_queue", &replacement]).await;
    }
    let case = sqlite("index-").await;
    forged(
        &case.db,
        &[
            "DROP INDEX nx_outbox_eligible",
            "CREATE INDEX nx_outbox_eligible ON nx_outbox(deployment,state,first_eligible_ms,id)",
        ],
    )
    .await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_valid_outbox_native_layout_survives_restart() {
    valid(&postgres("valid").await).await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_rejects_missing_check_nullability_and_index_method() {
    for (label, sql) in [
        (
            "check",
            "ALTER TABLE nx_effect_queue DROP CONSTRAINT nx_effect_queue_concurrency_check",
        ),
        (
            "null",
            "ALTER TABLE nx_effect_grants ALTER COLUMN declaration DROP NOT NULL",
        ),
    ] {
        forged(&postgres(label).await, &[sql]).await;
    }
    forged(&postgres("brin").await,&["DROP INDEX nx_outbox_eligible","CREATE INDEX nx_outbox_eligible ON nx_outbox USING brin(deployment,state,eligible_ms,id)"]).await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_rejects_foreign_namespace_tenant_link() {
    forged(&postgres("foreign").await,&["CREATE SCHEMA shadow","CREATE TABLE shadow.nx_effect_tenants(deployment TEXT,tenant TEXT,PRIMARY KEY(deployment,tenant))","ALTER TABLE nx_outbox DROP CONSTRAINT nx_outbox_deployment_tenant_fkey","ALTER TABLE nx_outbox ADD CONSTRAINT nx_outbox_deployment_tenant_fkey FOREIGN KEY(deployment,tenant) REFERENCES shadow.nx_effect_tenants(deployment,tenant)"]).await;
}
