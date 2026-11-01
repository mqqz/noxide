//! Fresh retained provider fixtures. These probe native enforcement and startup
//! auditing independently of job capture, authorization or execution.
use super::*;
use crate::database::{Database, Param};
use sqlx::Connection;
use std::{
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

struct SqliteFixture {
    db: Database,
    // Prevent last-handle async checkpoint/close from racing the next startup.
    _anchor: sqlx::SqliteConnection,
    _path: PathBuf,
}
async fn sqlite(label: &str) -> SqliteFixture {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-fixtures/jobs-layout-fixtures");
    std::fs::create_dir_all(&root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(root)
        .unwrap()
        .keep();
    let path = directory.join("layout.db");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
    }
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
        .foreign_keys(true);
    let anchor = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let db = Database::sqlite(&path);
    db.initialize().await.unwrap();
    eprintln!("retained SQLite layout fixture: {}", path.display());
    SqliteFixture {
        db,
        _anchor: anchor,
        _path: path,
    }
}

async fn postgres(label: &str) -> Database {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_jobs_layout_{label}_{}_{}",
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
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&format!("/{name}"));
    let db = Database::postgres(case.as_str()).unwrap();
    db.initialize().await.unwrap();
    eprintln!("retained PostgreSQL layout fixture: {name}");
    db
}

async fn insert_job(tx: &mut Transaction, id: &str, parent: &str) -> Result<()> {
    tx.execute("INSERT INTO nx_jobs(id,deployment,tenant,origin,ordinal,worker,action,contract,epoch,grant_version,payload,payload_digest,due_ms,eligible_ms,first_eligible_ms,attempts,fence,lease_until_ms,state,reason,reconciled_from) VALUES($1,'deployment','alpha',$1,0,'repair',2,'contract','epoch',1,'{}','digest',0,0,0,0,0,0,'pending','',NULLIF($2,''))", &[id.into(), parent.into()]).await?;
    Ok(())
}
async fn native_contract(db: &Database) {
    db.initialize().await.unwrap();
    let mut tx = db.begin(deadline()).await.unwrap();
    tx.check_job_layout().await.unwrap();
    tx.execute("INSERT INTO nx_job_runtime(singleton,deployment,contract,epoch,state,pending_limit,tenant_limit,concurrency) VALUES(1,'deployment','contract','epoch','active',1000,1000,2)", &[]).await.unwrap();
    tx.execute(
        "INSERT INTO nx_job_tenants(deployment,tenant,claim_seq) VALUES('deployment','alpha',0)",
        &[],
    )
    .await
    .unwrap();
    insert_job(&mut tx, "parent", "").await.unwrap();
    insert_job(&mut tx, "child", "parent").await.unwrap();
    tx.commit().await.unwrap();
    // PostgreSQL aborts a transaction after an error, so each negative has its
    // own transaction. All failures must come from native storage constraints.
    for sql in [
        "UPDATE nx_job_runtime SET pending_limit=1001",
        "UPDATE nx_job_runtime SET tenant_limit=0",
        "UPDATE nx_job_runtime SET pending_limit=1,tenant_limit=2",
        "UPDATE nx_job_runtime SET concurrency=3",
        "UPDATE nx_jobs SET payload='[]' WHERE id='parent'",
        "UPDATE nx_jobs SET attempts=6 WHERE id='parent'",
        "UPDATE nx_jobs SET due_ms=-1 WHERE id='parent'",
        "UPDATE nx_jobs SET state='cancelled' WHERE id='parent'",
        "UPDATE nx_jobs SET reconciled_from='missing' WHERE id='child'",
        "DELETE FROM nx_jobs WHERE id='parent'",
        "UPDATE nx_jobs SET tenant='missing' WHERE id='child'",
        "INSERT INTO nx_job_runtime(singleton,deployment,contract,epoch,state,pending_limit,tenant_limit,concurrency) VALUES(NULL,'d','c','e','active',1,1,1)",
    ] {
        let mut tx = db.begin(deadline()).await.unwrap();
        assert!(
            tx.execute(sql, &[]).await.is_err(),
            "native schema accepted {sql}"
        );
        tx.rollback().await.unwrap();
    }
    for (column, value) in [
        ("reason", Param::Text("€".repeat(8193))),
        (
            "payload",
            Param::Text(format!("{{\"data\":\"{}\"}}", "x".repeat(16384))),
        ),
        ("payload_digest", Param::Text("€".repeat(22))),
    ] {
        let mut tx = db.begin(deadline()).await.unwrap();
        assert!(
            tx.execute(
                &format!("UPDATE nx_jobs SET {column}=$1 WHERE id='parent'"),
                &[value]
            )
            .await
            .is_err(),
            "native byte bound accepted {column}"
        );
        tx.rollback().await.unwrap();
    }
    db.initialize().await.unwrap();
    let mut tx = db.begin_read(deadline()).await.unwrap();
    assert_eq!(
        tx.fetch::<2>(
            "SELECT id,COALESCE(reconciled_from,'') FROM nx_jobs ORDER BY id",
            &[]
        )
        .await
        .unwrap(),
        [
            [String::from("child"), String::from("parent")],
            [String::from("parent"), String::new()]
        ]
    );
    tx.commit().await.unwrap();
}

async fn forged_startup(db: &Database, statements: &[&str]) {
    let mut tx = db.begin(deadline()).await.unwrap();
    for sql in statements {
        tx.execute(sql, &[]).await.unwrap();
    }
    tx.commit().await.unwrap();
    assert!(
        db.initialize().await.is_err(),
        "startup accepted forged layout: {statements:?}"
    );
}

#[tokio::test]
async fn sqlite_valid_job_layout_enforces_native_bounds_and_links() {
    let fixture = sqlite("valid-").await;
    native_contract(&fixture.db).await;
    let mut tx = fixture.db.begin(deadline()).await.unwrap();
    assert!(
        tx.execute("UPDATE nx_job_runtime SET pending_limit=1.5", &[])
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn sqlite_rejects_missing_check_primary_key_and_index_shape() {
    for (label, from, to) in [
        (
            "missing-check-",
            "CHECK(tenant_limit<=pending_limit)",
            "CHECK(1)",
        ),
        (
            "missing-key-",
            "singleton BIGINT PRIMARY KEY",
            "singleton BIGINT",
        ),
        ("nullable-", "deployment TEXT NOT NULL", "deployment TEXT"),
    ] {
        let fixture = sqlite(label).await;
        let replacement = SQLITE[0].replacen(from, to, 1);
        assert_ne!(replacement, SQLITE[0]);
        forged_startup(&fixture.db, &["DROP TABLE nx_job_runtime", &replacement]).await;
    }
    let fixture = sqlite("wrong-index-").await;
    forged_startup(
        &fixture.db,
        &[
            "DROP INDEX nx_jobs_eligible",
            "CREATE INDEX nx_jobs_eligible ON nx_jobs(deployment,state,due_ms,id)",
        ],
    )
    .await;
    let fixture = sqlite("partial-index-").await;
    forged_startup(
        &fixture.db,
        &[
            "DROP INDEX nx_jobs_quota",
            "CREATE INDEX nx_jobs_quota ON nx_jobs(state,tenant) WHERE state='pending'",
        ],
    )
    .await;
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_valid_job_layout_enforces_native_bounds_and_links() {
    let db = postgres("valid").await;
    native_contract(&db).await;
    let mut tx = db.begin_read(deadline()).await.unwrap();
    let rows = tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class t ON t.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=current_schema() AND t.relname IN ('nx_job_runtime','nx_job_queue','nx_job_grants','nx_job_tenants','nx_jobs','nx_job_recurring','nx_job_occurrences') AND c.contype IN ('p','u','f','c')", &[]).await.unwrap();
    assert_eq!(rows, [[String::from("71")]]);
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_rejects_missing_check_and_changed_nullability() {
    for (label, sql) in [
        (
            "missingcheck",
            "ALTER TABLE nx_job_runtime DROP CONSTRAINT nx_job_runtime_concurrency_check",
        ),
        (
            "nullable",
            "ALTER TABLE nx_job_grants ALTER COLUMN declaration DROP NOT NULL",
        ),
        (
            "requiredlink",
            "ALTER TABLE nx_jobs ALTER COLUMN reconciled_from SET NOT NULL",
        ),
    ] {
        let db = postgres(label).await;
        forged_startup(&db, &[sql]).await;
    }
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_rejects_brin_and_partial_job_indexes() {
    let db = postgres("brin").await;
    forged_startup(
        &db,
        &[
            "DROP INDEX nx_jobs_eligible",
            "CREATE INDEX nx_jobs_eligible ON nx_jobs USING brin(deployment,state,eligible_ms,id)",
        ],
    )
    .await;
    let db = postgres("partialindex").await;
    forged_startup(
        &db,
        &[
            "DROP INDEX nx_jobs_quota",
            "CREATE INDEX nx_jobs_quota ON nx_jobs(state,tenant) WHERE state='pending'",
        ],
    )
    .await;
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_rejects_foreign_namespace_reconciliation_link() {
    let db = postgres("foreignkey").await;
    forged_startup(&db, &[
        "CREATE SCHEMA shadow",
        "CREATE TABLE shadow.nx_jobs(id TEXT PRIMARY KEY)",
        "ALTER TABLE nx_jobs DROP CONSTRAINT nx_jobs_reconciled_from_fkey",
        "ALTER TABLE nx_jobs ADD CONSTRAINT nx_jobs_reconciled_from_fkey FOREIGN KEY(reconciled_from) REFERENCES shadow.nx_jobs(id)",
    ]).await;
}

#[test]
fn fixed_constraint_normalization_preserves_literals_and_index_methods() {
    assert_ne!(
        ddl_key("CHECK(state IN ('active','paused'))"),
        ddl_key("CHECK(state IN ('public.active','paused'))")
    );
    assert_ne!(
        ddl_key(
            "CREATE INDEX nx_jobs_eligible ON public.nx_jobs USING btree (deployment,state,eligible_ms,id)"
        ),
        ddl_key(
            "CREATE INDEX nx_jobs_eligible ON public.nx_jobs USING brin (deployment,state,eligible_ms,id)"
        )
    );
}
