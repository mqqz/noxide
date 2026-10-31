//! Durable cursor deferral only; the selector owns canonical frontier contents.
use super::*;
use crate::Database;
use noxide_protocol::jobs::{Worker, WorkerAction};
use sqlx::Connection;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn at(ms: i64) -> Timestamp {
    Timestamp::from_unix_millis(ms).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + std::time::Duration::from_secs(5)
}

async fn deferred_scan(database: Database) {
    database.initialize().await.unwrap();
    let declaration = RecurringSchedule {
        name: "repair".into(),
        worker: "expiry".into(),
        action: 2,
        interval: Duration::from_millis(60_000).unwrap(),
        inputs: BTreeMap::new(),
        selection: None,
    };
    let mut tx = database.begin(deadline()).await.unwrap();
    tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'contract','incarnation','deployment')", &[]).await.unwrap();
    tx.execute("INSERT INTO nx_job_runtime(singleton,deployment,contract,epoch,state,pending_limit,tenant_limit,concurrency) VALUES(1,'deployment','contract','epoch','active',1000,1000,2)", &[]).await.unwrap();
    tx.execute(
        "UPDATE nx_creation_counter SET value=100 WHERE singleton=1",
        &[],
    )
    .await
    .unwrap();
    for tenant in ["alpha", "beta"] {
        let grant = Grant {
            scope: JobScope {
                deployment: "deployment".into(),
                tenant: tenant.into(),
            },
            worker: Worker {
                name: "expiry".into(),
                actions: vec![WorkerAction {
                    action: 2,
                    targets: BTreeMap::new(),
                }],
            },
            version: 1,
            contract: "contract".into(),
            epoch: "epoch".into(),
        };
        tx.execute("INSERT INTO nx_job_grants(deployment,tenant,worker,version,contract,epoch,state,declaration) VALUES('deployment',$1,'expiry',1,'contract','epoch','active',$2)", &[tenant.into(), serde_json::to_string(&grant).unwrap().into()]).await.unwrap();
    }
    // This opaque preexisting frontier is preserved byte-for-byte. No test
    // cursor is passed to the selector or presented as row progress.
    tx.execute("INSERT INTO nx_job_recurring(deployment,tenant,name,contract,epoch,grant_version,version,state,next_ms,cutoff_ms,cutoff_seq,cursor) VALUES('deployment','alpha','repair','contract','epoch',1,7,'active',1000,900,50,'persisted_frontier')", &[]).await.unwrap();
    tx.execute("INSERT INTO nx_job_recurring(deployment,tenant,name,contract,epoch,grant_version,version,state,next_ms,cutoff_ms,cutoff_seq,cursor) VALUES('deployment','beta','repair','contract','epoch',1,1,'active',1001,0,0,'')", &[]).await.unwrap();
    tx.commit().await.unwrap();
    let scope = JobScope {
        deployment: "deployment".into(),
        tenant: "alpha".into(),
    };
    let mut tx = database.begin(deadline()).await.unwrap();
    assert_eq!(tx.fetch::<1>("SELECT tenant FROM nx_job_recurring WHERE state='active' AND next_ms<=2000 ORDER BY next_ms,tenant,name LIMIT 1", &[]).await.unwrap(), [[String::from("alpha")]]);
    let mut calls = 16;
    let mut queue = QueueContext {
        tx: &mut tx,
        calls: &mut calls,
    };
    let batch = queue
        .begin_recurrence(&scope, &declaration, at(2000))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (batch.cutoff(), batch.cutoff_seq(), batch.cursor()),
        (at(900), 50, Some("persisted_frontier"))
    );
    queue.defer_recurrence(batch).await.unwrap();
    assert_eq!(
        calls, 14,
        "begin and deferral each consume one existing logical call"
    );
    tx.commit().await.unwrap();
    let mut tx = database.begin(deadline()).await.unwrap();
    assert_eq!(tx.fetch::<5>("SELECT CAST(version AS TEXT),CAST(next_ms AS TEXT),CAST(cutoff_ms AS TEXT),CAST(cutoff_seq AS TEXT),cursor FROM nx_job_recurring WHERE tenant='alpha'", &[]).await.unwrap(), [[String::from("8"), String::from("3000"), String::from("900"), String::from("50"), String::from("persisted_frontier")]]);
    assert_eq!(tx.fetch::<1>("SELECT tenant FROM nx_job_recurring WHERE state='active' AND next_ms<=2000 ORDER BY next_ms,tenant,name LIMIT 1", &[]).await.unwrap(), [[String::from("beta")]], "the no-progress tenant cannot monopolize the oldest due slot");
    let mut calls = 16;
    assert!(
        QueueContext {
            tx: &mut tx,
            calls: &mut calls
        }
        .begin_recurrence(&scope, &declaration, at(2999))
        .await
        .unwrap()
        .is_none()
    );
    let batch = QueueContext {
        tx: &mut tx,
        calls: &mut calls,
    }
    .begin_recurrence(&scope, &declaration, at(3000))
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        (batch.cutoff(), batch.cutoff_seq(), batch.cursor()),
        (at(900), 50, Some("persisted_frontier"))
    );
    assert!(
        QueueContext {
            tx: &mut tx,
            calls: &mut calls
        }
        .finish_recurrence(batch, Some("persisted_frontier"))
        .await
        .is_err(),
        "unchanged frontier must still fail the progress guard"
    );
    tx.rollback().await.unwrap();
    let mut tx = database.begin(deadline()).await.unwrap();
    let mut calls = 16;
    let batch = QueueContext {
        tx: &mut tx,
        calls: &mut calls,
    }
    .begin_recurrence(&scope, &declaration, at(3000))
    .await
    .unwrap()
    .unwrap();
    tx.execute(
        "UPDATE nx_job_recurring SET version=version+1 WHERE tenant='alpha'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        QueueContext {
            tx: &mut tx,
            calls: &mut calls
        }
        .defer_recurrence(batch)
        .await
        .is_err(),
        "a stale scan version cannot defer newer work"
    );
    tx.rollback().await.unwrap();
    let mut tx = database.begin(deadline()).await.unwrap();
    assert_eq!(tx.fetch::<2>("SELECT CAST((SELECT COUNT(*) FROM nx_jobs) AS TEXT),CAST((SELECT COUNT(*) FROM nx_job_occurrences) AS TEXT)", &[]).await.unwrap(), [[String::from("0"), String::from("0")]], "deferral creates neither jobs nor occurrences");
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn sqlite_no_progress_defers_scan_without_losing_cutoffs_or_tenant_fairness() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/capability-evidence/p10-recurrence-fixtures");
    std::fs::create_dir_all(&root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("defer-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    eprintln!("retained P10 recurrence fixture: {}", directory.display());
    deferred_scan(Database::sqlite(directory.join("recurrence.db"))).await;
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE; fixture retained"]
async fn postgres_no_progress_defers_scan_without_losing_cutoffs_or_tenant_fairness() {
    let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
    let name = format!(
        "nx_p10_defer_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    admin.close().await.unwrap();
    let mut url = url::Url::parse(&root).unwrap();
    url.set_path(&format!("/{name}"));
    eprintln!("retained P10 recurrence fixture: {name}");
    deferred_scan(Database::postgres(url.as_str()).unwrap()).await;
}
