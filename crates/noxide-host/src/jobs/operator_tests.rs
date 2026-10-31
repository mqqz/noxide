use crate::{
    Database,
    job_deployment::{EffectiveJobDeployment, JobDeployment, JobGrant, JobLimits},
};
use noxide_protocol::jobs::{JobContract, Worker, WorkerAction};
use sqlx::Connection;
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

fn approved() -> (JobContract, EffectiveJobDeployment) {
    let declaration = JobContract {
        workers: vec![Worker {
            name: "repair".into(),
            actions: vec![WorkerAction {
                action: 2,
                targets: Default::default(),
            }],
        }],
        ..Default::default()
    };
    let effective = JobDeployment {
        grants: vec![JobGrant {
            worker: "repair".into(),
            tenant: "alpha".into(),
            actions: BTreeSet::from([2]),
        }],
        limits: JobLimits::default(),
    }
    .effective(&declaration)
    .unwrap();
    (declaration, effective)
}
async fn setup(database: &Database) {
    database.initialize().await.unwrap();
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'approval','incarnation','generation') ON CONFLICT(singleton) DO UPDATE SET contract='approval',incarnation='incarnation',generation='generation'", &[]).await.unwrap();
    tx.commit().await.unwrap();
}
async fn activate(
    database: &Database,
    contract: &str,
    declaration: &JobContract,
    effective: &EffectiveJobDeployment,
) {
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let mut lease = crate::database::MaintenanceLease::new(
        permits.try_acquire_owned().unwrap(),
        Instant::now() + Duration::from_secs(5),
        crate::lifecycle_clock::Freshness::default(),
    );
    lease.begin(database).await.unwrap();
    lease
        .tx()
        .activate_jobs("generation", contract, Some(effective), Some(declaration))
        .await
        .unwrap();
    lease.tx().commit().await.unwrap();
    lease.finish().await.unwrap();
}
async fn operator_lifecycle(database: Database) {
    setup(&database).await;
    let (declaration, effective) = approved();
    activate(&database, "approval", &declaration, &effective).await;
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let original = tx
        .fetch::<1>("SELECT epoch FROM nx_job_runtime", &[])
        .await
        .unwrap()[0][0]
        .clone();
    tx.revoke_job_grant("generation", "alpha", "repair")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    activate(&database, "approval", &declaration, &effective).await;
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<2>("SELECT epoch,state FROM nx_job_runtime", &[])
            .await
            .unwrap()[0],
        [original.clone(), "active".into()]
    );
    assert_eq!(
        tx.fetch::<2>("SELECT CAST(version AS TEXT),state FROM nx_job_grants", &[])
            .await
            .unwrap()[0],
        [String::from("1"), String::from("revoked")]
    );
    tx.fork_job_runtime("generation").await.unwrap();
    let fork = tx
        .fetch::<2>("SELECT epoch,state FROM nx_job_runtime", &[])
        .await
        .unwrap()[0]
        .clone();
    assert_ne!(fork[0], original);
    assert_eq!(fork[1], "paused");
    tx.commit().await.unwrap();
    activate(&database, "approval", &declaration, &effective).await;
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<2>("SELECT epoch,state FROM nx_job_runtime", &[])
            .await
            .unwrap()[0],
        fork
    );
    assert!(
        tx.grant_job_service(
            "generation",
            "retired_approval",
            &effective.grants[0],
            &declaration
        )
        .await
        .is_err()
    );
    tx.grant_job_service("generation", "approval", &effective.grants[0], &declaration)
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<2>("SELECT CAST(version AS TEXT),state FROM nx_job_grants", &[])
            .await
            .unwrap()[0],
        [String::from("2"), String::from("active")]
    );
    tx.commit().await.unwrap();
    activate(&database, "new_approval", &declaration, &effective).await;
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_ne!(
        tx.fetch::<1>("SELECT epoch FROM nx_job_runtime", &[])
            .await
            .unwrap()[0][0],
        fork[0]
    );
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(version AS TEXT) FROM nx_job_grants", &[])
            .await
            .unwrap()[0][0],
        "3"
    );
    tx.commit().await.unwrap();
}
#[tokio::test]
async fn sqlite_operator_restart_revocation_and_restore_do_not_resume_authority() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/capability-evidence/p10-operator-fixtures");
    std::fs::create_dir_all(&root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("lifecycle-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    let path = directory.join("operator.db");
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
    // An idle fixture connection keeps the database open across setup and
    // startup. This prevents the last SQLite handle's asynchronous close and
    // WAL checkpoint from racing no-wait maintenance admission. Production
    // timeouts and startup behavior are unchanged.
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
        .foreign_keys(true)
        .pragma("trusted_schema", "OFF");
    let _anchor = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    eprintln!(
        "retained P10 operator lifecycle fixture: {}",
        path.display()
    );
    operator_lifecycle(Database::sqlite(path)).await;
}
