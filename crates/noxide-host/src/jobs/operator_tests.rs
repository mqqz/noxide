use crate::{
    Database,
    database::{
        Transaction,
        lifecycle::{AdmissionOwner, Registry, RequestScope},
    },
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
// Real operator commands use admitted ordinary transactions. Drain their
// registered providers before opening the next no-wait startup transaction.
async fn operator_phase<T>(
    database: &Database,
    operation: impl for<'a> std::ops::AsyncFnOnce(&'a mut Transaction) -> T,
) -> T {
    let registry = std::sync::Arc::new(Registry::default());
    let cap = Duration::from_secs(5);
    let scope = RequestScope::new(
        registry.clone(),
        tokio::time::Instant::now() + cap,
        cap,
        256,
    );
    let requests = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let databases = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let owner = AdmissionOwner::new(
        scope,
        std::sync::Arc::new(requests.try_acquire_owned().unwrap()),
        std::sync::Arc::new(databases.try_acquire_owned().unwrap()),
        None,
    );
    let value = owner
        .run(async {
            let mut tx = database
                .begin(owner.work_deadline().into_std())
                .await
                .unwrap();
            let value = operation(&mut tx).await;
            tx.commit().await.unwrap();
            value
        })
        .await;
    registry.shutdown().await.unwrap();
    value
}
async fn setup(database: &Database) {
    database.initialize().await.unwrap();
    operator_phase(database, async |tx: &mut Transaction| {
        tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'approval','incarnation','generation') ON CONFLICT(singleton) DO UPDATE SET contract='approval',incarnation='incarnation',generation='generation'", &[]).await.unwrap();
    }).await;
}
async fn activate(
    database: &Database,
    contract: &str,
    declaration: &JobContract,
    effective: &EffectiveJobDeployment,
    phase: &str,
) {
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let mut lease = crate::database::MaintenanceLease::new(
        permits.try_acquire_owned().unwrap(),
        Instant::now() + Duration::from_secs(5),
        crate::lifecycle_clock::Freshness::default(),
    );
    lease
        .begin(database)
        .await
        .unwrap_or_else(|error| panic!("P10 operator activation phase={phase} begin: {error:#}"));
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
    activate(&database, "approval", &declaration, &effective, "initial").await;
    let original = operator_phase(&database, async |tx: &mut Transaction| {
        let original = tx
            .fetch::<1>("SELECT epoch FROM nx_job_runtime", &[])
            .await
            .unwrap()[0][0]
            .clone();
        tx.revoke_job_grant("generation", "alpha", "repair")
            .await
            .unwrap();
        original
    })
    .await;
    activate(
        &database,
        "approval",
        &declaration,
        &effective,
        "restart_after_revoke",
    )
    .await;
    let fork = operator_phase(&database, async |tx: &mut Transaction| {
        assert_eq!(
            tx.fetch::<2>("SELECT epoch,state FROM nx_job_runtime", &[])
                .await
                .unwrap()[0],
            [original.clone(), String::from("active")]
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
        fork
    })
    .await;
    activate(
        &database,
        "approval",
        &declaration,
        &effective,
        "restart_after_fork",
    )
    .await;
    operator_phase(&database, async |tx: &mut Transaction| {
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
    })
    .await;
    activate(
        &database,
        "new_approval",
        &declaration,
        &effective,
        "contract_change",
    )
    .await;
    operator_phase(&database, async |tx: &mut Transaction| {
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
    })
    .await;
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

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE; fixture retained"]
async fn postgres_operator_restart_revocation_and_restore_do_not_resume_authority() {
    let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
    let name = format!(
        "nx_p10_operator_{}_{}",
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
    admin.close().await.unwrap();
    let mut url = url::Url::parse(&root).unwrap();
    url.set_path(&format!("/{name}"));
    eprintln!("retained P10 PostgreSQL operator lifecycle fixture: {name}");
    operator_lifecycle(Database::postgres(url.as_str()).unwrap()).await;
}
