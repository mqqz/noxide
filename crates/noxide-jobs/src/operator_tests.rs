use crate::JobOperatorTransaction as _;
use crate::{
    database::Database,
    database::{
        Transaction,
        lifecycle::{AdmissionOwner, Registry, RequestScope},
    },
    job_deployment::{EffectiveJobDeployment, JobDeployment, JobGrant, JobLimits},
};
use noxide_protocol::jobs::{JobContract, RecurringSchedule, Worker, WorkerAction};
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
        recurring: vec![RecurringSchedule {
            name: "periodic".into(),
            worker: "repair".into(),
            action: 2,
            interval: noxide_protocol::time::Duration::from_millis(60_000).unwrap(),
            inputs: Default::default(),
            selection: None,
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
fn operator_admission() -> (AdmissionOwner, std::sync::Arc<Registry>) {
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
    (owner, registry)
}
// Real operator commands use admitted ordinary transactions. Drain their
// registered providers before opening the next no-wait startup transaction.
async fn operator_phase<T>(
    database: &Database,
    operation: impl for<'a> std::ops::AsyncFnOnce(&'a mut Transaction) -> T,
) -> T {
    let (owner, registry) = operator_admission();
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
async fn activate_generation(
    database: &Database,
    generation: &str,
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
        .unwrap_or_else(|error| panic!("operator activation phase={phase} begin: {error:#}"));
    lease
        .tx()
        .activate_jobs(
            generation,
            contract,
            Some(effective),
            Some(declaration),
            false,
        )
        .await
        .unwrap();
    lease.tx().commit().await.unwrap();
    lease.finish().await.unwrap();
}
async fn activate(
    database: &Database,
    contract: &str,
    declaration: &JobContract,
    effective: &EffectiveJobDeployment,
    phase: &str,
) {
    activate_generation(
        database,
        "generation",
        contract,
        declaration,
        effective,
        phase,
    )
    .await;
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
    paused_generation_restart(&database, &declaration, &effective).await;
}
async fn paused_generation_restart(
    database: &Database,
    declaration: &JobContract,
    effective: &EffectiveJobDeployment,
) {
    let (job_id, watermark) = operator_phase(database, async |tx: &mut Transaction| {
        let payload = tx.fetch::<1>("SELECT declaration FROM nx_job_grants WHERE deployment='generation'", &[]).await.unwrap();
        let grant: crate::Grant = serde_json::from_str(&payload[0][0]).unwrap();
        let schedule = noxide_protocol::jobs::Schedule { source_action: 1, ordinal: 0, worker: "repair".into(), action: 2, targets: Default::default(), inputs: Default::default(), due_at: noxide_protocol::Value::TransactionTime };
        let now = noxide_protocol::time::Timestamp::UNIX_EPOCH;
        let job = crate::CapturedJob::capture(&schedule, "clock_recovery_pending".into(), &grant, 1, now, now, Default::default(), Default::default()).unwrap();
        let mut calls = 16;
        assert!(crate::QueueContext { tx: &mut *tx, calls: &mut calls }.enqueue(&job, now, 1000).await.unwrap());
        tx.execute("UPDATE nx_clock SET lifecycle_ms=123456,lifecycle_version=9 WHERE singleton=1", &[]).await.unwrap();
        let clock = tx.fetch::<2>("SELECT CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock WHERE singleton=1", &[]).await.unwrap()[0].clone();
        (job.id().unwrap(), clock)
    }).await;
    // Exercise the actual central clock recovery with a new key incarnation.
    // It retires the generation without resetting the observed lifecycle clock.

    let (owner, registry) = operator_admission();
    owner
        .run(database.recover_clock("fresh-incarnation"))
        .await
        .unwrap();
    registry.shutdown().await.unwrap();
    let generation = operator_phase(database, async |tx: &mut Transaction| {
        let generation = tx.fetch::<1>("SELECT generation FROM nx_deployment WHERE singleton=1", &[]).await.unwrap()[0][0].clone();
        assert_ne!(generation, "generation");
        assert_eq!(tx.fetch::<2>("SELECT CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock WHERE singleton=1", &[]).await.unwrap()[0], watermark);
        assert_eq!(tx.fetch::<1>("SELECT state FROM nx_jobs WHERE id=$1", &[job_id.as_str().into()]).await.unwrap()[0][0], "paused");
        assert_eq!(tx.fetch::<1>("SELECT state FROM nx_job_recurring WHERE deployment='generation'", &[]).await.unwrap()[0][0], "paused");
        assert_eq!(tx.fetch::<1>("SELECT state FROM nx_job_runtime", &[]).await.unwrap()[0][0], "paused");
        generation
    }).await;
    for phase in [
        "paused_generation_change",
        "paused_generation_second_restart",
    ] {
        activate_generation(
            database,
            &generation,
            "new_approval",
            declaration,
            effective,
            phase,
        )
        .await;
        operator_phase(database, async |tx: &mut Transaction| {
            assert_eq!(
                tx.fetch::<2>("SELECT deployment,state FROM nx_job_runtime", &[])
                    .await
                    .unwrap()[0],
                [generation.clone(), String::from("paused")]
            );
            assert_eq!(
                tx.fetch::<1>(
                    "SELECT state FROM nx_job_grants WHERE deployment=$1",
                    &[generation.as_str().into()]
                )
                .await
                .unwrap()[0][0],
                "revoked"
            );
            assert_eq!(
                tx.fetch::<1>(
                    "SELECT state FROM nx_job_recurring WHERE deployment=$1",
                    &[generation.as_str().into()]
                )
                .await
                .unwrap()[0][0],
                "paused"
            );
            let mut calls = 16;
            assert!(
                crate::QueueContext {
                    tx,
                    calls: &mut calls
                }
                .claim(&generation, noxide_protocol::time::Timestamp::UNIX_EPOCH)
                .await
                .is_err()
            );
        })
        .await;
    }
    operator_phase(database, async |tx: &mut Transaction| {
        tx.grant_job_service(
            &generation,
            "new_approval",
            &effective.grants[0],
            declaration,
        )
        .await
        .unwrap();
        assert_eq!(
            tx.fetch::<1>("SELECT state FROM nx_job_runtime", &[])
                .await
                .unwrap()[0][0],
            "active"
        );
        assert_eq!(
            tx.fetch::<1>(
                "SELECT state FROM nx_job_grants WHERE deployment=$1",
                &[generation.as_str().into()]
            )
            .await
            .unwrap()[0][0],
            "active"
        );
        assert_eq!(
            tx.fetch::<1>(
                "SELECT state FROM nx_job_recurring WHERE deployment=$1",
                &[generation.as_str().into()]
            )
            .await
            .unwrap()[0][0],
            "active"
        );
        assert_eq!(
            tx.fetch::<1>(
                "SELECT state FROM nx_job_grants WHERE deployment='generation'",
                &[]
            )
            .await
            .unwrap()[0][0],
            "revoked"
        );
        assert_eq!(
            tx.fetch::<1>(
                "SELECT state FROM nx_job_recurring WHERE deployment='generation'",
                &[]
            )
            .await
            .unwrap()[0][0],
            "paused"
        );
        assert_eq!(
            tx.fetch::<1>(
                "SELECT state FROM nx_jobs WHERE id=$1",
                &[job_id.as_str().into()]
            )
            .await
            .unwrap()[0][0],
            "paused"
        );
    })
    .await;
}
#[tokio::test]
async fn sqlite_operator_restart_revocation_and_restore_do_not_resume_authority() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-fixtures/job-operator-fixtures");
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
    eprintln!("retained operator lifecycle fixture: {}", path.display());
    operator_lifecycle(Database::sqlite(path)).await;
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE; fixture retained"]
async fn postgres_operator_restart_revocation_and_restore_do_not_resume_authority() {
    let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
    let name = format!(
        "nx_job_operator_{}_{}",
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
    eprintln!("retained PostgreSQL operator lifecycle fixture: {name}");
    operator_lifecycle(Database::postgres(url.as_str()).unwrap()).await;
}
