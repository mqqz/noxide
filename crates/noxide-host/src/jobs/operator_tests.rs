use super::*;
use crate::{
    Database,
    job_deployment::{JobDeployment, JobGrant, JobLimits},
};
use noxide_protocol::jobs::{Worker, WorkerAction};
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
    for line in include_str!("schema.sql")
        .lines()
        .filter(|line| line.starts_with("CREATE "))
    {
        let sql = line
            .replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
            .replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ");
        tx.execute(&sql, &[]).await.unwrap();
    }
    tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'approval','incarnation','generation') ON CONFLICT(singleton) DO UPDATE SET contract='approval',incarnation='incarnation',generation='generation'", &[]).await.unwrap();
    tx.commit().await.unwrap();
}
async fn operator_lifecycle(database: Database) {
    setup(&database).await;
    let (declaration, effective) = approved();
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.activate_jobs(
        "generation",
        "approval",
        Some(&effective),
        Some(&declaration),
    )
    .await
    .unwrap();
    let original = tx
        .fetch::<1>("SELECT epoch FROM nx_job_runtime", &[])
        .await
        .unwrap()[0][0]
        .clone();
    tx.commit().await.unwrap();
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.revoke_job_grant("generation", "alpha", "repair")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.activate_jobs(
        "generation",
        "approval",
        Some(&effective),
        Some(&declaration),
    )
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
        ["1".into(), "revoked".into()]
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
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.activate_jobs(
        "generation",
        "approval",
        Some(&effective),
        Some(&declaration),
    )
    .await
    .unwrap();
    assert_eq!(
        tx.fetch::<2>("SELECT epoch,state FROM nx_job_runtime", &[])
            .await
            .unwrap()[0],
        fork
    );
    assert!(
        tx.grant_job_service("generation", "retired_approval", &effective.grants[0])
            .await
            .is_err()
    );
    tx.grant_job_service("generation", "approval", &effective.grants[0])
        .await
        .unwrap();
    let rows = tx
        .fetch::<2>("SELECT CAST(version AS TEXT),state FROM nx_job_grants", &[])
        .await
        .unwrap();
    assert_eq!(rows[0], ["2".into(), "active".into()]);
    tx.activate_jobs(
        "generation",
        "new_approval",
        Some(&effective),
        Some(&declaration),
    )
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
    let temp = tempfile::tempdir().unwrap();
    operator_lifecycle(Database::sqlite(temp.path().join("operator.db"))).await;
}
