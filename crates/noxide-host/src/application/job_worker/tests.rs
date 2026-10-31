use super::*;
use crate::{
    application::jobs::{JobRunOutcome, tests::Case},
    jobs::{JobOperatorCommand as Command, JobOperatorResult as Output},
};

#[tokio::test]
async fn background_worker_executes_real_action_and_drains() {
    let case = Case::new(None, false).await;
    let job = case.create("ready").await;
    let service = case.app.start_job_service().unwrap().unwrap();
    assert!(case.app.start_job_service().is_err());
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if case.stored(&job).await.0 == "succeeded" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    service.shutdown().await.unwrap();
    case.app
        .request_lifecycle
        .wait_idle_for_test()
        .await
        .unwrap();
    assert_eq!(
        case.stored(&job).await,
        ("succeeded".into(), "finished".into(), 1)
    );
    let runtime = case.app.jobs.as_ref().unwrap();
    assert!(!runtime.running.load(Ordering::Acquire));
    assert_eq!(runtime.workers.available_permits(), 2);
    assert_eq!(runtime.database.available_permits(), 2);
    case.close().await;
}

#[tokio::test]
async fn shutdown_waits_for_in_flight_effect_and_actual_provider_drain() {
    use std::{future::Future, task::Poll};
    let case = Case::new(None, false).await;
    let job = case.create("ready").await;
    let gate = crate::failure_tests::EffectWait::new();
    let service = gate
        .scope(async { case.app.start_job_service().unwrap().unwrap() })
        .await;
    // The acknowledgment comes from the existing post-mutation boundary of the
    // actual action transaction, not from a timer or a synthetic queue executor.
    tokio::time::timeout(case.app.runtime.limits().wall_time, gate.wait_reached())
        .await
        .unwrap();
    let runtime = case.app.jobs.as_ref().unwrap();
    let capacity = usize::from(runtime.effective.limits.worker_concurrency);
    assert!(runtime.workers.available_permits() < capacity);
    assert!(runtime.database.available_permits() < capacity);
    assert!(case.app.request_lifecycle.ensure_idle().is_err());
    assert_eq!(
        case.stored(&job).await,
        (String::from("running"), String::from("ready"), 0)
    );
    let mut shutdown = Box::pin(service.shutdown());
    let first_poll =
        std::future::poll_fn(|cx| Poll::Ready(Future::poll(shutdown.as_mut(), cx))).await;
    assert!(
        first_poll.is_pending(),
        "shutdown returned while the action transaction was held"
    );
    assert!(runtime.workers.available_permits() < capacity);
    assert!(runtime.database.available_permits() < capacity);
    assert!(case.app.request_lifecycle.ensure_idle().is_err());
    gate.resume();
    shutdown.await.unwrap();
    // Assert immediately after shutdown, before any extra await could mask an
    // early return while registered provider cleanup still owns capacity.
    assert!(case.app.request_lifecycle.ensure_idle().is_ok());
    assert_eq!(runtime.workers.available_permits(), capacity);
    assert_eq!(runtime.database.available_permits(), capacity);
    assert!(!runtime.running.load(Ordering::Acquire));
    assert_eq!(
        case.stored(&job).await,
        (String::from("succeeded"), String::from("finished"), 1)
    );
    case.close().await;
}

#[tokio::test]
async fn operator_regrant_requires_linked_reconciliation_and_current_authority() {
    let case = Case::new(None, false).await;
    let job = case.create("ready").await;
    let id = job.id().unwrap();
    case.app
        .operate_jobs(Command::Revoke {
            tenant: "team".into(),
            worker: "repair".into(),
        })
        .await
        .unwrap();
    assert_eq!(case.stored(&job).await.0, "paused");
    assert!(
        case.app
            .operate_jobs(Command::Reconcile { id: id.clone() })
            .await
            .is_err()
    );
    assert_eq!(case.stored(&job).await.0, "paused");
    case.app
        .operate_jobs(Command::Grant {
            tenant: "team".into(),
            worker: "repair".into(),
        })
        .await
        .unwrap();
    assert_eq!(case.stored(&job).await.0, "paused");
    let Output::Reconciled { id: replacement } = case
        .app
        .operate_jobs(Command::Reconcile { id: id.clone() })
        .await
        .unwrap()
    else {
        panic!("expected linked replacement")
    };
    assert_ne!(id, replacement);
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let link = tx
        .fetch::<2>(
            "SELECT reconciled_from,state FROM nx_jobs WHERE id=$1",
            &[replacement.clone().into()],
        )
        .await
        .unwrap();
    assert_eq!(link[0], [id, "pending".into()]);
    tx.commit().await.unwrap();
    assert!(matches!(
        case.app.run_job_once().await.unwrap(),
        Some(JobRunOutcome::Completed {
            recovered: false,
            ..
        })
    ));
    assert_eq!(
        case.stored(&job).await,
        ("rejected".into(), "finished".into(), 0)
    );
    case.close().await;
}

#[tokio::test]
async fn inherited_worker_slot_cannot_bypass_another_application_capacity() {
    let first = Case::new(None, false).await;
    let second = Case::new(None, false).await;
    let first_runtime = first.app.jobs.as_ref().unwrap();
    let second_runtime = second.app.jobs.as_ref().unwrap();
    let slot = WorkerSlot {
        owner: first_runtime.workers.clone(),
        permit: Arc::new(first_runtime.workers.clone().try_acquire_owned().unwrap()),
    };
    WORKER_SLOT
        .scope(
            slot,
            second
                .app
                .request_scope(second.app.runtime.limits().wall_time)
                .run(async {
                    let admission = second.app.admit_job_invocation_work().await.unwrap();
                    assert_eq!(first_runtime.workers.available_permits(), 1);
                    assert_eq!(second_runtime.workers.available_permits(), 1);
                    drop(admission);
                    assert_eq!(second_runtime.workers.available_permits(), 2);
                }),
        )
        .await;
    assert_eq!(first_runtime.workers.available_permits(), 2);
    first.close().await;
    second.close().await;
}
