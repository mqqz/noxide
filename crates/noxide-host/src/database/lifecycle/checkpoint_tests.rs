use super::*;

fn scope() -> RequestScope {
    RequestScope::new(
        Arc::new(Registry::default()),
        tokio::time::Instant::now() + Duration::from_secs(60),
        Duration::from_secs(2),
        256,
    )
}
#[tokio::test(start_paused = true)]
async fn required_checkpoint_never_mints_context_or_restarts_deadline() {
    assert!(RequestScope::checkpoint_current().is_err());
    let scope = scope();
    let deadline = scope.work_deadline();
    scope
        .run(async {
            RequestScope::checkpoint_current().unwrap();
            tokio::time::advance(Duration::from_secs(1)).await;
            let nested = RequestScope::current_or_new(
                scope.root.registry.clone(),
                Duration::from_secs(2),
                256,
            );
            assert_eq!(nested.work_deadline(), deadline);
            nested
                .run(async {
                    RequestScope::checkpoint_current().unwrap();
                })
                .await;
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(
                RequestScope::checkpoint_current()
                    .unwrap_err()
                    .is::<Unavailable>()
            );
        })
        .await;
    assert!(!scope.root.cancelled.load(Ordering::Acquire));
    assert_eq!(scope.root.meter.snapshot(), (256, 0, 0));
}
#[tokio::test]
async fn completed_nested_results_and_approved_phase_do_not_cancel_root() {
    let scope = scope();
    scope
        .run(async {
            let nested = RequestScope::current_or_new(
                scope.root.registry.clone(),
                Duration::from_secs(1),
                256,
            );
            let failed: Result<()> = nested
                .run(async { Err(anyhow::anyhow!("bounded rejection")) })
                .await;
            assert!(failed.is_err());
            RequestScope::checkpoint_current().unwrap();
            let phase = scope.phase(Duration::from_secs(2));
            assert!(Arc::ptr_eq(&phase.root, &scope.root));
            phase
                .run(async {
                    RequestScope::checkpoint_current().unwrap();
                })
                .await;
            RequestScope::checkpoint_current().unwrap();
        })
        .await;
    assert!(!scope.root.cancelled.load(Ordering::Acquire));
}
#[tokio::test]
async fn owning_future_drop_cancels_root_and_later_phases() {
    let scope = scope();
    let worker = scope.clone();
    let (started, observed) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        worker
            .run(async {
                started.send(()).unwrap();
                std::future::pending::<()>().await
            })
            .await
    });
    observed.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(scope.root.cancelled.load(Ordering::Acquire));
    let phase = scope.phase(Duration::from_secs(60));
    assert!(
        phase
            .run(async { RequestScope::checkpoint_current() })
            .await
            .is_err()
    );
    assert_eq!(phase.root.meter.snapshot(), (256, 0, 0));
}
#[tokio::test]
async fn operator_token_is_transaction_bound_and_denies_request_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::sqlite(directory.path().join("operator-token.db"));
    database.initialize().await.unwrap();
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let checkpoint = tx.operator_checkpoint().unwrap();
    checkpoint.checkpoint().unwrap();
    let scope = scope();
    scope
        .run(async {
            assert!(checkpoint.checkpoint().is_err());
            assert!(tx.operator_checkpoint().is_err());
        })
        .await;
    checkpoint.checkpoint().unwrap();
    tx.commit().await.unwrap();
    assert!(checkpoint.checkpoint().is_err());
    assert!(tx.operator_checkpoint().is_err());
    let tx = database
        .begin(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let checkpoint = tx.operator_checkpoint().unwrap();
    drop(tx);
    assert!(checkpoint.checkpoint().is_err());
    let mut clock = database
        .begin_maintenance(Instant::now() + Duration::from_millis(200))
        .await
        .unwrap();
    assert!(
        clock.operator_checkpoint().is_err(),
        "SQLite maintenance lacks Control but remains a separate host class"
    );
    clock.rollback().await.unwrap();
    let absent = directory.path().join("must-not-create.db");
    assert!(
        scope
            .run(Database::sqlite(&absent).initialize())
            .await
            .is_err()
    );
    assert!(!absent.exists());
    let request = Arc::new(Semaphore::new(1));
    let slots = Arc::new(Semaphore::new(1));
    let owner = AdmissionOwner::new(
        scope.clone(),
        Arc::new(request.try_acquire_owned().unwrap()),
        Arc::new(slots.try_acquire_owned().unwrap()),
        None,
    );
    let before = scope.root.meter.snapshot();
    let result = owner.run(database.initialize()).await;
    assert!(result.unwrap_err().is::<Unavailable>());
    assert_eq!(
        scope.root.meter.snapshot(),
        before,
        "admitted bootstrap issued SQL"
    );
    assert_eq!(scope.root.registry.state.lock().unwrap().active, 0);
    owner
        .run(async {
            let mut ordinary = database
                .begin(owner.work_deadline().into_std())
                .await
                .unwrap();
            assert!(ordinary.operator_checkpoint().is_err());
            ordinary.rollback().await.unwrap();
        })
        .await;
}
