use super::*;

fn owner(
    registry: Arc<Registry>,
    cap: Duration,
) -> (AdmissionOwner, Arc<Semaphore>, Arc<Semaphore>) {
    let request = Arc::new(Semaphore::new(1));
    let database = Arc::new(Semaphore::new(1));
    let scope = RequestScope::new(registry, tokio::time::Instant::now() + cap, cap, 256);
    (
        AdmissionOwner::new(
            scope,
            Arc::new(request.clone().try_acquire_owned().unwrap()),
            Arc::new(database.clone().try_acquire_owned().unwrap()),
            None,
        ),
        request,
        database,
    )
}

#[tokio::test]
async fn frontend_cancel_retains_capacity_through_acknowledged_sqlite_close() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::sqlite(directory.path().join("owned.db"));
    database.initialize().await.unwrap();
    let registry = Arc::new(Registry::default());
    let (owner, requests, slots) = owner(registry.clone(), Duration::from_secs(2));
    let (started, observed) = tokio::sync::oneshot::channel();
    let working = database.clone();
    let frontend = tokio::spawn(async move {
        owner
            .run(async {
                let mut tx = working
                    .begin(owner.work_deadline().into_std())
                    .await
                    .unwrap();
                tx.execute("UPDATE nx_clock SET observed=42 WHERE singleton=1", &[])
                    .await
                    .unwrap();
                started.send(()).unwrap();
                std::future::pending::<()>().await;
                drop(tx);
            })
            .await;
    });
    observed.await.unwrap();
    assert_eq!(requests.available_permits(), 0);
    assert_eq!(slots.available_permits(), 0);
    frontend.abort();
    assert!(frontend.await.unwrap_err().is_cancelled());
    registry.shutdown().await.unwrap();
    assert_eq!(requests.available_permits(), 1);
    assert_eq!(slots.available_permits(), 1);
    let mut read = database
        .begin_read(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(
        read.fetch::<1>(
            "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
            &[]
        )
        .await
        .unwrap(),
        [["0".to_owned()]]
    );
    read.commit().await.unwrap();
}

#[tokio::test]
async fn committed_lost_ack_keeps_unknown_frontier_after_confirmed_stop() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::sqlite(directory.path().join("lost-ack.db"));
    database.initialize().await.unwrap();
    let registry = Arc::new(Registry::default());
    let (owner, requests, slots) = owner(registry.clone(), Duration::from_secs(2));
    owner
        .run(async {
            let mut tx = database
                .begin(owner.work_deadline().into_std())
                .await
                .unwrap();
            tx.execute("UPDATE nx_clock SET observed=42 WHERE singleton=1", &[])
                .await
                .unwrap();
            let error = crate::database::fault::lose_commit_ack(tx.commit())
                .await
                .unwrap_err();
            assert!(error.is::<commit::CommitFailure>());
            assert!(tx.commit_may_have_succeeded());
            assert!(!tx.commit_acknowledged());
            assert!(RequestScope::commit_pending());
            let cleanup = tx.rollback().await.unwrap_err();
            assert!(cleanup.is::<commit::CommitFailure>());
            assert!(!retryable(&cleanup));
        })
        .await;
    drop(owner);
    registry.shutdown().await.unwrap();
    assert_eq!(requests.available_permits(), 1);
    assert_eq!(slots.available_permits(), 1);
    let mut read = database
        .begin_read(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(
        read.fetch::<1>(
            "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
            &[]
        )
        .await
        .unwrap(),
        [["42".to_owned()]]
    );
    read.commit().await.unwrap();
}

#[tokio::test]
async fn original_scope_and_closed_registry_never_mint_new_admission() {
    let registry = Arc::new(Registry::default());
    let outer = tokio::time::Instant::now() + Duration::from_secs(1);
    let scope = RequestScope::new(registry.clone(), outer, Duration::from_secs(2), 256);
    scope
        .run(async {
            let nested =
                RequestScope::current_or_new(registry.clone(), Duration::from_secs(3), 256);
            assert_eq!(nested.deadline(), outer);
            assert_eq!(nested.phase(Duration::from_secs(60)).deadline(), outer);
            assert!(Arc::ptr_eq(&nested.root.provider, &scope.root.provider));
        })
        .await;
    registry.shutdown().await.unwrap();
    let (owner, requests, slots) = owner(registry, Duration::from_secs(1));
    let result = owner
        .begin(
            Database::sqlite("must-not-create.db"),
            owner.work_deadline().into_std(),
            true,
        )
        .await;
    assert!(result.err().unwrap().is::<Unavailable>());
    drop(owner);
    assert_eq!(requests.available_permits(), 1);
    assert_eq!(slots.available_permits(), 1);
}
