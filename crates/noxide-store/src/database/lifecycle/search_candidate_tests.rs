use super::*;
fn scope() -> RequestScope {
    RequestScope::new(
        Arc::new(Registry::default()),
        tokio::time::Instant::now() + Duration::from_secs(2),
        Duration::from_secs(2),
        256,
    )
}
#[tokio::test]
async fn candidate_budget_requires_owner_and_survives_nested_phases() {
    assert!(RequestScope::search_candidates_remaining().is_err());
    assert!(RequestScope::charge_search_candidates(0).is_err());
    let scope = scope();
    scope
        .run(async {
            assert_eq!(RequestScope::search_candidates_remaining().unwrap(), 256);
            RequestScope::charge_search_candidates(10).unwrap();
            let nested = RequestScope::current_or_new(
                scope.root.registry.clone(),
                Duration::from_secs(1),
                256,
            );
            nested
                .run(async {
                    RequestScope::charge_search_candidates(100).unwrap();
                })
                .await;
            let phase = scope.phase(Duration::from_secs(1));
            phase
                .run(async {
                    assert_eq!(RequestScope::search_candidates_remaining().unwrap(), 146);
                    RequestScope::charge_search_candidates(146).unwrap();
                })
                .await;
            assert!(RequestScope::charge_search_candidates(1).is_err());
            RequestScope::charge_search_candidates(0).unwrap();
            assert_eq!(RequestScope::search_candidates_remaining().unwrap(), 0);
            assert_eq!(scope.root.meter.snapshot(), (256, 0, 0));
        })
        .await;
}
#[tokio::test]
async fn concurrent_candidate_charge_has_one_winner_and_no_failed_work() {
    let scope = scope();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let work = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let scope = scope.clone();
        let barrier = barrier.clone();
        let work = work.clone();
        tasks.push(tokio::spawn(async move {
            scope
                .run(async {
                    barrier.wait().await;
                    let result = RequestScope::charge_search_candidates(256);
                    if result.is_ok() {
                        work.fetch_add(256, Ordering::AcqRel);
                    }
                    result.is_ok()
                })
                .await
        }));
    }
    barrier.wait().await;
    let a = tasks.remove(0).await.unwrap();
    let b = tasks.remove(0).await.unwrap();
    assert_ne!(a, b);
    assert_eq!(work.load(Ordering::Acquire), 256);
    scope
        .run(async {
            assert_eq!(RequestScope::search_candidates_remaining().unwrap(), 0);
        })
        .await;
}
#[tokio::test(start_paused = true)]
async fn candidate_zero_charge_still_rejects_expired_or_cancelled_scope() {
    let expired = scope();
    expired
        .run(async {
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(RequestScope::charge_search_candidates(0).is_err());
            assert!(RequestScope::search_candidates_remaining().is_err());
        })
        .await;
    let live = scope();
    live.root.cancelled.store(true, Ordering::Release);
    live.run(async {
        assert!(RequestScope::charge_search_candidates(0).is_err());
    })
    .await;
}
