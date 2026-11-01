use super::*;
use std::sync::atomic::Ordering;

fn clock(ms: i64, version: i64) -> DurableClock {
    DurableClock {
        watermark: Timestamp::from_unix_millis(ms).unwrap(),
        version,
    }
}
fn committed(clock: DurableClock, started: Instant) -> CommittedTick {
    CommittedTick {
        clock,
        started,
        credential_seconds: clock.watermark.unix_seconds_floor(),
    }
}
fn observed(clock: DurableClock, started: Instant) -> HeartbeatObservation {
    HeartbeatObservation { clock, started }
}

#[test]
fn startup_requires_own_confirmed_durable_tick() {
    let freshness = Freshness::default();
    let now = Instant::now();
    assert!(freshness.attempt_at(clock(1_000, 1), now).is_err());
    assert!(
        freshness
            .observe_at(observed(clock(1_000, 1), now), now)
            .is_err()
    );
    assert!(
        freshness
            .observe_at(observed(clock(2_000, 2), now), now)
            .is_err()
    );
    freshness
        .committed_at(committed(clock(1_000, 1), now), now)
        .unwrap();
    assert_eq!(
        freshness
            .attempt_at(clock(1_000, 1), now)
            .unwrap()
            .timestamp()
            .unix_millis(),
        1_000
    );
}

#[test]
fn stale_rereads_never_renew_five_second_lease() {
    let freshness = Freshness::default();
    let start = Instant::now();
    freshness
        .committed_at(committed(clock(1_000, 1), start), start)
        .unwrap();
    for millis in [1_000, 4_999, 5_000, 30_000] {
        let now = start + Duration::from_millis(millis);
        freshness
            .observe_at(observed(clock(1_000, 1), now), now)
            .unwrap();
        assert_eq!(
            freshness.attempt_at(clock(1_000, 1), now).is_ok(),
            millis < 5_000
        );
    }
}

#[test]
fn new_version_with_unchanged_watermark_proves_progress() {
    let freshness = Freshness::default();
    let start = Instant::now();
    freshness
        .committed_at(committed(clock(10_000, 1), start), start)
        .unwrap();
    let next = start + Duration::from_secs(4);
    freshness
        .observe_at(observed(clock(10_000, 2), next), next)
        .unwrap();
    // A higher version proves progress after the previous observation at t=0,
    // not this read at t=4. Another tick advances the proven lower bound.
    let following = start + Duration::from_secs(5);
    freshness
        .observe_at(observed(clock(10_000, 3), following), following)
        .unwrap();
    assert!(
        freshness
            .attempt_at(clock(10_000, 3), start + Duration::from_secs(8))
            .is_ok()
    );
    assert!(
        freshness
            .attempt_at(clock(10_000, 3), start + Duration::from_secs(9))
            .is_err()
    );
}

#[test]
fn stale_unseen_version_is_only_a_baseline_until_actual_new_progress() {
    let freshness = Freshness::default();
    let start = Instant::now();
    freshness
        .committed_at(committed(clock(10_000, 1), start), start)
        .unwrap();
    let stale = start + Duration::from_secs(30);
    freshness
        .observe_at(observed(clock(10_000, 99), stale), stale)
        .unwrap();
    assert!(freshness.attempt_at(clock(10_000, 99), stale).is_err());
    let next = stale + Duration::from_secs(1);
    freshness
        .observe_at(observed(clock(10_000, 100), next), next)
        .unwrap();
    assert!(freshness.attempt_at(clock(10_000, 100), next).is_ok());
}

#[test]
fn delayed_observation_regression_and_old_snapshots_fail_closed() {
    let freshness = Freshness::default();
    let start = Instant::now();
    freshness
        .committed_at(committed(clock(10_000, 2), start), start)
        .unwrap();
    assert!(
        freshness
            .observe_at(observed(clock(11_000, 3), start), start + FRESHNESS_LIMIT)
            .is_err()
    );
    assert!(
        freshness
            .observe_at(observed(clock(9_999, 3), start), start)
            .is_err()
    );
    assert!(
        freshness
            .observe_at(observed(clock(10_000, 1), start), start)
            .is_err()
    );
    assert!(
        freshness
            .observe_at(observed(clock(10_001, 2), start), start)
            .is_err()
    );
    assert!(freshness.attempt_at(clock(10_000, 1), start).is_err());
    assert!(freshness.attempt_at(clock(9_999, 3), start).is_err());
}

#[test]
fn delayed_higher_version_cannot_renew_from_current_read_start() {
    let freshness = Freshness::default();
    let start = Instant::now();
    freshness
        .committed_at(committed(clock(10_000, 1), start), start)
        .unwrap();
    let baseline = start + Duration::from_millis(30_000);
    freshness
        .observe_at(observed(clock(10_000, 99), baseline), baseline)
        .unwrap();
    assert!(freshness.attempt_at(clock(10_000, 99), baseline).is_err());

    // Final tick v100 commits at t=30.001, then ticking stops. The read starts
    // at t=34.900 and is delivered at t=39.800, matching the review reproducer.
    let read_started = start + Duration::from_millis(34_900);
    let delivered = start + Duration::from_millis(39_800);
    freshness
        .observe_at(observed(clock(10_000, 100), read_started), delivered)
        .unwrap();
    assert!(freshness.attempt_at(clock(10_000, 100), delivered).is_err());
    let reread = start + Duration::from_millis(39_900);
    freshness
        .observe_at(observed(clock(10_000, 100), reread), reread)
        .unwrap();
    assert!(freshness.attempt_at(clock(10_000, 100), reread).is_err());
}

#[test]
fn immediate_higher_version_expires_from_previous_observation_start() {
    let freshness = Freshness::default();
    let start = Instant::now();
    freshness
        .committed_at(committed(clock(10_000, 1), start), start)
        .unwrap();
    let baseline = start + Duration::from_millis(30_000);
    freshness
        .observe_at(observed(clock(10_000, 99), baseline), baseline)
        .unwrap();

    // Final tick commits at t=30.001. Even with immediate delivery at t=34.900,
    // the proven lower bound remains t=30.000 and expires exactly at t=35.000.
    let read_started = start + Duration::from_millis(34_900);
    freshness
        .observe_at(observed(clock(10_000, 100), read_started), read_started)
        .unwrap();
    for (millis, available) in [
        (34_900, true),
        (34_999, true),
        (35_000, false),
        (39_800, false),
    ] {
        assert_eq!(
            freshness
                .attempt_at(clock(10_000, 100), start + Duration::from_millis(millis))
                .is_ok(),
            available,
            "attempt at t={millis}ms"
        );
    }
}

#[test]
fn stopped_ticks_cannot_be_kept_fresh_by_repeated_reads() {
    let freshness = Freshness::default();
    let start = Instant::now();
    freshness
        .committed_at(committed(clock(10_000, 1), start), start)
        .unwrap();
    // New versions are read at t=1, 2, 3. The final v4 tick committed at
    // t=2.001. The final proof is anchored at the preceding read, t=2.000.
    for second in 1..=3 {
        let now = start + Duration::from_secs(second);
        freshness
            .observe_at(observed(clock(10_000, second as i64 + 1), now), now)
            .unwrap();
    }
    for (millis, available) in [(4_000, true), (6_999, true), (7_000, false), (8_000, false)] {
        let now = start + Duration::from_millis(millis);
        freshness
            .observe_at(observed(clock(10_000, 4), now), now)
            .unwrap();
        assert_eq!(
            freshness.attempt_at(clock(10_000, 4), now).is_ok(),
            available
        );
    }
}

#[test]
fn restart_and_delayed_own_tick_require_new_confirmed_fresh_progress() {
    let restarted = Freshness::default();
    let start = Instant::now();
    let current = start + Duration::from_millis(40_000);
    for version in [100, 101] {
        assert!(
            restarted
                .observe_at(observed(clock(10_000, version), current), current)
                .is_err()
        );
    }
    assert!(restarted.attempt_at(clock(10_000, 101), current).is_err());
    assert!(
        restarted
            .committed_at(
                committed(clock(10_000, 102), current),
                current + FRESHNESS_LIMIT
            )
            .is_err()
    );
    assert!(
        restarted
            .attempt_at(clock(10_000, 102), current + FRESHNESS_LIMIT)
            .is_err()
    );
    let confirmed = start + Duration::from_millis(46_000);
    restarted
        .committed_at(committed(clock(10_000, 103), confirmed), confirmed)
        .unwrap();
    assert!(restarted.attempt_at(clock(10_000, 103), confirmed).is_ok());
    assert!(
        restarted
            .attempt_at(clock(10_000, 103), confirmed + FRESHNESS_LIMIT)
            .is_err()
    );
}

#[test]
fn quarantined_cleanup_rejects_reads_and_late_progress_across_clones() {
    let freshness = Freshness::default();
    let start = Instant::now();
    freshness
        .committed_at(committed(clock(10_000, 1), start), start)
        .unwrap();
    let cleanup = freshness.clone();
    cleanup.quarantine();
    assert!(freshness.attempt_at(clock(10_000, 1), start).is_err());
    assert!(
        freshness
            .committed_at(committed(clock(11_000, 2), start), start)
            .is_err()
    );
    assert!(
        freshness
            .observe_at(observed(clock(11_000, 2), start), start)
            .is_err()
    );
}

async fn fixture(database: &Database) {
    database.initialize().await.unwrap();
}

async fn sample_tick(
    database: &Database,
    memory: &AtomicI64,
    millis: i64,
) -> Result<CommittedTick> {
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(2))
        .await?;
    tick_sampled(
        &mut tx,
        memory,
        Timestamp::from_unix_millis(millis)?,
        Instant::now(),
    )
    .await
}
async fn snapshot(database: &Database) -> DurableClock {
    let mut tx = database
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let value = read(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    value
}

async fn provider_contract(database: Database) {
    fixture(&database).await;
    let memory = AtomicI64::new(0);
    let freshness = Freshness::default();
    freshness
        .committed(sample_tick(&database, &memory, 100_123).await.unwrap())
        .unwrap();
    assert_eq!(snapshot(&database).await, clock(100_123, 1));

    // No request wall sample: an ahead credential cache must not jump lifecycle.
    memory.store(120, Ordering::Relaxed);
    freshness
        .committed(sample_tick(&database, &memory, 99_999).await.unwrap())
        .unwrap();
    assert_eq!(snapshot(&database).await, clock(100_123, 2));
    let mut get = database
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let attempt = freshness.attempt(&mut get).await.unwrap();
    assert_eq!(attempt.timestamp().unix_millis(), 100_123);
    get.commit().await.unwrap();
    assert_eq!(
        snapshot(&database).await,
        clock(100_123, 2),
        "GET must not write"
    );

    freshness
        .committed(sample_tick(&database, &memory, 130_456).await.unwrap())
        .unwrap();
    assert_eq!(
        attempt.timestamp().unix_millis(),
        100_123,
        "attempt value is fixed"
    );
    assert_eq!(snapshot(&database).await, clock(130_456, 3));

    // Restart discards all process memory. Durable time cannot revive an expiry.
    let restarted = Freshness::default();
    let reset_memory = AtomicI64::new(0);
    restarted
        .committed(
            sample_tick(&database, &reset_memory, 129_000)
                .await
                .unwrap(),
        )
        .unwrap();
    assert_eq!(snapshot(&database).await, clock(130_456, 4));
    let mut get = database
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        restarted
            .attempt(&mut get)
            .await
            .unwrap()
            .timestamp()
            .unix_millis(),
        130_456
    );
    get.commit().await.unwrap();

    let before = snapshot(&database).await;
    assert!(
        sample_tick(&database, &reset_memory, 1_000).await.is_err(),
        "existing credential rollback protection remains"
    );
    assert_eq!(snapshot(&database).await, before, "failed tick rolls back");

    // Exercise real recover-clock: credentials reset, lifecycle stays durable.
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let old_keys = crate::HostKeys::generate().unwrap();
    tx.deployment("clock-fixture", old_keys.incarnation(), true)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let old_lifecycle = snapshot(&database).await;
    database
        .recover_clock(&crate::HostKeys::generate().unwrap())
        .await
        .unwrap();
    assert_eq!(
        snapshot(&database).await,
        old_lifecycle,
        "recovery must retain lifecycle fields"
    );
    let after_recovery = Freshness::default();
    let mut get = database
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert!(
        after_recovery.attempt(&mut get).await.is_err(),
        "recovery cannot implicitly resume temporal serving"
    );
    get.commit().await.unwrap();

    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_clock SET lifecycle_version=$1 WHERE singleton=1",
        &[i64::MAX.into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(
        sample_tick(&database, &reset_memory, 140_000)
            .await
            .is_err()
    );
    assert_eq!(snapshot(&database).await, clock(130_456, i64::MAX));
}

#[tokio::test]
async fn sqlite_durable_lifecycle_contract() {
    let directory = tempfile::tempdir().unwrap();
    provider_contract(Database::sqlite(directory.path().join("clock.db"))).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable local server"]
async fn postgres_durable_lifecycle_contract() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").expect("NOXIDE_TEST_POSTGRES");
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_lifecycle_clock_{}",
        security::random_id()
            .unwrap()
            .replace('-', "a")
            .replace('_', "b")
            .to_lowercase()
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    provider_contract(Database::postgres(case.as_str()).unwrap()).await;
    // Deliberately retain this new fixture database for evidence; delete nothing.
}

#[tokio::test]
async fn production_tick_and_independent_observation_use_real_wall_and_database() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::sqlite(directory.path().join("real-clock.db"));
    fixture(&database).await;
    let freshness = Freshness::default();
    let memory = AtomicI64::new(0);
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    freshness
        .committed(tick(&mut tx, &memory).await.unwrap())
        .unwrap();
    let before = snapshot(&database).await;
    let observation =
        HeartbeatObservation::read(&database, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
    freshness.observe(observation).unwrap();
    assert_eq!(snapshot(&database).await, before);
    assert!(before.watermark.unix_millis() > 0);
    assert_eq!(TICK_INTERVAL, Duration::from_secs(1));
}

#[test]
fn snapshot_before_a_newer_publish_matches_a_recent_tick() {
    let freshness = Freshness::default();
    let start = Instant::now();
    freshness
        .committed_at(committed(clock(10_000, 1), start), start)
        .unwrap();
    let next = start + Duration::from_secs(1);
    freshness
        .committed_at(committed(clock(11_000, 2), next), next)
        .unwrap();
    // A request whose snapshot predates the second commit still sees tick 1.
    assert_eq!(
        freshness
            .attempt_at(clock(10_000, 1), next)
            .unwrap()
            .timestamp(),
        clock(10_000, 1).watermark
    );
    // An older clock that was never published is a regression.
    assert!(freshness.attempt_at(clock(10_000, 0), next).is_err());
    assert!(freshness.attempt_at(clock(9_000, 1), next).is_err());
    // A published tick outside the freshness window no longer qualifies.
    assert!(
        freshness
            .attempt_at(clock(10_000, 1), start + FRESHNESS_LIMIT)
            .is_err()
    );
}
