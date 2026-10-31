//! Acknowledged operator COMMIT must retain connection ownership until SQLx
//! confirms worker shutdown. The gate holds the real post-commit connection.
use super::*;
use std::{future::Future, path::PathBuf, task::Poll};
use tokio::sync::{Notify, Semaphore};

#[derive(Default)]
struct CloseGate {
    reached: AtomicBool,
    closed: AtomicBool,
    entered: Notify,
    resume: Notify,
}
tokio::task_local! { static CLOSE_GATE: Arc<CloseGate>; }
pub(super) async fn before_operator_close() {
    if let Ok(gate) = CLOSE_GATE.try_with(Clone::clone) {
        gate.reached.store(true, Ordering::Release);
        gate.entered.notify_one();
        gate.resume.notified().await;
    }
}
pub(super) fn operator_closed() {
    let _ = CLOSE_GATE.try_with(|gate| gate.closed.store(true, Ordering::Release));
}

struct Fixture {
    database: Database,
    observer: sqlx::SqliteConnection,
}
async fn fixture(label: &str) -> Fixture {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/capability-evidence/p10-bootstrap-close-fixtures");
    std::fs::create_dir_all(&root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix(label)
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
    // This idle observer permits deterministic reads after COMMIT and keeps
    // the fixture open. Production bootstrap/maintenance options are unchanged.
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .pragma("trusted_schema", "OFF");
    let observer = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    eprintln!("retained operator close fixture: {}", path.display());
    Fixture {
        database: Database::sqlite(path),
        observer,
    }
}
async fn maintenance_starts(database: &Database) {
    let slots = Arc::new(Semaphore::new(1));
    let mut lease = MaintenanceLease::new(
        slots.clone().try_acquire_owned().unwrap(),
        Instant::now() + Duration::from_secs(1),
        crate::lifecycle_clock::Freshness::default(),
    );
    lease.begin(database).await.unwrap();
    assert_eq!(
        lease
            .tx()
            .fetch::<1>("PRAGMA journal_mode", &[])
            .await
            .unwrap(),
        [[String::from("wal")]]
    );
    lease.finish().await.unwrap();
    assert_eq!(slots.available_permits(), 1);
}

#[tokio::test]
async fn initializer_and_account_commit_wait_for_sqlite_worker_close() {
    let mut fixture = fixture("acknowledged-").await;
    let gate = Arc::new(CloseGate::default());
    let mut initialize = Box::pin(CLOSE_GATE.scope(gate.clone(), fixture.database.initialize()));
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut initialize => panic!("initializer returned before its post-commit close gate: {result:?}"),
            _ = gate.entered.notified() => {}
        }
        assert!(gate.reached.load(Ordering::Acquire));
        assert!(!gate.closed.load(Ordering::Acquire));
        let committed: i64 = sqlx::query_scalar("SELECT version FROM nx_storage WHERE singleton=1").fetch_one(&mut fixture.observer).await.unwrap();
        assert_eq!(committed, STORAGE_VERSION);
        assert!(std::future::poll_fn(|cx| Poll::Ready(Future::poll(initialize.as_mut(), cx))).await.is_pending());
        gate.resume.notify_one();
        initialize.await.unwrap();
    }).await.expect("initializer close must stay within its original bootstrap deadline");
    assert!(
        gate.closed.load(Ordering::Acquire),
        "return must follow physical worker-close acknowledgment"
    );
    maintenance_starts(&fixture.database).await;

    let gate = Arc::new(CloseGate::default());
    let mut account = Box::pin(
        CLOSE_GATE.scope(
            gate.clone(),
            fixture
                .database
                .create_account("alice", "operator fixture password", ""),
        ),
    );
    let id = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut account => panic!("account returned before its post-commit close gate: {result:?}"),
            _ = gate.entered.notified() => {}
        }
        let committed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nx_accounts WHERE login_name='alice'").fetch_one(&mut fixture.observer).await.unwrap();
        assert_eq!(committed, 1);
        assert!(!gate.closed.load(Ordering::Acquire));
        assert!(std::future::poll_fn(|cx| Poll::Ready(Future::poll(account.as_mut(), cx))).await.is_pending());
        gate.resume.notify_one();
        account.await.unwrap()
    }).await.expect("account close must fit the existing operator transaction deadline");
    assert!(!id.is_empty());
    assert!(gate.closed.load(Ordering::Acquire));
    maintenance_starts(&fixture.database).await;
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&mut fixture.observer)
        .await
        .unwrap();
    assert_eq!(mode, "wal");
    fixture.observer.close().await.unwrap();
}

#[tokio::test]
async fn pre_ack_loss_stays_unknown_and_does_not_enter_acknowledged_close() {
    let mut fixture = fixture("lost-ack-").await;
    fixture.database.initialize().await.unwrap();
    let mut tx = fixture
        .database
        .begin(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    tx.execute("UPDATE nx_clock SET observed=7 WHERE singleton=1", &[])
        .await
        .unwrap();
    let gate = Arc::new(CloseGate::default());
    let error = CLOSE_GATE
        .scope(
            gate.clone(),
            crate::failure_tests::lose_commit_ack(tx.commit()),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<CommitFailure>(),
        Some(CommitFailure::Uncertain(_))
    ));
    assert!(!retryable(&error));
    assert!(tx.commit_may_have_succeeded());
    assert!(!tx.commit_acknowledged());
    assert!(!gate.reached.load(Ordering::Acquire));
    assert!(!gate.closed.load(Ordering::Acquire));
    let error = tx.rollback().await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<CommitFailure>(),
        Some(CommitFailure::Uncertain(_))
    ));
    assert!(!retryable(&error));
    assert!(tx.commit_may_have_succeeded());
    drop(tx);
    let observed: i64 = sqlx::query_scalar("SELECT observed FROM nx_clock WHERE singleton=1")
        .fetch_one(&mut fixture.observer)
        .await
        .unwrap();
    assert_eq!(
        observed, 7,
        "unknown acknowledgment never becomes proof of abort"
    );
    fixture.observer.close().await.unwrap();
}

#[tokio::test]
async fn after_ack_close_timeout_is_committed_cleanup_under_original_deadline() {
    let mut fixture = fixture("close-timeout-").await;
    fixture.database.initialize().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut tx = fixture.database.begin(deadline).await.unwrap();
    tx.execute("UPDATE nx_clock SET observed=11 WHERE singleton=1", &[])
        .await
        .unwrap();
    let gate = Arc::new(CloseGate::default());
    let error = CLOSE_GATE
        .scope(gate.clone(), tx.commit())
        .await
        .unwrap_err();
    assert!(gate.reached.load(Ordering::Acquire));
    assert!(
        !gate.closed.load(Ordering::Acquire),
        "the fixture never acknowledges the held close"
    );
    assert!(tx.commit_acknowledged());
    assert!(tx.commit_may_have_succeeded());
    assert_eq!(tx.deadline, deadline.into());
    assert!(matches!(tx.backend, Backend::Closed));
    assert!(matches!(
        error.downcast_ref::<CommitFailure>(),
        Some(CommitFailure::Committed(_))
    ));
    assert!(!retryable(&error));
    let error = tx.rollback().await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<CommitFailure>(),
        Some(CommitFailure::Committed(_))
    ));
    assert!(!retryable(&error));
    let observed: i64 = sqlx::query_scalar("SELECT observed FROM nx_clock WHERE singleton=1")
        .fetch_one(&mut fixture.observer)
        .await
        .unwrap();
    assert_eq!(observed, 11);
    fixture.observer.close().await.unwrap();
}
