use super::*;
use crate::test_support as fixture;
use std::time::Duration;

async fn read_advance(app: &Application, now: i64) {
    let mut tx = app
        .database
        .begin_read(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    security::observe_clock_read(&mut tx, now, &app.time.observed)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn stored_clock(db: &Database) -> i64 {
    let mut tx = db
        .begin_read(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let rows = tx
        .fetch::<1>(
            "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    rows[0][0].parse().unwrap()
}

async fn write_clock_uses_read_watermark(db: Database) {
    db.initialize().await.unwrap();
    db.create_account("alice", "clock regression password", "")
        .await
        .unwrap();
    let m = fixture::manifest();
    let app = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
        crate::DeploymentResources {
            effects: None,
            jobs: None,
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap();
    app.activate().await.unwrap();
    let wall = security::now().unwrap();
    let high = wall + 30;
    read_advance(&app, high).await;
    assert!(stored_clock(&db).await < high);
    let challenge = app.login_challenge().await.unwrap();
    assert_eq!(
        app.keys.verify(&challenge.cookie, high).unwrap().issued,
        high
    );
    let (expired_challenge, signed) = app.keys.issue(TokenKind::Login, "", wall - 60, 75).unwrap();
    assert!(app.keys.verify(&signed, wall).is_ok());
    assert!(matches!(
        app.login(
            &signed,
            &app.keys.csrf(&expired_challenge.nonce).unwrap(),
            "alice",
            "clock regression password"
        )
        .await,
        Err(RequestError::InvalidRequest)
    ));
    assert!(stored_clock(&db).await < high);

    let session = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "clock regression password",
        )
        .await
        .unwrap();
    assert_eq!(app.keys.verify(&session, high).unwrap().issued, high);
    assert_eq!(stored_clock(&db).await, high);

    read_advance(&app, high + 1).await;
    let page = app.view(&session, 1, None).await.unwrap();
    let html = std::str::from_utf8(&page.body).unwrap();
    let submission = fixture::hidden(html, "_submission");
    let csrf = fixture::hidden(html, "_csrf");
    let token = app.keys.verify(&submission, high + 1).unwrap();
    let (_, expired) = app
        .keys
        .issue(token.kind.clone(), &token.subject, wall - 60, 75)
        .unwrap();
    assert!(app.keys.verify(&expired, wall).is_ok());
    let input = Fields::from([("body".into(), "read watermark".into())]);
    assert!(
        app.submit(&session, 1, &expired, &csrf, input.clone())
            .await
            .is_err()
    );
    assert!(
        app.recover_form(&session, 1, &expired, &csrf, &input, true)
            .await
            .is_err()
    );
    // Writes leave a read watermark within the persist lag to the clock tick,
    // so concurrent writes do not contend on nx_clock.
    let lag = security::CLOCK_PERSIST_LAG;
    app.submit(&session, 1, &submission, &csrf, input.clone())
        .await
        .unwrap();
    assert_eq!(stored_clock(&db).await, high);
    read_advance(&app, high + lag).await;
    app.recover_form(&session, 1, &submission, &csrf, &input, true)
        .await
        .unwrap();
    assert_eq!(stored_clock(&db).await, high);
    // Beyond the lag (the tick is not persisting), the write persists it.
    read_advance(&app, high + lag + 1).await;
    app.logout(&session, &csrf).await.unwrap();
    assert_eq!(stored_clock(&db).await, high + lag + 1);

    // The exact boundary is evaluated against raw wall time, not an
    // already-substituted effective time, even if durable time lags.
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        app.observe_clock_write(&mut tx, high + lag + 1 - 60)
            .await
            .unwrap(),
        high + lag + 1
    );
    assert_eq!(
        app.observe_clock_write(&mut tx, high + lag + 1 - 61)
            .await
            .unwrap_err()
            .to_string(),
        "clock moved backwards beyond tolerance; use recover-clock with a fresh host key"
    );
    tx.rollback().await.unwrap();
    let durable = stored_clock(&db).await;
    read_advance(&app, wall + 120).await;
    let snapshot = {
        let mut tx = db
            .begin_read(std::time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let rows = tx.snapshot().await.unwrap();
        tx.commit().await.unwrap();
        rows
    };
    assert!(matches!(
        app.login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "clock regression password"
        )
        .await,
        Err(RequestError::Rejected)
    ));
    assert!(matches!(
        app.logout(&session, &csrf).await,
        Err(RequestError::Rejected)
    ));
    assert!(matches!(
        app.submit(&session, 1, &submission, &csrf, input.clone())
            .await,
        Err(RequestError::Rejected)
    ));
    assert!(
        app.recover_form(&session, 1, &submission, &csrf, &input, true)
            .await
            .is_err()
    );
    assert_eq!(stored_clock(&db).await, durable);
    let mut tx = db
        .begin_read(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(tx.snapshot().await.unwrap(), snapshot);
    tx.commit().await.unwrap();
    db.recover_clock(HostKeys::generate().unwrap().incarnation())
        .await
        .unwrap();
    assert!(
        app.checkpoint_clock().await.is_err(),
        "a dirty retired process must not checkpoint"
    );
}

#[tokio::test]
async fn sqlite_idle_checkpoint_takes_no_writer_lock() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("idle-checkpoint.db"));
    db.initialize().await.unwrap();
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let activated_wall = security::now().unwrap();
    security::observe_clock(&mut tx, activated_wall)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let m = fixture::manifest();
    let app = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
        crate::DeploymentResources {
            effects: None,
            jobs: None,
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap();
    app.activate().await.unwrap();
    assert!(app.time.checkpointed.load(Ordering::Relaxed) >= activated_wall);
    let mut writer = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(100), app.checkpoint_clock())
        .await
        .unwrap()
        .unwrap();
    writer.rollback().await.unwrap();

    let high = app.time.checkpointed.load(Ordering::Relaxed) + 1;
    read_advance(&app, high).await;
    app.checkpoint_clock().await.unwrap();
    assert_eq!(app.time.checkpointed.load(Ordering::Relaxed), high);
    assert_eq!(stored_clock(&db).await, high);
    let mut writer = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    // No read has advanced memory since the successful checkpoint. This
    // would hit the 200 ms deadline if a second checkpoint opened a writer.
    tokio::time::timeout(Duration::from_millis(100), app.checkpoint_clock())
        .await
        .unwrap()
        .unwrap();
    read_advance(&app, high + 1).await;
    assert!(app.checkpoint_clock().await.is_err());
    assert_eq!(app.time.checkpointed.load(Ordering::Relaxed), high);
    writer.rollback().await.unwrap();
    app.checkpoint_clock().await.unwrap();
    assert_eq!(app.time.checkpointed.load(Ordering::Relaxed), high + 1);
    assert_eq!(stored_clock(&db).await, high + 1);
}

#[tokio::test]
async fn sqlite_writes_honor_read_clock_before_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    write_clock_uses_read_watermark(Database::sqlite(temp.path().join("read-clock.db"))).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_writes_honor_read_clock_before_checkpoint() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_read_write_clock_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&format!("/{name}"));
    write_clock_uses_read_watermark(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
