//! Reproductions for the runtime review's contention and transport findings.
use crate::{Application, Database, HostKeys, manifest, runtime::Limits, test_support as fixture};
use noxide_protocol::{Fields, Manifest, TextField};
use std::{
    future::{Future, poll_fn},
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};

async fn app(db: Database, m: Manifest) -> Arc<Application> {
    db.initialize().await.unwrap();
    db.create_account("alice", "review test password", "")
        .await
        .unwrap();
    let app = Arc::new(
        Application::new(
            &fixture::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db,
            HostKeys::generate().unwrap(),
            Limits::default(),
        )
        .unwrap(),
    );
    app.activate().await.unwrap();
    app
}

async fn after_writer_wait<T>(db: &Database, operation: impl Future<Output = T>) -> T {
    let mut writer = db
        .begin(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    // Poll the request while BEGIN IMMEDIATE is blocked, then advance the
    // persisted fence using real time. No fabricated future clock is involved.
    let mut operation = std::pin::pin!(operation);
    let before = crate::security::now().unwrap();
    poll_fn(|cx| {
        assert!(operation.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    while crate::security::now().unwrap() == before {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    crate::security::observe_clock(&mut writer, crate::security::now().unwrap())
        .await
        .unwrap();
    writer.commit().await.unwrap();
    operation.await
}

#[tokio::test]
async fn request_clocks_are_sampled_after_writer_contention() {
    let temp = tempfile::tempdir().unwrap();
    let Database::Sqlite(options) = Database::sqlite(temp.path().join("clock.db")) else {
        unreachable!()
    };
    // Allow a complete second of contention without turning this clock test
    // into a busy-timeout test. Production requests retain their wall budget.
    let db = Database::Sqlite(options.busy_timeout(Duration::from_secs(2)));
    let app = app(db.clone(), fixture::manifest()).await;
    let challenge = after_writer_wait(&db, app.login_challenge()).await.unwrap();
    let session = after_writer_wait(
        &db,
        app.login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "review test password",
        ),
    )
    .await
    .unwrap();
    let page = after_writer_wait(&db, app.view(&session, 1, None))
        .await
        .unwrap();
    let html = String::from_utf8(page.body).unwrap();
    let submission = fixture::hidden(&html, "_submission");
    let csrf = fixture::hidden(&html, "_csrf");
    let input = Fields::from([("body".into(), "after contention".into())]);
    let saved = after_writer_wait(
        &db,
        app.submit(&session, 1, &submission, &csrf, input.clone()),
    )
    .await
    .unwrap();
    let recovered = after_writer_wait(
        &db,
        app.recover_form(&session, 1, &submission, &csrf, &input, true),
    )
    .await
    .unwrap();
    assert_eq!(saved.location, recovered.location);
    after_writer_wait(&db, app.logout(&session, &csrf))
        .await
        .unwrap();
    assert!(app.view(&session, 1, None).await.is_err());
}

async fn clock_conflict<T>(
    db: &Database,
    monitor: &mut sqlx::PgConnection,
    operation: impl Future<Output = T>,
) -> T {
    let mut reset = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    reset
        .execute("UPDATE nx_clock SET observed=0", &[])
        .await
        .unwrap();
    reset.commit().await.unwrap();
    let mut writer = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    crate::security::observe_clock(&mut writer, crate::security::now().unwrap())
        .await
        .unwrap();
    // The request sees the old clock and waits to update the same row. Commit
    // only after PostgreSQL reports that wait, forcing a SERIALIZABLE conflict.
    let mut operation = std::pin::pin!(operation);
    let blocked = async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'UPDATE nx_clock%')",
            ).fetch_one(&mut *monitor).await.unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::select! {
        _ = &mut operation => panic!("request finished before the clock writer committed"),
        result = tokio::time::timeout(Duration::from_secs(1), blocked) => result.unwrap(),
    }
    writer.commit().await.unwrap();
    operation.await
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_clock_conflicts_are_busy() {
    use crate::RequestError;
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_clock_{}",
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
    let db = Database::postgres(case.as_str()).unwrap();
    let mut monitor = sqlx::PgConnection::connect(case.as_str()).await.unwrap();
    let app = app(db.clone(), fixture::manifest()).await;
    let challenge = app.login_challenge().await.unwrap();
    let session = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "review test password",
        )
        .await
        .unwrap();
    let page = String::from_utf8(app.view(&session, 1, None).await.unwrap().body).unwrap();
    let csrf = fixture::hidden(&page, "_csrf");

    assert!(matches!(
        clock_conflict(&db, &mut monitor, app.view(&session, 1, None)).await,
        Err(RequestError::Busy)
    ));
    assert!(matches!(
        clock_conflict(&db, &mut monitor, app.login_challenge()).await,
        Err(RequestError::Busy)
    ));
    assert!(matches!(
        clock_conflict(
            &db,
            &mut monitor,
            app.login(
                &challenge.cookie,
                &challenge.csrf,
                "alice",
                "review test password"
            )
        )
        .await,
        Err(RequestError::Busy)
    ));
    assert!(matches!(
        clock_conflict(&db, &mut monitor, app.logout(&session, &csrf)).await,
        Err(RequestError::Busy)
    ));
    assert!(
        app.view(&session, 1, None).await.is_ok(),
        "aborted logout must keep the session"
    );

    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    crate::security::observe_clock(&mut tx, crate::security::now().unwrap() + 120)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        matches!(
            app.view(&session, 1, None).await,
            Err(RequestError::Rejected)
        ),
        "clock rollback must still fence admission"
    );
    monitor.close().await.unwrap();
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn browser_encoded_maximum_fields_save_and_recover() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let temp = tempfile::tempdir().unwrap();
    let mut m = fixture::manifest();
    m.resources[0].fields.push(TextField {
        kind: noxide_protocol::FieldKind::Text,
        optional: false,
        name: "extra".into(),
        label: "Extra".into(),
        max_bytes: 4096,
    });
    m.actions[0].fields.push("extra".into());
    let app = app(Database::sqlite(temp.path().join("forms.db")), m).await;
    let challenge = app.login_challenge().await.unwrap();
    let session = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "review test password",
        )
        .await
        .unwrap();
    let page = String::from_utf8(app.view(&session, 1, None).await.unwrap().body).unwrap();
    let token = fixture::hidden(&page, "_submission");
    let csrf = fixture::hidden(&page, "_csrf");
    let router = crate::http::router(
        app.clone(),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    let request = |body| {
        Request::builder()
            .method("POST")
            .uri("/actions/1")
            .header("Host", "localhost:8080")
            .header("Origin", "http://localhost:8080")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Cookie", format!("session={session}"))
            .body(Body::from(body))
            .unwrap()
    };
    let encoded = |tail: &str, token: &str| {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("_csrf", &csrf)
            .append_pair("_submission", token)
            .append_pair("body", &format!("{}{tail}", "\r\n".repeat(4095)))
            .append_pair("extra", &format!("{}x", "\r\n".repeat(4095)))
            .finish()
    };
    let body = encoded("x", &token);
    assert!(body.len() > 49_000);
    let saved = router.clone().oneshot(request(body)).await.unwrap();
    assert_eq!(saved.status(), StatusCode::SEE_OTHER);
    // An equivalent non-CRLF encoding has the same canonical receipt identity.
    let canonical = Fields::from([
        ("body".into(), format!("{}x", "\n".repeat(4095))),
        ("extra".into(), format!("{}x", "\n".repeat(4095))),
    ]);
    let replay = app
        .submit(&session, 1, &token, &csrf, canonical)
        .await
        .unwrap();
    assert_eq!(saved.headers()["Location"], replay.location.unwrap());
    let page = String::from_utf8(app.view(&session, 1, None).await.unwrap().body).unwrap();
    let fresh = fixture::hidden(&page, "_submission");
    let invalid = router
        .clone()
        .oneshot(request(encoded("xx", &fresh)))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = String::from_utf8(
        to_bytes(invalid.into_body(), noxide_protocol::MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("aria-invalid=\"true\"") && html.contains(&fresh));
    assert!(html.contains(&format!(">{}xx</textarea>", "\n".repeat(4096))));
    let oversized = router.oneshot(request("x".repeat(65_537))).await.unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

async fn clock_state(db: &Database) -> [String; 5] {
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let rows = tx.fetch::<5>("SELECT incarnation,generation,CAST((SELECT count(*) FROM nx_sessions) AS TEXT),CAST((SELECT count(*) FROM nx_records) AS TEXT),CAST((SELECT count(*) FROM nx_receipts) AS TEXT) FROM nx_deployment WHERE singleton=1", &[]).await.unwrap();
    tx.commit().await.unwrap();
    rows.into_iter().next().unwrap()
}

async fn restart_clock_app(db: &Database, keys: &crate::HostKeys) -> Arc<Application> {
    let m = fixture::manifest();
    let app = Arc::new(
        Application::new(
            &fixture::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db.clone(),
            serde_json::from_slice(&serde_json::to_vec(keys).unwrap()).unwrap(),
            Limits::default(),
        )
        .unwrap(),
    );
    app.activate().await.unwrap();
    app
}

async fn clock_rollback_and_recovery(db: Database) {
    use crate::security::{self, TokenKind};
    let old = app(db.clone(), fixture::manifest()).await;
    // The exact tolerance boundary is deterministic and independent of the
    // machine's clock. The persisted time can only increase during requests.
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        security::observe_clock(&mut tx, 10_000).await.unwrap(),
        10_000
    );
    assert_eq!(
        security::observe_clock(&mut tx, 9_940).await.unwrap(),
        10_000
    );
    assert!(security::observe_clock(&mut tx, 9_939).await.is_err());
    assert!(security::observe_clock(&mut tx, -1).await.is_err());
    let (_, expired_at_high_water) = old.keys.issue(TokenKind::Login, "", 9_900, 80).unwrap();
    assert!(old.keys.verify(&expired_at_high_water, 9_940).is_ok());
    assert!(old.keys.verify(&expired_at_high_water, 10_000).is_err());
    tx.commit().await.unwrap();
    let wall = security::now().unwrap();
    let future = wall + 30;
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        security::observe_clock(&mut tx, future).await.unwrap(),
        future
    );
    tx.commit().await.unwrap();

    // Every request path must use the effective clock, including newly issued
    // future-dated tokens; checking those against raw wall time would reject them.
    let challenge = old.login_challenge().await.unwrap();
    assert_eq!(
        old.keys.verify(&challenge.cookie, future).unwrap().issued,
        future
    );
    let session = old
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "review test password",
        )
        .await
        .unwrap();
    let html = String::from_utf8(old.view(&session, 1, None).await.unwrap().body).unwrap();
    let submission = fixture::hidden(&html, "_submission");
    let csrf = fixture::hidden(&html, "_csrf");
    let input = Fields::from([("body".into(), "preserved through clock recovery".into())]);
    let saved = old
        .submit(&session, 1, &submission, &csrf, input.clone())
        .await
        .unwrap();
    let replay = old
        .recover_form(&session, 1, &submission, &csrf, &input, true)
        .await
        .unwrap();
    assert_eq!(saved.location, replay.location);
    let token = old.keys.verify(&submission, future).unwrap();
    let (_, expired) = old
        .keys
        .issue(token.kind, &token.subject, wall - 60, 75)
        .unwrap();
    assert!(old.keys.verify(&expired, wall).is_ok());
    assert!(
        old.submit(&session, 1, &expired, &csrf, input.clone())
            .await
            .is_err(),
        "effective time must not revive expired authority"
    );

    let restarted = restart_clock_app(&db, &old.keys).await;
    restarted.view(&session, 1, None).await.unwrap();
    // Maintenance must use the same effective time and grace window.
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES('clock-expired','old','old',1,'old','old',$1)", &[(wall - 40).into()]).await.unwrap();
    tx.commit().await.unwrap();
    db.maintain().await.unwrap();
    assert_eq!(clock_state(&db).await[4], "1");
    old.logout(&session, &csrf).await.unwrap();
    assert!(restarted.view(&session, 1, None).await.is_err());
    let challenge = restarted.login_challenge().await.unwrap();
    let session = restarted
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "review test password",
        )
        .await
        .unwrap();

    // Simulate a large correction after expiry collection. Retaining only the
    // old token must never allow its already-committed action to execute again.
    let high = security::now().unwrap() + 7200;
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    security::observe_clock(&mut tx, high).await.unwrap();
    tx.execute("DELETE FROM nx_receipts WHERE expires<$1", &[high.into()])
        .await
        .unwrap();
    tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES('clock-retained','old','old',1,'old','old',$1)", &[(high + 900).into()]).await.unwrap();
    tx.commit().await.unwrap();
    assert!(restarted.login_challenge().await.is_err());
    assert!(db.maintain().await.is_err());
    let before = clock_state(&db).await;
    assert_eq!(&before[2..], ["1", "1", "1"]);
    assert!(
        db.recover_clock(&old.keys).await.is_err(),
        "same key cannot reset clock"
    );
    assert_eq!(clock_state(&db).await, before);

    // A failure after deployment/session writes must roll back the whole reset.
    let fresh = HostKeys::generate().unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute("DELETE FROM nx_clock", &[]).await.unwrap();
    tx.commit().await.unwrap();
    assert!(db.recover_clock(&fresh).await.is_err());
    assert_eq!(clock_state(&db).await, before);
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "INSERT INTO nx_clock(singleton,observed) VALUES(1,$1)",
        &[high.into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    db.recover_clock(&fresh).await.unwrap();
    let after = clock_state(&db).await;
    assert_ne!(after[0], before[0]);
    assert_ne!(after[1], before[1]);
    assert_eq!(&after[2..], ["0", "1", "1"]);
    assert!(old.login_challenge().await.is_err());
    assert!(
        old.activate().await.is_err(),
        "retired process must not reactivate itself"
    );
    assert_eq!(clock_state(&db).await, after);
    let recovered = restart_clock_app(&db, &fresh).await;
    assert!(recovered.view(&session, 1, None).await.is_err());
    assert!(
        fresh
            .verify(&challenge.cookie, security::now().unwrap())
            .is_err()
    );
    let challenge = recovered.login_challenge().await.unwrap();
    let session = recovered
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "review test password",
        )
        .await
        .unwrap();
    let html = String::from_utf8(recovered.view(&session, 1, None).await.unwrap().body).unwrap();
    let new_csrf = fixture::hidden(&html, "_csrf");
    assert!(
        recovered
            .submit(&session, 1, &submission, &new_csrf, input.clone())
            .await
            .is_err()
    );
    assert_eq!(clock_state(&db).await[3], "1");
    let new_submission = fixture::hidden(&html, "_submission");
    recovered
        .submit(&session, 1, &new_submission, &new_csrf, input)
        .await
        .unwrap();
    assert_eq!(clock_state(&db).await[3], "2");
    db.maintain().await.unwrap();
    assert!(db.recover_clock(&fresh).await.is_err());
    // Tokens issued by the recovered deployment retain normal expiry semantics.
    assert_eq!(
        fresh
            .verify(&session, security::now().unwrap())
            .unwrap()
            .kind,
        TokenKind::Session
    );
}

#[tokio::test]
async fn sqlite_clock_rollback_tolerance_and_recovery() {
    let temp = tempfile::tempdir().unwrap();
    clock_rollback_and_recovery(Database::sqlite(temp.path().join("recovery.db"))).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_clock_rollback_tolerance_and_recovery() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_clock_recovery_{}",
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
    clock_rollback_and_recovery(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
