//! Public action flow with one observed private root, including all retries and
//! post-commit delivery. Operator snapshots run only outside that request scope.
use super::*;
use crate::{
    Application, HostKeys, RequestError, manifest, runtime::Limits, test_support as fixture,
};
use noxide_protocol::Fields;

async fn idle(registry: &Registry, deadline: tokio::time::Instant) {
    loop {
        let changed = registry.changed.notified();
        {
            let state = registry.state.lock().unwrap();
            if state.active == 0 {
                assert!(!state.quarantined);
                return;
            }
        }
        tokio::time::timeout_at(deadline, changed).await.unwrap();
    }
}
async fn counts(database: &Database) -> (i64, i64, i64) {
    let mut tx = database
        .begin_read(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let rows=tx.fetch::<3>("SELECT CAST((SELECT COUNT(*) FROM nx_records) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts WHERE outcome<>'') AS TEXT)",&[]).await.unwrap();
    tx.commit().await.unwrap();
    (
        rows[0][0].parse().unwrap(),
        rows[0][1].parse().unwrap(),
        rows[0][2].parse().unwrap(),
    )
}
async fn application(database: Database) -> Application {
    database.initialize().await.unwrap();
    database
        .create_account("alice", "synthetic meter password", "")
        .await
        .unwrap();
    let manifest = fixture::manifest();
    let app = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&manifest).unwrap(),
        manifest::digest(&manifest).unwrap(),
        database,
        HostKeys::generate().unwrap(),
        Limits::default(),
        crate::assets::AssetBundle::default(),
    )
    .unwrap();
    app.activate().await.unwrap();
    app
}
async fn action_exhaustion(database: Database) {
    let mut app = application(database.clone()).await;
    let challenge = app.login_challenge().await.unwrap();
    let session = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "synthetic meter password",
        )
        .await
        .unwrap();
    let page = String::from_utf8(app.view(&session, 1, None).await.unwrap().body).unwrap();
    let submission = fixture::hidden(&page, "_submission");
    let csrf = fixture::hidden(&page, "_csrf");
    let input = Fields::from([("body".into(), "synthetic bounded action".into())]);
    idle(
        &app.request_lifecycle(),
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await;
    // Real HTTP classification must consume the SAME root as the endpoint.
    // This test-only observer records root construction, never SQL/input data.
    let (baseline, roots) = observe_roots(app.view(&session, 1, None)).await;
    baseline.unwrap();
    assert_eq!(roots.len(), 1);
    idle(&app.request_lifecycle(), roots[0].deadline()).await;
    let (_, reserved, endpoint_spent) = roots[0].root.meter.snapshot();
    assert_eq!(reserved, 0);
    let endpoint_envelope = endpoint_spent
        + if database.is_sqlite() {
            0
        } else {
            meter::POSTGRES_CLEANUP - roots[0].root.meter.cleanup_charged()
        };
    app = app
        .with_database_statement_limit(endpoint_envelope)
        .unwrap();
    app.view(&session, 1, None)
        .await
        .expect("endpoint alone fits chosen allowance");
    idle(
        &app.request_lifecycle(),
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await;
    let shared = Arc::new(app);
    let router = crate::http::router(
        shared.clone(),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/")
        .header("Host", "localhost:8080")
        .header("Cookie", format!("session={session}"))
        .body(axum::body::Body::empty())
        .unwrap();
    use tower::ServiceExt;
    let (response, http_roots) = observe_roots(router.oneshot(request)).await;
    assert_eq!(
        http_roots.len(),
        1,
        "classification/endpoint reminted a request budget"
    );
    let response = response.unwrap();
    assert_ne!(
        response.status(),
        axum::http::StatusCode::OK,
        "classification was not charged against endpoint allowance"
    );
    let registry = http_roots[0].root.registry.clone();
    idle(&registry, http_roots[0].deadline()).await;
    let (free, reserved, spent) = http_roots[0].root.meter.snapshot();
    assert_eq!(reserved, 0);
    assert_eq!(free + spent, endpoint_envelope);
    println!(
        "http_shared_classification endpoint_only_units={endpoint_spent} shared_limit={endpoint_envelope} combined_charged={spent} status={} roots=1",
        response.status()
    );
    app = Arc::try_unwrap(shared)
        .ok()
        .expect("router released application ownership");
    let mut first_success = None;
    for limit in 1..=128 {
        app = app.with_database_statement_limit(limit).unwrap();
        let scope = app.http_request_scope(
            crate::runtime::limiter::RequestClass::AuthenticatedAction,
            "/actions/1",
            None,
        );
        let result = scope
            .run(app.submit(&session, 1, &submission, &csrf, input.clone()))
            .await;
        idle(&app.request_lifecycle(), scope.deadline()).await;
        let (free, reserved, spent) = scope.root.meter.snapshot();
        assert_eq!(reserved, 0);
        assert_eq!(free + spent, limit);
        assert!(spent <= limit);
        let state = counts(&database).await;
        match result {
            Ok(response) => {
                assert_eq!(state, (1, 1, 1));
                println!(
                    "action_first_success limit={limit} charged={spent} response_status={} provider={}",
                    response.status,
                    if database.is_sqlite() {
                        "sqlite"
                    } else {
                        "postgres"
                    }
                );
                first_success = Some(limit);
                break;
            }
            Err(error) => {
                println!(
                    "action_exhausted limit={limit} outcome={error:?} charged={spent} remaining={free} cleanup_reserved={reserved} provider_stopped=true quarantined=false rows={} receipt_claims={} completed_receipts={}",
                    state.0, state.1, state.2
                );
                if matches!(error, RequestError::OutcomeUnknown) {
                    println!(
                        "unexpected_unknown limit={limit} charged={spent} rows={} receipts={}",
                        state.0, state.1
                    );
                }
                assert!(
                    !matches!(error, RequestError::OutcomeUnknown),
                    "quota-only refusal cannot cross COMMIT frontier"
                );
                assert_eq!(
                    state,
                    (0, 0, 0),
                    "exhausted actual quota published mutation or receipt"
                );
            }
        }
    }
    assert!(
        first_success.is_some(),
        "ordinary action must fit approved256 ceiling without changing logical16"
    );
    // A new request has its own approved total, while its retries/navigation share
    // that root. Replay uses the semantic receipt and never re-executes effects.
    app = app.with_database_statement_limit(256).unwrap();
    let scope = app.http_request_scope(
        crate::runtime::limiter::RequestClass::AuthenticatedAction,
        "/actions/1",
        None,
    );
    let recovered = scope
        .run(app.submit(&session, 1, &submission, &csrf, input.clone()))
        .await
        .unwrap();
    idle(&app.request_lifecycle(), scope.deadline()).await;
    assert_eq!(counts(&database).await, (1, 1, 1));
    let (_, reserved, spent) = scope.root.meter.snapshot();
    assert_eq!(reserved, 0);
    assert!(spent <= 256);
    println!(
        "action_receipt_replay charged={spent} status={}",
        recovered.status
    );
    // A distinct invocation takes a genuine known-aborted mutation attempt, then
    // retries under the same root instead of receiving a second256 allowance.
    let page = String::from_utf8(app.view(&session, 1, None).await.unwrap().body).unwrap();
    let fresh = fixture::hidden(&page, "_submission");
    let csrf = fixture::hidden(&page, "_csrf");
    idle(
        &app.request_lifecycle(),
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await;
    let scope = app.http_request_scope(
        crate::runtime::limiter::RequestClass::AuthenticatedAction,
        "/actions/1",
        None,
    );
    let retried = scope
        .run(crate::failure_tests::known_conflict_once(
            app.submit(&session, 1, &fresh, &csrf, input),
        ))
        .await
        .unwrap();
    idle(&app.request_lifecycle(), scope.deadline()).await;
    assert_eq!(counts(&database).await, (2, 2, 2));
    let (free, reserved, spent) = scope.root.meter.snapshot();
    assert_eq!(reserved, 0);
    assert_eq!(free + spent, 256);
    assert!(spent <= 256);
    println!(
        "action_known_abort_retry charged={spent} status={}",
        retried.status
    );
}

#[tokio::test]
async fn sqlite_actual_action_receipt_commit_delivery_exhaustion_is_atomic() {
    let directory = tempfile::tempdir().unwrap();
    action_exhaustion(Database::sqlite(directory.path().join("action-meter.db"))).await;
}

#[tokio::test]
#[ignore = "requires authorized disposable NOXIDE_TEST_POSTGRES"]
async fn postgres_actual_action_receipt_commit_delivery_exhaustion_is_atomic() {
    let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
    let name = format!(
        "nx_action_quota_{}_{}",
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
    println!("retained_fixture={name}");
    admin.close().await.unwrap();
    let mut url = url::Url::parse(&root).unwrap();
    url.set_path(&name);
    action_exhaustion(Database::postgres(url.as_str()).unwrap()).await;
}
