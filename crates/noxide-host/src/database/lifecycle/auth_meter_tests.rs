use super::*;
use crate::{
    Application, HostKeys, Registration, RequestError, manifest, runtime::Limits,
    test_support as fixture,
};
async fn idle(scope: &RequestScope) {
    loop {
        let changed = scope.root.registry.changed.notified();
        {
            let state = scope.root.registry.state.lock().unwrap();
            if state.active == 0 {
                assert!(!state.quarantined);
                return;
            }
        }
        tokio::time::timeout_at(scope.deadline(), changed)
            .await
            .unwrap();
    }
}
async fn snapshot(database: &Database) -> [String; 4] {
    let mut tx = database
        .begin_read(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let rows=tx.fetch::<4>("SELECT CAST((SELECT COUNT(*) FROM nx_accounts) AS TEXT),CAST((SELECT COUNT(*) FROM nx_sessions) AS TEXT),CAST((SELECT COUNT(*) FROM nx_records) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts) AS TEXT)",&[]).await.unwrap();
    tx.commit().await.unwrap();
    rows[0].clone()
}
fn envelope(scope: &RequestScope, sqlite: bool) -> u16 {
    let (_, _, spent) = scope.root.meter.snapshot();
    spent
        + if sqlite {
            0
        } else {
            meter::POSTGRES_CLEANUP - scope.root.meter.cleanup_charged()
        }
}
async fn case(database: Database) {
    database.initialize().await.unwrap();
    database
        .create_account("alice", "synthetic auth meter password", "")
        .await
        .unwrap();
    let declarations = fixture::manifest();
    let mut app = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&declarations).unwrap(),
        manifest::digest(&declarations).unwrap(),
        database.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
        crate::DeploymentResources {
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap()
    .with_registration(Registration::Open);
    app.activate().await.unwrap();
    let (challenge, roots) = observe_roots(app.login_challenge()).await;
    let challenge = challenge.unwrap();
    idle(&roots[0]).await;
    let (signed, roots) = observe_roots(app.login(
        &challenge.cookie,
        &challenge.csrf,
        "alice",
        "synthetic auth meter password",
    ))
    .await;
    let signed = signed.unwrap();
    idle(&roots[0]).await;
    let login_limit =
        envelope(&roots[0], database.is_sqlite()) - if database.is_sqlite() { 2 } else { 3 };
    let before = snapshot(&database).await;
    app = app.with_database_statement_limit(login_limit).unwrap();
    let (result, roots) = observe_roots(app.login(
        &challenge.cookie,
        &challenge.csrf,
        "alice",
        "synthetic auth meter password",
    ))
    .await;
    assert!(matches!(result, Err(RequestError::Busy)));
    idle(&roots[0]).await;
    assert_eq!(snapshot(&database).await, before);
    let (free, reserved, spent) = roots[0].root.meter.snapshot();
    assert_eq!(reserved, 0);
    assert_eq!(free + spent, login_limit);
    println!(
        "auth_login_low outcome=Busy limit={login_limit} charged={spent} free={free} cleanup_reserved=0 provider_stopped=true accounts={} sessions={} rows={} receipt_claims={}",
        before[0], before[1], before[2], before[3]
    );
    app = app.with_database_statement_limit(256).unwrap();
    let (result, roots) = observe_roots(app.register(
        &challenge.cookie,
        &challenge.csrf,
        "registration_baseline",
        "synthetic registration password",
        None,
    ))
    .await;
    result.unwrap();
    idle(&roots[0]).await;
    let register_limit =
        envelope(&roots[0], database.is_sqlite()) - if database.is_sqlite() { 2 } else { 3 };
    let before = snapshot(&database).await;
    app = app.with_database_statement_limit(register_limit).unwrap();
    let (result, roots) = observe_roots(app.register(
        &challenge.cookie,
        &challenge.csrf,
        "registration_quota_denied",
        "synthetic registration password",
        None,
    ))
    .await;
    assert!(matches!(result, Err(RequestError::Busy)));
    idle(&roots[0]).await;
    assert_eq!(snapshot(&database).await, before);
    let (free, reserved, spent) = roots[0].root.meter.snapshot();
    assert_eq!(reserved, 0);
    assert_eq!(free + spent, register_limit);
    println!(
        "auth_register_low outcome=Busy limit={register_limit} charged={spent} free={free} cleanup_reserved=0 provider_stopped=true accounts={} sessions={} rows={} receipt_claims={}",
        before[0], before[1], before[2], before[3]
    );
    app = app.with_database_statement_limit(256).unwrap();
    for cookie in [None, Some("invalid-session-token")] {
        let (result, roots) = observe_roots(app.view_page(cookie, 1, None, None)).await;
        assert!(matches!(result, Err(RequestError::Authentication)));
        idle(&roots[0]).await;
    }
    let (result, roots) = observe_roots(app.login(
        &challenge.cookie,
        &challenge.csrf,
        "alice",
        "wrong synthetic password",
    ))
    .await;
    assert!(matches!(result, Err(RequestError::Authentication)));
    idle(&roots[0]).await;
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_accounts SET state='disabled' WHERE login_name='alice'",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (result, roots) = observe_roots(app.view(&signed, 1, None)).await;
    assert!(matches!(result, Err(RequestError::Authentication)));
    idle(&roots[0]).await;
    let (result, roots) = observe_roots(app.login(
        &challenge.cookie,
        &challenge.csrf,
        "alice",
        "synthetic auth meter password",
    ))
    .await;
    assert!(matches!(result, Err(RequestError::Authentication)));
    idle(&roots[0]).await;
    assert_eq!(snapshot(&database).await, before);
    println!("auth_invalid_missing_disabled_controls=Authentication state_unchanged=true");
}
#[tokio::test]
async fn sqlite_quota_auth_unavailable_is_busy_credentials_still_fail() {
    let directory = tempfile::tempdir().unwrap();
    case(Database::sqlite(directory.path().join("auth-meter.db"))).await;
}
#[tokio::test]
#[ignore = "requires authorized disposable NOXIDE_TEST_POSTGRES"]
async fn postgres_quota_auth_unavailable_is_busy_credentials_still_fail() {
    let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
    let name = format!(
        "nx_auth_quota_{}_{}",
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
    case(Database::postgres(url.as_str()).unwrap()).await;
}
