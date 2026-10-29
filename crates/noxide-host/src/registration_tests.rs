use crate::{
    Application, Database, HostKeys, Registration, manifest,
    runtime::{Limits, limiter::HashGate},
    security, test_support as fixture,
};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tower::ServiceExt;

async fn app(db: Database, mode: Registration) -> Arc<Application> {
    db.initialize().await.unwrap();
    let m = fixture::manifest();
    let app = Arc::new(
        Application::new(
            &fixture::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db,
            HostKeys::generate().unwrap(),
            Limits::default(),
        )
        .unwrap()
        .with_registration(mode)
        .with_presentation(crate::Presentation {
            stylesheet: Some("body { color: red }".into()),
            ..crate::Presentation::default()
        })
        .unwrap(),
    );
    app.activate().await.unwrap();
    app
}
async fn snapshot(db: &Database) -> Vec<(String, Vec<[String; 1]>)> {
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let data = tx.snapshot().await.unwrap();
    tx.commit().await.unwrap();
    data
}
async fn post(
    router: axum::Router,
    challenge: &str,
    csrf: &str,
    user: &str,
    password: &str,
    invite: Option<&str>,
    circuit: bool,
) -> axum::response::Response {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("_csrf", csrf)
        .append_pair("username", user)
        .append_pair("password", password);
    if let Some(invite) = invite {
        form.append_pair("invite", invite);
    }
    let mut request = Request::builder()
        .method("POST")
        .uri("/register")
        .header("Host", "localhost:8080")
        .header("Origin", "http://localhost:8080")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", format!("login={challenge}"));
    if circuit {
        request = request.extension(crate::http::Peer::Circuit(123));
    }
    router
        .oneshot(request.body(Body::from(form.finish())).unwrap())
        .await
        .unwrap()
}
async fn invitation_contract(db: Database) {
    let app = app(db.clone(), Registration::Invite).await;
    db.initialize().await.unwrap(); // Reopening invokes check_layout on the fresh schema.
    let before = snapshot(&db).await;
    let router = crate::http::router(
        app.clone(),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    let page = router
        .oneshot(
            Request::builder()
                .uri("/register")
                .header("Host", "localhost:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let html =
        String::from_utf8(to_bytes(page.into_body(), 32768).await.unwrap().to_vec()).unwrap();
    assert!(html.contains("name=\"invite\""));
    assert!(!html.contains("<link"));
    assert!(!html.contains("<style"));
    assert_eq!(snapshot(&db).await, before);
    let code = db.mint_invite(None).await.unwrap();
    let expired = db.mint_invite(Some(0)).await.unwrap();
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    tx.check_storage().await.unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(version AS TEXT) FROM nx_storage", &[])
            .await
            .unwrap()[0][0],
        "6"
    );
    let invites=tx.fetch::<4>("SELECT issuer,CAST(expires AS TEXT),CASE WHEN redeemed_at IS NULL THEN 'fresh' ELSE 'used' END,CASE WHEN redeemed_by IS NULL THEN 'none' ELSE redeemed_by END FROM nx_invites ORDER BY expires DESC",&[]).await.unwrap();
    assert_eq!(invites.len(), 2);
    assert_eq!(invites[0][0], "operator");
    assert!(invites[0][1].parse::<i64>().unwrap() >= security::now().unwrap() + 7 * 86400 - 5);
    assert_eq!(invites[0][2], "fresh");
    assert_eq!(invites[0][3], "none");
    tx.commit().await.unwrap();
    let stored = serde_json::to_string(&snapshot(&db).await).unwrap();
    assert!(!stored.contains(&code));
    assert!(!stored.contains(&expired));
    let challenge = app.login_challenge().await.unwrap();
    let password = "registration test password";
    let (first, second) = tokio::join!(
        app.register(
            &challenge.cookie,
            &challenge.csrf,
            "bob",
            password,
            Some(&code)
        ),
        app.register(
            &challenge.cookie,
            &challenge.csrf,
            "carol",
            password,
            Some(&code)
        )
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let winner = if first.is_ok() { "bob" } else { "carol" };
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let accounts = tx
        .fetch::<4>(
            "SELECT id,tenant,CAST(epoch AS TEXT),password FROM nx_accounts",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0][0], winner);
    assert_eq!(accounts[0][1], "");
    assert_eq!(accounts[0][2], "1");
    assert!(accounts[0][3].starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_sessions", &[])
            .await
            .unwrap()[0][0],
        "0"
    );
    assert_eq!(
        tx.fetch::<1>(
            "SELECT redeemed_by FROM nx_invites WHERE redeemed_at IS NOT NULL",
            &[]
        )
        .await
        .unwrap()[0][0],
        winner
    );
    tx.commit().await.unwrap();
    let router = crate::http::router(
        app.clone(),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    let mut failure = None;
    for (user, password, invite) in [
        ("reused", password, code.as_str()),
        ("expired", password, expired.as_str()),
        ("badcode", password, "garbage"),
        ("Invalid", password, code.as_str()),
        ("short", "short", code.as_str()),
    ] {
        let response = post(
            router.clone(),
            &challenge.cookie,
            &challenge.csrf,
            user,
            password,
            Some(invite),
            false,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = to_bytes(response.into_body(), 32768).await.unwrap();
        if let Some(expected) = &failure {
            assert_eq!(&body, expected);
        } else {
            failure = Some(body);
        }
    }
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_accounts", &[])
            .await
            .unwrap()[0][0],
        "1"
    );
    tx.execute("UPDATE nx_storage SET version=5", &[])
        .await
        .unwrap();
    assert!(tx.check_storage().await.is_err());
    tx.rollback().await.unwrap();
    db.initialize().await.unwrap();
    let signed = app
        .login(&challenge.cookie, &challenge.csrf, winner, password)
        .await
        .unwrap();
    assert!(!signed.is_empty());
}
#[tokio::test]
async fn sqlite_invites_are_atomic_single_use_and_fresh_v6_rejects_v5() {
    let temp = tempfile::tempdir().unwrap();
    invitation_contract(Database::sqlite(temp.path().join("registration.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_invites_are_atomic_single_use_and_fresh_v6_rejects_v5() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_registration_{}",
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
    invitation_contract(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
#[tokio::test]
async fn closed_registration_has_no_page_cookie_lookup_or_hashing() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("closed.db"));
    let app = app(db.clone(), Registration::Closed).await;
    let before = snapshot(&db).await;
    let mut held = Vec::new();
    while app.admission_limits.database.available() != 0 {
        held.push(app.admission_limits.database.acquire().await.unwrap());
    }
    let session_check = app
        .admission_limits
        .session_check
        .database
        .acquire()
        .await
        .unwrap();
    let (_, signed) = app
        .keys
        .issue(
            security::TokenKind::Session,
            "nobody",
            security::now().unwrap(),
            3600,
        )
        .unwrap();
    let router = crate::http::router(
        app.clone(),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    for method in ["GET", "POST"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/register")
                    .header("Host", "localhost:8080")
                    .header("Cookie", format!("session={signed}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    drop((held, session_check));
    assert_eq!(snapshot(&db).await, before);
    assert_eq!(app.admission_limits.argon2.available(), 2);
}
#[tokio::test]
async fn open_registration_uses_host_forms_csrf_and_all_password_hash_bounds() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("open.db"));
    let app = app(db.clone(), Registration::Open).await;
    let router = crate::http::router(
        app.clone(),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    let page = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/register")
                .header("Host", "localhost:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
    let cookie = page.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("login=")
        .unwrap()
        .to_owned();
    let page =
        String::from_utf8(to_bytes(page.into_body(), 32768).await.unwrap().to_vec()).unwrap();
    assert!(!page.contains("name=\"invite\""));
    assert!(!page.contains("<link"));
    assert!(!page.contains("<style"));
    let csrf = fixture::hidden(&page, "_csrf");
    let before = snapshot(&db).await;
    let mut failure = None;
    let oversized = "x".repeat(257);
    for (cookie, csrf, user, password) in [
        ("", csrf.as_str(), "badcookie", "registration test password"),
        (
            cookie.as_str(),
            "wrong",
            "badcsrf",
            "registration test password",
        ),
        (
            cookie.as_str(),
            csrf.as_str(),
            "BadUser",
            "registration test password",
        ),
        (cookie.as_str(), csrf.as_str(), "badpass", "short"),
        (
            cookie.as_str(),
            csrf.as_str(),
            "toolong",
            oversized.as_str(),
        ),
    ] {
        let response = post(router.clone(), cookie, csrf, user, password, None, false).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = to_bytes(response.into_body(), 32768).await.unwrap();
        if let Some(expected) = &failure {
            assert_eq!(&body, expected);
        } else {
            failure = Some(body);
        }
        assert_eq!(snapshot(&db).await, before);
    }
    let response = post(
        router.clone(),
        &cookie,
        &csrf,
        "newuser",
        "registration test password",
        None,
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(snapshot(&db).await, before);
    let first = app.admission_limits.argon2.acquire().await.unwrap();
    let second = app.admission_limits.argon2.acquire().await.unwrap();
    assert_eq!(
        post(
            router.clone(),
            &cookie,
            &csrf,
            "newuser",
            "registration test password",
            None,
            false
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop((first, second));
    assert_eq!(snapshot(&db).await, before);
    let response = post(
        router.clone(),
        &cookie,
        &csrf,
        "newuser",
        "registration test password",
        None,
        false,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login");
    assert!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|h| !h.to_str().unwrap().starts_with("session="))
    );
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_sessions", &[])
            .await
            .unwrap()[0][0],
        "0"
    );
    tx.commit().await.unwrap();
    let maximum = "x".repeat(256);
    for (user, password) in [("maximum", maximum.as_str()), ("unicode", "كلمةسر")] {
        assert_eq!(
            post(router.clone(), &cookie, &csrf, user, password, None, false)
                .await
                .status(),
            StatusCode::SEE_OTHER
        );
    }
    while app.admission_limits.argon2_attempts.allow() {}
    assert_eq!(
        post(
            router,
            &cookie,
            &csrf,
            "limited",
            "registration test password",
            None,
            false
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
struct Resume(Arc<HashGate>);
impl Drop for Resume {
    fn drop(&mut self) {
        self.0.finish();
    }
}
#[tokio::test]
async fn cancelling_registration_keeps_hash_request_and_database_permits() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("cancel.db"));
    let app = app(db.clone(), Registration::Open).await;
    let challenge = app.login_challenge().await.unwrap();
    let gate = HashGate::new();
    let _resume = Resume(gate.clone());
    *app.admission_limits.hash_gate.lock().unwrap() = Some(gate.clone());
    let worker = {
        let app = app.clone();
        tokio::spawn(async move {
            app.register(
                &challenge.cookie,
                &challenge.csrf,
                "cancelled",
                "registration test password",
                None,
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    assert_eq!(app.admission_limits.argon2.available(), 1);
    assert_eq!(app.admission_limits.database.available(), 4);
    assert_eq!(app.admission_limits.requests.available(), 43);
    gate.finish();
    tokio::time::timeout(Duration::from_secs(3), async {
        while app.admission_limits.argon2.available() != 2
            || app.admission_limits.database.available() != 5
            || app.admission_limits.requests.available() != 44
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_accounts", &[])
            .await
            .unwrap()[0][0],
        "0"
    );
    tx.commit().await.unwrap();
}

async fn clock_recovery_invites_contract(db: Database) {
    let old = app(db.clone(), Registration::Invite).await;
    let redeemed = db.mint_invite(None).await.unwrap();
    let challenge = old.login_challenge().await.unwrap();
    old.register(
        &challenge.cookie,
        &challenge.csrf,
        "redeemed",
        "registration test password",
        Some(&redeemed),
    )
    .await
    .unwrap();
    let pending = db.mint_invite(None).await.unwrap();
    let now = security::now().unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_invites SET expires=$1 WHERE redeemed_at IS NULL",
        &[(now + 3600).into()],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE nx_clock SET observed=$1 WHERE singleton=1",
        &[(now + 7200).into()],
    )
    .await
    .unwrap();
    assert_eq!(tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_invites WHERE redeemed_at IS NULL AND expires>$1", &[(now + 7200).into()]).await.unwrap()[0][0], "0");
    tx.commit().await.unwrap();
    let before = snapshot(&db).await;
    assert!(db.recover_clock(&old.keys).await.is_err());
    assert_eq!(snapshot(&db).await, before);
    let keys = HostKeys::generate().unwrap();
    db.recover_clock(&keys).await.unwrap();
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>(
            "SELECT CAST(COUNT(*) AS TEXT) FROM nx_invites WHERE redeemed_at IS NULL",
            &[]
        )
        .await
        .unwrap()[0][0],
        "0"
    );
    assert_eq!(
        tx.fetch::<1>(
            "SELECT redeemed_by FROM nx_invites WHERE redeemed_at IS NOT NULL",
            &[]
        )
        .await
        .unwrap()[0][0],
        "redeemed"
    );
    tx.commit().await.unwrap();
    let m = fixture::manifest();
    let recovered = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        keys,
        Limits::default(),
    )
    .unwrap()
    .with_registration(Registration::Invite);
    recovered.activate().await.unwrap();
    let challenge = recovered.login_challenge().await.unwrap();
    assert!(
        recovered
            .register(
                &challenge.cookie,
                &challenge.csrf,
                "revived",
                "registration test password",
                Some(&pending)
            )
            .await
            .is_err()
    );
    let fresh = db.mint_invite(None).await.unwrap();
    recovered
        .register(
            &challenge.cookie,
            &challenge.csrf,
            "fresh",
            "registration test password",
            Some(&fresh),
        )
        .await
        .unwrap();
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    assert!(
        tx.fetch::<1>("SELECT id FROM nx_accounts WHERE id='revived'", &[])
            .await
            .unwrap()
            .is_empty()
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn sqlite_clock_recovery_invalidates_outstanding_invites() {
    let temp = tempfile::tempdir().unwrap();
    clock_recovery_invites_contract(Database::sqlite(temp.path().join("invite-recovery.db"))).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_clock_recovery_invalidates_outstanding_invites() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_invite_recovery_{}",
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
    clock_recovery_invites_contract(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
