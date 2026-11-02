//! Pins how a method and path choose a response, a request class and a deadline.
//! Admission budgets are chosen before routing, so the two must never disagree.
use super::*;
use crate::{
    Database, HostKeys, database::lifecycle::RequestScope, limiter::RequestClass, runtime::Limits,
    test_support as fixture,
};
use axum::body::Body;
use noxide_protocol::Manifest;
use tower::ServiceExt;

const WALL_TIME: Duration = Duration::from_secs(7);
const ASSET: &str = "/_noxide/assets/missing";

async fn application(
    manifest: &Manifest,
    component: &[u8],
    registration: crate::Registration,
    db: Database,
) -> Arc<Application> {
    db.initialize().await.unwrap();
    let app = Application::new(
        component,
        &serde_json::to_vec(manifest).unwrap(),
        crate::manifest::digest(manifest).unwrap(),
        db,
        HostKeys::generate().unwrap(),
        Limits {
            wall_time: WALL_TIME,
            ..Limits::default()
        },
        crate::DeploymentResources {
            effects: None,
            jobs: None,
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap()
    .with_registration(registration);
    app.activate().await.unwrap();
    Arc::new(app)
}

/// A manifest whose action 1 needs a session.
async fn signed_in(registration: crate::Registration, db: Database) -> Arc<Application> {
    application(
        &fixture::manifest(),
        &fixture::component(None),
        registration,
        db,
    )
    .await
}

/// A manifest whose action 1 is a public create and whose actions 2 and 3 use capabilities.
async fn anonymous(db: Database) -> Arc<Application> {
    application(
        &crate::anonymous_tests::declarations(),
        &crate::test_support::anonymous_component(),
        crate::Registration::Closed,
        db,
    )
    .await
}

fn class_name(class: RequestClass) -> &'static str {
    match class {
        RequestClass::Get => "get",
        RequestClass::AuthenticatedAction => "authenticated",
        RequestClass::AnonymousAction => "anonymous",
        RequestClass::PasswordHash => "password",
    }
}

/// The class and whole seconds of deadline a request is admitted with.
async fn admitted(app: &Application, method: &str, path: &str) -> (&'static str, u64) {
    let method = axum::http::Method::from_bytes(method.as_bytes()).unwrap();
    let class = request_class(app, &method, path);
    let scope = app.http_request_scope(class, path, None);
    let remaining = scope
        .run(async { RequestScope::current_work_deadline().unwrap() - tokio::time::Instant::now() })
        .await;
    (class_name(class), remaining.as_secs_f64().ceil() as u64)
}

async fn status(app: &Arc<Application>, method: &str, path: &str, kind: Kind) -> u16 {
    let origin = "http://localhost:8080";
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost:8080");
    if !matches!(kind, Kind::NoOrigin) {
        request = request.header(header::ORIGIN, origin);
    }
    let body = match kind {
        Kind::Bare => Body::empty(),
        Kind::Text => {
            request = request.header(header::CONTENT_TYPE, "text/plain");
            Body::from("x")
        }
        Kind::NoCsrf => {
            request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from("a=b")
        }
        Kind::Form | Kind::NoOrigin => {
            request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(format!("{}=x", app.presentation.csrf_field))
        }
    };
    router(app.clone(), Origin::parse(origin).unwrap())
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[derive(Clone, Copy)]
enum Kind {
    Bare,
    Form,
    NoCsrf,
    NoOrigin,
    Text,
}
use Kind::*;

#[tokio::test]
async fn signed_in_application_classifies_every_endpoint() {
    let temp = tempfile::tempdir().unwrap();
    let app = signed_in(
        crate::Registration::Open,
        Database::sqlite(temp.path().join("class.db")),
    )
    .await;
    for (method, path, class, seconds) in [
        ("GET", "/", "get", 7),
        ("GET", "/nope", "get", 7),
        ("GET", "/login", "get", 2),
        ("GET", "/register", "get", 2),
        ("GET", "/logout", "get", 2),
        ("GET", "/account", "get", 7),
        ("GET", "/_noxide/download", "get", 7),
        ("GET", ASSET, "get", 7),
        ("GET", "/_noxide/capability/1/1", "get", 7),
        ("POST", "/login", "password", 3),
        ("PUT", "/login", "password", 3),
        ("POST", "/register", "password", 3),
        ("POST", "/logout", "authenticated", 2),
        ("PUT", "/logout", "authenticated", 2),
        ("POST", "/actions/1", "authenticated", 7),
        ("POST", "/actions/999", "authenticated", 7),
        ("POST", "/actions/abc", "authenticated", 7),
        ("POST", "/nope", "authenticated", 7),
        ("POST", "/login/", "authenticated", 7),
        ("POST", "/_noxide/download", "authenticated", 7),
        ("POST", ASSET, "authenticated", 7),
        ("POST", "/_noxide/capability/1/1", "anonymous", 7),
        ("PUT", "/_noxide/capability/1/1", "anonymous", 7),
        ("POST", "/_noxide/capability/01/1", "authenticated", 7),
        ("POST", "/_noxide/capability/1/0", "authenticated", 7),
    ] {
        assert_eq!(
            admitted(&app, method, path).await,
            (class, seconds),
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn anonymous_actions_use_the_anonymous_class() {
    let temp = tempfile::tempdir().unwrap();
    let app = anonymous(Database::sqlite(temp.path().join("class.db"))).await;
    for (method, path, class, seconds) in [
        ("POST", "/actions/1", "anonymous", 7),
        ("PUT", "/actions/1", "anonymous", 7),
        ("GET", "/actions/1", "get", 7),
        ("POST", "/actions/999", "authenticated", 7),
    ] {
        assert_eq!(
            admitted(&app, method, path).await,
            (class, seconds),
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn closed_registration_still_uses_the_password_budget() {
    let temp = tempfile::tempdir().unwrap();
    let app = signed_in(
        crate::Registration::Closed,
        Database::sqlite(temp.path().join("class.db")),
    )
    .await;
    assert_eq!(admitted(&app, "POST", "/register").await, ("password", 3));
    assert_eq!(admitted(&app, "GET", "/register").await, ("get", 2));
}

#[tokio::test]
async fn signed_in_application_responses() {
    let temp = tempfile::tempdir().unwrap();
    let open = signed_in(
        crate::Registration::Open,
        Database::sqlite(temp.path().join("open.db")),
    )
    .await;
    for (method, path, kind, expected) in [
        ("GET", "/", Bare, 303),
        ("GET", "/nope", Bare, 404),
        ("GET", "/login", Bare, 200),
        ("GET", "/login/", Bare, 404),
        ("GET", "/register", Bare, 200),
        ("GET", "/logout", Bare, 404),
        ("GET", "/account", Bare, 303),
        ("GET", "/_noxide/download", Bare, 404),
        ("PUT", "/_noxide/download", Bare, 404),
        ("GET", ASSET, Bare, 404),
        ("POST", ASSET, Bare, 404),
        ("GET", "/_noxide/capability/1/1", Bare, 404),
        ("GET", "/_noxide/capability/01/1", Bare, 404),
        ("PUT", "/login", Bare, 405),
        ("DELETE", "/nope", Bare, 405),
        ("POST", "/login", NoOrigin, 403),
        ("POST", "/nope", NoOrigin, 403),
        ("POST", "/nope", Text, 415),
        ("POST", "/nope", NoCsrf, 403),
        ("POST", "/nope", Form, 404),
        ("POST", "/login", NoCsrf, 403),
        ("POST", "/login", Form, 400),
        ("POST", "/register", NoCsrf, 422),
        ("POST", "/register", Form, 422),
        ("POST", "/logout", Form, 303),
        ("POST", "/_noxide/capability/1/1", Form, 403),
        ("POST", "/_noxide/capability/01/1", Form, 404),
        ("POST", "/actions/1", Form, 303),
        ("POST", "/actions/999", Form, 404),
        ("POST", "/actions/abc", Form, 404),
        ("POST", "/actions/1?x=1", Form, 400),
    ] {
        assert_eq!(
            status(&open, method, path, kind).await,
            expected,
            "{method} {path}"
        );
    }
    let closed = signed_in(
        crate::Registration::Closed,
        Database::sqlite(temp.path().join("closed.db")),
    )
    .await;
    for (method, path, kind) in [
        ("GET", "/register", Bare),
        ("POST", "/register", Form),
        ("POST", "/register", NoOrigin),
        ("PUT", "/register", Bare),
    ] {
        assert_eq!(status(&closed, method, path, kind).await, 404, "{method}");
    }
}

#[tokio::test]
async fn anonymous_action_without_a_session_reaches_submission_checks() {
    let temp = tempfile::tempdir().unwrap();
    let app = anonymous(Database::sqlite(temp.path().join("anonymous.db"))).await;
    assert_eq!(status(&app, "POST", "/actions/1", Form).await, 403);
    assert_eq!(status(&app, "POST", "/actions/999", Form).await, 404);
}

#[tokio::test]
async fn host_and_path_length_are_checked_before_routing() {
    let temp = tempfile::tempdir().unwrap();
    let app = signed_in(
        crate::Registration::Open,
        Database::sqlite(temp.path().join("host.db")),
    )
    .await;
    for (host, path, expected) in [
        ("other:8080", "/login".to_owned(), 421),
        ("localhost:8080", "/".repeat(257), 400),
    ] {
        let response = router(app.clone(), Origin::parse("http://localhost:8080").unwrap())
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .header(header::HOST, host)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected, "{host}");
    }
}
