use crate::{
    Application, Database, HostKeys, manifest, runtime::Limits, security, test_support as fixture,
};
use noxide_protocol::*;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

fn declarations() -> Manifest {
    let mut m = fixture::manifest();
    m.resources[0].fields.push(TextField {
        kind: FieldKind::Boolean,
        optional: false,
        initial: None,
        name: "published".into(),
        label: "Published".into(),
        max_bytes: 5,
    });
    m.resources[0].fields.push(TextField {
        kind: FieldKind::Text,
        optional: true,
        initial: None,
        name: "private".into(),
        label: "Private field".into(),
        max_bytes: 128,
    });
    for op in &mut m.operations {
        op.policy = Policy {
            any: vec![vec![Predicate::Public]],
        };
        if matches!(op.kind, OperationKind::Read | OperationKind::List) {
            op.visibility = Some(Visibility {
                field: "published".into(),
                equals: "true".into(),
            });
            op.fields = Some(vec!["body".into(), "published".into()]);
        }
    }
    for (id, kind) in [(4, OperationKind::Update), (5, OperationKind::Delete)] {
        m.operations.push(Operation {
            list: None,
            id,
            resource: 1,
            kind,
            policy: Policy {
                any: vec![vec![Predicate::Capability]],
            },
            visibility: None,
            fields: None,
        });
    }
    m.actions[0]
        .fields
        .extend(["published".into(), "private".into()]);
    m.actions.push(Action {
        id: 2,
        version: 1,
        name: "Edit".into(),
        operation: 4,
        redirect: 2,
        fields: vec!["body".into(), "private".into()],
        layout: vec![],
        inspect: None,
    });
    m.actions.push(Action {
        id: 3,
        version: 1,
        name: "Delete".into(),
        operation: 5,
        redirect: 1,
        fields: vec![],
        layout: vec![],
        inspect: None,
    });
    for r in &mut m.routes {
        r.access = Access::PublicOptional;
    }
    m.routes[1].forms = vec![2, 3];
    m
}
fn emit(bytes: &[u8]) -> String {
    bytes
        .chunks(8)
        .map(|part| {
            let mut word = [0; 8];
            word[..part.len()].copy_from_slice(part);
            format!(
                "i64.const {} i32.const {} call $emit\n",
                i64::from_le_bytes(word),
                part.len()
            )
        })
        .collect()
}
fn component() -> Vec<u8> {
    component_with_redirect(false)
}
fn component_with_redirect(forged: bool) -> Vec<u8> {
    let page1 = emit(br#"{"page":{"title":"Create","nodes":[{"form":{"action":1}}]}}"#);
    let page2 =
        emit(br#"{"page":{"title":"Edit","nodes":[{"form":{"action":2}},{"form":{"action":3}}]}}"#);
    let kind = br#"{"version":3,"kind":{"#.len() + 1;
    let action = br#"{"version":3,"kind":{"action":"#.len();
    let route = br#"{"version":3,"kind":{"route":"#.len();
    let offset = br#"{"resource":1,"id":"#.len();
    let digits = format!(
        "i32.const {offset} local.set $i block $end loop $digit local.get $i call $result i32.wrap_i64 i32.const 255 i32.and local.tee $c i32.const 44 i32.eq br_if $end local.get $c i64.extend_i32_u i32.const 1 call $emit local.get $i i32.const 1 i32.add local.set $i br $digit end end"
    );
    let created = format!(
        "{} {digits} {} {digits} {}",
        emit(br#"{"created":{"resource":1,"id":"#),
        emit(br#", "destination":{"route":2,"target":"#),
        emit(b"}}}")
    );
    let created = if forged {
        format!(
            "{} {digits} {}",
            emit(br#"{"created":{"resource":1,"id":"#),
            emit(br#","destination":{"route":999,"target":null}}}"#)
        )
    } else {
        created
    };
    wat::parse_str(format!(r#"(component
      (import "noxide:application/host@0.1.0" (instance $h
        (export "emit" (func (param "word" u64) (param "length" u32)))
        (export "request-chunk" (func (param "offset" u32) (result u64)))
        (export "invoke" (func (param "operation" u32) (param "target" u64) (result u32)))
        (export "result-chunk" (func (param "offset" u32) (result u64)))))
      (alias export $h "emit" (func $emit)) (core func $emit (canon lower (func $emit)))
      (alias export $h "request-chunk" (func $request)) (core func $request (canon lower (func $request)))
      (alias export $h "invoke" (func $invoke)) (core func $invoke (canon lower (func $invoke)))
      (alias export $h "result-chunk" (func $result)) (core func $result (canon lower (func $result)))
      (core module $m
        (import "h" "emit" (func $emit (param i64 i32)))
        (import "h" "request" (func $request (param i32) (result i64)))
        (import "h" "invoke" (func $invoke (param i32 i64) (result i32)))
        (import "h" "result" (func $result (param i32) (result i64)))
        (func (export "handle") (local $op i32) (local $len i32) (local $i i32) (local $c i32)
          i32.const {kind} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 97 i32.eq
          if
            i32.const {action} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 48 i32.sub i32.const 2 i32.add local.set $op
            local.get $op i64.const 0 call $invoke local.set $len
            local.get $op i32.const 3 i32.eq if {created} else
              i32.const 0 local.set $i block $end loop $copy local.get $i local.get $len i32.ge_u br_if $end local.get $i call $result i32.const 1 call $emit local.get $i i32.const 1 i32.add local.set $i br $copy end end
            end
          else i32.const {route} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 49 i32.eq if {page1} else {page2} end end))
      (core instance $i (instantiate $m (with "h" (instance (export "emit" (func $emit)) (export "request" (func $request)) (export "invoke" (func $invoke)) (export "result" (func $result))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#)).unwrap()
}
async fn app(db: Database) -> Arc<Application> {
    db.initialize().await.unwrap();
    let m = declarations();
    let app = Arc::new(
        Application::new(
            &component(),
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
fn text(page: &crate::render::Rendered) -> &str {
    std::str::from_utf8(&page.body).unwrap()
}
fn secret(page: &crate::render::Rendered) -> String {
    text(page)
        .split("<pre>")
        .nth(1)
        .unwrap()
        .split("</pre>")
        .next()
        .unwrap()
        .into()
}
fn token(page: &crate::render::Rendered, action: u32) -> String {
    fixture::hidden(
        text(page)
            .split(&format!("action=\"/actions/{action}\""))
            .nth(1)
            .unwrap(),
        "_submission",
    )
}
async fn rows(db: &Database) -> Vec<(String, Vec<[String; 1]>)> {
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let rows = tx.snapshot().await.unwrap();
    tx.commit().await.unwrap();
    rows
}
async fn lifecycle(db: Database) {
    let app = app(db.clone()).await;
    let page = app.view_page(None, 1, None, None).await.unwrap();
    let cookie = page.anonymous_cookie.clone().unwrap();
    let submission = token(&page, 1);
    let csrf = fixture::hidden(text(&page), "_csrf");
    let input = Fields::from([
        ("body".into(), "public note".into()),
        ("published".into(), "true".into()),
        ("private".into(), "private-field-never-prefill".into()),
    ]);
    let before = rows(&db).await;
    let (_, other) = app
        .keys
        .issue(
            security::TokenKind::Anonymous,
            "",
            security::now().unwrap(),
            900,
        )
        .unwrap();
    for (cookie, csrf) in [
        ("", csrf.as_str()),
        (other.as_str(), csrf.as_str()),
        (cookie.as_str(), "wrong"),
    ] {
        assert!(
            app.submit(cookie, 1, &submission, csrf, input.clone())
                .await
                .is_err()
        );
        assert_eq!(rows(&db).await, before);
    }
    let page = app
        .submit(&cookie, 1, &submission, &csrf, input.clone())
        .await
        .unwrap();
    assert_eq!(page.status, 200);
    assert!(page.location.is_none());
    let old = secret(&page);
    assert_eq!(text(&page).matches(&old).count(), 1);
    let replay = app
        .submit(&cookie, 1, &submission, &csrf, input.clone())
        .await
        .unwrap();
    assert!(secret(&replay) == old);
    let mut rotated_keys: HostKeys =
        serde_json::from_value(serde_json::to_value(&*app.keys).unwrap()).unwrap();
    rotated_keys.rotate_edit_key().unwrap();
    let m = declarations();
    let retained = Application::new(
        &component(),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        rotated_keys,
        Limits::default(),
    )
    .unwrap();
    retained.activate().await.unwrap();
    let replay = retained
        .submit(&cookie, 1, &submission, &csrf, input.clone())
        .await
        .unwrap();
    assert!(secret(&replay) == old);
    let mut removed = serde_json::to_value(&*retained.keys).unwrap();
    removed["edit_keys"]
        .as_array_mut()
        .unwrap()
        .retain(|key| key["signing"] == true);
    let removed: HostKeys = serde_json::from_value(removed).unwrap();
    let retired_key = Application::new(
        &component(),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        removed,
        Limits::default(),
    )
    .unwrap();
    retired_key.activate().await.unwrap();
    let revoked = retired_key
        .submit(&cookie, 1, &submission, &csrf, input.clone())
        .await
        .unwrap();
    assert!(text(&revoked).contains("replaced or revoked"));
    assert!(!text(&revoked).contains(&old));
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let r=tx.fetch::<3>("SELECT CAST(id AS TEXT),CAST(cap_version AS TEXT),CASE WHEN owner IS NULL AND tenant='' THEN 'anonymous' ELSE 'owned' END FROM nx_records",&[]).await.unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0][1], "1");
    assert_eq!(r[0][2], "anonymous");
    let id = r[0][0].parse().unwrap();
    tx.commit().await.unwrap();
    let rotation = app.capability_page(1, id, Some(&cookie)).await.unwrap();
    let rotate_token = fixture::hidden(text(&rotation), "_submission");
    let rotate_csrf = fixture::hidden(text(&rotation), "_csrf");
    let rotated = app
        .rotate_capability(1, id, &cookie, &rotate_csrf, &rotate_token, &old)
        .await
        .unwrap();
    let new = secret(&rotated);
    assert!(new != old);
    let replay = app
        .rotate_capability(1, id, &cookie, &rotate_csrf, &rotate_token, &old)
        .await
        .unwrap();
    assert!(secret(&replay) == new);
    let revoked = app
        .submit(&cookie, 1, &submission, &csrf, input.clone())
        .await
        .unwrap();
    assert!(text(&revoked).contains("replaced or revoked"));
    assert!(!text(&revoked).contains(&new));
    assert!(!text(&revoked).contains(&old));
    let edit = app
        .view_page_anonymous(None, Some(&cookie), 2, Some(id), None)
        .await
        .unwrap();
    assert!(text(&edit).contains("type=\"password\" name=\"_capability\""));
    assert!(!text(&edit).contains("private-field-never-prefill"));
    let edit_token = token(&edit, 2);
    let edit_csrf = fixture::hidden(text(&edit), "_csrf");
    let changed = Fields::from([("body".into(), "changed".into())]);
    assert!(
        app.submit_with_capability(
            &cookie,
            2,
            &edit_token,
            &edit_csrf,
            changed.clone(),
            Some(&old)
        )
        .await
        .is_err()
    );
    assert!(
        app.submit_with_capability(&cookie, 2, &edit_token, &edit_csrf, changed.clone(), None)
            .await
            .is_err()
    );
    assert_eq!(
        app.submit_with_capability(
            &cookie,
            2,
            &edit_token,
            &edit_csrf,
            changed.clone(),
            Some(&new)
        )
        .await
        .unwrap()
        .status,
        303
    );
    let conflict = app
        .submit_with_capability(
            &cookie,
            2,
            &edit_token,
            &edit_csrf,
            Fields::from([("body".into(), "different replay".into())]),
            Some(&new),
        )
        .await;
    assert!(conflict.is_err());
    let second = app
        .view_page_anonymous(None, Some(&cookie), 2, Some(id), None)
        .await
        .unwrap();
    let stale = token(&second, 2);
    let second_csrf = fixture::hidden(text(&second), "_csrf");
    let third = app
        .view_page_anonymous(None, Some(&cookie), 2, Some(id), None)
        .await
        .unwrap();
    app.submit_with_capability(
        &cookie,
        2,
        &token(&third, 2),
        &second_csrf,
        Fields::from([("body".into(), "newer".into())]),
        Some(&new),
    )
    .await
    .unwrap();
    let conflict = app
        .submit_with_capability(&cookie, 2, &stale, &second_csrf, changed, Some(&new))
        .await
        .unwrap();
    assert_eq!(conflict.status, 409);
    assert!(!text(&conflict).contains(&new));
    assert!(!text(&conflict).contains(&old));
    let del = app
        .view_page_anonymous(None, Some(&cookie), 2, Some(id), None)
        .await
        .unwrap();
    let delete_token = token(&del, 3);
    let delete_csrf = fixture::hidden(text(&del), "_csrf");
    assert_eq!(
        app.submit_with_capability(
            &cookie,
            3,
            &delete_token,
            &delete_csrf,
            Fields::new(),
            Some(&new)
        )
        .await
        .unwrap()
        .status,
        303
    );
    let revoked = app
        .rotate_capability(1, id, &cookie, &rotate_csrf, &rotate_token, &old)
        .await
        .unwrap();
    assert!(text(&revoked).contains("replaced or revoked"));
    let snapshot = serde_json::to_string(&rows(&db).await).unwrap();
    assert!(!snapshot.contains(&old));
    assert!(!snapshot.contains(&new));
    assert!(!snapshot.contains(&cookie));
}
#[tokio::test]
async fn sqlite_anonymous_receipts_capability_rotation_and_secret_scrubbing() {
    let temp = tempfile::tempdir().unwrap();
    lifecycle(Database::sqlite(temp.path().join("anonymous.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_anonymous_receipts_capability_rotation_and_secret_scrubbing() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_anon_{}",
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
    lifecycle(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}

#[test]
fn capability_policies_are_standalone_mutations_and_never_ordinary_authority() {
    use crate::auth::{Principal, User};
    let good = declarations();
    assert!(manifest::validate(&good).is_ok());
    for kind in [
        OperationKind::Create,
        OperationKind::Read,
        OperationKind::List,
    ] {
        let mut bad = good.clone();
        bad.operations[3].kind = kind;
        assert!(manifest::validate(&bad).is_err());
    }
    let mut bad = good.clone();
    bad.operations[3].policy.any[0].push(Predicate::Owner);
    assert!(manifest::validate(&bad).is_err());
    let mut bad = good.clone();
    bad.operations[2].visibility = Some(Visibility {
        field: "published".into(),
        equals: "true".into(),
    });
    assert!(manifest::validate(&bad).is_err());
    for principal in [
        Principal::Anonymous,
        Principal::User(User {
            id: "alice".into(),
            tenant: "".into(),
            roles: vec![],
        }),
    ] {
        assert!(!crate::repository::allowed(
            &good.operations[3].policy,
            &principal,
            "alice",
            ""
        ));
    }
}

#[tokio::test]
async fn public_create_ignores_guest_redirect_and_requires_an_edit_signing_key() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("redirect.db"));
    db.initialize().await.unwrap();
    let m = declarations();
    let app = Application::new(
        &component_with_redirect(true),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
    )
    .unwrap();
    app.activate().await.unwrap();
    let page = app.view_page(None, 1, None, None).await.unwrap();
    let cookie = page.anonymous_cookie.clone().unwrap();
    let csrf = fixture::hidden(text(&page), "_csrf");
    let input = Fields::from([
        ("body".into(), "hello".into()),
        ("published".into(), "true".into()),
    ]);
    let handover = app
        .submit(&cookie, 1, &token(&page, 1), &csrf, input)
        .await
        .unwrap();
    assert_eq!(handover.status, 200);
    assert!(handover.location.is_none());
    assert!(text(&handover).contains("/notes/"));
    let mut legacy = serde_json::to_value(HostKeys::generate().unwrap()).unwrap();
    legacy.as_object_mut().unwrap().remove("edit_keys");
    let keys: HostKeys = serde_json::from_value(legacy).unwrap();
    let unbound = Database::sqlite(temp.path().join("unbound.db"));
    unbound.initialize().await.unwrap();
    let app = Application::new(
        &component(),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        unbound.clone(),
        keys,
        Limits::default(),
    )
    .unwrap();
    let before = rows(&unbound).await;
    assert!(app.activate().await.is_err());
    assert_eq!(rows(&unbound).await, before);
}

async fn post(
    router: axum::Router,
    path: &str,
    origin: &str,
    cookie: &str,
    fields: &[(&str, &str)],
) -> axum::response::Response {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let mut body = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in fields {
        body.append_pair(key, value);
    }
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("Host", "localhost:8080")
                .header("Origin", origin)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", cookie)
                .body(Body::from(body.finish()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn anonymous_http_csrf_cookie_flags_rotation_and_write_limits() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("http-anon.db"));
    let app = app(db.clone()).await;
    let router = crate::http::router(
        app.clone(),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header("Host", "localhost:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with("noxide_anon="));
    for flag in ["Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=900"] {
        assert!(cookie.contains(flag));
    }
    assert!(!cookie.contains("; Secure"));
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let html = String::from_utf8(
        to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let csrf = fixture::hidden(&html, "_csrf");
    let submission = fixture::hidden(&html, "_submission");
    let valid = [
        ("_csrf", csrf.as_str()),
        ("_submission", submission.as_str()),
        ("body", "web"),
        ("published", "true"),
    ];
    let before = rows(&db).await;
    let (_, other) = app
        .keys
        .issue(
            security::TokenKind::Anonymous,
            "",
            security::now().unwrap(),
            900,
        )
        .unwrap();
    let other = format!("noxide_anon={other}");
    for (origin, cookie, csrf) in [
        ("http://other.onion", cookie.as_str(), csrf.as_str()),
        ("http://localhost:8080", "", csrf.as_str()),
        ("http://localhost:8080", other.as_str(), csrf.as_str()),
        ("http://localhost:8080", cookie.as_str(), "wrong"),
    ] {
        let fields = [
            ("_csrf", csrf),
            ("_submission", submission.as_str()),
            ("body", "web"),
            ("published", "true"),
        ];
        assert!(
            !post(router.clone(), "/actions/1", origin, cookie, &fields)
                .await
                .status()
                .is_success()
        );
        assert_eq!(rows(&db).await, before);
    }
    let held = app
        .admission_limits
        .anonymous_writes
        .acquire()
        .await
        .unwrap();
    let busy = post(
        router.clone(),
        "/actions/1",
        "http://localhost:8080",
        &cookie,
        &valid,
    )
    .await;
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!busy.headers().contains_key(header::RETRY_AFTER));
    drop(held);
    assert_eq!(rows(&db).await, before);
    let response = post(
        router.clone(),
        "/actions/1",
        "http://localhost:8080",
        &cookie,
        &valid,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(!response.headers().contains_key(header::LOCATION));
    let handover = String::from_utf8(
        to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let old = handover
        .split("<pre>")
        .nth(1)
        .unwrap()
        .split("</pre>")
        .next()
        .unwrap()
        .to_owned();
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let id = tx
        .fetch::<1>("SELECT CAST(id AS TEXT) FROM nx_records", &[])
        .await
        .unwrap()[0][0]
        .clone();
    tx.commit().await.unwrap();
    let path = format!("/_noxide/capability/1/{id}");
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&path)
                .header("Host", "localhost:8080")
                .header("Cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let rotation = String::from_utf8(
        to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let csrf = fixture::hidden(&rotation, "_csrf");
    let submission = fixture::hidden(&rotation, "_submission");
    let fields = [
        ("_csrf", csrf.as_str()),
        ("_submission", submission.as_str()),
        ("_capability", old.as_str()),
    ];
    let response = post(
        router.clone(),
        &path,
        "http://localhost:8080",
        &cookie,
        &fields,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let rotation = String::from_utf8(
        to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!rotation.contains(&old));
    while app.admission_limits.anonymous_write_attempts.allow() {}
    assert_eq!(
        post(
            router.clone(),
            &path,
            "http://localhost:8080",
            &cookie,
            &fields
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let secure = crate::http::router(
        app,
        crate::http::Origin::parse("https://localhost:8080").unwrap(),
    );
    let response = secure
        .oneshot(
            Request::builder()
                .uri("/")
                .header("Host", "localhost:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("; Secure")
    );
}

use crate::test_support::record_actions as snapshot_guest;

#[tokio::test]
async fn capability_never_reaches_guest_or_widens_inspection_or_repository_authority() {
    for inspect in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let db = Database::sqlite(temp.path().join("guest-boundary.db"));
        db.initialize().await.unwrap();
        let mut m = declarations();
        if inspect {
            m.operations.push(Operation {
                list: None,
                id: 6,
                resource: 1,
                kind: OperationKind::Read,
                policy: Policy {
                    any: vec![vec![Predicate::Owner]],
                },
                visibility: None,
                fields: None,
            });
            m.actions[1].inspect = Some(Inspection {
                operation: 6,
                fields: vec!["private".into()],
            });
        }
        let keys = HostKeys::generate().unwrap();
        let secret = keys
            .edit_secret(keys.signing_edit_key().unwrap(), 1, 42, 1)
            .unwrap();
        let app = Application::new(
            &snapshot_guest::component("snapshot"),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db.clone(),
            keys,
            Limits::default(),
        )
        .unwrap();
        app.activate().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        tx.check_schema(&m).await.unwrap();
        let storage = tx.storage_resource(&m, 1).await.unwrap();
        let fields = Fields::from([
            ("body".into(), "public".into()),
            ("published".into(), "true".into()),
            ("private".into(), "not publicly visible".into()),
        ]);
        tx.allocate_creation().await.unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES($1,42,NULL,'',$2,'test-record',1,1,(SELECT value FROM nx_creation_counter WHERE singleton=1))",&[storage.into(),serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
        tx.commit().await.unwrap();
        let page = app.view_page(None, 2, Some(42), None).await.unwrap();
        assert!(!text(&page).contains("not publicly visible"));
        let cookie = page.anonymous_cookie.clone().unwrap();
        let submission = token(&page, 2);
        let csrf = fixture::hidden(text(&page), "_csrf");
        let result = app
            .submit_with_capability(
                &cookie,
                2,
                &submission,
                &csrf,
                Fields::from([("body".into(), "attempt".into())]),
                Some(&secret),
            )
            .await;
        if inspect {
            assert!(result.is_err());
        } else {
            let rejection = result.unwrap();
            assert_eq!(rejection.status, 422);
            assert!(!text(&rejection).contains(&secret));
            let message = text(&rejection)
                .split("<p class=\"application-error\">")
                .nth(1)
                .unwrap()
                .split("</p>")
                .next()
                .unwrap();
            assert!(message.contains("available_forms"));
            for hidden in [&cookie, &submission, &csrf, &secret] {
                assert!(!message.contains(hidden));
            }
            assert!(!message.contains("not publicly visible"));
        }
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        tx.check_schema(&m).await.unwrap();
        let record = crate::repository::load(&mut tx, &m, 1, 42)
            .await
            .unwrap()
            .unwrap();
        let grant = security::RecordTarget {
            resource: 1,
            id: 42,
            incarnation: record.incarnation.clone(),
            revision: record.revision,
            route: 2,
        };
        let request = RequestView {
            version: VERSION,
            kind: RequestKind::Action(2),
            target: Some(42),
            input: Fields::from([
                ("body".into(), "forged".into()),
                ("private".into(), "".into()),
            ]),
            inspection: None,
            available_forms: vec![],
        };
        let mut effects = crate::repository::Effects {
            tx,
            manifest: Arc::new(m),
            principal: crate::auth::Principal::Anonymous,
            request,
            outcome: None,
            grant: Some(grant),
            capability_grant: None,
            record: Some(record),
            calls: 16,
            cursor: None,
            more: None,
        };
        assert!(effects.invoke(4, 0).await.is_err());
        effects.tx.rollback().await.unwrap();
    }
}

async fn persistent_resource_secret_contract(db: Database) {
    let original = app(db.clone()).await;
    let page = original.view_page(None, 1, None, None).await.unwrap();
    let cookie = page.anonymous_cookie.clone().unwrap();
    let csrf = fixture::hidden(text(&page), "_csrf");
    let created = original
        .submit(
            &cookie,
            1,
            &token(&page, 1),
            &csrf,
            Fields::from([
                ("body".into(), "original".into()),
                ("published".into(), "true".into()),
            ]),
        )
        .await
        .unwrap();
    let old = secret(&created);
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let id = tx
        .fetch::<1>("SELECT CAST(id AS TEXT) FROM nx_records", &[])
        .await
        .unwrap()[0][0]
        .parse()
        .unwrap();
    tx.commit().await.unwrap();
    let mut rebound = declarations();
    rebound.resources[0].id = 901;
    for op in &mut rebound.operations {
        op.resource = 901;
    }
    rebound.routes[1].resource = Some(901);
    let keys: HostKeys =
        serde_json::from_value(serde_json::to_value(&*original.keys).unwrap()).unwrap();
    let changed = Application::new(
        &component(),
        &serde_json::to_vec(&rebound).unwrap(),
        manifest::digest(&rebound).unwrap(),
        db.clone(),
        keys,
        Limits::default(),
    )
    .unwrap();
    changed.activate().await.unwrap();
    let page = changed
        .view_page_anonymous(None, Some(&cookie), 2, Some(id), None)
        .await
        .unwrap();
    let csrf = fixture::hidden(text(&page), "_csrf");
    assert_eq!(
        changed
            .submit_with_capability(
                &cookie,
                2,
                &token(&page, 2),
                &csrf,
                Fields::from([("body".into(), "rebound".into())]),
                Some(&old)
            )
            .await
            .unwrap()
            .status,
        303
    );
    let rotation = changed
        .capability_page(901, id, Some(&cookie))
        .await
        .unwrap();
    let rotated = changed
        .rotate_capability(
            901,
            id,
            &cookie,
            &fixture::hidden(text(&rotation), "_csrf"),
            &fixture::hidden(text(&rotation), "_submission"),
            &old,
        )
        .await
        .unwrap();
    let current = secret(&rotated);
    let mut renamed = rebound.clone();
    renamed.resources[0].name = "renamed_notes".into();
    renamed.resources[0].id = 1901;
    for op in &mut renamed.operations {
        op.resource = 1901;
    }
    renamed.routes[1].resource = Some(1901);
    db.schema_apply(
        &renamed,
        &crate::schema::Migration {
            version: 1,
            from: crate::schema::digest(&rebound.resources).unwrap(),
            to: crate::schema::digest(&renamed.resources).unwrap(),
            operations: vec![crate::schema::MigrationOp::RenameResource {
                from: "notes".into(),
                to: "renamed_notes".into(),
            }],
        },
    )
    .await
    .unwrap();
    let keys: HostKeys =
        serde_json::from_value(serde_json::to_value(&*original.keys).unwrap()).unwrap();
    let changed = Application::new(
        &component(),
        &serde_json::to_vec(&renamed).unwrap(),
        manifest::digest(&renamed).unwrap(),
        db,
        keys,
        Limits::default(),
    )
    .unwrap();
    changed.activate().await.unwrap();
    let page = changed
        .view_page_anonymous(None, Some(&cookie), 2, Some(id), None)
        .await
        .unwrap();
    let csrf = fixture::hidden(text(&page), "_csrf");
    assert_eq!(
        changed
            .submit_with_capability(
                &cookie,
                2,
                &token(&page, 2),
                &csrf,
                Fields::from([("body".into(), "renamed".into())]),
                Some(&current)
            )
            .await
            .unwrap()
            .status,
        303
    );
    let rotation = changed
        .capability_page(1901, id, Some(&cookie))
        .await
        .unwrap();
    let rotated = changed
        .rotate_capability(
            1901,
            id,
            &cookie,
            &fixture::hidden(text(&rotation), "_csrf"),
            &fixture::hidden(text(&rotation), "_submission"),
            &current,
        )
        .await
        .unwrap();
    let latest = secret(&rotated);
    let page = changed
        .view_page_anonymous(None, Some(&cookie), 2, Some(id), None)
        .await
        .unwrap();
    let csrf = fixture::hidden(text(&page), "_csrf");
    assert_eq!(
        changed
            .submit_with_capability(
                &cookie,
                3,
                &token(&page, 3),
                &csrf,
                Fields::new(),
                Some(&latest)
            )
            .await
            .unwrap()
            .status,
        303
    );
}
#[tokio::test]
async fn sqlite_edit_secrets_survive_bundle_rebinding_and_resource_rename() {
    let temp = tempfile::tempdir().unwrap();
    persistent_resource_secret_contract(Database::sqlite(temp.path().join("identity.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_edit_secrets_survive_bundle_rebinding_and_resource_rename() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_edit_identity_{}",
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
    persistent_resource_secret_contract(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}

async fn capability_conflict_projection_contract(db: Database) {
    let app = app(db.clone()).await;
    let create = app.view_page(None, 1, None, None).await.unwrap();
    let cookie = create.anonymous_cookie.clone().unwrap();
    let csrf = fixture::hidden(text(&create), "_csrf");
    let handover = app
        .submit(
            &cookie,
            1,
            &token(&create, 1),
            &csrf,
            Fields::from([
                ("body".into(), "initial".into()),
                ("published".into(), "true".into()),
            ]),
        )
        .await
        .unwrap();
    let capability = secret(&handover);
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let id = tx
        .fetch::<1>("SELECT CAST(id AS TEXT) FROM nx_records", &[])
        .await
        .unwrap()[0][0]
        .parse()
        .unwrap();
    tx.commit().await.unwrap();
    let stale = app
        .view_page_anonymous(None, Some(&cookie), 2, Some(id), None)
        .await
        .unwrap();
    let csrf = fixture::hidden(text(&stale), "_csrf");
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let storage = tx.storage_resource(&app.manifest, 1).await.unwrap();
    let changed = Fields::from([
        ("body".into(), "current_public_value".into()),
        ("published".into(), "true".into()),
        ("private".into(), "capability_private_server_value".into()),
    ]);
    tx.execute(
        "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2 AND id=$3",
        &[
            serde_json::to_string(&changed).unwrap().into(),
            storage.into(),
            (id as i64).into(),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    for (action, input) in [
        (2, Fields::from([("body".into(), "visitor input".into())])),
        (3, Fields::new()),
    ] {
        let response = app
            .submit_with_capability(
                &cookie,
                action,
                &token(&stale, action),
                &csrf,
                input,
                Some(&capability),
            )
            .await
            .unwrap();
        assert_eq!(response.status, 409);
        assert!(!text(&response).contains("capability_private_server_value"));
        assert!(!text(&response).contains(&capability));
        assert!(!text(&response).contains("aria-label=\"Current values\""));
    }
}
#[tokio::test]
async fn sqlite_capability_conflicts_never_disclose_nonprojected_fields() {
    let temp = tempfile::tempdir().unwrap();
    capability_conflict_projection_contract(Database::sqlite(
        temp.path().join("conflict-projection.db"),
    ))
    .await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_capability_conflicts_never_disclose_nonprojected_fields() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_cap_conflict_{}",
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
    capability_conflict_projection_contract(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}

async fn custom_presentation_contract(db: Database) {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;
    let presentation = crate::Presentation {
        anonymous_cookie: "visitor".into(),
        registration_path: "/join".into(),
        capability_path: "/manage".into(),
        csrf_field: "check".into(),
        submission_field: "ticket".into(),
        capability_field: "edit_key".into(),
        ..crate::Presentation::default()
    };
    let app = Arc::new(
        Arc::try_unwrap(app(db.clone()).await)
            .ok()
            .unwrap()
            .with_presentation(presentation)
            .unwrap()
            .with_registration(crate::Registration::Open),
    );
    let router = crate::http::router(
        app.clone(),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    let get = |path: &str, cookie: &str| {
        Request::builder()
            .uri(path)
            .header("Host", "localhost:8080")
            .header("Cookie", cookie)
            .body(Body::empty())
            .unwrap()
    };
    let response = router.clone().oneshot(get("/", "")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with("visitor="));
    let html = String::from_utf8(
        to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    for marker in [
        "noxide_anon",
        "/_noxide/capability/",
        "name=\"_csrf\"",
        "name=\"_submission\"",
        "name=\"_capability\"",
    ] {
        assert!(!html.contains(marker), "{marker}");
    }
    let csrf = fixture::hidden(&html, "check");
    let submission = fixture::hidden(&html, "ticket");
    let fields = [
        ("check", csrf.as_str()),
        ("ticket", submission.as_str()),
        ("body", "custom form"),
        ("published", "true"),
    ];
    let before = rows(&db).await;
    let wrong_cookie = cookie.replacen("visitor=", "noxide_anon=", 1);
    assert!(
        !post(
            router.clone(),
            "/actions/1",
            "http://localhost:8080",
            &wrong_cookie,
            &fields
        )
        .await
        .status()
        .is_success()
    );
    let mut old_fields = fields;
    old_fields[0].0 = "_csrf";
    assert!(
        !post(
            router.clone(),
            "/actions/1",
            "http://localhost:8080",
            &cookie,
            &old_fields
        )
        .await
        .status()
        .is_success()
    );
    old_fields = fields;
    old_fields[1].0 = "_submission";
    assert!(
        !post(
            router.clone(),
            "/actions/1",
            "http://localhost:8080",
            &cookie,
            &old_fields
        )
        .await
        .status()
        .is_success()
    );
    assert_eq!(rows(&db).await, before);
    let response = post(
        router.clone(),
        "/actions/1",
        "http://localhost:8080",
        &cookie,
        &fields,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let handover = String::from_utf8(
        to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let secret = handover
        .split("<pre>")
        .nth(1)
        .unwrap()
        .split("</pre>")
        .next()
        .unwrap();
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let id = tx
        .fetch::<1>("SELECT CAST(id AS TEXT) FROM nx_records", &[])
        .await
        .unwrap()[0][0]
        .clone();
    tx.commit().await.unwrap();
    let response = router
        .clone()
        .oneshot(get(&format!("/notes/{id}"), &cookie))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("name=\"edit_key\""));
    assert!(!html.contains("name=\"_capability\""));
    let edit = html.split("action=\"/actions/2\"").nth(1).unwrap();
    let csrf = fixture::hidden(edit, "check");
    let submission = fixture::hidden(edit, "ticket");
    let fields = [
        ("check", csrf.as_str()),
        ("ticket", submission.as_str()),
        ("edit_key", secret),
        ("body", "edited through custom fields"),
    ];
    let response = post(
        router.clone(),
        "/actions/2",
        "http://localhost:8080",
        &cookie,
        &fields,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let path = format!("/manage/1/{id}");
    let response = router.clone().oneshot(get(&path, &cookie)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let html = String::from_utf8(
        to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains(&format!("action=\"{path}\"")));
    assert!(html.contains("name=\"edit_key\""));
    assert!(!html.contains("_noxide"));
    let csrf = fixture::hidden(&html, "check");
    let submission = fixture::hidden(&html, "ticket");
    let rotation = [
        ("check", csrf.as_str()),
        ("ticket", submission.as_str()),
        ("edit_key", secret),
    ];
    assert_eq!(
        post(
            router.clone(),
            &path,
            "http://localhost:8080",
            &cookie,
            &rotation
        )
        .await
        .status(),
        StatusCode::OK
    );
    for old in [format!("/_noxide/capability/1/{id}"), "/register".into()] {
        assert_eq!(
            router
                .clone()
                .oneshot(get(&old, &cookie))
                .await
                .unwrap()
                .status(),
            StatusCode::SEE_OTHER
        );
    }
    let response = router.clone().oneshot(get("/join", "")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let challenge = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let html = String::from_utf8(
        to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("action=\"/join\""));
    assert!(!html.contains("/register"));
    assert!(!html.contains("_csrf"));
    let csrf = fixture::hidden(&html, "check");
    let registration = [
        ("check", csrf.as_str()),
        ("username", "newuser"),
        ("password", "custom registration password"),
    ];
    let rejected = post(
        router.clone(),
        "/join",
        "http://localhost:8080",
        "",
        &registration,
    )
    .await;
    let html = String::from_utf8(
        to_bytes(rejected.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("href=\"/join\""));
    assert!(!html.contains("/register"));
    let response = post(
        router,
        "/join",
        "http://localhost:8080",
        &challenge,
        &registration,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login");
    let closed = Arc::new(
        Arc::try_unwrap(app)
            .ok()
            .unwrap()
            .with_registration(crate::Registration::Closed),
    );
    let router = crate::http::router(
        closed,
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    assert_eq!(
        router
            .clone()
            .oneshot(get("/join", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post(router, "/join", "http://localhost:8080", "", &[])
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn sqlite_custom_presentation_hides_fixed_markers_and_preserves_credentials() {
    let temp = tempfile::tempdir().unwrap();
    custom_presentation_contract(Database::sqlite(temp.path().join("presentation.db"))).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_custom_presentation_hides_fixed_markers_and_preserves_credentials() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_presentation_{}",
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
    custom_presentation_contract(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_initial_fields_reject_clients_and_stale_contracts() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("initial.db"));
    db.initialize().await.unwrap();
    db.create_account("alice", "initial test password", "")
        .await
        .unwrap();
    for public in [true, false] {
        let mut m = declarations();
        m.resources[0].fields[1].initial = Some("true".into());
        m.actions[0].fields.retain(|f| f != "published");
        if !public {
            m.operations[2].policy.any = vec![vec![Predicate::Owner]];
        }
        let keys = serde_json::to_vec(&HostKeys::generate().unwrap()).unwrap();
        let make = |m: &Manifest| {
            Arc::new(
                Application::new(
                    &component(),
                    &serde_json::to_vec(m).unwrap(),
                    manifest::digest(m).unwrap(),
                    db.clone(),
                    serde_json::from_slice(&keys).unwrap(),
                    Limits::default(),
                )
                .unwrap(),
            )
        };
        let app = make(&m);
        app.activate().await.unwrap();
        let session = if public {
            None
        } else {
            let challenge = app.login_challenge().await.unwrap();
            Some(
                app.login(
                    &challenge.cookie,
                    &challenge.csrf,
                    "alice",
                    "initial test password",
                )
                .await
                .unwrap(),
            )
        };
        let page = app
            .view_page(session.as_deref(), 1, None, None)
            .await
            .unwrap();
        let cookie = session.unwrap_or_else(|| page.anonymous_cookie.clone().unwrap());
        let submission = token(&page, 1);
        let csrf = fixture::hidden(text(&page), "_csrf");
        assert!(!text(&page).contains("name=\"published\""));
        let before = rows(&db).await;
        for value in ["on", "false"] {
            assert!(
                app.submit(
                    &cookie,
                    1,
                    &submission,
                    &csrf,
                    Fields::from([
                        ("body".into(), "attempt".into()),
                        ("published".into(), value.into()),
                    ])
                )
                .await
                .is_err()
            );
            assert_eq!(rows(&db).await, before);
        }
        let input = Fields::from([("body".into(), "approved".into())]);
        assert!(
            app.submit(&cookie, 1, &submission, &csrf, input.clone())
                .await
                .is_ok()
        );
        // Use an unused token, so rejection cannot be explained by receipt replay.
        let page = app
            .view_page(
                if public { None } else { Some(cookie.as_str()) },
                1,
                None,
                None,
            )
            .await
            .unwrap();
        let stale_cookie = if public {
            page.anonymous_cookie
                .clone()
                .unwrap_or_else(|| cookie.clone())
        } else {
            cookie.clone()
        };
        let submission = token(&page, 1);
        let csrf = fixture::hidden(text(&page), "_csrf");
        let mut changed = m.clone();
        changed.resources[0].fields[1].initial = Some("false".into());
        let changed = make(&changed);
        changed.activate().await.unwrap();
        assert!(
            changed
                .submit(&stale_cookie, 1, &submission, &csrf, input)
                .await
                .is_err()
        );
    }
}
