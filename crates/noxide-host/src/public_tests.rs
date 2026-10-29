use crate::{
    Application, Database, HostKeys, RequestError,
    auth::{Principal, User},
    database::Param,
    manifest,
    repository::{self, Effects},
    runtime::Limits,
    security, test_support as fixture,
};
use noxide_protocol::*;
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

fn declarations() -> Manifest {
    let mut m = fixture::manifest();
    m.resources[0].fields.extend([
        TextField {
            kind: FieldKind::Boolean,
            optional: false,
            initial: None,
            name: "published".into(),
            label: "Published".into(),
            max_bytes: 5,
        },
        TextField {
            kind: FieldKind::Text,
            optional: false,
            initial: None,
            name: "secret".into(),
            label: "Secret".into(),
            max_bytes: 64,
        },
    ]);
    m.actions.clear();
    m.routes[0].forms.clear();
    for op in &mut m.operations[..2] {
        op.policy.any = vec![vec![Predicate::Public]];
        op.visibility = Some(Visibility {
            field: "published".into(),
            equals: "true".into(),
        });
        op.fields = Some(vec!["body".into()]);
    }
    m.routes[0].access = Access::Public;
    m.routes[1].access = Access::Public;
    for (id, predicate) in [
        (4, Predicate::Owner),
        (5, Predicate::SameTenant),
        (
            6,
            Predicate::Role {
                name: "reader".into(),
                tenant_scoped: false,
            },
        ),
        (
            7,
            Predicate::Role {
                name: "reader".into(),
                tenant_scoped: true,
            },
        ),
    ] {
        m.operations.push(Operation {
            id,
            resource: 1,
            kind: OperationKind::List,
            policy: Policy {
                any: vec![vec![predicate]],
            },
            visibility: None,
            fields: None,
        });
    }
    m.routes.push(Route {
        id: 3,
        path: "/private".into(),
        resource: None,
        operations: vec![4],
        forms: vec![],
        access: Access::Authenticated,
    });
    m
}

fn create_action(m: &mut Manifest) {
    let mut action = fixture::manifest().actions.remove(0);
    action.fields = m.resources[0]
        .fields
        .iter()
        .map(|field| field.name.clone())
        .collect();
    m.actions.push(action);
}

#[test]
fn manifest_public_policy_must_stand_alone() {
    for policy in [
        vec![vec![Predicate::Public, Predicate::Owner]],
        vec![vec![Predicate::Public], vec![Predicate::Owner]],
        vec![vec![Predicate::Public, Predicate::Public]],
    ] {
        let mut m = declarations();
        m.operations[0].policy.any = policy;
        assert!(
            manifest::validate(&m)
                .unwrap_err()
                .to_string()
                .contains("stand alone")
        );
    }
}

#[test]
fn manifest_public_read_requires_visibility_and_projection() {
    for case in 0..7 {
        let mut m = declarations();
        match case {
            0 => m.operations[0].kind = OperationKind::Create,
            1 => m.operations[0].visibility = None,
            2 => m.operations[0].fields = None,
            3 => m.operations[0].fields = Some(vec![]),
            4 => m.operations[0].fields = Some(vec!["body".into(), "body".into()]),
            5 => m.operations[0].fields = Some(vec!["absent".into()]),
            _ => m.operations[0].kind = OperationKind::Delete,
        }
        assert!(manifest::validate(&m).is_err(), "case {case}");
    }
}

#[test]
fn manifest_visibility_requires_canonical_boolean_or_choice() {
    for (field, equals) in [
        ("body", "true"),
        ("absent", "true"),
        ("published", "on"),
        ("published", "TRUE"),
    ] {
        let mut m = declarations();
        m.operations[0].visibility = Some(Visibility {
            field: field.into(),
            equals: equals.into(),
        });
        assert!(manifest::validate(&m).is_err(), "{field}={equals}");
    }
    let mut m = declarations();
    m.resources[0].fields[1].kind = FieldKind::Choice {
        variants: vec![ChoiceVariant {
            key: "live".into(),
            label: "Published".into(),
        }],
    };
    for op in &mut m.operations[..2] {
        op.visibility.as_mut().unwrap().equals = "live".into();
    }
    manifest::validate(&m).unwrap();
    m.operations[0].visibility.as_mut().unwrap().equals = "Published".into();
    assert!(manifest::validate(&m).is_err());
}

#[test]
fn manifest_private_operations_forbid_public_metadata() {
    for visibility in [true, false] {
        let mut m = declarations();
        if visibility {
            m.operations[2].visibility = m.operations[0].visibility.clone();
        } else {
            m.operations[2].fields = Some(vec!["body".into()]);
        }
        assert!(
            manifest::validate(&m)
                .unwrap_err()
                .to_string()
                .contains("private operations")
        );
    }
}

#[test]
fn manifest_action_inspection_cannot_use_public_read() {
    let mut m = declarations();
    m.operations.push(Operation {
        id: 8,
        resource: 1,
        kind: OperationKind::Update,
        policy: Policy {
            any: vec![vec![Predicate::Owner]],
        },
        visibility: None,
        fields: None,
    });
    let mut action = fixture::manifest().actions.remove(0);
    action.operation = 8;
    action.inspect = Some(Inspection {
        operation: 2,
        fields: vec!["body".into()],
    });
    m.actions.push(action);
    m.routes[1].access = Access::PublicOptional;
    m.routes[1].forms.push(1);
    assert!(
        manifest::validate(&m)
            .unwrap_err()
            .to_string()
            .contains("inspection cannot")
    );
}

#[test]
fn manifest_public_routes_require_public_operations_and_no_forms() {
    let mut m = declarations();
    m.routes[0].operations = vec![4];
    assert!(manifest::validate(&m).is_err());
    let mut m = declarations();
    create_action(&mut m);
    m.routes[0].forms.push(1);
    assert!(
        manifest::validate(&m)
            .unwrap_err()
            .to_string()
            .contains("public routes cannot have forms")
    );
}

#[test]
fn manifest_optional_routes_allow_private_operations_and_forms() {
    let mut m = declarations();
    create_action(&mut m);
    m.routes[0].access = Access::PublicOptional;
    m.routes[0].operations = vec![4];
    m.routes[0].forms.push(1);
    manifest::validate(&m).unwrap();
}

#[test]
fn manifest_public_operations_allow_every_route_access() {
    for access in [
        Access::Authenticated,
        Access::Public,
        Access::PublicOptional,
    ] {
        let mut m = declarations();
        m.routes[0].access = access.clone();
        m.routes[1].access = access;
        manifest::validate(&m).unwrap();
    }
}

fn effects(
    tx: crate::database::Transaction,
    m: &Manifest,
    principal: Principal,
    route: u32,
    target: Option<u64>,
) -> Effects {
    Effects {
        tx,
        manifest: Arc::new(m.clone()),
        principal,
        request: RequestView {
            version: VERSION,
            kind: RequestKind::Route(route),
            target,
            input: Fields::new(),
            inspection: None,
            available_forms: vec![],
        },
        outcome: None,
        grant: None,
        capability_grant: None,
        record: None,
        calls: 64,
        cursor: None,
        more: None,
    }
}

async fn public_repository(db: Database, choice: bool) {
    let mut m = declarations();
    let published = if choice { "live" } else { "true" };
    let unpublished = if choice { "draft" } else { "false" };
    if choice {
        m.resources[0].fields[1].kind = FieldKind::Choice {
            variants: vec![
                ChoiceVariant {
                    key: published.into(),
                    label: "Published".into(),
                },
                ChoiceVariant {
                    key: unpublished.into(),
                    label: "Draft".into(),
                },
            ],
        };
        for op in &mut m.operations[..2] {
            op.visibility.as_mut().unwrap().equals = published.into();
        }
    }
    manifest::validate(&m).unwrap();
    db.initialize().await.unwrap();
    db.create_account("alice", "public test password", "")
        .await
        .unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.bind_schema(&m).await.unwrap();
    for id in 1_i64..=20 {
        let fields = Fields::from([
            ("body".into(), format!("body{id}")),
            (
                "published".into(),
                if id % 2 == 1 { published } else { unpublished }.into(),
            ),
            ("secret".into(), "hidden".into()),
        ]);
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision) VALUES(1,$1,'alice','',$2,'public-fixture',1)", &[id.into(), serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
    }
    tx.commit().await.unwrap();
    for principal in [
        Principal::Anonymous,
        Principal::User(User {
            id: "bob".into(),
            tenant: "".into(),
            roles: vec![],
        }),
    ] {
        let tx = db
            .begin_read(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let mut e = effects(tx, &m, principal, 1, None);
        let mut ids = BTreeSet::new();
        loop {
            let records: Vec<Record> =
                serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            for record in &records {
                assert_eq!(record.id % 2, 1);
                assert_eq!(
                    record.fields.keys().map(String::as_str).collect::<Vec<_>>(),
                    ["body"]
                );
                assert!(ids.insert(record.id));
            }
            if records.is_empty() {
                break;
            }
            e.cursor = e.more.take();
            if e.cursor.is_none() {
                break;
            }
        }
        assert_eq!(ids.len(), 10);
        e.request.kind = RequestKind::Route(2);
        for id in 1..=21 {
            e.request.target = Some(id);
            let record: Option<Record> =
                serde_json::from_slice(&e.invoke(2, id).await.unwrap()).unwrap();
            assert_eq!(record.is_some(), id <= 20 && id % 2 == 1);
            if let Some(record) = record {
                assert_eq!(record.fields.len(), 1);
                assert!(record.fields.contains_key("body"));
            }
        }
        e.tx.commit().await.unwrap();
    }
    for op in &m.operations[3..] {
        assert!(!repository::allowed(
            &op.policy,
            &Principal::Anonymous,
            "",
            ""
        ));
        assert!(!repository::allowed(
            &op.policy,
            &Principal::Anonymous,
            "alice",
            ""
        ));
        let mut private = m.clone();
        private.routes[2].operations = vec![op.id];
        let tx = db
            .begin_read(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let mut e = effects(tx, &private, Principal::Anonymous, 3, None);
        let records: Vec<Record> =
            serde_json::from_slice(&e.invoke(op.id, 0).await.unwrap()).unwrap();
        assert!(records.is_empty());
        e.tx.commit().await.unwrap();
    }
    let tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let mut private = m.clone();
    private.operations[1].policy.any = vec![vec![Predicate::Owner]];
    private.operations[1].visibility = None;
    private.operations[1].fields = None;
    private.routes[1].access = Access::Authenticated;
    let mut e = effects(
        tx,
        &private,
        Principal::User(User {
            id: "alice".into(),
            tenant: "".into(),
            roles: vec![],
        }),
        2,
        Some(1),
    );
    let record: Record = serde_json::from_slice::<Option<Record>>(&e.invoke(2, 1).await.unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(record.fields.len(), 3);
    assert!(record.fields.contains_key("secret"));
    e.tx.commit().await.unwrap();
    let tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let mut e = effects(tx, &m, Principal::Anonymous, 1, None);
    assert!(
        e.invoke(4, 0).await.is_err(),
        "public route cannot borrow private operations"
    );
    e.tx.rollback().await.unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let invalid = Fields::from([
        ("body".into(), "valid".into()),
        ("published".into(), published.into()),
        ("secret".into(), "invalid\u{1}".into()),
    ]);
    tx.execute(
        "UPDATE nx_records SET fields=$1 WHERE id=19",
        &[serde_json::to_string(&invalid).unwrap().into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let mut e = effects(tx, &m, Principal::Anonymous, 1, None);
    assert!(
        e.invoke(1, 0).await.is_err(),
        "validate hidden stored fields before projecting"
    );
    e.request.kind = RequestKind::Route(2);
    e.request.target = Some(19);
    assert!(e.invoke(2, 19).await.is_err());
    e.tx.rollback().await.unwrap();
}

fn guest(nodes: Vec<Instruction>, invoke: Option<u32>) -> Vec<u8> {
    let bytes =
        serde_json::to_vec(&ResponseIntent::Page(Document::new("Articles", nodes))).unwrap();
    let emit = bytes
        .chunks(8)
        .map(|part| {
            let mut word = [0; 8];
            word[..part.len()].copy_from_slice(part);
            format!(
                "i64.const {} i32.const {} call $emit",
                i64::from_le_bytes(word),
                part.len()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let invoke = invoke
        .map(|id| format!("i32.const {id} i64.const 0 call $invoke drop"))
        .unwrap_or_default();
    wat::parse_str(format!(r#"(component
      (import "noxide:application/host@0.1.0" (instance $host
        (export "emit" (func (param "word" u64) (param "length" u32)))
        (export "invoke" (func (param "operation" u32) (param "target" u64) (result u32)))))
      (alias export $host "emit" (func $emit)) (core func $emit (canon lower (func $emit)))
      (alias export $host "invoke" (func $invoke)) (core func $invoke (canon lower (func $invoke)))
      (core module $m
        (import "h" "emit" (func $emit (param i64 i32)))
        (import "h" "invoke" (func $invoke (param i32 i64) (result i32)))
        (func (export "handle") {invoke} {emit}))
      (core instance $i (instantiate $m (with "h" (instance (export "emit" (func $emit)) (export "invoke" (func $invoke))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#)).unwrap()
}

async fn application(
    db: &Database,
    m: &Manifest,
    nodes: Vec<Instruction>,
    invoke: Option<u32>,
) -> Arc<Application> {
    let app = Arc::new(
        Application::new(
            &guest(nodes, invoke),
            &serde_json::to_vec(m).unwrap(),
            manifest::digest(m).unwrap(),
            db.clone(),
            HostKeys::generate().unwrap(),
            Limits::default(),
        )
        .unwrap(),
    );
    app.activate().await.unwrap();
    app
}

async fn public_request_flows(db: Database) {
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderValue, Request, StatusCode},
    };
    use tower::ServiceExt;
    db.initialize().await.unwrap();
    db.create_account("alice", "public test password", "")
        .await
        .unwrap();
    let mut m = declarations();
    m.routes[0].access = Access::PublicOptional;
    m.routes.push(Route {
        id: 4,
        path: "/public".into(),
        resource: None,
        operations: vec![1],
        forms: vec![],
        access: Access::Public,
    });
    let app = application(
        &db,
        &m,
        vec![Instruction::Text("Public articles".into())],
        None,
    )
    .await;
    let challenge = app.login_challenge().await.unwrap();
    let session = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "public test password",
        )
        .await
        .unwrap();
    let router = crate::http::router(
        app.clone(),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    let request = |path: &str, cookie: Option<HeaderValue>| {
        let mut request = Request::builder()
            .uri(path)
            .header("Host", "localhost:8080");
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        request.body(Body::empty()).unwrap()
    };
    let (_, expired) = app
        .keys
        .issue(
            security::TokenKind::Session,
            "alice",
            security::now().unwrap() - 4000,
            3600,
        )
        .unwrap();
    for cookie in [
        None,
        Some(HeaderValue::from_static("session=garbage")),
        Some(HeaderValue::from_str(&format!("session={expired}")).unwrap()),
    ] {
        let response = router.clone().oneshot(request("/", cookie)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["Cache-Control"], "no-store");
        assert!(response.headers().get("Set-Cookie").is_none());
        let body = to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
            .await
            .unwrap();
        assert!(!std::str::from_utf8(&body).unwrap().contains("Sign out"));
    }
    let cookie = HeaderValue::from_str(&format!("session={session}")).unwrap();
    let response = router
        .clone()
        .oneshot(request("/", Some(cookie.clone())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
        .await
        .unwrap();
    assert!(std::str::from_utf8(&body).unwrap().contains("/logout"));
    for malformed in [
        HeaderValue::from_bytes(&[0xff]).unwrap(),
        HeaderValue::from_static("session=one; session=two"),
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request("/public", Some(malformed)))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        router
            .clone()
            .oneshot(request("/private", None))
            .await
            .unwrap()
            .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        router
            .clone()
            .oneshot(request("/private", Some(cookie.clone())))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let token = app.keys.verify(&session, security::now().unwrap()).unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "DELETE FROM nx_sessions WHERE id=$1",
        &[token.nonce.as_str().into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let response = router
        .clone()
        .oneshot(request("/", Some(cookie.clone())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), MAX_OUTPUT_BYTES)
        .await
        .unwrap();
    assert!(!std::str::from_utf8(&body).unwrap().contains("/logout"));
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "INSERT INTO nx_sessions(id,principal,epoch,expires) VALUES($1,'alice',1,$2)",
        &[token.nonce.into(), Param::Number(token.expires)],
    )
    .await
    .unwrap();
    tx.execute("ALTER TABLE nx_sessions RENAME TO nx_sessions_offline", &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        router
            .clone()
            .oneshot(request("/", Some(cookie.clone())))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        router
            .clone()
            .oneshot(request("/public", Some(cookie)))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute("ALTER TABLE nx_sessions_offline RENAME TO nx_sessions", &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let forged = application(&db, &m, vec![], Some(4)).await;
    assert!(matches!(
        forged.view_page(None, 4, None, None).await,
        Err(RequestError::Rejected)
    ));
    create_action(&mut m);
    m.routes[0].forms = vec![1];
    let forms = application(&db, &m, vec![Instruction::Form { action: 1 }], None).await;
    let anonymous_page = forms.view_page(None, 1, None, None).await.unwrap();
    let anonymous_html = std::str::from_utf8(&anonymous_page.body).unwrap();
    assert_eq!(anonymous_page.status, 200);
    assert!(
        !anonymous_html.contains("action=\"/actions/1\"")
            && !anonymous_html.contains("name=\"_submission\""),
        "declared unavailable forms are omitted without granting anonymous mutation credentials"
    );
    let challenge = forms.login_challenge().await.unwrap();
    let session = forms
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "public test password",
        )
        .await
        .unwrap();
    assert!(forms.view_page(Some(&session), 1, None, None).await.is_ok());
}

#[tokio::test]
async fn sqlite_public_reads_filter_and_project_every_page() {
    let temp = tempfile::tempdir().unwrap();
    public_repository(Database::sqlite(temp.path().join("public.db")), false).await;
}
#[tokio::test]
async fn sqlite_public_route_access_and_auth_failures() {
    let temp = tempfile::tempdir().unwrap();
    public_request_flows(Database::sqlite(temp.path().join("public-flow.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_public_reads_and_route_access() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for case in ["repository", "choice", "http"] {
        let name = format!(
            "nx_public_{case}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut case_url = url::Url::parse(&url).unwrap();
        case_url.set_path(&format!("/{name}"));
        let db = Database::postgres(case_url.as_str()).unwrap();
        if case == "http" {
            public_request_flows(db).await;
        } else {
            public_repository(db, case == "choice").await;
        }
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn sqlite_public_choice_reads_filter_and_project_every_page() {
    let temp = tempfile::tempdir().unwrap();
    public_repository(Database::sqlite(temp.path().join("public-choice.db")), true).await;
}
