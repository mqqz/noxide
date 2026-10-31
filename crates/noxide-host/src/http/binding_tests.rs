//! HTTP adapter regressions use binding IDs distinct from every execution ID.
use super::*;
use crate::{Database, HostKeys, manifest, runtime::Limits, test_support as fixture};
use noxide_protocol::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn component() -> Vec<u8> {
    fn emit(bytes: &[u8]) -> String {
        bytes
            .chunks(8)
            .map(|chunk| {
                let mut word = [0; 8];
                word[..chunk.len()].copy_from_slice(chunk);
                format!(
                    "i64.const {} i32.const {} call $emit\n",
                    i64::from_le_bytes(word),
                    chunk.len()
                )
            })
            .collect()
    }
    let page = emit(
        &serde_json::to_vec(&ResponseIntent::Page(Document::new(
            "Alternate binding",
            vec![Instruction::Form { action: 91 }],
        )))
        .unwrap(),
    );
    let execute = emit(&serde_json::to_vec(&ResponseIntent::Execute).unwrap());
    let kind = format!("{{\"version\":{VERSION},\"kind\":{{").len() + 1;
    wat::parse_str(format!(r#"(component
        (import "noxide:application/host@0.1.0" (instance $host
            (export "emit" (func (param "word" u64) (param "length" u32)))
            (export "request-chunk" (func (param "offset" u32) (result u64)))))
        (alias export $host "emit" (func $emit))
        (alias export $host "request-chunk" (func $request))
        (core func $emit (canon lower (func $emit)))
        (core func $request (canon lower (func $request)))
        (core module $guest
            (import "h" "emit" (func $emit (param i64 i32)))
            (import "h" "request" (func $request (param i32) (result i64)))
            (func (export "handle")
                i32.const {kind} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 97 i32.eq
                if {execute} else {page} end))
        (core instance $i (instantiate $guest (with "h" (instance
            (export "emit" (func $emit)) (export "request" (func $request))))))
        (func (export "handle") (canon lift (core func $i "handle"))))"#)).unwrap()
}

async fn application(
    collision: Option<Predicate>,
) -> (tempfile::TempDir, Database, Arc<Application>) {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("bindings.db"));
    db.initialize().await.unwrap();
    let mut m = fixture::manifest();
    m.operations[2].policy = Policy {
        any: vec![vec![Predicate::Public]],
    };
    m.web_bindings[0].id = 91;
    m.routes[0].forms = vec![91];
    m.routes[0].access = Access::PublicOptional;
    if let Some(policy) = collision {
        let mut operation = m.operations[2].clone();
        operation.id = 4;
        operation.kind = OperationKind::Update;
        operation.policy = Policy {
            any: vec![vec![policy]],
        };
        m.operations.push(operation);
        let mut unrelated = m.actions[0].clone();
        unrelated.id = 91;
        unrelated.steps[0].operation = 4;
        unrelated.steps[0].target = Target::Named("target".into());
        unrelated.targets = vec![fixture::page_target(1, vec![2], Revision::Exact)];
        m.actions.push(unrelated);
    }
    let app = Arc::new(
        Application::new(
            &component(),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db.clone(),
            HostKeys::generate().unwrap(),
            Limits::default(),
            crate::DeploymentResources {
                jobs: None,
                assets: crate::assets::AssetBundle::default(),
                blobs: None,
            },
        )
        .unwrap(),
    );
    app.activate().await.unwrap();
    (temp, db, app)
}

async fn exchange(address: std::net::SocketAddr, body: Option<&str>, cookie: &str) -> String {
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = if let Some(body) = body {
        format!(
            "POST /actions/91 HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nCookie: {cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    } else {
        format!("GET / HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
    };
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        socket.read_to_string(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    response
}

async fn socket_case(collision: Option<Predicate>) {
    let (_temp, db, app) = application(collision.clone()).await;
    let listener = Listener::loopback("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let address = match &listener.0 {
        ListenerKind::Tcp(tcp) => tcp.local_addr().unwrap(),
        #[cfg(unix)]
        _ => unreachable!(),
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(
        listener,
        app,
        Origin::parse(&format!("http://{address}")).unwrap(),
        async {
            let _ = stopped.await;
        },
    ));
    let page = exchange(address, None, "").await;
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.contains("action=\"/actions/91\""));
    let cookie = page
        .split_once("set-cookie: noxide_anon=")
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap();
    let cookie = format!("noxide_anon={cookie}");
    let token = fixture::hidden(&page, "_submission");
    let csrf = fixture::hidden(&page, "_csrf");
    let encode = |value: &str, capability: bool| {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("_csrf", &csrf)
            .append_pair("_submission", &token)
            .append_pair("body", value);
        if capability {
            form.append_pair("_capability", "unrelated action secret");
        }
        form.finish()
    };
    if collision.is_some() {
        // Execution 91 is a capability mutation; binding 91 invokes public create 1.
        // That unrelated declaration must not admit a capability field here.
        let rejected = exchange(address, Some(&encode("forged", true)), &cookie).await;
        assert!(rejected.starts_with("HTTP/1.1 400"), "{rejected}");
    }
    // Invalid input takes HTTP's recovery path and retains binding 91 for retry.
    let invalid = exchange(address, Some(&encode("", false)), &cookie).await;
    assert!(invalid.starts_with("HTTP/1.1 422"), "{invalid}");
    assert!(invalid.contains("action=\"/actions/91\"") && invalid.contains(&token));
    let body = encode("one mutation through an alternate binding", false);
    let saved = exchange(address, Some(&body), &cookie).await;
    assert!(saved.starts_with("HTTP/1.1 200"), "{saved}");
    let secret = saved
        .split_once("<pre>")
        .unwrap()
        .1
        .split_once("</pre>")
        .unwrap()
        .0;
    let replay = exchange(address, Some(&body), &cookie).await;
    assert!(replay.starts_with("HTTP/1.1 200"), "{replay}");
    assert!(replay.contains(&format!("<pre>{secret}</pre>")));
    let mut tx = db
        .begin_read((tokio::time::Instant::now() + Duration::from_secs(3)).into_std())
        .await
        .unwrap();
    for table in ["nx_records", "nx_receipts"] {
        assert_eq!(
            tx.fetch::<1>(&format!("SELECT CAST(COUNT(*) AS TEXT) FROM {table}"), &[])
                .await
                .unwrap()[0][0],
            "1"
        );
    }
    tx.commit().await.unwrap();
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn alternate_binding_http_submits_replays_and_recovers_without_matching_core_id() {
    socket_case(None).await;
}

#[tokio::test]
async fn colliding_core_id_cannot_grant_http_capability_fields() {
    socket_case(Some(Predicate::Capability)).await;
}

#[tokio::test]
async fn binding_target_controls_http_admission_class_despite_core_id_collision() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let (_temp, _db, app) = application(Some(Predicate::Owner)).await;
    let router = router(app.clone(), Origin::parse("http://localhost:8080").unwrap());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/actions/91")
                .header("Host", "localhost:8080")
                .header("Origin", "http://localhost:8080")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .extension(Peer::Circuit(1))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // A fresh circuit cannot afford an anonymous mutation. Treating the
    // colliding owner-only core as authoritative would admit it for less cost.
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!app.admission_limits.charge_circuit(
        Peer::Circuit(2),
        crate::runtime::limiter::RequestClass::AnonymousAction
    ));
    assert_eq!(
        app.admission_limits.circuit_millitokens(1),
        app.admission_limits.circuit_millitokens(2)
    );
}
