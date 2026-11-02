#[tokio::test]
async fn browser_encoded_maximum_fields_save_and_recover() {
    use crate::{
        Application, Database, HostKeys, manifest, runtime::Limits, test_support as fixture,
    };
    use noxide_protocol::{Fields, Manifest, TextField};
    use std::sync::Arc;

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
                crate::DeploymentResources {
                    effects: None,
                    jobs: None,
                    assets: crate::assets::AssetBundle::default(),
                    blobs: None,
                },
            )
            .unwrap(),
        );
        app.activate().await.unwrap();
        app
    }

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let temp = tempfile::tempdir().unwrap();
    let mut m = fixture::manifest();
    m.resources[0].fields.push(TextField {
        immutable: false,
        kind: noxide_protocol::FieldKind::Text,
        optional: false,
        initial: None,
        name: "extra".into(),
        label: "Extra".into(),
        max_bytes: 4096,
    });
    fixture::add_input(&mut m.actions[0], &m.resources[0], "extra");
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
    let router = crate::router(
        app.clone(),
        crate::Origin::parse("http://localhost:8080").unwrap(),
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

use super::*;
#[cfg(unix)]
#[tokio::test]
async fn unix_listener_cleans_up_only_its_own_socket() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("runtime.sock");
    let listener = Listener::unix(&path).unwrap();
    assert!(Listener::unix(&path).is_err());
    assert!(path.exists());
    drop(listener);
    assert!(!path.exists());
    let listener = Listener::unix(&path).unwrap();
    std::fs::rename(&path, temp.path().join("old.sock")).unwrap();
    std::fs::write(&path, "replacement").unwrap();
    drop(listener);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
    assert!(Listener::unix(&path).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
}
async fn exchange(address: std::net::SocketAddr, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(bytes).unwrap();
    let headers = response
        .split_once("\r\n\r\n")
        .unwrap()
        .0
        .to_ascii_lowercase();
    assert!(!headers.contains("\r\ndate:"), "{headers}");
    assert!(!headers.contains("\r\nserver:"), "{headers}");
    assert!(!response.contains("noxide"), "{response}");
    response
}

#[tokio::test]
async fn socket_responses_use_deployment_presentation_without_clock_headers() {
    use crate::{
        Database, HostKeys, Presentation, manifest, runtime::Limits, test_support as fixture,
    };
    for custom in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let db = Database::sqlite(temp.path().join("http.db"));
        db.initialize().await.unwrap();
        db.create_account("alice", "socket test password", "")
            .await
            .unwrap();
        let m = fixture::manifest();
        let p = if custom {
            Presentation {
                session_cookie: "account".into(),
                login_cookie: "challenge".into(),
                login_path: "/signin".into(),
                logout_path: "/signout".into(),
                action_path: "/submit".into(),
                stylesheet_path: "/theme.css".into(),
                stylesheet: Some("body { color: #123; margin: 1rem }".into()),
                csrf_field: "check".into(),
                submission_field: "ticket".into(),
                ..Presentation::default()
            }
        } else {
            Presentation::default()
        };
        let app = Arc::new(
            Application::new(
                &fixture::component(Some("trap")),
                &serde_json::to_vec(&m).unwrap(),
                manifest::digest(&m).unwrap(),
                db,
                HostKeys::generate().unwrap(),
                Limits::default(),
                crate::DeploymentResources {
                    effects: None,
                    jobs: None,
                    assets: crate::assets::AssetBundle::default(),
                    blobs: None,
                },
            )
            .unwrap()
            .with_presentation(p.clone())
            .unwrap(),
        );
        app.activate().await.unwrap();
        let listener = Listener::loopback("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = match &listener.0 {
            ListenerKind::Tcp(tcp) => tcp.local_addr().unwrap(),
            #[cfg(unix)]
            _ => unreachable!(),
        };
        let origin = format!("http://{address}");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(serve(
            listener,
            app,
            Origin::parse(&origin).unwrap(),
            async {
                let _ = stopped.await;
            },
        ));
        let get = |path: &str, cookie: &str| {
            format!(
                "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nCookie: {cookie}\r\n\r\n"
            )
        };
        let post = |path: &str, cookie: &str, body: &str| {
            format!(
                "POST {path} HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: {cookie}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let cookie = |response: &str, name: &str| {
            response
                .split_once(&format!("set-cookie: {name}="))
                .unwrap()
                .1
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        };
        let redirected = exchange(address, &get("/", "")).await;
        assert!(redirected.starts_with("HTTP/1.1 303"));
        assert!(redirected.contains(&format!("location: {}\r\n", p.login_path)));
        if !custom {
            let absent_css = exchange(address, &get(&p.stylesheet_path, "")).await;
            // An unconfigured asset must behave like any unknown path,
            // rather than retaining a distinctive anonymous 404 endpoint.
            assert_eq!(absent_css, exchange(address, &get("/missing", "")).await);
        }
        let login = exchange(address, &get(&p.login_path, "")).await;
        assert!(login.starts_with("HTTP/1.1 200"));
        assert!(login.contains("HttpOnly; SameSite=Strict"));
        assert_eq!(login.contains("rel=\"stylesheet\""), custom);
        let csrf = fixture::hidden(&login, &p.csrf_field);
        let challenge = cookie(&login, &p.login_cookie);
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair(&p.csrf_field, &csrf)
            .append_pair("username", "alice")
            .append_pair("password", "socket test password")
            .finish();
        let signed = exchange(
            address,
            &post(
                &p.login_path,
                &format!("{}={challenge}", p.login_cookie),
                &body,
            ),
        )
        .await;
        assert!(signed.starts_with("HTTP/1.1 303"));
        let session = cookie(&signed, &p.session_cookie);
        let cookie_header = format!("{}={session}", p.session_cookie);
        let page = exchange(address, &get("/", &cookie_header)).await;
        assert!(page.starts_with("HTTP/1.1 200"));
        assert!(page.contains(&format!("action=\"{}/1\"", p.action_path)));
        assert!(page.contains(&format!("action=\"{}\"", p.logout_path)));
        assert_eq!(page.contains("rel=\"stylesheet\""), custom);
        let submission = fixture::hidden(&page, &p.submission_field);
        // The account navigation has a CSRF field too; it uses the same session token.
        let csrf = fixture::hidden(&page, &p.csrf_field);
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair(&p.csrf_field, &csrf)
            .append_pair(&p.submission_field, &submission)
            .append_pair("body", "a note")
            .finish();
        let recovery = exchange(
            address,
            &post(&format!("{}/1", p.action_path), &cookie_header, &body),
        )
        .await;
        assert!(recovery.starts_with("HTTP/1.1 422"));
        assert!(recovery.contains(&format!("action=\"{}/1\"", p.action_path)));
        assert_eq!(recovery.contains("rel=\"stylesheet\""), custom);
        let css = exchange(address, &get(&p.stylesheet_path, &cookie_header)).await;
        if custom {
            assert!(css.starts_with("HTTP/1.1 200"));
            assert!(css.ends_with(p.stylesheet.as_ref().unwrap()));
        } else {
            assert!(css.starts_with("HTTP/1.1 404"));
        }
        let missing = exchange(address, &get("/missing", &cookie_header)).await;
        assert!(missing.starts_with("HTTP/1.1 404"));
        let logout = exchange(
            address,
            &post(
                &p.logout_path,
                &cookie_header,
                &format!("{}={csrf}", p.csrf_field),
            ),
        )
        .await;
        assert!(logout.starts_with("HTTP/1.1 303"));
        assert!(logout.contains(&format!("set-cookie: {}=;", p.session_cookie)));
        let malformed = exchange(address, "GET / HTTP/1.1\r\nbad header\r\n\r\n").await;
        assert!(malformed.starts_with("HTTP/1.1 400"));
        stop.send(()).unwrap();
        serving.await.unwrap().unwrap();
    }
}

#[test]
fn strict_form_canonicalization() {
    assert_eq!(
        decode_form(b"body=hello+world%0D%0A").unwrap()["body"],
        "hello world\n"
    );
    for invalid in [
        b"body=a&body=b".as_slice(),
        b"body=%FF",
        b"body=%",
        b"body=%GG",
    ] {
        assert!(decode_form(invalid).is_err());
    }
    assert!(
        decode_form(format!("body={}", "x".repeat(noxide_protocol::MAX_INPUT_BYTES)).as_bytes())
            .is_err()
    );
}
#[test]
fn form_parser_bounds_transaction_inputs_and_host_controls() {
    let form = (0..35)
        .map(|index| format!("field{index}=x"))
        .collect::<Vec<_>>()
        .join("&");
    assert_eq!(decode_form(form.as_bytes()).unwrap().len(), 35);
    assert!(decode_form(format!("{form}&extra=x").as_bytes()).is_err());
}

#[test]
fn origin_has_no_clearnet_default() {
    assert!(Origin::parse("https://example.com").is_err());
    assert!(Origin::parse("http://localhost:8080").is_ok());
    assert!(Origin::parse("http://user@localhost/").is_err());
    assert!(Origin::parse("http://localhost/path").is_err());
}
