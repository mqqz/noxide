use super::*;
use crate::{
    Database, HostKeys, manifest,
    runtime::{
        Limits,
        limiter::{BoundedPermits, HashGate},
    },
    test_support as fixture,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROXY: &[u8] = b"PROXY TCP6 fc00:dead:beef:4dad::ffff:ffff ::1 65535 42\r\n";

#[test]
fn proxy_parser_checks_exact_tor_v1_grammar() {
    assert!(parse_proxy_line(PROXY).unwrap() == Peer::Circuit(u32::MAX));
    for bad in [
        "PROXY TCP6 fc00:dead:beef:4dad::1 ::1 1 2",
        "proxy TCP6 fc00:dead:beef:4dad::1 ::1 1 2\r\n",
        "PROXY TCP4 fc00:dead:beef:4dad::1 ::1 1 2\r\n",
        "PROXY  TCP6 fc00:dead:beef:4dad::1 ::1 1 2\r\n",
        "PROXY TCP6 fc00:dead:beef:4dae::1 ::1 1 2\r\n",
        "PROXY TCP6 fc00:dead:beef:4dad::1 invalid 1 2\r\n",
        "PROXY TCP6 fc00:dead:beef:4dad::1 ::1 +1 2\r\n",
        "PROXY TCP6 fc00:dead:beef:4dad::1 ::1 a 2\r\n",
        "PROXY TCP6 fc00:dead:beef:4dad::1 ::1 65536 2\r\n",
        "PROXY TCP6 fc00:dead:beef:4dad::1 ::1 000001 2\r\n",
        "PROXY TCP6 fc00:dead:beef:4dad::1 ::1 1 2 extra\r\n",
    ] {
        assert!(
            parse_proxy_line(bad.as_bytes()).is_err(),
            "invalid test vector accepted"
        );
    }
    let mut non_ascii = PROXY.to_vec();
    non_ascii[0] = 0xff;
    assert!(parse_proxy_line(&non_ascii).is_err());
    assert!(parse_proxy_line(&[b'x'; PROXY_LINE_MAX + 1]).is_err());
    assert!(
        parse_proxy_line(b"PROXY TCP6 fc00:dead:beef:4dad:: :: 0 00000\r\n").unwrap()
            == Peer::Circuit(0)
    );
}

#[tokio::test]
async fn proxy_reader_preserves_pipelined_http_and_single_byte_fragments() {
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (mut client, server) = tokio::io::duplex(4096);
    client.write_all(&[PROXY, request].concat()).await.unwrap();
    client.shutdown().await.unwrap();
    let (mut stream, peer) = read_proxy(server).await.unwrap();
    assert!(peer == Peer::Circuit(u32::MAX));
    let mut remainder = Vec::new();
    stream.read_to_end(&mut remainder).await.unwrap();
    assert_eq!(remainder, request);
    let (mut client, server) = tokio::io::duplex(1);
    let sending = tokio::spawn(async move {
        for byte in [PROXY, request].concat() {
            client.write_all(&[byte]).await.unwrap();
        }
        client.shutdown().await.unwrap();
    });
    let (mut stream, peer) = read_proxy(server).await.unwrap();
    assert!(peer == Peer::Circuit(u32::MAX));
    let mut remainder = Vec::new();
    stream.read_to_end(&mut remainder).await.unwrap();
    assert_eq!(remainder, request);
    sending.await.unwrap();
    for bytes in [
        b"PROXY TCP6 missing CRLF".to_vec(),
        vec![b'x'; PROXY_LINE_MAX + 1],
    ] {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(&bytes).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(read_proxy(server).await.is_err());
    }
}

#[tokio::test]
async fn proxy_reader_bounds_total_time_for_slow_senders() {
    let (mut client, server) = tokio::io::duplex(4096);
    client.write_all(b"P").await.unwrap();
    let sending = tokio::spawn(async move {
        for byte in b"ROXY TCP6 fc00:dead:beef:4dad::1" {
            tokio::time::sleep(Duration::from_millis(400)).await;
            if client.write_all(&[*byte]).await.is_err() {
                break;
            }
        }
    });
    let started = tokio::time::Instant::now();
    assert!(
        tokio::time::timeout(
            PROXY_LINE_TIMEOUT + Duration::from_secs(1),
            read_proxy(server)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(started.elapsed() >= PROXY_LINE_TIMEOUT);
    sending.abort();
    let _ = sending.await;
}

async fn application() -> (tempfile::TempDir, Arc<Application>) {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("admission.db"));
    db.initialize().await.unwrap();
    db.create_account("alice", "admission test password", "")
        .await
        .unwrap();
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
        .unwrap(),
    );
    app.activate().await.unwrap();
    (temp, app)
}

async fn fill(permits: &BoundedPermits) -> Vec<tokio::sync::OwnedSemaphorePermit> {
    let count = permits.available();
    let mut held = Vec::new();
    for _ in 0..count {
        held.push(permits.acquire().await.unwrap());
    }
    held
}

#[tokio::test]
async fn busy_responses_are_identical_across_every_admission_resource() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let (_temp, app) = application().await;
    let challenge = app.login_challenge().await.unwrap();
    let session = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "admission test password",
        )
        .await
        .unwrap();
    let router = router(app.clone(), Origin::parse("http://localhost:8080").unwrap());
    let mut expected = None;
    for cause in 0..5 {
        let permits = match cause {
            0 => Some(&app.admission_limits.requests),
            1 => Some(&app.admission_limits.database),
            2 => Some(&app.admission_limits.wasm),
            3 => Some(&app.admission_limits.argon2),
            _ => None,
        };
        let held = if let Some(permits) = permits {
            fill(permits).await
        } else {
            while app.admission_limits.argon2_attempts.allow() {}
            Vec::new()
        };
        let request = if cause >= 3 {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("_csrf", &challenge.csrf)
                .append_pair("username", "alice")
                .append_pair("password", "admission test password")
                .finish();
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("Host", "localhost:8080")
                .header("Origin", "http://localhost:8080")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("login={}", challenge.cookie))
                .body(Body::from(body))
                .unwrap()
        } else {
            Request::builder()
                .uri(if cause == 2 { "/" } else { "/login" })
                .header("Host", "localhost:8080")
                .header("Cookie", format!("session={session}"))
                .body(Body::empty())
                .unwrap()
        };
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "cause {cause}"
        );
        assert!(!response.headers().contains_key("Retry-After"));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], CSP);
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), noxide_protocol::MAX_OUTPUT_BYTES)
            .await
            .unwrap()
            .to_vec();
        if let Some((expected_headers, expected_body)) = &expected {
            assert_eq!(&headers, expected_headers);
            assert_eq!(&body, expected_body);
        } else {
            expected = Some((headers, body));
        }
        drop(held);
    }
}

struct Resume(Arc<HashGate>);
impl Drop for Resume {
    fn drop(&mut self) {
        self.0.finish();
    }
}

#[tokio::test]
async fn cancelling_login_keeps_all_hash_worker_capacity_until_finished() {
    let (_temp, app) = application().await;
    let challenge = app.login_challenge().await.unwrap();
    let gate = HashGate::new();
    let _resume = Resume(gate.clone());
    *app.admission_limits.hash_gate.lock().unwrap() = Some(gate.clone());
    let worker = {
        let app = app.clone();
        tokio::spawn(async move {
            app.login(
                &challenge.cookie,
                &challenge.csrf,
                "alice",
                "admission test password",
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
    assert_eq!(app.admission_limits.database.available(), 7);
    assert_eq!(app.admission_limits.requests.available(), 63);
    gate.finish();
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.admission_limits.argon2.available() != 2
            || app.admission_limits.database.available() != 8
            || app.admission_limits.requests.available() != 64
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn tor_unix_validates_directory_and_preserves_existing_paths() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("run");
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("service.sock");
    let gid = std::fs::metadata(&directory).unwrap().gid();
    for mode in [0o750, 0o770, 0o2770, 0o2700] {
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(Listener::tor_unix(&path, gid).is_err());
        assert!(!path.exists());
    }
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o2750)).unwrap();
    assert!(Listener::tor_unix(&path, gid.wrapping_add(1)).is_err());
    assert!(!path.exists());
    let socket = Listener::tor_unix(&path, gid).unwrap();
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o660);
    assert_eq!(metadata.gid(), gid);
    assert!(Listener::tor_unix(&path, gid).is_err());
    drop(socket);
    assert!(!path.exists());
    std::fs::write(&path, b"existing").unwrap();
    assert!(Listener::tor_unix(&path, gid).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"existing");
}

async fn tcp_server(
    app: Arc<Application>,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = Listener::loopback("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let ListenerKind::Tcp(tcp) = &listener.0 else {
        unreachable!()
    };
    let address = tcp.local_addr().unwrap();
    let origin = Origin::parse(&format!("http://{address}")).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        serve(listener, app, origin, async {
            let _ = stopped.await;
        })
        .await
        .unwrap();
    });
    (address, stop, server)
}

async fn response<T: tokio::io::AsyncRead + Unpin>(stream: &mut T) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        match stream.read_exact(&mut byte).await {
            Ok(_) => bytes.push(byte[0]),
            Err(_) if bytes.is_empty() => return None,
            Err(error) => panic!("incomplete HTTP headers: {error}"),
        }
        assert!(bytes.len() <= 32 * 1024);
    }
    let text = std::str::from_utf8(&bytes).unwrap();
    let length = text
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(|s| s.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    assert!(length <= noxide_protocol::MAX_OUTPUT_BYTES);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    bytes.extend_from_slice(&body);
    Some(bytes)
}

#[tokio::test]
async fn client_disconnect_does_not_free_argon2_capacity_early() {
    let (_temp, app) = application().await;
    let challenge = app.login_challenge().await.unwrap();
    let gate = HashGate::new();
    let _resume = Resume(gate.clone());
    *app.admission_limits.hash_gate.lock().unwrap() = Some(gate.clone());
    let (address, stop, server) = tcp_server(app.clone()).await;
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("_csrf", &challenge.csrf)
        .append_pair("username", "alice")
        .append_pair("password", "admission test password")
        .finish();
    let request = format!(
        "POST /login HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nCookie: login={}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        challenge.cookie,
        body.len()
    );
    client.write_all(request.as_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    drop(client);
    tokio::task::yield_now().await;
    assert_eq!(app.admission_limits.argon2.available(), 1);
    gate.finish();
    tokio::time::timeout(Duration::from_secs(3), async {
        while app.admission_limits.argon2.available() != 2
            || app.admission_limits.database.available() != 8
            || app.admission_limits.requests.available() != 64
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stop.send(()).unwrap();
    server.await.unwrap();
}

#[test]
fn circuit_connection_guards_enforce_limits_and_release_entries() {
    let counts: CircuitCounts = Arc::new(Mutex::new(HashMap::new()));
    let mut guards = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_CIRCUIT {
        guards.push(CircuitConnection::acquire(counts.clone(), 1).unwrap());
    }
    assert!(CircuitConnection::acquire(counts.clone(), 1).is_none());
    let other = CircuitConnection::acquire(counts.clone(), 2).unwrap();
    guards.pop();
    assert!(CircuitConnection::acquire(counts.clone(), 1).is_some());
    drop(guards);
    drop(other);
    assert!(counts.lock().unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn plain_tcp_and_unix_listeners_reject_proxy_lines_as_http() {
    let (temp, app) = application().await;
    let (address, stop, server) = tcp_server(app.clone()).await;
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client.write_all(PROXY).await.unwrap();
    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 400"));
    stop.send(()).unwrap();
    server.await.unwrap();
    let path = temp.path().join("plain.sock");
    let listener = Listener::unix(&path).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(
        listener,
        app,
        Origin::parse("http://localhost:8080").unwrap(),
        async {
            let _ = stopped.await;
        },
    ));
    let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
    client.write_all(PROXY).await.unwrap();
    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 400"));
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn tor_unix_preserves_http_bytes_and_caps_connections_per_circuit() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (temp, app) = application().await;
    let run = temp.path().join("tor-run");
    std::fs::create_dir(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o2750)).unwrap();
    let gid = std::fs::metadata(&run).unwrap().gid();
    let path = run.join("service.sock");
    let listener = Listener::tor_unix(&path, gid).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(
        listener,
        app,
        Origin::parse("http://localhost:8080").unwrap(),
        async {
            let _ = stopped.await;
        },
    ));
    let request = b"GET /login HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
    let mut clients = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_CIRCUIT {
        let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
        client.write_all(&[PROXY, request].concat()).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), response(&mut client))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 200"));
        clients.push(client);
    }
    let mut fifth = tokio::net::UnixStream::connect(&path).await.unwrap();
    fifth.write_all(&[PROXY, request].concat()).await.unwrap();
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(1), fifth.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    let mut other = tokio::net::UnixStream::connect(&path).await.unwrap();
    other
        .write_all(
            &[
                b"PROXY TCP6 fc00:dead:beef:4dad::1 ::1 1 2\r\n".as_slice(),
                request,
            ]
            .concat(),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), response(&mut other))
            .await
            .unwrap()
            .unwrap()
            .starts_with(b"HTTP/1.1 200")
    );
    clients.pop();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
            client.write_all(&[PROXY, request].concat()).await.unwrap();
            if response(&mut client).await.is_some() {
                clients.push(client);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut untrusted = tokio::net::UnixStream::connect(&path).await.unwrap();
    untrusted.write_all(request).await.unwrap();
    let mut bytes = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), untrusted.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(
        bytes.is_empty(),
        "Tor transport cannot fall back to ordinary HTTP"
    );
    drop(clients);
    drop(other);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    assert!(!path.exists());
}
