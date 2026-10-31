use super::*;
use std::net::IpAddr;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsAcceptor;

fn endpoint() -> Endpoint {
    Endpoint::checked("hooks.example.com", 443, "/webhook").unwrap()
}
fn body() -> JsonBody {
    JsonBody::checked(br#"{"message":"fixture-sensitive"}"#.to_vec()).unwrap()
}
fn key() -> IdempotencyKey {
    IdempotencyKey::from_host("effect-test-123".into()).unwrap()
}
fn test_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            include_bytes!("fixtures/ca.der").to_vec(),
        ))
        .unwrap();
    roots
}
fn client(proxy: TorProxy) -> Transport {
    Transport::with_roots(proxy, test_roots())
}
fn server_config() -> Arc<rustls::ServerConfig> {
    server_config_for(include_bytes!("fixtures/server.der"))
}
fn server_config_for(cert: &[u8]) -> Arc<rustls::ServerConfig> {
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/server-key.der").to_vec(),
    ));
    let certificate = rustls::pki_types::CertificateDer::from(cert.to_vec());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate], key)
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}
async fn listener() -> (TcpListener, TorProxy) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = TorProxy::loopback(listener.local_addr().unwrap()).unwrap();
    (listener, proxy)
}
async fn greeting(stream: &mut TcpStream) {
    let mut request = [0; 3];
    stream.read_exact(&mut request).await.unwrap();
    assert!(request == [5, 1, 0], "unexpected SOCKS greeting");
    stream.write_all(&[5, 0]).await.unwrap();
}
async fn request(stream: &mut TcpStream, command: u8) -> (Vec<u8>, u16, u8) {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert!(header[..3] == [5, command, 0], "unexpected SOCKS command");
    let length = match header[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await.unwrap() as usize,
        _ => panic!("invalid address type"),
    };
    let mut address = vec![0; length];
    stream.read_exact(&mut address).await.unwrap();
    let port = stream.read_u16().await.unwrap();
    (address, port, header[3])
}
async fn socks_accept(listener: &TcpListener, address: IpAddr, delay: Duration) -> TcpStream {
    socks_accept_with(listener, address, delay, 0, 443).await
}
async fn socks_accept_with(
    listener: &TcpListener,
    address: IpAddr,
    delay: Duration,
    reply_port: u16,
    endpoint_port: u16,
) -> TcpStream {
    let (mut resolve, _) = listener.accept().await.unwrap();
    greeting(&mut resolve).await;
    let (host, port, kind) = request(&mut resolve, 0xf0).await;
    assert!(
        host == b"hooks.example.com" && port == 0 && kind == 3,
        "RESOLVE must use only the canonical approved hostname"
    );
    tokio::time::sleep(delay).await;
    let mut reply = vec![5, 0, 0];
    match address {
        IpAddr::V4(ip) => {
            reply.push(1);
            reply.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(4);
            reply.extend(ip.octets());
        }
    }
    reply.extend(reply_port.to_be_bytes());
    resolve.write_all(&reply).await.unwrap();
    let mut end = [0];
    assert!(
        matches!(resolve.read(&mut end).await, Ok(0)),
        "RESOLVE stream must close before application data"
    );
    let (mut connect, _) = listener.accept().await.unwrap();
    greeting(&mut connect).await;
    let (numeric, port, kind) = request(&mut connect, 1).await;
    let expected = match address {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    assert!(
        numeric == expected && port == endpoint_port && kind != 3,
        "CONNECT must use the validated numeric address and approved port"
    );
    connect
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    connect
}
async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 4_096, "request headers exceeded bound");
        bytes.push(reader.read_u8().await.unwrap());
    }
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut request = httparse::Request::new(&mut headers);
    request.parse(&bytes).unwrap();
    assert!(
        request.method == Some("POST") && request.path == Some("/webhook"),
        "request target mismatch"
    );
    let length = request
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .unwrap();
    let length = std::str::from_utf8(length.value)
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut data = vec![0; length];
    reader.read_exact(&mut data).await.unwrap();
    bytes.extend(data);
    bytes
}
async fn exchange(response: Vec<u8>, address: IpAddr) -> (Result<Response, Error>, Vec<u8>) {
    let (listener, proxy) = listener().await;
    let fixture = tokio::spawn(async move {
        let socket = socks_accept(&listener, address, Duration::ZERO).await;
        let mut tls = TlsAcceptor::from(server_config())
            .accept(socket)
            .await
            .unwrap();
        assert!(
            tls.get_ref().1.server_name() == Some("hooks.example.com"),
            "TLS SNI must preserve the approved hostname"
        );
        let request = read_request(&mut tls).await;
        let _ = tls.write_all(&response).await;
        let _ = tls.flush().await;
        let _ = tls.shutdown().await;
        request
    });
    let transport = client(proxy);
    let secret = BearerSecret::from_host("fixture-secret-AB".into()).unwrap();
    let result = transport
        .post(
            &endpoint(),
            &body(),
            &key(),
            Some(&secret),
            Instant::now() + ATTEMPT_LIMIT,
        )
        .await;
    (result, fixture.await.unwrap())
}

#[test]
fn canonical_endpoint_rejects_ip_spellings_and_syntax_normalization() {
    for host in [
        "127.0.0.1",
        "127.1",
        "2130706433",
        "0177.0.0.1",
        "0x7f000001",
        "0x7f.0.0.1",
        "127.0.0.0x1",
        "8.8.8.0x8",
        "1.2.3.004",
        "[::1]",
        "::ffff:8.8.8.8",
        "user@hooks.example.com",
        "hooks.example.com.",
        "Hooks.example.com",
        "hooks..example.com",
        "hóoks.example.com",
        "hooks.example.com:443",
        "hooks.onion",
        "hooks.localhost",
        "hooks.invalid",
        "hooks.test",
        "-hooks.example.com",
    ] {
        assert!(
            Endpoint::checked(host, 443, "/webhook").is_err(),
            "noncanonical hostname admitted"
        );
    }
    for path in [
        "",
        "https://hooks.example.com/",
        "//webhook",
        "/a/../b",
        "/a/./b",
        "/a?x=1",
        "/a#fragment",
        "/a%2Fb",
        "/%0D%0A",
        "/a\\b",
        "/x\r\nHost:y",
    ] {
        assert!(
            Endpoint::checked("hooks.example.com", 443, path).is_err(),
            "noncanonical path admitted"
        );
    }
    assert!(Endpoint::checked("hooks.example.com", 0, "/").is_err());
    assert!(Endpoint::checked("hooks.example.com", 8443, "/.well-known/hooks").is_ok());
    assert!(TorProxy::loopback("8.8.8.8:9050".parse().unwrap()).is_err());
    assert!(TorProxy::loopback("127.0.0.1:0".parse().unwrap()).is_err());
}

#[test]
fn address_policy_rejects_all_special_purpose_classes_and_mapped_forms() {
    for address in [
        "0.1.2.3",
        "10.0.0.1",
        "100.64.0.0",
        "100.127.255.255",
        "127.255.1.1",
        "169.254.1.1",
        "172.31.255.255",
        "192.0.0.9",
        "192.0.2.1",
        "192.31.196.1",
        "192.52.193.1",
        "192.88.99.1",
        "192.168.1.1",
        "192.175.48.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "::ffff:127.0.0.1",
        "::8.8.8.8",
        "64:ff9b::808:808",
        "64:ff9b:1::1",
        "100::1",
        "100:0:0:1::1",
        "2001::1",
        "2001:1::1",
        "2001:20::1",
        "2001:db8::1",
        "2002:808:808::1",
        "2620:4f:8000::1",
        "3fff::1",
        "5f00::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
    ] {
        assert!(
            !config::public_ip(address.parse().unwrap()),
            "special-purpose address admitted"
        );
    }
    for address in [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.215.14",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    ] {
        assert!(
            config::public_ip(address.parse().unwrap()),
            "ordinary global address rejected"
        );
    }
}

#[test]
fn payload_keys_secrets_and_debugging_are_bounded_and_redacted() {
    assert!(matches!(
        JsonBody::checked(vec![b'x'; 65_537]),
        Err(Error::BodyLimit)
    ));
    assert!(matches!(
        JsonBody::checked(b"fixture-sensitive invalid json".to_vec()),
        Err(Error::Json)
    ));
    assert!(IdempotencyKey::from_host("x\r\nHost:wrong".into()).is_err());
    assert!(BearerSecret::from_host("fixture-secret\r\nOther: value".into()).is_err());
    assert!(BearerSecret::from_host("x".repeat(2_049)).is_err());
    let secret = BearerSecret::from_host("fixture-secret-AB".into()).unwrap();
    for debug in [
        format!("{:?}", secret),
        format!("{:?}", body()),
        format!("{:?}", endpoint()),
    ] {
        assert!(
            !debug.contains("fixture-secret")
                && !debug.contains("fixture-sensitive")
                && !debug.contains("hooks.example.com"),
            "sensitive debug output"
        );
    }
}

#[tokio::test]
async fn real_tls_post_uses_remote_resolve_numeric_connect_and_finite_headers() {
    for address in ["8.8.8.8", "2001:4860:4860::8888"] {
        let (result, request) = exchange(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            address.parse().unwrap(),
        )
        .await;
        assert!(
            matches!(
                result,
                Ok(Response {
                    status: 200,
                    discard: Discard::Complete,
                    ..
                })
            ),
            "valid local TLS exchange failed"
        );
        let request = std::str::from_utf8(&request).unwrap();
        assert!(
            request.contains("Host: hooks.example.com\r\n")
                && request.contains("Authorization: Bearer fixture-secret-AB\r\n")
                && request.contains("Idempotency-Key: effect-test-123\r\n"),
            "fixed host-owned header contract failed"
        );
        assert!(
            !request.contains("Cookie:")
                && !request.contains("User-Agent:")
                && !request.contains("Forwarded:"),
            "unexpected header authority"
        );
        assert!(
            request.ends_with(r#"{"message":"fixture-sensitive"}"#),
            "body mismatch"
        );
    }
}

async fn parser(response: Vec<u8>) -> Result<Response, Error> {
    let (socket, mut server) = tokio::io::duplex(131_072);
    let fixture = tokio::spawn(async move {
        let _ = read_request(&mut server).await;
        let _ = server.write_all(&response).await;
    });
    let outcome = http::post(
        socket,
        &endpoint(),
        &body(),
        &key(),
        None,
        Instant::now() + Duration::from_secs(1),
    )
    .await;
    fixture.await.unwrap();
    outcome
}
#[tokio::test]
async fn strict_http_framing_interims_and_header_limits() {
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: \xc2\xa01\r\n\r\nx".to_vec(),
        b"HTTP/1.1 101 Upgrade\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\n folded:value\r\n\r\n".to_vec(),
        b"HTTP/1.1 999 Unknown\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\n".to_vec(),
    ] {
        assert!(
            parser(response).await.is_err(),
            "ambiguous HTTP response admitted"
        );
    }
    let response=b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
    assert!(matches!(
        parser(response.to_vec()).await,
        Ok(Response {
            status: 204,
            discard: Discard::Complete,
            ..
        })
    ));
    let storm = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(3);
    assert!(matches!(parser(storm).await, Err(Error::ResponseLimit)));
    let large = format!("HTTP/1.1 200 OK\r\nX-Large: {}\r\n\r\n", "x".repeat(8_192));
    assert!(matches!(
        parser(large.into_bytes()).await,
        Err(Error::ResponseLimit)
    ));
    let many = format!("HTTP/1.1 200 OK\r\n{}\r\n", "X:a\r\n".repeat(33));
    assert!(parser(many.into_bytes()).await.is_err());
}

#[tokio::test]
async fn final_status_survives_oversize_and_invalid_chunk_body() {
    for (response, expected) in [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 16385\r\n\r\n".to_vec(),
            Discard::LimitExceeded,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 999999999999999999999999999\r\n\r\n".to_vec(),
            Discard::LimitExceeded,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx".to_vec(),
            Discard::Invalid,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n".to_vec(),
            Discard::Invalid,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;extension=x\r\nx\r\n0\r\n\r\n"
                .to_vec(),
            Discard::Invalid,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            Discard::Invalid,
        ),
        (
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{}0\r\n\r\n",
                "1\r\nx\r\n".repeat(257)
            )
            .into_bytes(),
            Discard::LimitExceeded,
        ),
        (
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n{}\r\n",
                "X:a\r\n".repeat(17)
            )
            .into_bytes(),
            Discard::LimitExceeded,
        ),
    ] {
        assert!(
            matches!(parser(response).await,Ok(Response{status:200,discard,..}) if discard==expected),
            "known final status lost during discard"
        );
    }
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 16385\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n".to_vec(),
    ] {
        let (outcome, _) = exchange(response, "8.8.8.8".parse().unwrap()).await;
        assert!(
            matches!(
                outcome,
                Ok(Response {
                    status: 200,
                    discard: Discard::LimitExceeded | Discard::Invalid,
                    ..
                })
            ),
            "authenticated final status lost during discard"
        );
    }
    for status in [201, 403, 429, 503] {
        let response = format!("HTTP/1.1 {status} Status\r\nContent-Length: 16385\r\n\r\n");
        assert!(
            matches!(parser(response.into_bytes()).await, Ok(Response {status:received, discard:Discard::LimitExceeded,..}) if received==status)
        );
    }
    let valid=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nX-Checksum: ignored\r\n\r\n";
    assert!(matches!(
        parser(valid.to_vec()).await,
        Ok(Response {
            status: 200,
            discard: Discard::Complete,
            ..
        })
    ));
    assert!(matches!(parser(b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/secret\r\nContent-Length: 0\r\n\r\n".to_vec()).await,Err(Error::Redirect(302))));
}

#[tokio::test]
async fn retry_after_is_bounded_metadata_not_a_remote_read() {
    for (value, expected) in [
        ("30", Some(30)),
        ("86400", Some(86_400)),
        ("86401", None),
        ("999999999", None),
        ("Wed, 21 Oct 2026 07:28:00 GMT", None),
    ] {
        let response =
            format!("HTTP/1.1 429 Slow\r\nRetry-After: {value}\r\nContent-Length: 0\r\n\r\n");
        assert!(
            matches!(parser(response.into_bytes()).await,Ok(Response{status:429,retry_after_seconds,..}) if retry_after_seconds==expected)
        );
    }
}

#[tokio::test]
async fn socks_failures_close_io_without_connect_or_tls_fallback() {
    for raw in [
        vec![4, 0, 0, 1, 8, 8, 8, 8, 0, 0],
        vec![5, 7, 0, 1, 8, 8, 8, 8, 0, 0],
        vec![5, 0, 1, 1, 8, 8, 8, 8, 0, 0],
        vec![5, 0, 0, 3, 1, b'x', 0, 0],
        vec![5, 0, 0, 1, 8, 8, 8],
        vec![5, 0, 0, 1, 8, 8, 8, 8, 0],
        vec![5, 0, 0, 1, 127, 0, 0, 1, 0, 0],
    ] {
        let (listener, proxy) = listener().await;
        let fixture = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            greeting(&mut socket).await;
            let _ = request(&mut socket, 0xf0).await;
            socket.write_all(&raw).await.unwrap();
            socket.shutdown().await.unwrap();
            let mut byte = [0];
            assert!(
                matches!(socket.read(&mut byte).await, Ok(0) | Err(_)),
                "failed RESOLVE leaked further protocol data"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(10), listener.accept())
                    .await
                    .is_err(),
                "failed RESOLVE retried or fell back"
            );
        });
        assert!(socks::connect(proxy, &endpoint()).await.is_err());
        fixture.await.unwrap();
    }
    for reply in [[4, 0], [5, 2], [5, 255]] {
        let (listener, proxy) = listener().await;
        let fixture = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            socket.write_all(&reply).await.unwrap();
            let mut byte = [0];
            assert!(
                matches!(socket.read(&mut byte).await, Ok(0) | Err(_)),
                "unexpected authentication fallback"
            );
        });
        assert!(matches!(
            socks::connect(proxy, &endpoint()).await,
            Err(Error::Socks)
        ));
        fixture.await.unwrap();
    }
}

#[tokio::test]
async fn connect_domain_reply_and_truncated_port_are_rejected_before_tls() {
    for raw in [
        vec![5, 0, 0, 3, 1, b'x', 0, 0],
        vec![5, 0, 1, 1, 0, 0, 0, 0, 0, 0],
        vec![5, 0, 0, 1, 0, 0, 0, 0, 0],
    ] {
        let (listener, proxy) = listener().await;
        let fixture = tokio::spawn(async move {
            let (mut resolve, _) = listener.accept().await.unwrap();
            greeting(&mut resolve).await;
            let _ = request(&mut resolve, 0xf0).await;
            resolve
                .write_all(&[5, 0, 0, 1, 8, 8, 8, 8, 0, 0])
                .await
                .unwrap();
            let (mut socket, _) = listener.accept().await.unwrap();
            greeting(&mut socket).await;
            let _ = request(&mut socket, 1).await;
            socket.write_all(&raw).await.unwrap();
            socket.shutdown().await.unwrap();
            let mut byte = [0];
            assert!(
                matches!(socket.read(&mut byte).await, Ok(0) | Err(_)),
                "TLS started after invalid SOCKS CONNECT reply"
            );
        });
        assert!(socks::connect(proxy, &endpoint()).await.is_err());
        fixture.await.unwrap();
    }
}

#[tokio::test]
async fn response_port_metadata_never_changes_approved_destination_or_host() {
    let (listener, proxy) = listener().await;
    let fixture = tokio::spawn(async move {
        let socket = socks_accept_with(
            &listener,
            "8.8.8.8".parse().unwrap(),
            Duration::ZERO,
            65535,
            8443,
        )
        .await;
        let mut tls = TlsAcceptor::from(server_config())
            .accept(socket)
            .await
            .unwrap();
        let bytes = read_request(&mut tls).await;
        assert!(
            std::str::from_utf8(&bytes)
                .unwrap()
                .contains("Host: hooks.example.com:8443\r\n"),
            "host authority changed"
        );
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
    });
    let endpoint = Endpoint::checked("hooks.example.com", 8443, "/webhook").unwrap();
    assert!(matches!(
        client(proxy)
            .post(
                &endpoint,
                &body(),
                &key(),
                None,
                Instant::now() + ATTEMPT_LIMIT
            )
            .await,
        Ok(Response { status: 200, .. })
    ));
    fixture.await.unwrap();
}

#[tokio::test]
async fn untrusted_ca_and_wrong_tls_name_fail_before_http_or_secret_disclosure() {
    for wrong_name in [false, true] {
        let (listener, proxy) = listener().await;
        let fixture = tokio::spawn(async move {
            let socket = socks_accept(&listener, "8.8.8.8".parse().unwrap(), Duration::ZERO).await;
            let config = if wrong_name {
                server_config_for(include_bytes!("fixtures/wrong-server.der"))
            } else {
                server_config()
            };
            if let Ok(mut tls) = TlsAcceptor::from(config).accept(socket).await {
                let mut byte = [0];
                assert!(
                    !matches!(tls.read(&mut byte).await,Ok(n) if n>0),
                    "HTTP bytes disclosed before TLS authentication"
                );
            }
        });
        let transport = if wrong_name {
            client(proxy)
        } else {
            Transport::new(proxy)
        };
        let secret = BearerSecret::from_host("fixture-secret-AB".into()).unwrap();
        assert!(matches!(
            transport
                .post(
                    &endpoint(),
                    &body(),
                    &key(),
                    Some(&secret),
                    Instant::now() + ATTEMPT_LIMIT
                )
                .await,
            Err(Error::Tls)
        ));
        fixture.await.unwrap();
    }
}

#[tokio::test]
async fn post_header_deadline_preserves_status_and_closes_the_stream() {
    let (listener, proxy) = listener().await;
    let fixture = tokio::spawn(async move {
        let socket = socks_accept(&listener, "8.8.8.8".parse().unwrap(), Duration::ZERO).await;
        let mut tls = TlsAcceptor::from(server_config())
            .accept(socket)
            .await
            .unwrap();
        let _ = read_request(&mut tls).await;
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        let mut byte = [0];
        assert!(
            matches!(tls.read(&mut byte).await, Ok(0) | Err(_)),
            "deadline did not close response I/O"
        );
    });
    let transport = client(proxy);
    let outcome = transport
        .post(
            &endpoint(),
            &body(),
            &key(),
            None,
            Instant::now() + Duration::from_millis(500),
        )
        .await;
    assert!(
        matches!(
            outcome,
            Ok(Response {
                status: 200,
                discard: Discard::Deadline,
                ..
            })
        ),
        "known 2xx was lost on body deadline"
    );
    tokio::time::timeout(Duration::from_secs(1), fixture)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(transport.slots.available_permits(), 2);
}

#[tokio::test]
async fn explicit_cancel_closes_resolve_tls_and_response_io_and_releases_slot() {
    for phase in [0, 1, 2, 3] {
        let (listener, proxy) = listener().await;
        let (reached, ready) = tokio::sync::oneshot::channel();
        let fixture = tokio::spawn(async move {
            if phase == 0 {
                let (mut stream, _) = listener.accept().await.unwrap();
                greeting(&mut stream).await;
                let _ = request(&mut stream, 0xf0).await;
                reached.send(()).unwrap();
                let mut byte = [0];
                assert!(matches!(stream.read(&mut byte).await, Ok(0) | Err(_)));
            } else {
                let mut socket =
                    socks_accept(&listener, "8.8.8.8".parse().unwrap(), Duration::ZERO).await;
                if phase == 1 {
                    let mut hello = [0; 4096];
                    assert!(socket.read(&mut hello).await.unwrap() > 0);
                    reached.send(()).unwrap();
                    let mut byte = [0];
                    assert!(matches!(socket.read(&mut byte).await, Ok(0) | Err(_)));
                } else {
                    let mut tls = TlsAcceptor::from(server_config())
                        .accept(socket)
                        .await
                        .unwrap();
                    let _ = read_request(&mut tls).await;
                    if phase == 3 {
                        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                            .await
                            .unwrap();
                        tls.flush().await.unwrap();
                    }
                    reached.send(()).unwrap();
                    let mut byte = [0];
                    assert!(matches!(tls.read(&mut byte).await, Ok(0) | Err(_)));
                }
            }
        });
        let transport = Arc::new(client(proxy));
        let sending = transport.clone();
        let task = tokio::spawn(async move {
            sending
                .post(
                    &endpoint(),
                    &body(),
                    &key(),
                    None,
                    Instant::now() + ATTEMPT_LIMIT,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), ready)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), fixture)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(transport.slots.available_permits(), 2);
    }
}

#[tokio::test]
async fn canceled_blocked_request_write_leaves_no_detached_writer() {
    let (socket, mut peer) = tokio::io::duplex(1);
    let task = tokio::spawn(async move {
        http::post(
            socket,
            &endpoint(),
            &body(),
            &key(),
            None,
            Instant::now() + ATTEMPT_LIMIT,
        )
        .await
    });
    let _ = peer.read_u8().await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let mut rest = [0; 4];
    let n = peer.read(&mut rest).await.unwrap();
    assert!(n <= 1);
    assert_eq!(peer.read(&mut rest).await.unwrap(), 0);
}

#[tokio::test]
async fn concurrency_has_two_slots_no_queue_and_expired_caller_does_no_io() {
    let (listener, proxy) = listener().await;
    let transport = Arc::new(client(proxy));
    assert!(matches!(
        transport
            .post(&endpoint(), &body(), &key(), None, Instant::now())
            .await,
        Err(Error::Deadline)
    ));
    let mut tasks = Vec::new();
    let mut sockets = Vec::new();
    for _ in 0..2 {
        let sending = transport.clone();
        tasks.push(tokio::spawn(async move {
            sending
                .post(
                    &endpoint(),
                    &body(),
                    &key(),
                    None,
                    Instant::now() + ATTEMPT_LIMIT,
                )
                .await
        }));
        let (mut socket, _) = listener.accept().await.unwrap();
        greeting(&mut socket).await;
        let _ = request(&mut socket, 0xf0).await;
        sockets.push(socket);
    }
    assert!(matches!(
        transport
            .post(
                &endpoint(),
                &body(),
                &key(),
                None,
                Instant::now() + ATTEMPT_LIMIT
            )
            .await,
        Err(Error::Busy)
    ));
    for task in tasks {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    for mut socket in sockets {
        let mut byte = [0];
        assert!(matches!(socket.read(&mut byte).await, Ok(0) | Err(_)));
    }
    assert_eq!(transport.slots.available_permits(), 2);
}

#[tokio::test]
async fn one_connect_deadline_spans_resolve_numeric_connect_and_tls() {
    let (listener, proxy) = listener().await;
    let fixture = tokio::spawn(async move {
        // Deliberate provider delay consumes six seconds of the SAME connect
        // phase before TLS begins; this is timing input, not ordering evidence.
        let mut socket = socks_accept(
            &listener,
            "8.8.8.8".parse().unwrap(),
            Duration::from_secs(6),
        )
        .await;
        let mut buffer = [0; 1_024];
        let mut total = 0;
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n;
                    assert!(total <= 8_192, "unexpected pre-TLS application data");
                }
            }
        }
        assert!(total > 0, "TLS phase was not reached");
    });
    let transport = client(proxy);
    let started = Instant::now();
    let result = transport
        .post(
            &endpoint(),
            &body(),
            &key(),
            None,
            started + Duration::from_secs(60),
        )
        .await;
    assert!(matches!(result, Err(Error::Deadline)));
    eprintln!("P11 connect deadline: {}ms", started.elapsed().as_millis());
    assert!(
        started.elapsed() >= CONNECT_LIMIT && started.elapsed() < Duration::from_secs(11),
        "connect deadline reset after a protocol phase"
    );
    tokio::time::timeout(Duration::from_secs(1), fixture)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(transport.slots.available_permits(), 2);
}

#[tokio::test]
async fn one_total_deadline_includes_connect_request_headers_and_body_discard() {
    let (listener, proxy) = listener().await;
    let fixture = tokio::spawn(async move {
        let socket = socks_accept(
            &listener,
            "8.8.8.8".parse().unwrap(),
            Duration::from_secs(6),
        )
        .await;
        let mut tls = TlsAcceptor::from(server_config())
            .accept(socket)
            .await
            .unwrap();
        let _ = read_request(&mut tls).await;
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        let mut byte = [0];
        assert!(
            matches!(tls.read(&mut byte).await, Ok(0) | Err(_)),
            "total deadline did not close the body stream"
        );
    });
    let transport = client(proxy);
    let started = Instant::now();
    let result = transport
        .post(
            &endpoint(),
            &body(),
            &key(),
            None,
            started + Duration::from_secs(60),
        )
        .await;
    assert!(matches!(
        result,
        Ok(Response {
            status: 200,
            discard: Discard::Deadline,
            ..
        })
    ));
    eprintln!("P11 total deadline: {}ms", started.elapsed().as_millis());
    assert!(
        started.elapsed() >= ATTEMPT_LIMIT && started.elapsed() < Duration::from_secs(31),
        "attempt deadline reset after connection or response headers"
    );
    tokio::time::timeout(Duration::from_secs(1), fixture)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(transport.slots.available_permits(), 2);
}
