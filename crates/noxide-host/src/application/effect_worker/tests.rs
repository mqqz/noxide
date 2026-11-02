//! Actual outbox worker -> Tor SOCKS RESOLVE/numeric CONNECT -> TLS -> POST.
//! The proxy/receiver are test listeners; no external network is contacted.
use super::*;
use crate::{
    application::effects::tests::{Case, declarations},
    effect_deployment::{EffectDeployment, EffectGrant, EffectLimits, EffectSecret},
    effects::{DeliveryResult, Preflight},
};
use std::{
    future::Future,
    net::SocketAddr,
    task::Poll,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_rustls::TlsAcceptor;

impl Application {
    pub(crate) fn effect_test_parts(
        &self,
    ) -> (
        Arc<Manifest>,
        String,
        String,
        EffectiveEffectDeployment,
        u16,
        Option<rustls::RootCertStore>,
    ) {
        let runtime = self.effects.as_ref().expect("effect runtime");
        (
            self.manifest.clone(),
            self.deployment.clone(),
            self.contract.clone(),
            runtime.effective.clone(),
            self.database_statement_limit,
            runtime.test_roots.lock().unwrap().clone(),
        )
    }
    /// One delivery context per test application, standing in for the worker process.
    pub(crate) async fn effect_delivery(&self) -> Arc<EffectDelivery> {
        let runtime = self.effects.as_ref().expect("effect runtime");
        runtime
            .delivery
            .get_or_init(|| async {
                let delivery =
                    Arc::new(effect_delivery_from_test_parts(self, self.database.clone()));
                delivery.activate().await.expect("activate effect delivery");
                delivery
            })
            .await
            .clone()
    }
    pub(crate) async fn run_effect_once(
        &self,
    ) -> std::result::Result<Option<EffectRunOutcome>, RequestError> {
        self.effect_delivery().await.run_effect_once().await
    }
    pub(crate) async fn start_effect_service(&self) -> Result<Option<EffectService>> {
        self.effect_delivery()
            .await
            .start_effect_service()
            .map(Some)
    }
}

/// A delivery context over `database`, as a worker process would build one.
pub(in crate::application) fn effect_delivery_from_test_parts(
    app: &Application,
    database: Database,
) -> EffectDelivery {
    let (manifest, deployment, contract, effective, limit, roots) = app.effect_test_parts();
    let delivery =
        EffectDelivery::from_parts(database, manifest, deployment, contract, effective, limit);
    *delivery.runtime.test_roots.lock().unwrap() = roots;
    delivery
}

fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            include_bytes!("../../../../noxide-effect-delivery/src/transport/fixtures/ca.der")
                .to_vec(),
        ))
        .unwrap();
    roots
}
fn tls() -> TlsAcceptor {
    let cert = rustls::pki_types::CertificateDer::from(
        include_bytes!("../../../../noxide-effect-delivery/src/transport/fixtures/server.der")
            .to_vec(),
    );
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        include_bytes!("../../../../noxide-effect-delivery/src/transport/fixtures/server-key.der")
            .to_vec(),
    ));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}
async fn greeting(socket: &mut TcpStream) {
    let mut bytes = [0; 3];
    socket.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, [5, 1, 0]);
    socket.write_all(&[5, 0]).await.unwrap();
}
async fn connect(listener: &TcpListener) -> TcpStream {
    let (mut resolve, _) = listener.accept().await.unwrap();
    greeting(&mut resolve).await;
    let mut head = [0; 4];
    resolve.read_exact(&mut head).await.unwrap();
    assert_eq!(head, [5, 0xf0, 0, 3]);
    let len = resolve.read_u8().await.unwrap();
    let mut host = vec![0; len as usize];
    resolve.read_exact(&mut host).await.unwrap();
    assert_eq!(host, b"hooks.example.com");
    assert_eq!(resolve.read_u16().await.unwrap(), 0);
    resolve
        .write_all(&[5, 0, 0, 1, 8, 8, 8, 8, 0, 0])
        .await
        .unwrap();
    let mut eof = [0];
    assert_eq!(resolve.read(&mut eof).await.unwrap(), 0);
    drop(resolve);
    let (mut socket, _) = listener.accept().await.unwrap();
    greeting(&mut socket).await;
    let mut request = [0; 10];
    socket.read_exact(&mut request).await.unwrap();
    assert_eq!(request, [5, 1, 0, 1, 8, 8, 8, 8, 1, 187]);
    socket
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    socket
}
struct Request {
    key: String,
    body: serde_json::Value,
    authorization: Option<String>,
}
async fn receive(listener: &TcpListener) -> (tokio_rustls::server::TlsStream<TcpStream>, Request) {
    let mut tls = tls().accept(connect(listener).await).await.unwrap();
    assert_eq!(tls.get_ref().1.server_name(), Some("hooks.example.com"));
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 4096);
        bytes.push(tls.read_u8().await.unwrap());
    }
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut request = httparse::Request::new(&mut headers);
    assert!(request.parse(&bytes).unwrap().is_complete());
    assert_eq!(request.method, Some("POST"));
    assert_eq!(request.path, Some("/webhook"));
    let header = |name: &str| {
        request
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| std::str::from_utf8(h.value).unwrap().to_owned())
    };
    assert_eq!(header("host").as_deref(), Some("hooks.example.com"));
    let key = header("idempotency-key").unwrap();
    let authorization = header("authorization");
    let length: usize = header("content-length").unwrap().parse().unwrap();
    assert!(length <= 65536);
    let mut body = vec![0; length];
    tls.read_exact(&mut body).await.unwrap();
    (
        tls,
        Request {
            key,
            body: serde_json::from_slice(&body).unwrap(),
            authorization,
        },
    )
}
fn config(proxy: SocketAddr) -> EffectDeployment {
    EffectDeployment {
        grants: vec![EffectGrant {
            endpoint: "events".into(),
            tenant: "team".into(),
            host: "hooks.example.com".into(),
            port: 443,
            path: "/webhook".into(),
        }],
        secrets: vec![],
        tor_proxy: proxy,
        limits: EffectLimits::default(),
        runtime_directory: None,
    }
}
async fn case(db: Option<Database>, proxy: SocketAddr, secret: bool) -> Case {
    let mut manifest = declarations(false);
    manifest.effects.as_mut().unwrap().emissions.truncate(1);
    let mut deployment = config(proxy);
    if secret {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-fixtures/effect-secret-fixtures");
        std::fs::create_dir_all(&root).unwrap();
        let directory = tempfile::Builder::new()
            .prefix("secret-")
            .tempdir_in(root)
            .unwrap()
            .keep();
        let directory = std::fs::canonicalize(directory).unwrap();
        let path = directory.join("token");
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"host-only-test-token").unwrap();
        drop(file);
        manifest.effects.as_mut().unwrap().endpoints[0].secret_slot = Some("token".into());
        deployment.secrets = vec![EffectSecret {
            slot: "token".into(),
            path,
        }];
    }
    let case = Case::configured(db, manifest, deployment).await;
    *case
        .app
        .effects
        .as_ref()
        .unwrap()
        .test_roots
        .lock()
        .unwrap() = Some(roots());
    case
}
async fn outbox(case: &Case) -> Vec<[String; 4]> {
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let rows = tx
        .fetch::<4>(
            "SELECT id,state,CAST(attempts AS TEXT),CAST(round AS TEXT) FROM nx_outbox ORDER BY id",
            &[],
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    rows
}
async fn acknowledged<T>(receiver: oneshot::Receiver<T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), receiver)
        .await
        .unwrap()
        .unwrap()
}

async fn shutdown_contract(database: Option<Database>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let case = case(database, listener.local_addr().unwrap(), true).await;
    case.create("ready").await;
    let (reached, at_receiver) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let receiver = tokio::spawn(async move {
        let (mut tls, request) = receive(&listener).await;
        reached.send(request).ok().unwrap();
        wait.await.unwrap();
        tls.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        let _ = tls.shutdown().await;
    });
    let service = case.app.start_effect_service().await.unwrap().unwrap();
    let request = acknowledged(at_receiver).await;
    let initial = outbox(&case).await;
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0][1], "running");
    assert_eq!(request.key, initial[0][0]);
    assert_eq!(
        request.authorization.as_deref(),
        Some("Bearer host-only-test-token")
    );
    assert_eq!(request.body["actor"], case.actor);
    assert_eq!(request.body["caption"], serde_json::Value::Null);
    assert!(request.body.get("token").is_none());
    // The acknowledged receiver has the POST, but has not returned its status.
    // Polling shutdown must remain pending while the actual socket/slot live.
    let mut stopping = Box::pin(service.shutdown());
    std::future::poll_fn(|cx| {
        assert!(stopping.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let physical = Arc::downgrade(
        case.app
            .effect_delivery()
            .await
            .runtime
            .owner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap(),
    );
    assert_eq!(
        physical.upgrade().unwrap().active_claims(),
        std::slice::from_ref(&request.key)
    );
    // Trusted local inspection remains available during an admitted send.
    assert!(
        matches!(case.app.operate_effects(effects::EffectOperatorCommand::Inspect {after:String::new()}).await.unwrap(),effects::EffectOperatorResult::Effects(rows) if rows.len()==1)
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), stopping)
        .await
        .unwrap()
        .unwrap();
    receiver.await.unwrap();
    assert!(
        physical.upgrade().is_none(),
        "delivery owner remained after confirmed drain"
    );
    let rows = outbox(&case).await;
    assert_eq!(rows[0][1], "delivered");
    assert_eq!(rows[0][2], "1");
    let (records, receipts, captures, _) = case.state().await;
    assert_eq!((records, receipts, captures.len()), (1, 1, 1));
    assert!(case.app.start_effect_service().await.is_err());
    case.close().await;
}
async fn ambiguous_receiver_contract(database: Option<Database>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let case = case(database, listener.local_addr().unwrap(), false).await;
    case.create("ready").await;
    let receiver = tokio::spawn(async move {
        let (first_tls, first) = receive(&listener).await;
        drop(first_tls); // Receiver application committed, acknowledgment was lost.
        let (mut tls, second) = receive(&listener).await;
        assert_eq!(first.key, second.key);
        assert_eq!(first.body, second.body);
        tls.write_all(b"HTTP/1.1 208 Already Reported\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        let _ = tls.shutdown().await;
        (first, second)
    });
    assert!(matches!(
        case.app.run_effect_once().await.unwrap(),
        Some(EffectRunOutcome::Retrying(_))
    ));
    let rows = outbox(&case).await;
    let id = rows[0][0].clone();
    assert_eq!(rows[0][1], "pending");
    // An explicit operator round avoids advancing the production retry clock.
    // The original immutable body and receiver key survive that reconciliation.
    case.app
        .operate_effects(effects::EffectOperatorCommand::RevokeEndpoint {
            tenant: "team".into(),
            endpoint: "events".into(),
        })
        .await
        .unwrap();
    case.app
        .operate_effects(effects::EffectOperatorCommand::GrantEndpoint {
            tenant: "team".into(),
            endpoint: "events".into(),
        })
        .await
        .unwrap();
    case.app
        .operate_effects(effects::EffectOperatorCommand::Retry { id: id.clone() })
        .await
        .unwrap();
    assert_eq!(
        case.app.run_effect_once().await.unwrap(),
        Some(EffectRunOutcome::Delivered)
    );
    let (first, second) = receiver.await.unwrap();
    assert_eq!(first.key, id);
    assert_eq!(second.key, id);
    let rows = outbox(&case).await;
    assert_eq!(
        rows[0],
        [
            id,
            String::from("delivered"),
            String::from("1"),
            String::from("1")
        ]
    );
    let (records, receipts, _, _) = case.state().await;
    assert_eq!((records, receipts), (1, 1));
    case.close().await;
}
async fn lost_database_ack_contract(database: Option<Database>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let case = case(database, listener.local_addr().unwrap(), false).await;
    case.create("ready").await;
    let receiver = tokio::spawn(async move {
        let (mut tls, request) = receive(&listener).await;
        tls.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        let _ = tls.shutdown().await;
        request
    });
    let delivery = case.app.effect_delivery().await;
    let runtime = &delivery.runtime;
    let owner = runtime.delivery_owner().unwrap();
    let scope = delivery.effect_request_scope().unwrap();
    let physical = owner.try_attempt(scope.deadline()).unwrap();
    scope
        .run(async {
            let mut calls = 16;
            let claim = delivery
                .claim_effect(&scope, &physical, &owner, &mut calls)
                .await
                .unwrap()
                .unwrap();
            let Preflight::Send(prepared) = delivery
                .preflight_effect(&scope, &physical, &claim, &mut calls)
                .await
                .unwrap()
            else {
                panic!("not admitted")
            };
            let captured = &prepared.captured;
            let endpoint = noxide_effect_delivery::transport::Endpoint::checked(
                &captured.binding().host,
                captured.binding().port,
                &captured.binding().path,
            )
            .unwrap();
            let body =
                noxide_effect_delivery::transport::JsonBody::checked(captured.body().to_vec())
                    .unwrap();
            let key = noxide_effect_delivery::transport::IdempotencyKey::from_host(
                captured.receiver_key().unwrap(),
            )
            .unwrap();
            let result = owner
                .transport
                .post(
                    &endpoint,
                    &body,
                    &key,
                    None,
                    scope.work_deadline() - Duration::from_secs(2),
                )
                .await;
            assert!(matches!(
                noxide_effect_delivery::worker::classify(result),
                DeliveryResult::Delivered
            ));
            let result = crate::failure_tests::lose_commit_ack(delivery.finalize_effect(
                &scope,
                &physical,
                &claim,
                &mut calls,
                DeliveryResult::Delivered,
            ))
            .await;
            assert!(matches!(result, Err(RequestError::OutcomeUnknown)));
        })
        .await;
    physical.finish().await.unwrap();
    owner.drain().await.unwrap();
    runtime.release_owner(owner);
    let request = receiver.await.unwrap();
    let rows = outbox(&case).await;
    assert_eq!(rows[0][0], request.key);
    assert_eq!(rows[0][1], "delivered");
    // This fresh authoritative claim probes durable state; a lost DB reply is
    // never evidence that the receiver needs another POST.
    assert_eq!(case.app.run_effect_once().await.unwrap(), None);
    let (records, receipts, _, _) = case.state().await;
    assert_eq!((records, receipts), (1, 1));
    case.close().await;
}
#[tokio::test]
async fn sqlite_real_tor_tls_worker_and_shutdown_wait_for_inflight_post() {
    shutdown_contract(None).await;
}
#[tokio::test]
async fn sqlite_ambiguous_receiver_ack_retries_same_key_and_body() {
    ambiguous_receiver_contract(None).await;
}
#[tokio::test]
async fn sqlite_known_delivery_lost_database_ack_is_probed_without_repost() {
    lost_database_ack_contract(None).await;
}

#[tokio::test]
async fn claim_mutex_wait_uses_original_delivery_deadline() {
    let case = case(None, "127.0.0.1:9050".parse().unwrap(), false).await;
    let delivery = case.app.effect_delivery().await;
    let runtime = &delivery.runtime;
    let owner = runtime.delivery_owner().unwrap();
    let held = owner.claim_lock.lock().await;
    tokio::time::pause();
    let cap = Duration::from_millis(200);
    let scope = RequestScope::new(runtime.lifecycle.clone(), Instant::now() + cap, cap, 256);
    let physical = owner.try_attempt(scope.deadline()).unwrap();
    let mut calls = 16;
    let mut claiming =
        Box::pin(scope.run(delivery.claim_effect(&scope, &physical, &owner, &mut calls)));
    std::future::poll_fn(|cx| {
        assert!(claiming.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_millis(151)).await;
    assert!(matches!(claiming.await, Err(RequestError::Busy)));
    assert_eq!(calls, 16);
    drop(held);
    physical.finish().await.unwrap();
    tokio::time::resume();
    runtime.release_owner(owner);
    case.close().await;
}
async fn postgres(label: &str) -> Database {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_effect_worker_{label}_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    assert!(name.len() <= 63);
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut url = url::Url::parse(&url).unwrap();
    url.set_path(&format!("/{name}"));
    Database::postgres(url.as_str()).unwrap()
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_worker_role_delivers_without_reaching_application_data() {
    use sqlx::Connection;
    let base = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let (prefix, _) = base.rsplit_once('/').unwrap();
    let name = format!(
        "nx_worker_{}",
        crate::security::random_id()
            .unwrap()
            .replace('-', "a")
            .replace('_', "b")
            .to_lowercase()
    );
    let role = format!("{name}_role");
    let mut admin = sqlx::PgConnection::connect(&base).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE ROLE {role} LOGIN PASSWORD 'worker-test'"))
        .execute(&mut admin)
        .await
        .unwrap();
    let owner_url = format!("{prefix}/{name}");
    let owner = Database::postgres(&owner_url).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let case = case(Some(owner), listener.local_addr().unwrap(), false).await;
    case.create("ready").await;
    let mut own = sqlx::PgConnection::connect(&owner_url).await.unwrap();
    for grant in noxide_effect_delivery::POSTGRES_WORKER_GRANTS {
        sqlx::query(&grant.replace("ROLE", &role))
            .execute(&mut own)
            .await
            .unwrap();
    }
    // The role reaches delivery state and nothing the application stores.
    let mut restricted = sqlx::PgConnection::connect(&format!(
        "{}://{role}:worker-test@{}/{name}",
        prefix.split_once("://").unwrap().0,
        prefix.split_once('@').unwrap().1,
    ))
    .await
    .unwrap();
    for table in ["nx_records", "nx_accounts", "nx_blobs"] {
        assert!(
            sqlx::query(&format!("SELECT 1 FROM {table} LIMIT 1"))
                .fetch_optional(&mut restricted)
                .await
                .is_err(),
            "{table}"
        );
    }
    restricted.close().await.unwrap();
    let delivery = Arc::new(effect_delivery_from_test_parts(
        &case.app,
        Database::postgres(&format!(
            "{}://{role}:worker-test@{}/{name}",
            prefix.split_once("://").unwrap().0,
            prefix.split_once('@').unwrap().1,
        ))
        .unwrap(),
    ));
    delivery.activate().await.unwrap();
    let receiver = tokio::spawn(async move {
        let (mut tls, request) = receive(&listener).await;
        tls.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        let _ = tls.shutdown().await;
        request
    });
    assert_eq!(
        delivery.run_effect_once().await.unwrap(),
        Some(EffectRunOutcome::Delivered)
    );
    receiver.await.unwrap();
    assert_eq!(outbox(&case).await[0][1], "delivered");
    case.close().await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_real_tor_tls_worker_and_shutdown_wait_for_inflight_post() {
    shutdown_contract(Some(postgres("shutdown").await)).await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_ambiguous_receiver_ack_retries_same_key_and_body() {
    ambiguous_receiver_contract(Some(postgres("ambiguous").await)).await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_known_delivery_lost_database_ack_is_probed_without_repost() {
    lost_database_ack_contract(Some(postgres("dback").await)).await;
}
