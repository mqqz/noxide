use super::*;

use crate::{Database, HostKeys, manifest, runtime::Limits, test_support as fixture};
use noxide_protocol::*;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn seed(db: &Database, m: &Manifest) {
    if m.operations.iter().any(|op| !op.filter.is_empty()) {
        db.reconcile_query_indexes(m).await.unwrap();
    }
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.bind_schema(m).await.unwrap();
    let parent = tx.storage_resource(m, 2).await.unwrap();
    for id in [10i64, 20] {
        tx.allocate_creation().await.unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,NULL,'',$3,'parent',1,(SELECT value FROM nx_creation_counter WHERE singleton=1))", &[parent.into(),id.into(),r#"{"published":"true","locked":"false"}"#.into()]).await.unwrap();
    }
    let child = tx.storage_resource(m, 1).await.unwrap();
    for id in 1i64..=12 {
        let fields = Fields::from([
            ("body".into(), format!("reply {id}")),
            ("published".into(), "true".into()),
            (
                "thread".into(),
                if id % 2 == 0 { "10" } else { "20" }.into(),
            ),
        ]);
        tx.allocate_creation().await.unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES($1,$2,NULL,'',$3,'child',1,1,(SELECT value FROM nx_creation_counter WHERE singleton=1))", &[child.into(),id.into(),serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
    }
    tx.commit().await.unwrap();
}
async fn redirect_app(db: Database) -> (Application, Manifest) {
    db.initialize().await.unwrap();
    let mut m = fixture::parent_declarations();
    m.web_bindings[0].redirect = Redirect {
        route: 3,
        source: RedirectSource::Reference {
            step: 0,
            field: "thread".into(),
        },
    };
    manifest::validate(&m).unwrap();
    let app = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
        noxide_host::DeploymentResources {
            effects: None,
            jobs: None,
            assets: noxide_admission::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap();
    app.activate().await.unwrap();
    seed(&db, &m).await;
    (app, m)
}

#[tokio::test]
async fn committed_anonymous_create_recovers_original_secret_after_disconnect() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("disconnect.db"));
    let (app, m) = redirect_app(db.clone()).await;
    let app = Arc::new(app);
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
    let server = tokio::spawn(serve(
        listener,
        app.clone(),
        Origin::parse(&origin).unwrap(),
        async {
            let _ = stopped.await;
        },
    ));
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket
        .write_all(
            format!("GET /threads/10 HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut received = String::new();
    socket.read_to_string(&mut received).await.unwrap();
    let cookie = received
        .split_once("set-cookie: noxide_anon=")
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap();
    let submission = fixture::hidden(&received, "_submission");
    let csrf = fixture::hidden(&received, "_csrf");
    let form: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("_submission", &submission)
        .append_pair("_csrf", &csrf)
        .append_pair("body", "disconnect reply")
        .append_pair("published", "true")
        .finish();
    let request = format!(
        "POST /actions/1 HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nCookie: noxide_anon={cookie}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}",
        form.len()
    );
    let committed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    *app.postcommit_barrier.lock().unwrap() = Some((committed.clone(), resume.clone()));
    let mut lost = tokio::net::TcpStream::connect(address).await.unwrap();
    lost.write_all(request.as_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), committed.notified())
        .await
        .unwrap();
    // No response can have been emitted: the handler is paused after commit.
    drop(lost);
    let mut tx = db
        .begin_read((tokio::time::Instant::now() + Duration::from_secs(5)).into_std())
        .await
        .unwrap();
    let storage = tx.storage_resource(&m, 1).await.unwrap();
    let row = tx
        .fetch::<1>("SELECT outcome FROM nx_receipts WHERE outcome<>''", &[])
        .await
        .unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&row[0][0]).unwrap();
    let outcome: serde_json::Value = receipt["handover"].clone();
    let original = app
        .test_keys()
        .edit_secret(
            outcome["key_id"].as_u64().unwrap() as u32,
            storage as u32,
            outcome["id"].as_u64().unwrap(),
            outcome["cap_version"].as_u64().unwrap(),
        )
        .unwrap();
    tx.commit().await.unwrap();
    resume.notify_one();
    let mut replay = tokio::net::TcpStream::connect(address).await.unwrap();
    replay.write_all(request.as_bytes()).await.unwrap();
    let mut recovered = String::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        replay.read_to_string(&mut recovered),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(recovered.starts_with("HTTP/1.1 200"), "{recovered}");
    assert!(recovered.contains(&format!("<pre>{original}</pre>")));
    let mut tx = db
        .begin_read((tokio::time::Instant::now() + Duration::from_secs(5)).into_std())
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>(
            "SELECT CAST(COUNT(*) AS TEXT) FROM nx_records WHERE resource=$1 AND id>12",
            &[storage.into()]
        )
        .await
        .unwrap()[0][0],
        "1"
    );
    tx.commit().await.unwrap();
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
