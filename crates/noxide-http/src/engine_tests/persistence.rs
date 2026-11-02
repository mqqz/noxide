use crate::auth::AccountAdmin as _;
use crate::{Application, Database, HostKeys, manifest, runtime::Limits, test_support as fixture};
use noxide_protocol::{Fields, Manifest};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

async fn concurrent_gets_write_nothing(db: Database) {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let app = app(db.clone(), fixture::manifest()).await;
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
    let page = app.view(&session, 1, None).await.unwrap();
    let html = std::str::from_utf8(&page.body).unwrap();
    // Populate both records and receipts so the dump checks meaningful rows.
    app.submit(
        &session,
        1,
        &fixture::hidden(html, "_submission"),
        &fixture::hidden(html, "_csrf"),
        Fields::from([("body".into(), "read-only fixture".into())]),
    )
    .await
    .unwrap();
    let before = storage_snapshot(&db).await;
    let router = crate::router(app, crate::Origin::parse("http://localhost:8080").unwrap());
    let mut reads = tokio::task::JoinSet::new();
    for path in ["/login", "/"] {
        for _ in 0..2 {
            let router = router.clone();
            let session = session.clone();
            reads.spawn(async move {
                // Keep four clients active while rendering all 400 GETs. A
                // 400-client retry storm can starve cold PostgreSQL connections
                // on small runners. Overload rejection has dedicated admission
                // tests; this test checks that successful concurrent reads never
                // change storage.
                tokio::time::timeout(Duration::from_secs(60), async {
                    for _ in 0..100 {
                        loop {
                            let request = Request::builder()
                                .uri(path)
                                .header("Host", "localhost:8080")
                                .header("Cookie", format!("session={session}"))
                                .body(Body::empty())
                                .unwrap();
                            let response = router.clone().oneshot(request).await.unwrap();
                            if response.status() != StatusCode::SERVICE_UNAVAILABLE {
                                assert_eq!(response.status(), StatusCode::OK);
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                    }
                })
                .await
                .unwrap();
            });
        }
    }
    while let Some(read) = reads.join_next().await {
        read.unwrap();
    }
    assert_eq!(storage_snapshot(&db).await, before);
}

#[tokio::test]
async fn sqlite_concurrent_gets_write_nothing() {
    let temp = tempfile::tempdir().unwrap();
    concurrent_gets_write_nothing(Database::sqlite(temp.path().join("gets.db"))).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_read_paths_and_checkpoints() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for case in ["gets", "timer"] {
        let name = format!(
            "nx_read_{case}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&url).unwrap();
        url.set_path(&format!("/{name}"));
        let db = Database::postgres(url.as_str()).unwrap();
        match case {
            "gets" => concurrent_gets_write_nothing(db).await,
            _ => server_checkpoints_read_advances(db).await,
        }
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}

async fn server_checkpoints_read_advances(db: Database) {
    use crate::{Listener, Origin, security};
    let app = app(db.clone(), fixture::manifest()).await;
    let before = security::now().unwrap();
    // Advance only through a read, without changing the durable row.
    while security::now().unwrap() == before {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let snapshot = storage_snapshot(&db).await;
    let challenge = app.login_challenge().await.unwrap();
    let effective = app
        .test_keys()
        .verify(&challenge.cookie, security::now().unwrap())
        .unwrap()
        .issued;
    assert!(effective > before);
    assert_eq!(storage_snapshot(&db).await, snapshot);
    let listener = Listener::loopback("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let server_app = app.clone();
    let server = tokio::spawn(async move {
        crate::serve(
            listener,
            server_app,
            Origin::parse("http://localhost:8080").unwrap(),
            async {
                let _ = shutdown.await;
            },
        )
        .await
        .unwrap();
    });
    // Exercise the production one-second timer without changing dependencies or
    // introducing a configurable checkpoint interval solely for tests.
    tokio::time::timeout(
        crate::lifecycle_clock::TICK_INTERVAL + Duration::from_secs(5),
        async {
            loop {
                let mut tx = db
                    .begin_read(Instant::now() + Duration::from_secs(2))
                    .await
                    .unwrap();
                let rows = tx
                    .fetch::<1>(
                        "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
                        &[],
                    )
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
                if rows[0][0].parse::<i64>().unwrap() >= effective {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        },
    )
    .await
    .unwrap();
    stop.send(()).unwrap();
    server.await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&app) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn sqlite_server_checkpoints_read_advances() {
    let temp = tempfile::tempdir().unwrap();
    server_checkpoints_read_advances(Database::sqlite(temp.path().join("server-clock.db"))).await;
}

async fn storage_snapshot(db: &Database) -> Vec<(String, Vec<[String; 1]>)> {
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let snapshot = tx.snapshot().await.unwrap();
    tx.commit().await.unwrap();
    snapshot
}

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
