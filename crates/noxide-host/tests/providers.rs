mod support;
use noxide_host::{Application, Database, HostKeys, manifest, runtime::Limits};
use noxide_protocol::Fields;
use sqlx::{Connection, Row};
use std::sync::Arc;

async fn conformance(
    database: Database,
    sqlite_path: Option<&std::path::Path>,
    pg_url: Option<&str>,
) {
    database.initialize().await.unwrap();
    database
        .create_account("alice", "twelve word password", "one")
        .await
        .unwrap();
    database
        .create_account("bob", "another secure password", "one")
        .await
        .unwrap();
    let declarations = support::manifest();
    let bytes = serde_json::to_vec(&declarations).unwrap();
    let approved = manifest::digest(&declarations).unwrap();
    let keys = HostKeys::generate().unwrap();
    let saved_keys = serde_json::to_vec(&keys).unwrap();
    let app = Arc::new(
        Application::new(
            &support::component(None),
            &bytes,
            approved,
            database.clone(),
            keys,
            Limits::default(),
        )
        .unwrap(),
    );
    app.activate().await.unwrap();
    let challenge = app.login_challenge().await.unwrap();
    let alice = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "twelve word password",
        )
        .await
        .unwrap();
    let challenge = app.login_challenge().await.unwrap();
    let bob = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "bob",
            "another secure password",
        )
        .await
        .unwrap();
    let page = String::from_utf8(app.view(&alice, 1, None).await.unwrap().body).unwrap();
    let submission = support::hidden(&page, "_submission");
    let csrf = support::hidden(&page, "_csrf");
    let fields = Fields::from([("body".into(), "Alice's private note <script>".into())]);
    assert!(
        app.submit(&bob, 1, &submission, &csrf, fields.clone())
            .await
            .is_err()
    );
    assert!(
        app.submit(&alice, 1, &submission, "bad", fields.clone())
            .await
            .is_err()
    );
    let first = app
        .submit(&alice, 1, &submission, &csrf, fields.clone())
        .await
        .unwrap();
    assert_eq!(first.status, 303);
    let replay = app
        .submit(&alice, 1, &submission, &csrf, fields.clone())
        .await
        .unwrap();
    assert_eq!(first.location, replay.location);
    let changed = Fields::from([("body".into(), "different input".into())]);
    assert!(
        app.submit(&alice, 1, &submission, &csrf, changed)
            .await
            .is_err()
    );
    let (one, two) = tokio::join!(
        app.submit(&alice, 1, &submission, &csrf, fields.clone()),
        app.submit(&alice, 1, &submission, &csrf, fields.clone())
    );
    assert_eq!(one.unwrap().location, two.unwrap().location);
    // A genuinely new token is raced across independently instantiated hosts.
    // This also models loss of the first HTTP response after commit.
    let restarted = Application::new(
        &support::component(None),
        &bytes,
        approved,
        database.clone(),
        serde_json::from_slice(&saved_keys).unwrap(),
        Limits::default(),
    )
    .unwrap();
    restarted.activate().await.unwrap();
    let page = String::from_utf8(app.view(&alice, 1, None).await.unwrap().body).unwrap();
    let fresh = support::hidden(&page, "_submission");
    let (left, right) = tokio::join!(
        app.submit(&alice, 1, &fresh, &csrf, fields.clone()),
        restarted.submit(&alice, 1, &fresh, &csrf, fields.clone())
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left.location, right.location);
    assert_eq!(
        restarted
            .submit(&alice, 1, &submission, &csrf, fields.clone())
            .await
            .unwrap()
            .location,
        first.location
    );
    let protected = Fields::from([
        ("body".into(), "forged owner".into()),
        ("owner".into(), "bob".into()),
    ]);
    assert!(
        app.submit(&alice, 1, &fresh, &csrf, protected)
            .await
            .is_err()
    );
    for failure in ["trap", "invalid", "loop", "twice"] {
        let hostile = Application::new(
            &support::component(Some(failure)),
            &bytes,
            approved,
            database.clone(),
            serde_json::from_slice(&saved_keys).unwrap(),
            Limits::default(),
        )
        .unwrap();
        hostile.activate().await.unwrap();
        let page = String::from_utf8(hostile.view(&alice, 1, None).await.unwrap().body).unwrap();
        let token = support::hidden(&page, "_submission");
        assert!(
            hostile
                .submit(&alice, 1, &token, &csrf, fields.clone())
                .await
                .is_err(),
            "{failure}"
        );
    }
    assert!(
        app.view(&alice, 1, None).await.is_err(),
        "code-only replacements retire the old host"
    );
    let app = application_again(&bytes, approved, database.clone(), &saved_keys).await;
    let (records, receipts) = if let Some(path) = sqlite_path {
        let mut connection = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new().filename(path),
        )
        .await
        .unwrap();
        let r=sqlx::query("SELECT (SELECT COUNT(*) FROM nx_records) AS records, (SELECT COUNT(*) FROM nx_receipts) AS receipts").fetch_one(&mut connection).await.unwrap();
        (r.get::<i64, _>("records"), r.get::<i64, _>("receipts"))
    } else {
        let mut connection = sqlx::PgConnection::connect(pg_url.unwrap()).await.unwrap();
        let r=sqlx::query("SELECT (SELECT COUNT(*) FROM nx_records) AS records, (SELECT COUNT(*) FROM nx_receipts) AS receipts").fetch_one(&mut connection).await.unwrap();
        (r.get::<i64, _>("records"), r.get::<i64, _>("receipts"))
    };
    assert_eq!(
        (records, receipts),
        (2, 2),
        "failed guest execution must leave no durable state"
    );
    // An approved replacement must still satisfy the persisted resource schema.
    let mut incompatible = declarations.clone();
    incompatible.resources[0].fields[0].name = "other".into();
    let replacement = Application::new(
        &support::component(None),
        &serde_json::to_vec(&incompatible).unwrap(),
        manifest::digest(&incompatible).unwrap(),
        database.clone(),
        serde_json::from_slice(&saved_keys).unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert!(replacement.activate().await.is_err());
    assert!(app.view(&alice, 1, None).await.is_ok());
    app.logout(&alice, &csrf).await.unwrap();
    assert!(
        app.submit(&alice, 1, &submission, &csrf, fields)
            .await
            .is_err()
    );
    // Retired deployment namespaces cannot be revived by rolling back code.
    let mut changed = declarations.clone();
    changed.actions[0].version += 1;
    let replacement = Application::new(
        &support::component(None),
        &serde_json::to_vec(&changed).unwrap(),
        manifest::digest(&changed).unwrap(),
        database.clone(),
        serde_json::from_slice(&saved_keys).unwrap(),
        Limits::default(),
    )
    .unwrap();
    replacement.activate().await.unwrap();
    assert!(app.view(&bob, 1, None).await.is_err());
    let rollback = Application::new(
        &support::component(None),
        &bytes,
        approved,
        database.clone(),
        serde_json::from_slice(&saved_keys).unwrap(),
        Limits::default(),
    )
    .unwrap();
    rollback.activate().await.unwrap();
    assert!(app.view(&bob, 1, None).await.is_err());
    assert!(rollback.view(&bob, 1, None).await.is_ok());
    let restored = Application::new(
        &support::component(None),
        &bytes,
        approved,
        database.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
    )
    .unwrap();
    restored.activate().await.unwrap();
    assert!(restored.view(&bob, 1, None).await.is_err());
    assert!(rollback.view(&bob, 1, None).await.is_err());
    database.maintain().await.unwrap();
}

async fn application_again(
    bytes: &[u8],
    approved: [u8; 32],
    db: Database,
    keys: &[u8],
) -> Application {
    let app = Application::new(
        &support::component(None),
        bytes,
        approved,
        db,
        serde_json::from_slice(keys).unwrap(),
        Limits::default(),
    )
    .unwrap();
    app.activate().await.unwrap();
    app
}

#[tokio::test]
async fn sqlite_transactional_contract() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("runtime.db");
    conformance(Database::sqlite(&path), Some(&path), None).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable test cluster"]
async fn postgres_transactional_contract() {
    let url =
        std::env::var("NOXIDE_TEST_POSTGRES").expect("disposable PostgreSQL test database URL");
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "noxide_test_{}",
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
    conformance(
        Database::postgres(case.as_str()).unwrap(),
        None,
        Some(case.as_str()),
    )
    .await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
