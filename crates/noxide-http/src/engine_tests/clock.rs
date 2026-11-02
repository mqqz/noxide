use super::prelude::*;
use crate::auth::AccountAdmin as _;
use crate::security::TokenKind;
use crate::test_support as fixture;
use noxide_admission::temporal::AttemptTime;
use tokio::time::Instant;

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable local server"]
async fn postgres_http_stop_waits_for_actual_inflight_backend_termination() {
    use sqlx::{Connection, Row};
    let budget = crate::security::CLOCK_CHECKPOINT_BEGIN_DEADLINE;
    for delay in [0, budget.as_millis() as u64 + 5] {
        let (database, url) = postgres_fixture("http_stop").await;
        let app = Arc::new(build(database.clone(), HostKeys::generate().unwrap()).await);
        app.activate().await.unwrap();
        let before = clock(&database).await;
        let mut monitor = sqlx::PgConnection::connect(&url).await.unwrap();
        // A real server-side barrier inside the actual production clock UPDATE;
        // this exercises cancellation of admitted work, not an idle Rust task.
        sqlx::query("CREATE FUNCTION nx_clock_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_catalog.pg_sleep(1.5); RETURN NEW; END $$").execute(&mut monitor).await.unwrap();
        sqlx::query("CREATE TRIGGER nx_clock_pause BEFORE UPDATE ON nx_clock FOR EACH ROW EXECUTE FUNCTION nx_clock_pause()").execute(&mut monitor).await.unwrap();
        let listener = crate::Listener::loopback("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let serving = app.clone();
        let server = tokio::spawn(async move {
            crate::serve(
                listener,
                serving,
                crate::Origin::parse("http://localhost:8080").unwrap(),
                async {
                    let _ = shutdown.await;
                },
            )
            .await
        });
        let pid=tokio::time::timeout(Duration::from_secs(3),async {
            loop {
                let rows=sqlx::query("SELECT pid FROM pg_catalog.pg_stat_activity WHERE datname=pg_catalog.current_database() AND application_name LIKE 'nx-clock-%' AND wait_event='PgSleep' AND query LIKE 'UPDATE nx_clock%'").fetch_all(&mut monitor).await.unwrap();
                if let Some(row)=rows.first(){break row.get::<i32,_>(0);}
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        // First branch cancels during proven live provider work. Second branch
        // lets the original client deadline pass before asking HTTP to stop.
        tokio::time::sleep(Duration::from_millis(delay)).await;
        let stopped = std::time::Instant::now();
        stop.send(()).unwrap();
        tokio::time::timeout(tick_wait(), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(stopped.elapsed() < budget);
        let present: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE pid=$1")
                .bind(pid)
                .fetch_one(&mut monitor)
                .await
                .unwrap();
        assert_eq!(
            present, 0,
            "HTTP returned before its maintenance backend stopped"
        );
        assert!(app.test_maintenance().try_acquire().is_ok());
        assert!(!app.test_maintenance_running().load(Ordering::Acquire));
        assert_eq!(
            clock(&database).await,
            before,
            "canceled UPDATE must not refresh durable progress"
        );
    }
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable local server"]
async fn postgres_post_commit_gate_release_keeps_original_budget_and_no_freshness() {
    use sqlx::{Connection, Row};
    let (_, url) = postgres_fixture("gate_budget").await;
    let mut configured = url::Url::parse(&url).unwrap();
    configured
        .query_pairs_mut()
        .append_pair("options", "-c search_path=public,pg_catalog");
    let database = Database::postgres(configured.as_str()).unwrap();
    let app = Arc::new(build(database.clone(), HostKeys::generate().unwrap()).await);
    app.activate().await.unwrap();
    let activated = Instant::now();
    let before = clock(&database).await;
    let mut monitor = sqlx::PgConnection::connect(configured.as_str())
        .await
        .unwrap();
    // Trusted-provider fault injection, matching R's exact production repro:
    // spend 80ms before COMMIT, then pause the actual post-COMMIT unlock query.
    sqlx::query("CREATE FUNCTION public.pg_advisory_unlock_all() RETURNS void LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_catalog.pg_sleep(1.0); PERFORM pg_catalog.pg_advisory_unlock_all(); END $$").execute(&mut monitor).await.unwrap();
    sqlx::query("CREATE FUNCTION nx_clock_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.lifecycle_version != OLD.lifecycle_version THEN PERFORM pg_catalog.pg_sleep(0.08); END IF; RETURN NEW; END $$").execute(&mut monitor).await.unwrap();
    sqlx::query("CREATE TRIGGER nx_clock_pause BEFORE UPDATE ON nx_clock FOR EACH ROW EXECUTE FUNCTION nx_clock_pause()").execute(&mut monitor).await.unwrap();
    let listener = crate::Listener::loopback("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let serving = app.clone();
    let server = tokio::spawn(async move {
        crate::serve(
            listener,
            serving,
            crate::Origin::parse("http://localhost:8080").unwrap(),
            async {
                let _ = shutdown.await;
            },
        )
        .await
    });
    let (pid,age_ms)=tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            let rows=sqlx::query("SELECT pid,CAST(extract(epoch FROM(pg_catalog.clock_timestamp()-backend_start))*1000 AS BIGINT) FROM pg_catalog.pg_stat_activity WHERE datname=pg_catalog.current_database() AND application_name LIKE 'nx-clock-%' AND wait_event='PgSleep' AND query LIKE 'SELECT pg_advisory_unlock_all%'").fetch_all(&mut monitor).await.unwrap();
            if let Some(row)=rows.first(){break (row.get::<i32,_>(0),row.get::<i64,_>(1));}
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    let observed = std::time::Instant::now();
    stop.send(()).unwrap();
    tokio::time::timeout(tick_wait(), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        age_ms as u128 + observed.elapsed().as_millis()
            <= crate::security::CLOCK_CHECKPOINT_BEGIN_DEADLINE.as_millis(),
        "post-COMMIT unlock enlarged the original maintenance budget"
    );
    let present: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE pid=$1")
            .bind(pid)
            .fetch_one(&mut monitor)
            .await
            .unwrap();
    assert_eq!(present, 0);
    assert!(app.test_maintenance().try_acquire().is_ok());
    assert!(!app.test_maintenance_running().load(Ordering::Acquire));
    assert_eq!(
        clock(&database).await[2],
        before[2] + 1,
        "the COMMIT is durable even though gate release was interrupted"
    );
    // Advance beyond the startup lease but before a falsely renewed tick lease
    // would expire. This is deadline advancement, not a race-ordering sleep.
    tokio::time::sleep_until(activated + Duration::from_millis(5_050)).await;
    assert!(
        matches!(temporal(&app).await, Err(RequestError::Busy)),
        "a post-COMMIT cleanup failure must not renew temporal freshness"
    );
}
use std::time::Duration;

#[tokio::test]
async fn account_endpoint_obeys_persisted_clock_after_memory_reset() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("account-clock.db"));
    db.initialize().await.unwrap();
    let id = db
        .create_account("alice", "clock regression password", "team")
        .await
        .unwrap();
    let m = fixture::manifest();
    let app = Arc::new(
        Application::new(
            &fixture::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db.clone(),
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
    let wall = security::now().unwrap();
    let (valid, signed) = app
        .test_keys()
        .issue(TokenKind::Session, &id, wall, 3600)
        .unwrap();
    let (expiring, short) = app
        .test_keys()
        .issue(TokenKind::Session, &id, wall - 60, 75)
        .unwrap();
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    for token in [&valid, &expiring] {
        tx.execute(
            "INSERT INTO nx_sessions(id,principal,epoch,expires) VALUES($1,$2,1,$3)",
            &[
                token.nonce.as_str().into(),
                id.as_str().into(),
                token.expires.into(),
            ],
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    let router = crate::router(
        app.clone(),
        crate::Origin::parse("http://localhost:8080").unwrap(),
    );
    for (advance, cookie, accepted) in [
        (0, &signed, true),
        (30, &short, false),
        (120, &signed, false),
    ] {
        let mut tx = db
            .begin(std::time::Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        tx.execute(
            "UPDATE nx_clock SET observed=$1 WHERE singleton=1",
            &[(wall + advance).into()],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        // A restarted process has no in-memory watermark to protect it.
        app.test_clock().store(0, Ordering::Relaxed);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/account")
                    .header("host", "localhost:8080")
                    .header("cookie", format!("session={cookie}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status() == StatusCode::OK, accepted);
        let body = to_bytes(response.into_body(), 65536).await.unwrap();
        assert_eq!(
            String::from_utf8(body.to_vec()).unwrap().contains(&id),
            accepted
        );
    }
}

async fn temporal(app: &Application) -> std::result::Result<AttemptTime, RequestError> {
    let mut tx = app
        .test_database()
        .begin_read(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let value = app.test_temporal_attempt(&mut tx).await;
    tx.commit().await.unwrap();
    value
}

async fn postgres_fixture(label: &str) -> (Database, String) {
    use sqlx::Connection;
    let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
    let name = format!(
        "nx_clock_{label}_{}",
        security::random_id()
            .unwrap()
            .replace('-', "a")
            .replace('_', "b")
            .to_lowercase()
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut url = url::Url::parse(&root).unwrap();
    url.set_path(&name);
    (Database::postgres(url.as_str()).unwrap(), url.to_string())
}

/// Outer wait for work bounded by one clock tick budget, plus scheduling margin.
fn tick_wait() -> Duration {
    crate::security::CLOCK_CHECKPOINT_BEGIN_DEADLINE + Duration::from_millis(500)
}

async fn build(database: Database, keys: HostKeys) -> Application {
    database.initialize().await.unwrap();
    let manifest = fixture::manifest();
    Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&manifest).unwrap(),
        manifest::digest(&manifest).unwrap(),
        database,
        keys,
        Limits::default(),
        crate::DeploymentResources {
            effects: None,
            jobs: None,
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap()
}

async fn clock(database: &Database) -> [i64; 3] {
    let mut tx = database
        .begin_read(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let row = tx.fetch::<3>("SELECT CAST(observed AS TEXT),CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock WHERE singleton=1", &[]).await.unwrap();
    tx.commit().await.unwrap();
    row[0].clone().map(|field| field.parse().unwrap())
}
