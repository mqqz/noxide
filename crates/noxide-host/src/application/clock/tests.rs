use super::*;
use crate::{database::Param, test_support as fixture};

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
async fn temporal(app: &Application) -> std::result::Result<AttemptTime, RequestError> {
    let mut tx = app
        .database
        .begin_read(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let value = app.temporal_attempt(&mut tx).await;
    tx.commit().await.unwrap();
    value
}

async fn provider_contract(database: Database) {
    let app = build(database.clone(), HostKeys::generate().unwrap()).await;
    assert_eq!(clock(&database).await, [0, 0, 0]);
    assert!(temporal(&app).await.is_err());
    assert!(
        crate::failure_tests::lose_commit_ack(app.activate())
            .await
            .is_err()
    );
    assert_eq!(clock(&database).await[2], 1);
    assert!(temporal(&app).await.is_err());
    app.activate().await.unwrap();
    let startup = clock(&database).await;
    assert!(startup[0] > 0 && startup[1] >= startup[0] * 1_000);
    assert_eq!(startup[2], 2);
    let attempt = temporal(&app).await.unwrap();
    // Requests and temporal reads cannot cause durable clock writes.
    app.login_challenge().await.unwrap();
    assert_eq!(clock(&database).await, startup);
    app.tick_clock().await.unwrap();
    let later = clock(&database).await;
    assert_eq!(later[2], startup[2] + 1);
    assert!(later[1] >= startup[1]);
    assert_eq!(attempt.timestamp().unix_millis(), startup[1]);

    // Actual request DB admission is exhausted while its private connections
    // remain open. Clock maintenance opens an independent reserved connection.
    let mut requests = Vec::new();
    while let Ok(Ok(permit)) = tokio::time::timeout(
        Duration::from_millis(10),
        app.admission_limits.requests().request(),
    )
    .await
    {
        requests.push(permit);
    }
    let mut connections = Vec::new();
    while let Ok(Ok(permit)) = tokio::time::timeout(
        Duration::from_millis(10),
        app.admission_limits.database().acquire(),
    )
    .await
    {
        let tx = database
            .begin_read(std::time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        connections.push((permit, tx));
    }
    let mut wasm = Vec::new();
    while let Ok(Ok(permit)) = tokio::time::timeout(
        Duration::from_millis(10),
        app.admission_limits.wasm().acquire(),
    )
    .await
    {
        wasm.push(permit);
    }
    assert!(!requests.is_empty() && !connections.is_empty() && !wasm.is_empty());
    tokio::time::timeout(Duration::from_millis(500), app.tick_clock())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(clock(&database).await[2], startup[2] + 2);
    for (_, mut tx) in connections {
        tx.commit().await.unwrap();
    }
    drop((requests, wasm));

    // Two processes of the same generation race real provider transactions.
    // Conflicts may reject one attempt, but every success advances exactly once.
    let peer_keys = serde_json::from_slice(&serde_json::to_vec(&*app.keys).unwrap()).unwrap();
    let peer = build(database.clone(), peer_keys).await;
    peer.activate().await.unwrap();
    let before_race = clock(&database).await;
    let (left, right) = tokio::join!(app.tick_clock(), peer.tick_clock());
    let committed = i64::from(left.is_ok()) + i64::from(right.is_ok());
    assert!(committed >= 1);
    let after_race = clock(&database).await;
    assert_eq!(after_race[2], before_race[2] + committed);
    assert!(after_race[1] >= before_race[1]);

    let before_block = clock(&database).await;
    let mut writer = database
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    writer
        .execute(
            "UPDATE nx_clock SET observed=observed WHERE singleton=1",
            &[],
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), app.tick_clock())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(clock(&database).await, before_block);
    writer.rollback().await.unwrap();
    app.tick_clock().await.unwrap();

    // Simulate a committed forward jump before recovery. Recovery resets only
    // credential seconds; startup after rollback must retain the future expiry
    // watermark even though trusted wall time is now lower.
    let prior = clock(&database).await;
    let future_ms = prior[1] + 7_200_000;
    let mut tx = database
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_clock SET observed=$1,lifecycle_ms=$2,lifecycle_version=$3 WHERE singleton=1",
        &[
            (prior[0] + 7_200).into(),
            future_ms.into(),
            (prior[2] + 1).into(),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let before_rotation = clock(&database).await;
    let keys = HostKeys::generate().unwrap();
    database.recover_clock(&keys).await.unwrap();
    let recovered = clock(&database).await;
    assert_eq!(&recovered[1..], &before_rotation[1..]);
    assert!(
        app.tick_clock().await.is_err(),
        "retired generation cannot tick"
    );
    assert!(
        temporal(&app).await.is_err(),
        "retired generation cannot consume time"
    );
    let replacement = build(database.clone(), keys).await;
    assert!(temporal(&replacement).await.is_err());
    replacement.activate().await.unwrap();
    assert_eq!(clock(&database).await[1], future_ms);
    assert!(temporal(&replacement).await.is_ok());
}

#[tokio::test]
async fn sqlite_integrated_clock_startup_capacity_and_rotation() {
    let dir = tempfile::tempdir().unwrap();
    provider_contract(Database::sqlite(dir.path().join("integrated-clock.db"))).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable local server"]
async fn postgres_integrated_clock_startup_capacity_and_rotation() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "p06_integrate_{}",
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
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    provider_contract(Database::postgres(case.as_str()).unwrap()).await;
}

#[tokio::test]
async fn startup_unknown_commit_never_publishes_temporal_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let database = Database::sqlite(dir.path().join("startup-unknown.db"));
    let app = Arc::new(build(database.clone(), HostKeys::generate().unwrap()).await);
    assert!(
        crate::failure_tests::lose_commit_ack(app.activate())
            .await
            .is_err()
    );
    assert_eq!(
        clock(&database).await[2],
        1,
        "commit happened but acknowledgement was lost"
    );
    assert!(app.generation.get().is_none());
    assert!(temporal(&app).await.is_err());
    assert!(app.start_clock_service().is_err());
    app.activate().await.unwrap();
    assert_eq!(clock(&database).await[2], 2);
    assert!(temporal(&app).await.is_ok());
}

#[tokio::test]
async fn blocked_tick_deadline_cancellation_and_service_drain_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let database = Database::sqlite(dir.path().join("cancel-clock.db"));
    let app = Arc::new(build(database.clone(), HostKeys::generate().unwrap()).await);
    app.activate().await.unwrap();
    let before = clock(&database).await;
    let mut writer = database
        .begin(std::time::Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), app.tick_clock())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(clock(&database).await, before);
    let ticking = app.clone();
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe = closed.clone();
    let complete = Arc::new(tokio::sync::Notify::new());
    let completed = complete.clone();
    let blocked = tokio::spawn(async move {
        crate::database::MAINTENANCE_CLOSE_PROBE
            .scope(probe, async {
                assert!(ticking.tick_clock().await.is_err());
                completed.notify_one();
                std::future::pending::<()>().await;
            })
            .await;
    });
    // Explicit completion + worker-close acknowledgement, with the writer still
    // held: no sleep is used to infer that failed maintenance stopped working.
    tokio::time::timeout(Duration::from_millis(500), complete.notified())
        .await
        .unwrap();
    assert!(closed.load(Ordering::Acquire));
    blocked.abort();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), blocked)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled()
    );
    assert!(app.maintenance.try_acquire().is_ok());
    let service = app.start_clock_service().unwrap();
    assert!(app.start_clock_service().is_err());
    tokio::time::sleep(Duration::from_millis(1_020)).await;
    tokio::time::timeout(Duration::from_millis(500), service.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(!app.maintenance_running.load(Ordering::Acquire));
    assert!(app.maintenance.try_acquire().is_ok());
    writer.rollback().await.unwrap();
    app.tick_clock().await.unwrap();
    assert_eq!(clock(&database).await[2], before[2] + 1);
    let restarted = app.start_clock_service().unwrap();
    drop(restarted); // Early serve cancellation/error uses this path.
    tokio::time::timeout(Duration::from_millis(500), async {
        while app.maintenance_running.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unavailable_maintenance_capacity_cannot_renew_stale_time() {
    let dir = tempfile::tempdir().unwrap();
    let database = Database::sqlite(dir.path().join("stale-clock.db"));
    let app = Arc::new(build(database.clone(), HostKeys::generate().unwrap()).await);
    app.activate().await.unwrap();
    let startup = clock(&database).await;
    let reserved = app.maintenance.try_acquire().unwrap();
    let service = app.start_clock_service().unwrap();
    tokio::time::sleep(Duration::from_millis(5_050)).await;
    assert_eq!(clock(&database).await, startup);
    assert!(matches!(temporal(&app).await, Err(RequestError::Busy)));
    drop(reserved);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(clock(&database).await[2] > startup[2]);
    assert!(temporal(&app).await.is_ok());
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn storage_ten_requires_explicit_migration_and_is_never_reinitialized() {
    let dir = tempfile::tempdir().unwrap();
    let database = Database::sqlite(dir.path().join("storage-ten.db"));
    let mut tx = database
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "CREATE TABLE nx_storage(singleton BIGINT PRIMARY KEY,version BIGINT NOT NULL)",
        &[],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO nx_storage VALUES(1,10)", &[])
        .await
        .unwrap();
    tx.execute(
        "CREATE TABLE nx_clock(singleton BIGINT PRIMARY KEY,observed BIGINT NOT NULL)",
        &[],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO nx_clock VALUES(1,$1)",
        &[Param::Number(123_456)],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let error = database.initialize().await.unwrap_err();
    assert!(error.to_string().contains("explicit reviewed migration"));
    let mut tx = database
        .begin_read(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(observed AS TEXT) FROM nx_clock", &[])
            .await
            .unwrap(),
        [["123456".to_string()]]
    );
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(version AS TEXT) FROM nx_storage", &[])
            .await
            .unwrap(),
        [["10".to_string()]]
    );
    tx.commit().await.unwrap();
}

async fn postgres_fixture(label: &str) -> (Database, String) {
    use sqlx::Connection;
    let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
    let name = format!(
        "p06_{label}_{}",
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

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable local server"]
async fn postgres_http_stop_waits_for_actual_inflight_backend_termination() {
    use sqlx::{Connection, Row};
    for delay in [0, 205] {
        let (database, url) = postgres_fixture("http_stop").await;
        let app = Arc::new(build(database.clone(), HostKeys::generate().unwrap()).await);
        app.activate().await.unwrap();
        let before = clock(&database).await;
        let mut monitor = sqlx::PgConnection::connect(&url).await.unwrap();
        // A real server-side barrier inside the actual production clock UPDATE;
        // this exercises cancellation of admitted work, not an idle Rust task.
        sqlx::query("CREATE FUNCTION nx_clock_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_catalog.pg_sleep(0.3); RETURN NEW; END $$").execute(&mut monitor).await.unwrap();
        sqlx::query("CREATE TRIGGER nx_clock_pause BEFORE UPDATE ON nx_clock FOR EACH ROW EXECUTE FUNCTION nx_clock_pause()").execute(&mut monitor).await.unwrap();
        let listener = crate::http::Listener::loopback("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let serving = app.clone();
        let server = tokio::spawn(async move {
            crate::http::serve(
                listener,
                serving,
                crate::http::Origin::parse("http://localhost:8080").unwrap(),
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
        // lets the old 200ms client deadline pass before asking HTTP to stop.
        tokio::time::sleep(Duration::from_millis(delay)).await;
        let stopped = std::time::Instant::now();
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_millis(250), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(stopped.elapsed() < Duration::from_millis(200));
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
        assert!(app.maintenance.try_acquire().is_ok());
        assert!(!app.maintenance_running.load(Ordering::Acquire));
        assert_eq!(
            clock(&database).await,
            before,
            "canceled UPDATE must not refresh durable progress"
        );
    }
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable local server"]
async fn postgres_lost_control_quarantines_capacity_and_service_readiness() {
    use sqlx::{Connection, Row};
    let (database, url) = postgres_fixture("quarantine").await;
    let app = Arc::new(build(database.clone(), HostKeys::generate().unwrap()).await);
    app.activate().await.unwrap();
    let before = clock(&database).await;
    let mut monitor = sqlx::PgConnection::connect(&url).await.unwrap();
    sqlx::query("CREATE FUNCTION nx_clock_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_catalog.pg_sleep(0.3); RETURN NEW; END $$").execute(&mut monitor).await.unwrap();
    sqlx::query("CREATE TRIGGER nx_clock_pause BEFORE UPDATE ON nx_clock FOR EACH ROW EXECUTE FUNCTION nx_clock_pause()").execute(&mut monitor).await.unwrap();
    let service = app.start_clock_service().unwrap();
    let control=tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            let rows=sqlx::query("SELECT c.pid FROM pg_catalog.pg_stat_activity c WHERE c.datname=pg_catalog.current_database() AND c.application_name LIKE 'nx-ctl-%' AND EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity w WHERE w.datname=c.datname AND w.application_name LIKE 'nx-clock-%' AND w.wait_event='PgSleep')").fetch_all(&mut monitor).await.unwrap();
            if let Some(row)=rows.first(){break row.get::<i32,_>(0);}
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    // Test-only provider failure: remove precisely this fixture's host control
    // session while its corresponding work UPDATE is known to be in-flight.
    sqlx::query("SELECT pg_catalog.pg_terminate_backend($1)")
        .bind(control)
        .execute(&mut monitor)
        .await
        .unwrap();
    assert!(service.shutdown().await.is_err());
    assert!(
        app.maintenance.try_acquire().is_err(),
        "unknown cleanup must not release its reserved slot"
    );
    assert!(
        app.maintenance_running.load(Ordering::Acquire),
        "unknown cleanup must not release service ownership"
    );
    assert!(app.start_clock_service().is_err());
    assert!(matches!(temporal(&app).await, Err(RequestError::Busy)));
    assert_eq!(
        clock(&database).await,
        before,
        "unknown cleanup cannot publish clock progress"
    );
}

#[tokio::test]
async fn aborted_service_keeps_unknown_owner_and_temporal_readiness_quarantined() {
    let dir = tempfile::tempdir().unwrap();
    let database = Database::sqlite(dir.path().join("aborted-service.db"));
    let app = Arc::new(build(database, HostKeys::generate().unwrap()).await);
    app.activate().await.unwrap();
    let service = app.start_clock_service().unwrap();
    service.task.as_ref().unwrap().abort();
    assert!(service.shutdown().await.is_err());
    assert!(app.maintenance_running.load(Ordering::Acquire));
    assert!(matches!(temporal(&app).await, Err(RequestError::Busy)));
    assert!(app.start_clock_service().is_err());
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
    let activated = tokio::time::Instant::now();
    let before = clock(&database).await;
    let mut monitor = sqlx::PgConnection::connect(configured.as_str())
        .await
        .unwrap();
    // Trusted-provider fault injection, matching R's exact production repro:
    // spend 80ms before COMMIT, then pause the actual post-COMMIT unlock query.
    sqlx::query("CREATE FUNCTION public.pg_advisory_unlock_all() RETURNS void LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_catalog.pg_sleep(0.3); PERFORM pg_catalog.pg_advisory_unlock_all(); END $$").execute(&mut monitor).await.unwrap();
    sqlx::query("CREATE FUNCTION nx_clock_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.lifecycle_version != OLD.lifecycle_version THEN PERFORM pg_catalog.pg_sleep(0.08); END IF; RETURN NEW; END $$").execute(&mut monitor).await.unwrap();
    sqlx::query("CREATE TRIGGER nx_clock_pause BEFORE UPDATE ON nx_clock FOR EACH ROW EXECUTE FUNCTION nx_clock_pause()").execute(&mut monitor).await.unwrap();
    let listener = crate::http::Listener::loopback("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let serving = app.clone();
    let server = tokio::spawn(async move {
        crate::http::serve(
            listener,
            serving,
            crate::http::Origin::parse("http://localhost:8080").unwrap(),
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
    tokio::time::timeout(Duration::from_millis(250), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        age_ms as u128 + observed.elapsed().as_millis() <= 200,
        "post-COMMIT unlock enlarged the original 200ms maintenance budget"
    );
    let present: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE pid=$1")
            .bind(pid)
            .fetch_one(&mut monitor)
            .await
            .unwrap();
    assert_eq!(present, 0);
    assert!(app.maintenance.try_acquire().is_ok());
    assert!(!app.maintenance_running.load(Ordering::Acquire));
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
