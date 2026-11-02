//! A real worker process against the same guest behaviour as the in-process runtime.
use anyhow::Result;
use noxide_guest::{GuestBusy, Limits, pool::GuestPool};
use noxide_host_calls::HostCalls;
use noxide_protocol::{RequestKind, RequestView, ResponseIntent, VERSION};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::time::Instant;

fn request() -> RequestView {
    RequestView {
        params: Default::default(),
        available_forms: Vec::new(),
        version: VERSION,
        kind: RequestKind::Route(1),
        target: None,
        input: Default::default(),
        inspection: Default::default(),
    }
}

fn component(body: &str) -> Vec<u8> {
    let page: String = br#"{"page":{"title":"Fresh","nodes":[{"text":"Hello"}]}}"#
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
        .collect();
    wat::parse_str(format!(
        r#"(component
      (import "noxide:application/host@0.1.0" (instance $h
        (export "emit" (func (param "word" u64) (param "length" u32)))
        (export "invoke" (func (param "operation" u32) (param "target" u64) (result u32)))))
      (alias export $h "emit" (func $emit))
      (alias export $h "invoke" (func $invoke))
      (core func $emit (canon lower (func $emit)))
      (core func $invoke (canon lower (func $invoke)))
      (core module $m
        (import "h" "emit" (func $emit (param i64 i32)))
        (import "h" "invoke" (func $invoke (param i32 i64) (result i32)))
        (memory (export "memory") 1)
        (func (export "handle") {body} {page}))
      (core instance $i (instantiate $m (with "h" (instance
        (export "emit" (func $emit)) (export "invoke" (func $invoke))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#
    ))
    .unwrap()
}

#[derive(Default)]
struct Storage {
    invoked: u32,
    refuse: bool,
}
impl HostCalls for Storage {
    fn storage_allowed(&self) -> bool {
        true
    }
    async fn invoke(&mut self, _: u32, _: u64) -> Result<Vec<u8>> {
        self.invoked += 1;
        anyhow::ensure!(!self.refuse, "policy refused");
        Ok(b"row".to_vec())
    }
    fn follow_source(&mut self, _: u32, _: u64) -> Result<()> {
        Ok(())
    }
    async fn follow(&mut self, _: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

fn pool(body: &str, concurrency: usize) -> Arc<GuestPool> {
    let limits = Limits {
        concurrency,
        ..Limits::default()
    };
    Arc::new(
        GuestPool::start(
            Path::new(env!("CARGO_BIN_EXE_noxide-guest")),
            "best_effort",
            &component(body),
            limits,
        )
        .unwrap(),
    )
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[tokio::test]
async fn a_worker_runs_requests_and_asks_the_server_for_storage() {
    let pool = pool("i32.const 1 i64.const 0 call $invoke drop", 1);
    for _ in 0..3 {
        let attempt = pool
            .run(
                request(),
                Some(Storage::default()),
                1_000_000,
                8,
                deadline(),
            )
            .await;
        assert!(matches!(attempt.result.unwrap(), ResponseIntent::Page(_)));
        assert_eq!(attempt.effects.unwrap().invoked, 1);
        // Every guest import is charged, so this counts more than storage calls.
        assert!(attempt.calls_left < 8);
        assert!(attempt.fuel_left < 1_000_000);
    }
    assert_eq!(pool.idle_workers(), 1);
}

#[tokio::test]
async fn a_refused_call_fails_with_the_servers_error() {
    let pool = pool("i32.const 1 i64.const 0 call $invoke drop", 1);
    let attempt = pool
        .run(
            request(),
            Some(Storage {
                invoked: 0,
                refuse: true,
            }),
            1_000_000,
            8,
            deadline(),
        )
        .await;
    assert_eq!(attempt.result.unwrap_err().to_string(), "policy refused");
    assert_eq!(pool.idle_workers(), 1);
}

#[tokio::test]
async fn a_trapping_guest_leaves_the_worker_usable() {
    let pool = pool("unreachable", 1);
    let attempt = pool
        .run(
            request(),
            Some(Storage::default()),
            1_000_000,
            8,
            deadline(),
        )
        .await;
    assert!(attempt.result.is_err());
    assert_eq!(pool.idle_workers(), 1);
}

#[tokio::test]
async fn fuel_stops_a_looping_guest() {
    let pool = pool("(loop $forever br $forever)", 1);
    let attempt = pool
        .run(request(), Some(Storage::default()), 10_000, 8, deadline())
        .await;
    assert!(attempt.result.is_err());
    assert_eq!(attempt.fuel_left, 0);
}

#[tokio::test]
async fn a_loop_past_the_deadline_is_reported_as_busy() {
    let pool = pool("(loop $forever br $forever)", 1);
    let attempt = pool
        .run(
            request(),
            Some(Storage::default()),
            u64::MAX / 2,
            8,
            Instant::now() + Duration::from_millis(100),
        )
        .await;
    assert!(attempt.result.unwrap_err().is::<GuestBusy>());
    assert_eq!(
        pool.idle_workers(),
        1,
        "an honest worker survives a deadline"
    );
}

#[tokio::test]
async fn a_lost_worker_is_replaced() {
    // Hold up the reply past the grace period by making the storage call itself slow.
    struct Slow;
    impl HostCalls for Slow {
        fn storage_allowed(&self) -> bool {
            true
        }
        async fn invoke(&mut self, _: u32, _: u64) -> Result<Vec<u8>> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(Vec::new())
        }
        fn follow_source(&mut self, _: u32, _: u64) -> Result<()> {
            Ok(())
        }
        async fn follow(&mut self, _: u32) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }
    let pool = pool("i32.const 1 i64.const 0 call $invoke drop", 1);
    let attempt = pool
        .run(
            request(),
            Some(Slow),
            1_000_000,
            8,
            Instant::now() + Duration::from_millis(50),
        )
        .await;
    assert!(attempt.result.is_err());
    for _ in 0..400 {
        if pool.idle_workers() == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("worker was not replaced");
}

#[tokio::test]
async fn an_application_serves_and_writes_through_a_worker() {
    use noxide_host::{AccountAdmin as _, Application, Database, DeploymentResources, HostKeys};
    use noxide_test_support as fixture;
    let directory = tempfile::tempdir().unwrap();
    let db = Database::sqlite(directory.path().join("worker.db"));
    db.initialize().await.unwrap();
    db.create_account("alice", "worker test password", "")
        .await
        .unwrap();
    let manifest = fixture::manifest();
    let component = fixture::component(None);
    let mut app = Application::new(
        &component,
        &serde_json::to_vec(&manifest).unwrap(),
        noxide_host::manifest::digest(&manifest).unwrap(),
        db,
        HostKeys::generate().unwrap(),
        Limits::default(),
        DeploymentResources {
            effects: None,
            jobs: None,
            assets: noxide_host::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap();
    let pool = Arc::new(
        GuestPool::start(
            Path::new(env!("CARGO_BIN_EXE_noxide-guest")),
            "best_effort",
            &component,
            Limits {
                concurrency: 1,
                ..Limits::default()
            },
        )
        .unwrap(),
    );
    app.use_guest_workers(pool.clone());
    app.activate().await.unwrap();
    let challenge = app.login_challenge().await.unwrap();
    let session = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "worker test password",
        )
        .await
        .unwrap();
    let page = app.view(&session, 1, None).await.unwrap();
    let body = String::from_utf8(page.body).unwrap();
    assert!(body.contains("No notes yet"));
    let submission = fixture::hidden(&body, "_submission");
    let csrf = fixture::hidden(&body, "_csrf");
    app.submit(
        &session,
        1,
        &submission,
        &csrf,
        std::collections::BTreeMap::from([("body".to_string(), "through a worker".to_string())]),
    )
    .await
    .unwrap();
    assert_eq!(pool.idle_workers(), 1);
    // With no worker left the page fails, so the guest was never in this process.
    pool.close();
    assert!(app.view(&session, 1, None).await.is_err());
}
