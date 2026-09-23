use noxide_host::runtime::{Limits, Runtime};
use noxide_protocol::{RequestKind, RequestView, VERSION};

fn request() -> RequestView {
    RequestView {
        version: VERSION,
        kind: RequestKind::Route(1),
        target: None,
        input: Default::default(),
    }
}

fn component(body: &str, extra: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(component
      (import "noxide:application/host@0.1.0" (instance $h
        (export "emit" (func (param "word" u64) (param "length" u32)))
        (export "request-length" (func (result u32)))))
      (alias export $h "emit" (func $emit))
      (alias export $h "request-length" (func $len))
      (core func $emit (canon lower (func $emit)))
      (core func $len (canon lower (func $len)))
      (core module $m
        (import "h" "emit" (func $emit (param i64 i32)))
        (import "h" "len" (func $len (result i32)))
        (memory (export "memory") 1)
        (global $seen (mut i32) (i32.const 0))
        {extra}
        (func (export "handle") {body}))
      (core instance $i (instantiate $m (with "h" (instance
        (export "emit" (func $emit)) (export "len" (func $len))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#
    ))
    .unwrap()
}

fn emit_page() -> String {
    let bytes = br#"{"page":{"title":"Fresh","nodes":[{"text":"Hello"}]}}"#;
    bytes
        .chunks(8)
        .map(|c| {
            let mut word = [0; 8];
            word[..c.len()].copy_from_slice(c);
            format!(
                "i64.const {} i32.const {} call $emit\n",
                i64::from_le_bytes(word),
                c.len()
            )
        })
        .collect()
}

#[tokio::test]
async fn fresh_memory_and_globals_on_every_request() {
    let wasm = component(
        &format!(
            "global.get $seen if unreachable end i32.const 1 global.set $seen i32.const 0 i32.load if unreachable end i32.const 0 i32.const 42 i32.store {}",
            emit_page()
        ),
        "",
    );
    let app = Runtime::compile(&wasm, Limits::default()).unwrap();
    for _ in 0..3 {
        assert!(app.render_only(request()).await.is_ok());
    }
    let (a, b) = tokio::join!(app.render_only(request()), app.render_only(request()));
    assert!(a.is_ok() && b.is_ok());
}

#[tokio::test]
async fn initialization_has_no_request_authority() {
    let wasm = component(&emit_page(), "(func $start call $len drop) (start $start)");
    let app = Runtime::compile(&wasm, Limits::default()).unwrap();
    assert!(app.render_only(request()).await.is_err());
}

#[tokio::test]
async fn traps_loops_memory_growth_and_host_call_limits_terminate() {
    for body in [
        "unreachable",
        "(loop $forever br $forever)",
        "i32.const 2048 memory.grow drop",
        "i64.const 0 i32.const 9 call $emit",
    ] {
        let app = Runtime::compile(&component(body, ""), Limits::default()).unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                app.render_only(request())
            )
            .await
            .unwrap()
            .is_err()
        );
    }
    let limits = Limits {
        host_calls: 1,
        ..Limits::default()
    };
    let app = Runtime::compile(&component(&emit_page(), ""), limits).unwrap();
    assert!(app.render_only(request()).await.is_err());
}

#[test]
fn reject_unapproved_imports_native_artifacts_and_core_modules() {
    for wasm in [
        b"\x7fELFpretend-cache".to_vec(),
        wat::parse_str("(module)").unwrap(),
        wat::parse_str(r#"(component (import "wasi:filesystem/types" (instance)))"#).unwrap(),
    ] {
        assert!(Runtime::compile(&wasm, Limits::default()).is_err());
    }
}

#[test]
fn reject_cleanup_hooks_and_incomplete_contracts_at_admission() {
    let post = wat::parse_str(
        r#"(component
      (core module $m (func (export "handle")) (func (export "cleanup")))
      (core instance $i (instantiate $m))
      (alias core export $i "cleanup" (core func $cleanup))
      (func (export "handle") (canon lift (core func $i "handle") (post-return $cleanup))))"#,
    )
    .unwrap();
    assert!(Runtime::compile(&post, Limits::default()).is_err());
    assert!(Runtime::compile(&wat::parse_str("(component)").unwrap(), Limits::default()).is_err());
    let resource = wat::parse_str(
        r#"(component (type $t (resource (rep i32))) (core func (canon resource.new $t)))"#,
    )
    .unwrap();
    assert!(Runtime::compile(&resource, Limits::default()).is_err());
}

#[tokio::test]
async fn fresh_tables_and_bounded_table_growth() {
    let body = format!(
        "i32.const 0 table.get $table ref.is_null i32.eqz if unreachable end i32.const 0 ref.func $f table.set $table {}",
        emit_page()
    );
    let extra = "(table $table 1 funcref) (func $f) (elem declare func $f)";
    let app = Runtime::compile(&component(&body, extra), Limits::default()).unwrap();
    for _ in 0..3 {
        app.render_only(request()).await.unwrap();
    }
    let app = Runtime::compile(
        &component("ref.null func i32.const 8192 table.grow $table drop", extra),
        Limits::default(),
    )
    .unwrap();
    assert!(app.render_only(request()).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_hostile_requests_leave_capacity_and_release_memory() {
    let body = format!(
        "call $len i32.const 256 i32.gt_u if i32.const 255 memory.grow drop i32.const 0 i32.const 7 i32.const 16777216 memory.fill (loop $busy br $busy) else {} end",
        emit_page()
    );
    let limits = Limits {
        memory_bytes: 16 * 1024 * 1024,
        fuel: 100_000_000,
        wall_time: std::time::Duration::from_millis(250),
        concurrency: 4,
        ..Limits::default()
    };
    let app = Runtime::compile(&component(&body, ""), limits).unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..3 {
        let runtime = app.clone();
        let mut input = request();
        input.input.insert("large".into(), "x".repeat(300));
        tasks.spawn(async move {
            assert!(runtime.render_only(input).await.is_err());
        });
    }
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    app.render_only(request()).await.unwrap();
    let started = std::time::Instant::now();
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    app.render_only(request()).await.unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let peak = status.lines().find(|l| l.starts_with("VmHWM:")).unwrap();
        println!(
            "hostile concurrency: {}; cleanup {:?}",
            peak,
            started.elapsed()
        );
        let kib: usize = peak.split_whitespace().nth(1).unwrap().parse().unwrap();
        assert!(
            kib < 512 * 1024,
            "bounded test exceeded its host allocation envelope"
        );
    }
}
