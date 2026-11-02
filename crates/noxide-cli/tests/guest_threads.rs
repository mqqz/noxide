//! Workers skip confinement's thread count, which needs `/proc`. Landlock binds only the
//! calling thread and its later children, so this holds them to the one thread. In its
//! own file because it looks at every worker this test process has started.
use noxide_guest::{Limits, pool::GuestPool};
use std::path::Path;

const COMPONENT: &str = r#"(component
  (import "noxide:application/host@0.1.0" (instance $h
    (export "emit" (func (param "word" u64) (param "length" u32)))))
  (alias export $h "emit" (func $emit))
  (core func $emit (canon lower (func $emit)))
  (core module $m
    (import "h" "emit" (func $emit (param i64 i32)))
    (memory (export "memory") 1)
    (func (export "handle")))
  (core instance $i (instantiate $m (with "h" (instance (export "emit" (func $emit))))))
  (func (export "handle") (canon lift (core func $i "handle"))))"#;

#[test]
fn a_ready_worker_has_one_thread() {
    let own = std::process::id().to_string();
    let _pool = GuestPool::start(
        Path::new(env!("CARGO_BIN_EXE_noxide-guest")),
        "best_effort",
        &wat::parse_str(COMPONENT).unwrap(),
        Limits {
            concurrency: 1,
            ..Limits::default()
        },
        1,
    )
    .unwrap();
    let field = |status: &str, name: &str| -> String {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .trim()
            .to_owned()
    };
    let mut workers = 0;
    for entry in std::fs::read_dir("/proc").unwrap() {
        let Ok(status) = std::fs::read_to_string(entry.unwrap().path().join("status")) else {
            continue;
        };
        if field(&status, "Name:") != "noxide-guest" {
            continue;
        }
        // A worker's parent is the broker this test started.
        let Ok(parent) =
            std::fs::read_to_string(format!("/proc/{}/status", field(&status, "PPid:")))
        else {
            continue;
        };
        if field(&parent, "PPid:") != own {
            continue;
        }
        workers += 1;
        assert_eq!(field(&status, "Threads:"), "1", "a worker started a thread");
    }
    assert_eq!(workers, 1);
}
