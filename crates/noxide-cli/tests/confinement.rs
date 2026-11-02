//! The deployed process tree holds its keys apart and is really confined.
#![cfg(target_os = "linux")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_test_support as support;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::Command,
    time::timeout,
};

fn children(pid: u32) -> Vec<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .map(|child| child.parse().unwrap())
        .collect()
}
fn name(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap()
        .trim()
        .to_owned()
}
fn status(pid: u32, field: &str) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix(&format!("{field}:"))
                .map(str::trim)
                .map(str::to_owned)
        })
        .unwrap()
}
async fn get(socket: &Path) -> String {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream
        .write_all(b"GET /login HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(5), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

#[tokio::test]
async fn serving_process_is_confined_and_fails_closed_without_its_key_service() {
    if !std::fs::read_to_string("/sys/kernel/security/lsm")
        .is_ok_and(|lsm| lsm.contains("landlock"))
    {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let manifest = support::manifest();
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(root.join("app.wasm"), support::component(None)).unwrap();
    let config = root.join("config.json");
    let socket = root.join("runtime.sock");
    std::fs::write(&config, serde_json::to_vec(&serde_json::json!({
        "database": {"sqlite": "runtime.db"}, "keys": "keys.json",
        "component": "app.wasm", "manifest": "manifest.json",
        "approved_contract": URL_SAFE_NO_PAD.encode(noxide_host::manifest::digest(&manifest).unwrap()),
        "origin": "http://localhost:8080", "listen": {"unix": "runtime.sock"}
    })).unwrap()).unwrap();
    let initialized = Command::new(env!("CARGO_BIN_EXE_noxide"))
        .arg("init")
        .arg(&config)
        .output()
        .await
        .unwrap();
    assert!(initialized.status.success());
    let mut supervisor = Command::new(env!("CARGO_BIN_EXE_noxide"))
        .arg("serve")
        .arg(&config)
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(supervisor.stdout.take().unwrap());
    let mut ready = String::new();
    timeout(Duration::from_secs(10), stdout.read_line(&mut ready))
        .await
        .unwrap()
        .unwrap();
    assert!(ready.contains("Runtime listening"), "{ready}");
    assert!(get(&socket).await.starts_with("HTTP/1.1 200"));

    // An operator command is the database's last other connection when it exits.
    // SQLite would then unlink the sidecars, which a confined server cannot recreate.
    let lookup = Command::new(env!("CARGO_BIN_EXE_noxide"))
        .arg("account-lookup")
        .arg(&config)
        .arg("nobody")
        .output()
        .await
        .unwrap();
    assert!(!lookup.status.success(), "fixture has no such account");
    let response = get(&socket).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let server = children(supervisor.id().unwrap())
        .into_iter()
        .find(|pid| name(*pid) == "noxide-server")
        .expect("server process");
    let keyd = children(server)
        .into_iter()
        .find(|pid| name(*pid) == "noxide-keyd")
        .expect("key service process");
    for pid in [server, keyd] {
        assert_eq!(status(pid, "Seccomp"), "2", "{}", name(pid));
        assert_eq!(status(pid, "NoNewPrivs"), "1", "{}", name(pid));
    }
    // Same-user processes cannot read the key service's memory.
    assert!(std::fs::read(format!("/proc/{keyd}/mem")).is_err());
    // The key file is open in the key service only, and in neither afterwards.
    for pid in [server, keyd] {
        for descriptor in std::fs::read_dir(format!("/proc/{pid}/fd"))
            .into_iter()
            .flatten()
        {
            if let Ok(target) = std::fs::read_link(descriptor.unwrap().path()) {
                assert!(!target.ends_with("keys.json"), "{pid} holds the key file");
            }
        }
    }

    // A session needs the keys. With the service gone, nothing is issued.
    Command::new("kill")
        .arg("-KILL")
        .arg(keyd.to_string())
        .status()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let response = get(&socket).await;
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert!(
        !response.to_ascii_lowercase().contains("set-cookie"),
        "{response}"
    );
    assert!(get(&socket).await.starts_with("HTTP/1.1 503"));

    Command::new("kill")
        .arg("-TERM")
        .arg(supervisor.id().unwrap().to_string())
        .status()
        .await
        .unwrap();
    timeout(Duration::from_secs(10), supervisor.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!socket.exists(), "stopped server left its socket behind");
}
