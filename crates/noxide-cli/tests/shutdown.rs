#![cfg(unix)]

#[allow(dead_code)]
#[path = "../../noxide-host/tests/support/mod.rs"]
mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::Command,
    time::timeout,
};

#[tokio::test]
async fn unix_signals_drain_connections_and_remove_socket() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
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
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    // The second start uses exactly the same path, exercising a service restart.
    for signal in ["-TERM", "-INT"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_noxide"))
            .arg("serve")
            .arg(&config)
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        timeout(Duration::from_secs(10), stdout.read_line(&mut ready))
            .await
            .unwrap()
            .unwrap();
        assert!(ready.contains("Runtime listening"), "{ready}");

        // Leave one accepted request incomplete. A second completed request
        // proves the accept loop has reached both connections before signaling.
        let mut pending = UnixStream::connect(&socket).await.unwrap();
        let headers = b"GET /login HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\n";
        pending.write_all(headers).await.unwrap();
        let mut probe = UnixStream::connect(&socket).await.unwrap();
        probe.write_all(headers).await.unwrap();
        probe.write_all(b"\r\n").await.unwrap();
        let mut response = String::new();
        timeout(Duration::from_secs(5), probe.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        let sent = Command::new("kill")
            .arg(signal)
            .arg(child.id().unwrap().to_string())
            .status()
            .await
            .unwrap();
        assert!(sent.success());
        pending.write_all(b"\r\n").await.unwrap();
        response.clear();
        timeout(
            Duration::from_secs(5),
            pending.read_to_string(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{signal}: {response}");
        let status = timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(status.success(), "{signal}: {status}");
        assert!(!socket.exists(), "{signal} left the socket pathname behind");
    }
    let _rebound = tokio::net::UnixListener::bind(&socket).unwrap();
}
