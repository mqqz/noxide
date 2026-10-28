#[allow(dead_code)]
#[path = "../../noxide-host/tests/support/mod.rs"]
mod support;

use noxide_host::{Application, Database, HostKeys, manifest, runtime::Limits};
use std::path::Path;

async fn recover(config: &Path) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
        .arg("recover-clock")
        .arg(config)
        .output()
        .await
        .unwrap()
}

#[tokio::test]
async fn clock_recovery_requires_a_private_new_key() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let db = Database::sqlite(root.join("runtime.db"));
    db.initialize().await.unwrap();
    db.create_account("alice", "clock test password", "")
        .await
        .unwrap();
    let m = support::manifest();
    let component = support::component(None);
    let old_keys = HostKeys::generate().unwrap();
    let old = Application::new(
        &component,
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        old_keys,
        Limits::default(),
    )
    .unwrap();
    old.activate().await.unwrap();
    let challenge = old.login_challenge().await.unwrap();
    let session = old
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "clock test password",
        )
        .await
        .unwrap();
    let key_path = root.join("fresh.json");
    let config = root.join("config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "database": {"sqlite": "runtime.db"}, "keys": "fresh.json",
            "component": "unused.wasm", "manifest": "unused.json", "approved_contract": "unused",
            "origin": "http://localhost:8080", "listen": {"tcp": "127.0.0.1:8080"}
        }))
        .unwrap(),
    )
    .unwrap();
    let generated = tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
        .arg("keygen")
        .arg(&key_path)
        .output()
        .await
        .unwrap();
    assert!(generated.status.success());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let denied = recover(&config).await;
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stderr).contains("private"));
        old.view(&session, 1, None).await.unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let recovered = recover(&config).await;
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(old.login_challenge().await.is_err());
    let fresh: HostKeys = serde_json::from_slice(&std::fs::read(&key_path).unwrap()).unwrap();
    let new = Application::new(
        &component,
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db,
        fresh,
        Limits::default(),
    )
    .unwrap();
    new.activate().await.unwrap();
    assert!(new.view(&session, 1, None).await.is_err());
    let challenge = new.login_challenge().await.unwrap();
    new.login(
        &challenge.cookie,
        &challenge.csrf,
        "alice",
        "clock test password",
    )
    .await
    .unwrap();
    let reused = recover(&config).await;
    assert!(!reused.status.success());
    assert!(String::from_utf8_lossy(&reused.stderr).contains("fresh host key"));
    new.login_challenge().await.unwrap();
}
