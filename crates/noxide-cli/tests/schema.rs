#[allow(dead_code)]
#[path = "../../noxide-host/tests/support/mod.rs"]
mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_host::{Application, Database, HostKeys, manifest, runtime::Limits};
use noxide_protocol::{FieldKind, TextField};
use std::path::Path;

async fn cli(args: &[&Path], command: &str) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
        .arg("schema")
        .arg(command)
        .args(args)
        .output()
        .await
        .unwrap()
}

#[tokio::test]
async fn schema_drafts_require_backfills_and_apply_the_approved_target() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let database = Database::sqlite(root.join("runtime.db"));
    database.initialize().await.unwrap();
    let source = support::manifest();
    let keys = serde_json::to_vec(&HostKeys::generate().unwrap()).unwrap();
    let component = support::component(None);
    let app = Application::new(
        &component,
        &serde_json::to_vec(&source).unwrap(),
        manifest::digest(&source).unwrap(),
        database.clone(),
        serde_json::from_slice(&keys).unwrap(),
        Limits::default(),
    )
    .unwrap();
    app.activate().await.unwrap();
    let mut target = source.clone();
    target.resources[0].fields.push(TextField {
        name: "completed".into(),
        label: "Completed".into(),
        max_bytes: 8,
        kind: FieldKind::Boolean,
        optional: false,
    });
    target.actions[0].fields.push("completed".into());
    let old = root.join("old.json");
    let new = root.join("new.json");
    let migration = root.join("001.json");
    let config = root.join("config.json");
    std::fs::write(&old, serde_json::to_vec(&source).unwrap()).unwrap();
    std::fs::write(&new, serde_json::to_vec(&target).unwrap()).unwrap();
    std::fs::write(&config,serde_json::to_vec(&serde_json::json!({
        "database":{"sqlite":"runtime.db"},"keys":"keys.json","component":"app.wasm","manifest":"new.json",
        "approved_contract":URL_SAFE_NO_PAD.encode(manifest::digest(&target).unwrap()),"origin":"http://localhost:8080","listen":{"tcp":"127.0.0.1:8080"}
    })).unwrap()).unwrap();
    assert!(
        cli(&[&old, &new, &migration], "diff")
            .await
            .status
            .success()
    );
    let mut draft: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&migration).unwrap()).unwrap();
    assert!(draft["operations"][0]["value"].is_null());
    assert!(!cli(&[&config, &migration], "check").await.status.success());
    app.activate().await.unwrap();
    draft["operations"][0]["value"] = serde_json::json!("false");
    std::fs::write(&migration, serde_json::to_vec(&draft).unwrap()).unwrap();
    let checked = cli(&[&config, &migration], "check").await;
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    app.activate().await.unwrap();
    let applied = cli(&[&config, &migration], "apply").await;
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(app.activate().await.is_err());
    assert!(cli(&[&config, &migration], "apply").await.status.success());
    let new_app = Application::new(
        &component,
        &serde_json::to_vec(&target).unwrap(),
        manifest::digest(&target).unwrap(),
        database,
        serde_json::from_slice(&keys).unwrap(),
        Limits::default(),
    )
    .unwrap();
    new_app.activate().await.unwrap();
    let mut configuration: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    configuration["approved_contract"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0; 32]));
    std::fs::write(&config, serde_json::to_vec(&configuration).unwrap()).unwrap();
    assert!(!cli(&[&config, &migration], "apply").await.status.success());
}
