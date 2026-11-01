#![cfg(unix)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_host::{
    Application, Database, DeploymentResources, EffectDeployment, EffectGrant, EffectLimits,
    EffectSecret, HostKeys, runtime::Limits,
};
use noxide_protocol::{effects::*, *};
use noxide_test_support as support;
use std::{collections::BTreeSet, path::Path};
const PRIVATE_BODY: &str = "PRIVATE_CLI_EFFECT_BODY";
const PRIVATE_SECRET: &str = "PRIVATE_CLI_EFFECT_TOKEN";
fn declarations() -> Manifest {
    let mut manifest = support::manifest();
    manifest.effects = Some(EffectContract {
        endpoints: vec![EffectEndpoint {
            name: "events".into(),
            secret_slot: Some("delivery_token".into()),
        }],
        emissions: (0..2)
            .map(|ordinal| EmitEffect {
                source_action: 1,
                ordinal,
                endpoint: "events".into(),
                fields: vec![PayloadField {
                    schema: Input {
                        name: "message".into(),
                        label: "Message".into(),
                        kind: FieldKind::Text,
                        optional: false,
                        max_bytes: 4096,
                    },
                    value: Value::Input("body".into()),
                }],
            })
            .collect(),
    });
    manifest
}
async fn command(
    root: &Path,
    family: &str,
    operation: &str,
    args: &[&str],
    secrets: &[&str],
    success: bool,
) -> String {
    // Relative CONFIG exercises the central trusted config-parent resolution.
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
        .current_dir(root)
        .arg(family)
        .arg(operation)
        .arg("config.json")
        .args(args)
        .output()
        .await
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    for secret in secrets {
        assert!(
            !stdout.contains(secret) && !stderr.contains(secret),
            "CLI disclosed private effect fixture material"
        );
    }
    assert_eq!(
        output.status.success(),
        success,
        "{family} {operation}: {stderr}"
    );
    stdout.trim().to_owned()
}
fn listing(raw: &str) -> Vec<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["effects"]
    );
    let fields = BTreeSet::from([
        "id",
        "deployment",
        "tenant",
        "endpoint",
        "state",
        "attempts",
        "round",
        "eligible",
    ]);
    let rows = value["effects"].as_array().unwrap().clone();
    for row in &rows {
        assert_eq!(
            row.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            fields
        );
        assert_eq!(row["attempts"], 0);
    }
    rows
}
async fn inspect(root: &Path, secrets: &[&str]) -> Vec<serde_json::Value> {
    listing(&command(root, "effects", "inspect", &[], secrets, true).await)
}
#[tokio::test]
async fn actual_effect_cli_reconciles_explicitly_preserves_keys_and_redacts_payloads() {
    use std::os::unix::fs::PermissionsExt;
    let evidence = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-fixtures/effects-cli-fixtures");
    std::fs::create_dir_all(&evidence).unwrap();
    let root = tempfile::Builder::new()
        .prefix("operator-")
        .tempdir_in(evidence)
        .unwrap()
        .keep();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!("retained actual effects CLI fixture: {}", root.display());
    let db = Database::sqlite(root.join("runtime.db"));
    db.initialize().await.unwrap();
    db.create_account("alice", "private CLI effect password", "team")
        .await
        .unwrap();
    let manifest = declarations();
    let effects = EffectDeployment {
        grants: vec![EffectGrant {
            endpoint: "events".into(),
            tenant: "team".into(),
            host: "receiver.org".into(),
            port: 443,
            path: "/events".into(),
        }],
        secrets: vec![EffectSecret {
            slot: "delivery_token".into(),
            path: root.join("delivery-token"),
        }],
        tor_proxy: "127.0.0.1:9".parse().unwrap(),
        limits: EffectLimits {
            pending_per_app: 10,
            pending_per_tenant: 10,
            worker_concurrency: 1,
        },
        runtime_directory: Some(root.clone()),
    };
    let approved =
        noxide_host::deployment::approval_digest(&manifest, None, None, Some(&effects)).unwrap();
    let component = support::component(None);
    let declaration_bytes = serde_json::to_vec(&manifest).unwrap();
    let keys = serde_json::to_vec(&HostKeys::generate().unwrap()).unwrap();
    for (name, bytes) in [
        ("app.wasm", component.as_slice()),
        ("manifest.json", declaration_bytes.as_slice()),
        ("keys.json", keys.as_slice()),
        ("delivery-token", PRIVATE_SECRET.as_bytes()),
    ] {
        std::fs::write(root.join(name), bytes).unwrap();
    }
    for name in ["keys.json", "delivery-token"] {
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut serialized_effects = serde_json::to_value(&effects).unwrap();
    serialized_effects["secrets"][0]["path"] = serde_json::json!("delivery-token");
    let configuration = serde_json::json!({"database":{"sqlite":"runtime.db"},"keys":"keys.json","component":"app.wasm","manifest":"manifest.json","effects":serialized_effects,"approved_contract":URL_SAFE_NO_PAD.encode(approved),"origin":"http://localhost:8080","listen":{"tcp":"127.0.0.1:8080"}});
    std::fs::write(
        root.join("config.json"),
        serde_json::to_vec(&configuration).unwrap(),
    )
    .unwrap();
    let app = Application::new(
        &component,
        &declaration_bytes,
        approved,
        db.clone(),
        serde_json::from_slice(&keys).unwrap(),
        Limits::default(),
        DeploymentResources {
            assets: Default::default(),
            blobs: None,
            jobs: None,
            effects: Some(effects.clone()),
        },
    )
    .unwrap();
    app.activate().await.unwrap();
    let challenge = app.login_challenge().await.unwrap();
    let cookie = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "private CLI effect password",
        )
        .await
        .unwrap();
    let page = app.view(&cookie, 1, None).await.unwrap();
    let html = String::from_utf8(page.body).unwrap();
    let submission = support::hidden(&html, "_submission");
    let csrf = support::hidden(&html, "_csrf");
    app.submit(
        &cookie,
        1,
        &submission,
        &csrf,
        Fields::from([("body".into(), PRIVATE_BODY.into())]),
    )
    .await
    .unwrap();
    drop(app);
    let serialized_keys = String::from_utf8(keys.clone()).unwrap();
    let key_value: serde_json::Value = serde_json::from_slice(&keys).unwrap();
    let private_key = key_value["key"].to_string();
    let secret_path = root.join("delivery-token").to_string_lossy().into_owned();
    let secrets = [
        PRIVATE_BODY,
        PRIVATE_SECRET,
        serialized_keys.as_str(),
        private_key.as_str(),
        cookie.as_str(),
        submission.as_str(),
        csrf.as_str(),
        secret_path.as_str(),
    ];
    let initial = inspect(&root, &secrets).await;
    assert_eq!(initial.len(), 2);
    assert!(initial.iter().all(|row| row["state"] == "pending"));
    let first = initial[0]["id"].as_str().unwrap().to_owned();
    let second = initial[1]["id"].as_str().unwrap().to_owned();
    // Neither an idle nor a runtime-paused worker-once may touch the proxy.
    // At every worker invocation below all captures are Paused, never Pending.
    command(
        &root,
        "effects",
        "revoke",
        &["team", "events"],
        &secrets,
        true,
    )
    .await;
    assert!(
        inspect(&root, &secrets)
            .await
            .iter()
            .all(|row| row["state"] == "paused")
    );
    assert_eq!(
        command(&root, "effects", "worker-once", &[], &secrets, true).await,
        "null"
    );
    command(
        &root,
        "effects",
        "grant",
        &["team", "events"],
        &secrets,
        true,
    )
    .await;
    assert!(
        inspect(&root, &secrets)
            .await
            .iter()
            .all(|row| row["state"] == "paused")
    );
    command(&root, "effects", "resume", &[&first], &secrets, true).await;
    command(
        &root,
        "effects",
        "revoke-secret",
        &["delivery_token"],
        &secrets,
        true,
    )
    .await;
    assert!(
        inspect(&root, &secrets)
            .await
            .iter()
            .all(|row| row["state"] == "paused")
    );
    command(
        &root,
        "effects",
        "grant-secret",
        &["delivery_token"],
        &secrets,
        true,
    )
    .await;
    assert!(
        inspect(&root, &secrets)
            .await
            .iter()
            .all(|row| row["state"] == "paused")
    );
    command(&root, "effects", "resume", &[&first], &secrets, true).await;
    command(&root, "effects", "cancel", &[&first], &secrets, true).await;
    command(&root, "effects", "retry", &[&first], &secrets, false).await;
    command(
        &root,
        "effects",
        "grant",
        &["team", "undeclared"],
        &secrets,
        false,
    )
    .await;
    command(
        &root,
        "effects",
        "grant-secret",
        &["undeclared"],
        &secrets,
        false,
    )
    .await;
    // One shared fork control fences both capability families. Same-approval
    // inspect/startup preserves the pause until explicit current grants.
    command(&root, "jobs", "fork", &[], &secrets, true).await;
    let restarted = inspect(&root, &secrets).await;
    assert_eq!(restarted[0]["id"], first);
    assert_eq!(restarted[0]["state"], "cancelled");
    assert_eq!(restarted[1]["id"], second);
    assert_eq!(restarted[1]["state"], "paused");
    command(&root, "effects", "worker-once", &[], &secrets, false).await;
    command(
        &root,
        "effects",
        "grant",
        &["team", "events"],
        &secrets,
        true,
    )
    .await;
    command(
        &root,
        "effects",
        "grant-secret",
        &["delivery_token"],
        &secrets,
        true,
    )
    .await;
    let granted = inspect(&root, &secrets).await;
    assert_eq!(granted[1]["state"], "paused");
    command(&root, "effects", "retry", &[&second], &secrets, true).await;
    let retried = inspect(&root, &secrets).await;
    assert_eq!(retried[1]["id"], second);
    assert_eq!(retried[1]["round"], 1);
    assert_eq!(retried[1]["state"], "pending");
    command(&root, "effects", "cancel", &[&second], &secrets, true).await;
    let final_rows = inspect(&root, &secrets).await;
    assert_eq!(final_rows.len(), 2);
    assert!(final_rows.iter().all(|row| row["state"] == "cancelled"));
    assert_eq!(
        command(&root, "effects", "worker-once", &[], &secrets, true).await,
        "null"
    );
    // Review and read-only source rendering do not create replacement captures.
    let app = Application::new(
        &component,
        &declaration_bytes,
        approved,
        db,
        serde_json::from_slice(&keys).unwrap(),
        Limits::default(),
        DeploymentResources {
            assets: Default::default(),
            blobs: None,
            jobs: None,
            effects: Some(effects),
        },
    )
    .unwrap();
    app.activate().await.unwrap();
    let page = app.view(&cookie, 1, None).await.unwrap();
    // The static support guest renders no record data; rendering must still succeed.
    assert!(
        String::from_utf8(page.body)
            .unwrap()
            .contains("Private notes")
    );
    drop(app);
    assert_eq!(inspect(&root, &secrets).await.len(), 2);
    let mut unapproved = configuration;
    unapproved["effects"]["grants"][0]["path"] = serde_json::json!("/changed");
    std::fs::write(
        root.join("config.json"),
        serde_json::to_vec(&unapproved).unwrap(),
    )
    .unwrap();
    command(&root, "effects", "inspect", &[], &secrets, false).await;
}
