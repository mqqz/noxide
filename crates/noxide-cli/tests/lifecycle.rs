#![cfg(unix)]
#[allow(dead_code)]
#[path = "../../noxide-host/tests/support/mod.rs"]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_noxide"))
        .current_dir(root)
        .env("XDG_STATE_HOME", root.parent().unwrap().join("state"))
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}
fn bundle(root: &Path) -> String {
    fs::create_dir_all(root.join("target/noxide/bundle")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='app'\nversion='0.1.0'\n",
    )
    .unwrap();
    let bundle = root.join("target/noxide/bundle");
    fs::write(
        root.join("target/noxide/latest.json"),
        serde_json::to_vec(&bundle).unwrap(),
    )
    .unwrap();
    fs::write(
        bundle.join("bundle.json"),
        br#"{"name":"app","backend":"local"}"#,
    )
    .unwrap();
    let manifest = support::manifest();
    fs::write(
        bundle.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(bundle.join("app.component.wasm"), support::component(None)).unwrap();
    URL_SAFE_NO_PAD.encode(noxide_host::manifest::digest(&manifest).unwrap())
}
#[test]
fn approvals_are_explicit_separate_and_bound_to_the_selected_contract() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    let digest = bundle(&root);
    let rejected = run(&root, &["serve"]);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("contract approval requires a terminal")
    );
    assert!(!run(&root, &["approve", "wrong"]).status.success());
    let accepted = run(&root, &["approve", "--dev", &digest]);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    // Development approval cannot authorize serving.
    assert!(!run(&root, &["serve"]).status.success());
    let accepted = run(&root, &["approve", &digest]);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let state = temp.path().join("state/noxide");
    let deployment = fs::read_dir(state)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.join("serve/runtime.json").exists())
        .unwrap();
    let config = deployment.join("serve/runtime.json");
    assert!(
        run(&root, &["validate", config.to_str().unwrap()])
            .status
            .success()
    );
    let keys = deployment.join("serve/host-keys.json");
    let saved_keys = fs::read(&keys).unwrap();
    fs::remove_file(&keys).unwrap();
    let missing_keys = run(&root, &["approve", &digest]);
    assert!(!missing_keys.status.success());
    assert!(
        String::from_utf8_lossy(&missing_keys.stderr)
            .contains("refusing to generate a replacement")
    );
    assert!(!keys.exists());
    fs::write(&keys, saved_keys).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o600)).unwrap();
    let original = fs::read(&config).unwrap();
    let mut manifest = support::manifest();
    manifest.resources[0].fields[0].max_bytes += 1;
    fs::write(
        root.join("target/noxide/bundle/manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    assert!(!run(&root, &["serve"]).status.success());
    assert_eq!(fs::read(config).unwrap(), original);
}
#[test]
fn build_provenance_does_not_bypass_component_admission() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    let digest = bundle(&root);
    for backend in ["local", "isolated"] {
        fs::write(
            root.join("target/noxide/bundle/bundle.json"),
            serde_json::to_vec(&serde_json::json!({"name":"app","backend":backend})).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("target/noxide/bundle/app.component.wasm"),
            b"invalid component",
        )
        .unwrap();
        assert!(!run(&root, &["approve", &digest]).status.success());
    }
}
