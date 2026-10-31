use noxide_protocol::*;
use std::{path::Path, process::Output};

fn manifest() -> Manifest {
    Manifest {
        version: VERSION,
        assets: Vec::new(),
        blobs: None,
        resources: vec![Resource {
            id: 1,
            name: "notes".into(),
            fields: vec![TextField {
                name: "body".into(),
                label: "Body".into(),
                kind: FieldKind::Text,
                max_bytes: 20,
                optional: false,
                initial: None,
            }],
            gate: None,
            expiry: None,
            unique: Vec::new(),
        }],
        operations: vec![Operation {
            id: 1,
            resource: 1,
            kind: OperationKind::Read,
            policy: Policy {
                any: vec![vec![Predicate::Owner]],
            },
            bind: Default::default(),
            scope: None,
            via: None,
            filter: Vec::new(),
            disclose: Vec::new(),
            fields: None,
            visibility: None,
            list: None,
        }],
        routes: vec![
            Route {
                id: 2,
                path: "/".into(),
                resource: None,
                operations: Vec::new(),
                forms: Vec::new(),
                access: Access::Public,
                params: Vec::new(),
            },
            Route {
                id: 1,
                path: "/note/{id}".into(),
                resource: Some(1),
                operations: vec![1],
                forms: Vec::new(),
                access: Access::Authenticated,
                params: Vec::new(),
            },
        ],
        actions: Vec::new(),
        web_bindings: Vec::new(),
    }
}

fn run(root: &Path, command: &str, input: &str) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
        .current_dir(root)
        .args([command, input])
        .output()
        .unwrap()
}

#[test]
fn deployment_review_does_not_open_database_keys_component_or_store() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_vec(&manifest()).unwrap(),
    )
    .unwrap();
    let mut config = serde_json::json!({
        "database": {"postgres": "postgresql://unused@127.0.0.1:1/no_database"},
        "manifest": "manifest.json", "component": "missing/component.wasm",
        "keys": "missing/keys.json", "assets": "missing/assets.pack",
        "approved_contract": "", "origin": "http://localhost:8080",
        "listen": {"tcp": "127.0.0.1:8080"},
    });
    let write_config = |config: &serde_json::Value| {
        std::fs::write(
            root.join("runtime.json"),
            serde_json::to_vec(config).unwrap(),
        )
        .unwrap()
    };
    write_config(&config);
    let contract = run(root, "contract-hash", "manifest.json");
    assert!(contract.status.success(), "{:?}", contract);
    let review = run(root, "deployment-hash", "runtime.json");
    assert!(review.status.success(), "{:?}", review);
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    let contract = String::from_utf8(contract.stdout).unwrap();
    assert_eq!(review["manifest_digest"], contract.trim());
    assert_eq!(review["deployment_digest"], contract.trim());
    assert!(review["requested_blobs"].is_null());
    assert!(review["effective_blobs"].is_null());
    assert!(!root.join("missing").exists());

    config["blobs"] = serde_json::json!({
        "directory": "missing/store", "ceilings": blobs::BlobCeilings::default(),
    });
    write_config(&config);
    let denied = run(root, "deployment-hash", "runtime.json");
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr)
            .contains("blob configuration has no requested blob policy")
    );
    assert!(!root.join("missing").exists());
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 2);
}
