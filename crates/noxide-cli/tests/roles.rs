use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_protocol::*;
use std::path::Path;

fn manifest() -> Manifest {
    Manifest {
        version: VERSION,
        resources: vec![Resource {
            id: 1,
            name: "notes".into(),
            fields: vec![TextField {
                name: "body".into(),
                label: "Body".into(),
                kind: FieldKind::Text,
                optional: false,
                initial: None,
                max_bytes: 20,
            }],
        }],
        operations: vec![Operation {
            id: 1,
            resource: 1,
            kind: OperationKind::List,
            policy: Policy {
                any: vec![
                    vec![
                        Predicate::Owner,
                        Predicate::Role {
                            name: "moderator".into(),
                            tenant_scoped: false,
                        },
                    ],
                    vec![Predicate::Role {
                        name: "editor".into(),
                        tenant_scoped: true,
                    }],
                ],
            },
            fields: None,
            visibility: None,
            list: None,
        }],
        routes: vec![Route {
            id: 1,
            path: "/".into(),
            resource: None,
            operations: vec![1],
            forms: vec![],
            access: Access::Authenticated,
        }],
        actions: vec![],
    }
}
async fn run(cwd: &Path, config: &Path, command: &str, args: &[&str]) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
        .current_dir(cwd)
        .arg("role")
        .arg(command)
        .arg(config)
        .args(args)
        .output()
        .await
        .unwrap()
}
#[tokio::test]
async fn roles_cli_approved_scope_relative_paths_and_usage() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let db = noxide_host::Database::sqlite(root.path().join("runtime.db"));
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "one")
        .await
        .unwrap();
    let m = manifest();
    let digest = URL_SAFE_NO_PAD.encode(noxide_host::manifest::digest(&m).unwrap());
    std::fs::write(
        root.path().join("manifest.json"),
        serde_json::to_vec(&m).unwrap(),
    )
    .unwrap();
    let config = root.path().join("config.json");
    let mut cfg = serde_json::json!({"database":{"sqlite":"runtime.db"},"keys":"missing.json","component":"missing.wasm","manifest":"manifest.json","approved_contract":digest,"origin":"http://localhost:8080","listen":{"tcp":"127.0.0.1:8080"}});
    std::fs::write(&config, serde_json::to_vec(&cfg).unwrap()).unwrap();
    for (role, flags) in [
        ("moderator", vec!["--global"]),
        ("editor", vec!["--tenant", "one"]),
    ] {
        let mut args = vec!["alice", role];
        args.extend(flags);
        for expected in [": changed", ": unchanged"] {
            let o = run(elsewhere.path(), &config, "grant", &args).await;
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
            assert!(String::from_utf8_lossy(&o.stdout).contains(expected));
            assert!(o.stderr.is_empty());
        }
    }
    let o = run(elsewhere.path(), &config, "list", &["alice"]).await;
    assert!(o.status.success());
    assert_eq!(
        String::from_utf8(o.stdout).unwrap(),
        "ROLE\tSCOPE\tTENANT\neditor\ttenant\tone\nmoderator\tglobal\t-\n"
    );
    for args in [
        vec!["alice", "moderator"],
        vec!["alice", "moderator", "--global", "--global"],
        vec!["alice", "moderator", "--global", "--tenant", "one"],
        vec!["alice", "moderator", "--tenant", ""],
        vec!["alice", "moderator", "--tenant"],
        vec!["alice", "moderator", "--unknown"],
        vec!["alice", "moderator", "--global", "extra"],
        vec!["missing", "moderator", "--global"],
        vec!["alice", "editor", "--global"],
        vec!["alice", "moderator", "--tenant", "one"],
        vec!["alice", "editor", "--tenant", "two"],
        vec!["alice", "absent", "--global"],
        vec!["bad-user", "moderator", "--global"],
    ] {
        let o = run(elsewhere.path(), &config, "grant", &args).await;
        assert!(!o.status.success(), "{args:?}");
        assert!(o.stdout.is_empty());
        assert!(!o.stderr.is_empty());
    }
    cfg["approved_contract"] = "wrong".into();
    std::fs::write(&config, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let o = run(
        elsewhere.path(),
        &config,
        "grant",
        &["alice", "moderator", "--global"],
    )
    .await;
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not approved"));
    // Neither listing nor revocation requires the old manifest or application.
    std::fs::remove_file(root.path().join("manifest.json")).unwrap();
    assert!(
        run(elsewhere.path(), &config, "list", &["alice"])
            .await
            .status
            .success()
    );
    for expected in [": changed", ": unchanged"] {
        let o = run(
            elsewhere.path(),
            &config,
            "revoke",
            &["alice", "moderator", "--global"],
        )
        .await;
        assert!(o.status.success());
        assert!(String::from_utf8_lossy(&o.stdout).contains(expected));
    }
    assert_eq!(db.list_roles("alice").await.unwrap().len(), 1);
    assert!(
        run(
            elsewhere.path(),
            &config,
            "revoke",
            &["alice", "editor", "--tenant", "one"]
        )
        .await
        .status
        .success()
    );
    let o = run(elsewhere.path(), &config, "list", &["alice"]).await;
    assert!(o.status.success());
    assert_eq!(o.stdout, b"ROLE\tSCOPE\tTENANT\n");
    cfg["database"] = serde_json::json!({"postgres":"postgresql://secret_user:private_password@remote.invalid/database"});
    std::fs::write(&config, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let o = run(elsewhere.path(), &config, "list", &["alice"]).await;
    assert!(!o.status.success());
    let e = String::from_utf8_lossy(&o.stderr);
    assert!(!e.contains("private_password"));
    assert!(!e.contains("secret_user"));
}
