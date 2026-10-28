use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[tokio::test]
async fn operator_invite_prints_one_random_code_and_rejects_expiry_overflow() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let db = noxide_host::Database::sqlite(root.join("runtime.db"));
    db.initialize().await.unwrap();
    let config = root.join("config.json");
    std::fs::write(&config,serde_json::to_vec(&serde_json::json!({"database":{"sqlite":"runtime.db"},"keys":"unused.json","component":"unused.wasm","manifest":"unused.json","approved_contract":"unused","origin":"http://localhost:8080","listen":{"tcp":"127.0.0.1:8080"},"registration":"invite"})).unwrap()).unwrap();
    let mut codes = Vec::new();
    for days in [None, Some("1")] {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"));
        command.arg("invite").arg(&config);
        if let Some(days) = days {
            command.args(["--expires-days", days]);
        }
        let output = command.output().await.unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let output = String::from_utf8(output.stdout).unwrap();
        assert_eq!(output.lines().count(), 1);
        let code = output.trim_end();
        assert_eq!(code.len(), 43);
        assert_eq!(URL_SAFE_NO_PAD.decode(code).unwrap().len(), 32);
        codes.push(code.to_owned());
    }
    assert!(codes[0] != codes[1]);
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
        .arg("invite")
        .arg(&config)
        .args(["--expires-days", "18446744073709551615"])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
