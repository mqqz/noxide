#[tokio::test]
async fn edit_key_rotation_keeps_token_authority_and_old_edit_keys_private() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("keys.json");
    let generated = tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
        .arg("keygen")
        .arg(&path)
        .output()
        .await
        .unwrap();
    assert!(generated.status.success());
    let before: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(before["edit_keys"].as_array().unwrap().len(), 1);
    assert_eq!(before["edit_keys"][0]["signing"], true);
    let rotated = tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
        .arg("edit-key-rotate")
        .arg(&path)
        .output()
        .await
        .unwrap();
    assert!(rotated.status.success());
    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(before["key"] == after["key"]);
    assert!(before["incarnation"] == after["incarnation"]);
    assert_eq!(after["edit_keys"].as_array().unwrap().len(), 2);
    assert_eq!(after["edit_keys"][0]["signing"], false);
    assert_eq!(after["edit_keys"][1]["signing"], true);
    assert!(before["edit_keys"][0]["key"] == after["edit_keys"][0]["key"]);
    assert!(after["edit_keys"][0]["id"] != after["edit_keys"][1]["id"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let denied = tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
            .arg("edit-key-rotate")
            .arg(&path)
            .output()
            .await
            .unwrap();
        assert!(!denied.status.success());
        assert!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap()
                == after
        );
    }
}
