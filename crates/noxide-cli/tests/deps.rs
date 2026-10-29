use std::{fs, process::Command};

#[test]
fn dependency_options_are_strict_and_executor_is_explicit() {
    let root = tempfile::tempdir().unwrap();
    let app = root.path().join("app");
    fs::create_dir(&app).unwrap();
    fs::write(
        app.join("Cargo.toml"),
        "[package]\nname='app'\nversion='0.1.0'\n",
    )
    .unwrap();
    let framework = root.path().join("framework");
    fs::create_dir_all(framework.join("tools")).unwrap();
    fs::write(
        framework.join("tools/build_vm.py"),
        "import sys\nprint(repr(sys.argv))\nsys.exit(1)\n",
    )
    .unwrap();
    for isolated in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_noxide"));
        command
            .current_dir(&app)
            .env("XDG_STATE_HOME", root.path().join("state"))
            .args(["deps", "check", "--framework"])
            .arg(&framework);
        if isolated {
            command.arg("--isolated");
        }
        let result = command.output().unwrap();
        assert!(!result.status.success());
        let text = String::from_utf8_lossy(&result.stdout);
        assert!(text.contains("--deps-check"), "{text}");
        assert_eq!(text.contains("--local"), !isolated);
        assert!(!text.contains("--metadata"));
        assert!(!app.join("target/noxide/latest.json").exists());
    }
    for flags in [
        vec!["resolve"],
        vec!["check", "--output", "/unused"],
        vec!["check", "--kernel", "/unused"],
        vec!["check", "--name", "app"],
        vec!["check", "--app", ".", "--app", "."],
        vec!["check", "--toolchain"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_noxide"))
            .arg("deps")
            .args(flags)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!result.stderr.is_empty());
    }
}

#[test]
fn installed_kit_resolves_and_checks_without_framework_checkout() {
    let root = tempfile::tempdir().unwrap();
    let app = root.path().join("app 'quoted");
    fs::create_dir_all(app.join("src")).unwrap();
    fs::write(app.join("Cargo.toml"), "[package]\nname='app'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nserde='1'\n[workspace]\n").unwrap();
    fs::write(app.join("src/lib.rs"), "intentionally uncompilable").unwrap();
    fs::write(
        app.join("build.rs"),
        "fn main() { panic!(\"not executed\"); }",
    )
    .unwrap();
    let candidate = root.path().join("candidate");
    let output = Command::new(env!("CARGO_BIN_EXE_noxide"))
        .current_dir(&app)
        .env("XDG_STATE_HOME", root.path().join("state"))
        .args(["deps", "resolve", "--output"])
        .arg(&candidate)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!app.join("Cargo.lock").exists());
    assert!(candidate.join("Cargo.lock").is_file());
    assert!(!candidate.join("bundle.json").exists());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Comparison unavailable"));
    assert!(stdout.contains("cp --"));
    fs::copy(candidate.join("Cargo.lock"), app.join("Cargo.lock")).unwrap();
    let before = fs::read(app.join("Cargo.lock")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_noxide"))
        .current_dir(app.join("src"))
        .env("XDG_STATE_HOME", root.path().join("state"))
        .args(["deps", "check"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(before, fs::read(app.join("Cargo.lock")).unwrap());
    assert!(!app.join("target").exists());
}
