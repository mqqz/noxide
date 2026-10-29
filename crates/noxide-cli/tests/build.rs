use std::{fs, process::Command};

#[test]
fn build_backend_selection_is_explicit_and_kernel_cannot_silently_run_locally() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tools")).unwrap();
    // Record routing without compiling application code or launching a VM.
    fs::write(
        root.path().join("tools/build_vm.py"),
        "import sys\nprint('BACKEND=vm' if '--local' not in sys.argv else 'BACKEND=local')\nsys.exit(1)\n",
    )
    .unwrap();
    for isolated in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_noxide"));
        command
            .env("XDG_STATE_HOME", root.path().join("state"))
            .args(["check", "--framework"])
            .arg(root.path())
            .arg("--output")
            .arg(root.path().join("output"));
        if isolated {
            command.arg("--isolated");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(if isolated {
                "BACKEND=vm"
            } else {
                "BACKEND=local"
            })
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_noxide"))
        .args(["build", "--kernel", "/unused"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--kernel requires --isolated"));
}

#[test]
fn discovers_current_project_and_allocates_managed_output() {
    let root = tempfile::tempdir().unwrap();
    let framework = root.path().join("framework");
    fs::create_dir_all(framework.join("tools")).unwrap();
    fs::write(
        framework.join("tools/build_vm.py"),
        "import sys\nprint('ARGS='+repr(sys.argv[1:]))\nsys.exit(1)\n",
    )
    .unwrap();
    let app = root.path().join("my-forum");
    fs::create_dir(&app).unwrap();
    fs::write(
        app.join("Cargo.toml"),
        "[package]\nname='my-forum'\nversion='0.1.0'\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_noxide"))
        .env("XDG_STATE_HOME", root.path().join("state"))
        .current_dir(&app)
        .args(["test", "--framework"])
        .arg(&framework)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("my_forum"), "{stdout}");
    assert!(stdout.contains(app.to_str().unwrap()), "{stdout}");
    assert!(stdout.contains("target/noxide/build-"), "{stdout}");
    assert!(stdout.contains("--test"), "{stdout}");
    assert!(stdout.contains("--local"), "{stdout}");
}

#[cfg(unix)]
#[test]
fn interrupting_a_build_terminates_its_executor() {
    use std::{
        io::{BufRead, BufReader},
        process::Stdio,
        time::{Duration, Instant},
    };
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("tools")).unwrap();
    fs::write(root.path().join("tools/build_vm.py"),
        "import signal,sys,time\nsignal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\nprint('EXECUTOR_READY', flush=True)\ntime.sleep(60)\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_noxide"))
        .env("XDG_STATE_HOME", root.path().join("state"))
        .args(["build", "--name", "app", "--framework"])
        .arg(root.path())
        .arg("--output")
        .arg(root.path().join("output"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.contains("EXECUTOR_READY"));
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("build did not stop its executor");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn refuses_to_snapshot_operator_state_inside_the_application() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname='app'\nversion='0.1.0'\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_noxide"))
        .current_dir(root.path())
        .env("XDG_STATE_HOME", root.path().join("state"))
        .args(["build", "--name", "app"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("state must be outside"));
    assert!(!root.path().join("target").exists());
}

#[test]
fn python_startup_hooks_cannot_execute_application_code_on_the_host() {
    let root = tempfile::tempdir().unwrap();
    let app = root.path().join("app");
    fs::create_dir(&app).unwrap();
    fs::write(
        app.join("Cargo.toml"),
        "[package]\nname='app'\nversion='0.1.0'\n",
    )
    .unwrap();
    // This is an inert host-startup canary; never compile application code here.
    let canary = root.path().join("startup-executed");
    fs::write(
        app.join("sitecustomize.py"),
        format!(
            "from pathlib import Path\nPath({:?}).write_text('unexpected startup')\n",
            canary
        ),
    )
    .unwrap();
    fs::create_dir(root.path().join("tools")).unwrap();
    fs::write(
        root.path().join("tools/build_vm.py"),
        "import sys\nprint('TRUSTED_BUILDER')\nsys.exit(1)\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_noxide"))
        .current_dir(&app)
        .env("XDG_STATE_HOME", root.path().join("state"))
        .env("PYTHONPATH", &app)
        .args(["build", "--isolated", "--framework"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("TRUSTED_BUILDER"));
    assert!(
        !canary.exists(),
        "application startup hook escaped isolation"
    );
}
