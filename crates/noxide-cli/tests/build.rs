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
