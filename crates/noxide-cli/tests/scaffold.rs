use std::{fs, path::Path, process::Command};

fn create(path: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_noxide"))
        .env("XDG_STATE_HOME", path.parent().unwrap().join("state"))
        .arg("new")
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn writes_a_standalone_owner_scoped_app_without_running_cargo() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("my-notes");
    let output = create(&project);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let source = fs::read_to_string(project.join("src/lib.rs")).unwrap();
    assert_eq!(source, include_str!("../templates/notes.rs"));
    assert_eq!(
        source,
        include_str!("../../../examples/private-notes/src/lib.rs")
    );
    let manifest = fs::read_to_string(project.join("Cargo.toml")).unwrap();
    assert!(manifest.contains("name = \"my-notes\""));
    assert!(manifest.contains("[workspace]"));
    let readme = fs::read_to_string(project.join("README.md")).unwrap();
    assert!(readme.contains("--name my_notes"));
    assert!(!readme.contains("__NAME__"));
    assert!(!project.join("Cargo.lock").exists());
    assert!(!project.join("target").exists());
}

#[test]
fn refuses_existing_paths_and_invalid_names_without_changing_them() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("notes");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("keep"), "user work").unwrap();
    assert!(!create(&project).status.success());
    assert_eq!(
        fs::read_to_string(project.join("keep")).unwrap(),
        "user work"
    );
    assert_eq!(fs::read_dir(&project).unwrap().count(), 1);
    for name in ["BadName", "bad name", "9notes", "crate", "gen"] {
        let project = root.path().join(name);
        assert!(!create(&project).status.success(), "{name}");
        assert!(!project.exists());
    }
}

#[cfg(unix)]
#[test]
fn never_follows_a_destination_symlink() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("notes");
    let target = root.path().join("target");
    std::os::unix::fs::symlink(&target, &project).unwrap();
    assert!(!create(&project).status.success());
    assert!(!target.exists());
    fs::create_dir(&target).unwrap();
    assert!(!create(&project).status.success());
    assert_eq!(fs::read_dir(target).unwrap().count(), 0);
}
