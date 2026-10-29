use std::{env, fs, path::PathBuf, process::Command};
fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("build-kit.bin");
    let packaged = root.join("build-kit.bin");
    if packaged.is_file() && !root.join("../../tools/package_build_kit.py").is_file() {
        println!("cargo:rerun-if-changed={}", packaged.display());
        fs::copy(packaged, output).unwrap();
        return;
    }
    let source = root.join("../..");
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "README.md",
        "tools/package_build_kit.py",
        "tools/build_vm.py",
        "tools/build_local.py",
        "tools/build_recipe.py",
        "crates/noxide",
        "crates/noxide-macros",
        "crates/noxide-protocol",
    ] {
        println!("cargo:rerun-if-changed={}", source.join(name).display());
    }
    assert!(
        Command::new("python3")
            .arg(source.join("tools/package_build_kit.py"))
            .arg("--output")
            .arg(output)
            .status()
            .expect("Python 3.11+ is required to package the CLI")
            .success(),
        "source distributions require tools/package_build_kit.py before cargo package"
    );
}
