//! Explicit build registration is required before the tokenizer can compile.
//! The future host build script must call this guard; the independent harness
//! does so without registering any runtime module or capability.
use std::{env, process::Command};

pub const RUST_RELEASE: &str = "1.98.0";

pub fn supported_release(release: &str) -> bool {
    release == RUST_RELEASE
}

pub fn verify() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    let compiler = env::var_os("RUSTC").expect("Cargo must identify its compiler");
    let output = Command::new(compiler)
        .args(["--version", "--verbose"])
        .output()
        .expect("inspect tokenizer compiler");
    assert!(output.status.success(), "inspect tokenizer compiler");
    let version = std::str::from_utf8(&output.stdout).expect("compiler identity is UTF-8");
    let release = version
        .lines()
        .find_map(|line| line.strip_prefix("release: "))
        .expect("compiler release missing");
    assert!(
        supported_release(release),
        "search tokenizer compiler changed; review semantics, bump tokenizer identity and rebuild indexes explicitly"
    );
    println!("cargo:rustc-env=NOXIDE_SEARCH_RUST_RELEASE={RUST_RELEASE}");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiler_upgrade_needs_an_explicit_tokenizer_decision() {
        assert!(supported_release("1.98.0"));
        for release in ["1.98.1", "1.99.0", "1.98.0-nightly", ""] {
            assert!(!supported_release(release));
        }
    }
}
