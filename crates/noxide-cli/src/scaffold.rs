//! Writes trusted starter files without executing application code.
use anyhow::{Context, Result, bail, ensure};
use std::{fs, io::Write, path::Path};

const SOURCE: &str = include_str!("../templates/notes.rs");
const README: &str = include_str!("../templates/README.md");

pub fn create(destination: &Path) -> Result<()> {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("destination must end in a UTF-8 package name")?;
    validate_name(name)?;
    // Refuse files, directories, and dangling symlinks alike. Never merge or
    // remove an existing project, including after a partially completed write.
    fs::create_dir(destination).context("destination must be new and its parent must exist")?;
    let write = |path: &str, bytes: &[u8]| -> Result<()> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(path))?
            .write_all(bytes)?;
        Ok(())
    };
    let result = (|| -> Result<()> {
        fs::create_dir(destination.join("src"))?;
        let manifest = format!(
            "[package]\nname = {name:?}\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
             [lib]\ncrate-type = [\"cdylib\", \"rlib\"]\n\n\
             [dependencies]\nnoxide = {{ path = \"../../crates/noxide\", version = \"={}\" }}\n\n\
             [workspace]\n\n[profile.release]\nopt-level = \"s\"\npanic = \"abort\"\nstrip = true\n",
            env!("CARGO_PKG_VERSION"),
        );
        write("Cargo.toml", manifest.as_bytes())?;
        write("src/lib.rs", SOURCE.as_bytes())?;
        write(
            "README.md",
            README
                .replace("__NAME__", name)
                .replace("__CRATE__", &name.replace('-', "_"))
                .as_bytes(),
        )?;
        write(".gitignore", b"/target\n")?;
        Ok(())
    })();
    result.with_context(|| {
        format!(
            "starter incomplete at {}; existing files were retained",
            destination.display()
        )
    })?;
    println!(
        "Created {}. Start with src/lib.rs; README.md has the check/build commands.",
        destination.display()
    );
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_'),
        "package name must start with a lowercase ASCII letter and contain only lowercase letters, digits, '-' or '_' (at most 64 bytes)"
    );
    let crate_name = name.replace('-', "_");
    if [
        "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
        "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move",
        "mut", "pub", "ref", "return", "self", "static", "struct", "super", "trait", "true",
        "type", "unsafe", "use", "where", "while", "abstract", "become", "box", "do", "final",
        "gen", "macro", "override", "priv", "try", "typeof", "unsized", "virtual", "yield", "std",
        "core", "alloc", "test",
    ]
    .contains(&crate_name.as_str())
    {
        bail!("package name is reserved by Rust");
    }
    Ok(())
}
