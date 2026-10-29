//! Operator-owned state and the build kit embedded in the trusted CLI.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn private_directory(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "state directory must be a real directory: {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.mode() & 0o077 == 0 && metadata.uid() == fs::metadata("/proc/self")?.uid(),
            "state directory must be private and owned by this user: {}",
            path.display()
        );
    }
    Ok(())
}

pub fn state_root() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME or XDG_STATE_HOME required")?)
            .join(".local/state"),
    };
    ensure!(base.is_absolute(), "state home must be absolute");
    fs::create_dir_all(&base)?;
    let root = base.join("noxide");
    private_directory(&root)?;
    Ok(root.canonicalize()?)
}

pub fn state(project: &Path, development: bool) -> Result<PathBuf> {
    let root = external_state(project)?;
    let key = format!(
        "{:x}",
        Sha256::digest(project.canonicalize()?.as_os_str().as_encoded_bytes())
    );
    let path = root.join(key);
    private_directory(&path)?;
    let path = path.join(if development { "dev" } else { "serve" });
    private_directory(&path)?;
    Ok(path)
}

pub fn kit() -> Result<PathBuf> {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/build-kit.bin"));
    let root = state_root()?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let cache_lock = options.open(root.join("sdk.lock"))?;
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match cache_lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < until => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Err(error) => return Err(anyhow::anyhow!("SDK cache busy or unavailable: {error}")),
        }
    }
    let path = root.join(format!("sdk-{:x}", Sha256::digest(bytes)));
    private_directory(&path)?;
    let mut remaining = bytes.as_slice();
    while !remaining.is_empty() {
        let name_len = u32::from_le_bytes(remaining[..4].try_into()?) as usize;
        let data_len = u32::from_le_bytes(remaining[4..8].try_into()?) as usize;
        let name = std::str::from_utf8(&remaining[8..8 + name_len])?;
        let data = &remaining[8 + name_len..8 + name_len + data_len];
        let file = path.join(name);
        fs::create_dir_all(file.parent().unwrap())?;
        if file.try_exists()? {
            ensure!(
                fs::symlink_metadata(&file)?.is_file()
                    && super::read(&file, data.len() as u64)? == data,
                "embedded SDK cache modified: {}",
                file.display()
            );
        } else {
            super::create(&file, data, false)?;
        }
        remaining = &remaining[8 + name_len + data_len..];
    }
    Ok(path)
}

pub fn lock(state: &Path) -> Result<fs::File> {
    let path = state.join("deployment.lock");
    if !path.try_exists()? {
        super::create(&path, b"", true)?;
    }
    ensure!(
        fs::symlink_metadata(&path)?.is_file(),
        "invalid deployment lock"
    );
    let file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    file.try_lock()
        .context("another lifecycle command owns this deployment")?;
    Ok(file)
}

pub fn discover(start: &Path) -> Result<PathBuf> {
    let mut path = start.canonicalize()?;
    loop {
        if path.join("Cargo.toml").is_file() {
            return Ok(path);
        }
        ensure!(
            path.pop(),
            "no Cargo.toml found; run this command inside an application project"
        );
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSettings {
    pub kernel: Option<PathBuf>,
    pub toolchain: Option<PathBuf>,
}

pub fn settings() -> Result<BuildSettings> {
    let path = state_root()?.join("build.json");
    if !path.try_exists()? {
        return Ok(BuildSettings::default());
    }
    Ok(serde_json::from_slice(&super::read(&path, 16384)?)?)
}

pub fn setup(args: &[std::ffi::OsString]) -> Result<()> {
    let mut settings = settings()?;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .context("usage: noxide setup [--kernel FILE] [--toolchain DIRECTORY]")?;
        let path = PathBuf::from(value).canonicalize()?;
        if flag == "--kernel" {
            ensure!(path.is_file(), "kernel must be a readable file");
            fs::File::open(&path)?;
            ensure!(
                std::process::Command::new("qemu-system-x86_64")
                    .arg("--version")
                    .status()?
                    .success(),
                "QEMU is required for isolated builds"
            );
            settings.kernel = Some(path);
        } else if flag == "--toolchain" {
            ensure!(
                path.join("bin/rustc").is_file()
                    && path.join("lib/rustlib/wasm32-unknown-unknown/lib").is_dir(),
                "toolchain requires rustc and wasm32-unknown-unknown libraries"
            );
            settings.toolchain = Some(path);
        } else {
            anyhow::bail!("unknown setup option");
        }
    }
    let root = state_root()?;
    let _lock = lock(&root)?;
    let temporary = root.join("build-settings.tmp");
    super::create(&temporary, &serde_json::to_vec_pretty(&settings)?, true)?;
    fs::rename(temporary, root.join("build.json"))?;
    println!(
        "Saved operator build settings. Local builds remain the default; select --isolated explicitly."
    );
    Ok(())
}

pub fn external_state(project: &Path) -> Result<PathBuf> {
    let root = state_root()?;
    ensure!(
        !root.starts_with(project.canonicalize()?),
        "Noxide state must be outside the application source directory; set XDG_STATE_HOME to an external directory"
    );
    Ok(root)
}
