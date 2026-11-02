//! `noxide serve`: validates assets, then runs the deployed processes as children.
//! This process holds no keys and handles no requests. Direct deployments run
//! `noxide-server` and `noxide-effects-worker` themselves, under separate users.
use super::{config, read, shutdown_signal, sibling};
use anyhow::{Context, Result, ensure};
use noxide_assets::AssetBundle;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};
use tokio::process::{Child, Command};

/// Validate and compile the configured asset pack. Hostile-adjacent CSS and image
/// parsing stays in this process, which never holds keys.
pub fn compile_assets(path: &Path) -> Result<Option<String>> {
    let (config, base) = config(path)?;
    let Some(assets) = &config.assets else {
        return Ok(None);
    };
    let manifest = noxide_host::manifest::parse(&read(&base.join(&config.manifest), 32_768)?)?;
    let bundle = noxide_asset_admission::from_pack(
        &manifest.assets,
        &read(
            &base.join(assets),
            noxide_assets::MAX_ASSET_PACK_BYTES as u64,
        )?,
    )?;
    let compiled = bundle.to_compiled()?;
    let target = compiled_path(&base.join(assets));
    let temporary = target.with_extension("compiled.tmp");
    std::fs::write(&temporary, &compiled)?;
    std::fs::rename(&temporary, &target)?;
    Ok(Some(AssetBundle::compiled_digest(&compiled)))
}

pub fn compiled_path(pack: &Path) -> PathBuf {
    let mut name = pack.as_os_str().to_owned();
    name.push(".compiled");
    PathBuf::from(name)
}

pub async fn run(command: &str, args: &[OsString]) -> Result<()> {
    ensure!(args.len() <= 2, "usage: noxide serve [CONFIG.json]");
    let _lock = if args.len() == 1 {
        Some(super::project::lock(&super::project::state(
            &super::project::discover(&std::env::current_dir()?)?,
            false,
        )?)?)
    } else {
        None
    };
    let path = if args.len() == 2 {
        PathBuf::from(&args[1])
    } else {
        super::lifecycle::prepare(
            &super::project::discover(&std::env::current_dir()?)?,
            false,
            None,
        )
        .await?
    };
    let digest = compile_assets(&path)?;
    let mut server = Command::new(sibling("noxide-server")?);
    server.arg(&path).arg("--supervised").kill_on_drop(true);
    if let Some(digest) = &digest {
        server.args(["--assets-digest", digest]);
    }
    if command == "validate" {
        let status = server.arg("--validate").status().await?;
        ensure!(status.success(), "deployment validation failed");
        return Ok(());
    }
    let (config, base) = config(&path)?;
    let socket = match &config.listen {
        super::ListenConfig::Unix(socket) | super::ListenConfig::TorUnix { path: socket, .. } => {
            Some(base.join(socket))
        }
        super::ListenConfig::Tcp(_) => None,
    };
    let shutdown = shutdown_signal()?;
    let mut server = server.spawn().context("cannot start noxide-server")?;
    let mut worker = None;
    if config.effects.is_some() {
        worker = Some(
            Command::new(sibling("noxide-effects-worker")?)
                .arg(&path)
                .arg("--supervised")
                .kill_on_drop(true)
                .spawn()
                .context("cannot start noxide-effects-worker")?,
        );
    }
    let status = tokio::select! {
        status = server.wait() => Some(status?),
        _ = shutdown => None,
    };
    if let Some(worker) = &mut worker {
        stop(worker).await?;
    }
    let status = match status {
        Some(status) => status,
        None => {
            stop(&mut server).await?;
            server.wait().await?
        }
    };
    if let Some(socket) = socket {
        noxide_http::reclaim_stale_socket(&socket)?;
    }
    ensure!(status.success(), "noxide-server stopped: {status}");
    Ok(())
}

async fn stop(child: &mut Child) -> Result<()> {
    super::lifecycle::stop(child).await
}
