//! The serving process. Startup runs on one thread: it starts the key service,
//! binds its socket and activates the deployment, then confines itself before
//! any thread exists to serve a request. Links no asset parsers and no outbound
//! transport.
#![cfg_attr(test, allow(clippy::too_many_lines))]
#![forbid(unsafe_code)]
#[path = "../config.rs"]
mod config;
use anyhow::{Context, Result, ensure};
use config::*;
use noxide_guest::pool::GuestPool;
use noxide_host::{Application, HostKeys, assets::AssetBundle, runtime::Limits};
use noxide_http::{BoundListener, Origin};
use std::{path::PathBuf, sync::Arc};

struct Arguments {
    config: PathBuf,
    assets_digest: Option<String>,
    validate: bool,
}
fn arguments() -> Result<Arguments> {
    const USAGE: &str =
        "usage: noxide-server CONFIG.json [--assets-digest DIGEST] [--validate] [--supervised]";
    let mut args = std::env::args_os().skip(1);
    let mut parsed = Arguments {
        config: args.next().context(USAGE)?.into(),
        assets_digest: None,
        validate: false,
    };
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--validate") => parsed.validate = true,
            Some("--supervised") => stop_with_parent()?,
            Some("--assets-digest") => {
                parsed.assets_digest = Some(
                    args.next()
                        .and_then(|d| d.into_string().ok())
                        .context(USAGE)?,
                );
            }
            _ => anyhow::bail!(USAGE),
        }
    }
    Ok(parsed)
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let arguments = arguments()?;
    let (config, base) = config(&arguments.config)?;
    let approved = decode_digest(&config.approved_contract)?;
    let declarations = read(&base.join(&config.manifest), 32_768)?;
    let manifest = noxide_host::manifest::parse(&declarations)?;
    ensure!(
        config.approval(&manifest)?.digest == approved,
        "deployment did not approve this contract and effective policy"
    );
    let assets = match &config.assets {
        Some(pack) => {
            let digest = arguments
                .assets_digest
                .as_ref()
                .or(config.approved_assets.as_ref())
                .context("assets require approved_assets; run noxide assets-compile")?;
            let mut compiled = base.join(pack).into_os_string();
            compiled.push(".compiled");
            AssetBundle::from_compiled(
                &manifest.assets,
                &read(
                    compiled.as_ref(),
                    2 * noxide_host::assets::MAX_ASSET_PACK_BYTES as u64,
                )?,
                digest,
            )?
        }
        None => AssetBundle::default(),
    };
    // Reads the key file in its own process. This process never holds it.
    let keys = HostKeys::remote(noxide_keys::KeyClient::spawn(
        &sibling("noxide-keyd")?,
        &base.join(&config.keys),
        &[config.confinement.argument()],
    )?);
    let store = database(&config.database, &base)?;
    let component = read(&base.join(&config.component), 2 * 1024 * 1024)?;
    // The first worker's compile is the component's admission check.
    let pool = Arc::new(GuestPool::start(
        &sibling("noxide-guest")?,
        config.confinement.argument(),
        &component,
        Limits::default(),
        config.guest_worker_requests,
    )?);
    let workers = pool.clone();
    let app = Application::with_workers(
        pool,
        &component,
        &declarations,
        approved,
        store.clone(),
        keys,
        noxide_host::DeploymentResources {
            effects: config.effect_deployment(&base),
            jobs: config.jobs.clone(),
            assets,
            blobs: config
                .blobs
                .as_ref()
                .map(|deployment| noxide_host::BlobDeployment {
                    directory: base.join(&deployment.directory),
                    ceilings: deployment.ceilings.clone(),
                }),
        },
    )?
    .with_presentation(config.presentation)?
    .with_signed_in_reserve(config.signed_in_reserve)?
    .with_database_statement_limit(config.database_statement_limit)?
    .with_registration(config.registration);
    let app = Arc::new(app);
    let startup = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if arguments.validate {
        return startup.block_on(async {
            app.activate().await?;
            app.settled().await
        });
    }
    let listener = match &config.listen {
        ListenConfig::Tcp(address) => BoundListener::loopback(*address)?,
        ListenConfig::Unix(path) => {
            let path = base.join(path);
            noxide_http::reclaim_stale_socket(&path)?;
            BoundListener::unix(&path)?
        }
        ListenConfig::TorUnix { path, tor_gid } => {
            let path = base.join(path);
            noxide_http::reclaim_stale_socket(&path)?;
            BoundListener::tor_unix(&path, *tor_gid)?
        }
    };
    startup.block_on(async {
        app.activate().await?;
        app.settled().await
    })?;
    drop(startup);
    let mut policy = store_policy(config.confinement, &store.confinement()?);
    policy.writable.extend(
        config
            .blobs
            .as_ref()
            .map(|deployment| base.join(&deployment.directory)),
    );
    confine(&policy, "server")?;
    let origin = Origin::parse(&config.origin)?;
    tokio::runtime::Runtime::new()?.block_on(async move {
        let _sidecars = store.hold_sidecars().await?;
        let shutdown = shutdown_signal()?;
        let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let noticed = lost.clone();
        // Without its broker this server cannot replace a worker, so stop and let the
        // supervisor restart everything.
        let shutdown = async move {
            tokio::select! {
                () = shutdown => {}
                () = workers.broker_lost() => {
                    noticed.store(true, std::sync::atomic::Ordering::Release);
                }
            }
        };
        println!("Runtime listening with the approved application contract.");
        noxide_http::serve(listener.start()?, app, origin, shutdown).await?;
        ensure!(
            !lost.load(std::sync::atomic::Ordering::Acquire),
            "the guest broker stopped"
        );
        Ok(())
    })
}
