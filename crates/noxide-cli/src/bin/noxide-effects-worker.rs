//! Delivers captured effects, outside the serving process. Holds no host keys,
//! runs no guest code, and can reach only the store, its secret files and the
//! local Tor proxy.
#![forbid(unsafe_code)]
#[path = "../config.rs"]
mod config;
#[path = "../delivery.rs"]
mod delivery;
use anyhow::{Context, Result};
use config::*;
use delivery::effect_delivery;
use std::{sync::Arc, time::Duration};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let path = std::path::PathBuf::from(
        args.next()
            .context("usage: noxide-effects-worker CONFIG.json")?,
    );
    match args
        .next()
        .as_deref()
        .and_then(|argument| argument.to_str())
    {
        None => {}
        Some("--supervised") => stop_with_parent()?,
        Some(_) => anyhow::bail!("usage: noxide-effects-worker CONFIG.json [--supervised]"),
    }
    let (config, base) = config(&path)?;
    let delivery = Arc::new(effect_delivery(&path)?);
    let store = database(&config.database, &base)?;
    let effects = config
        .effect_deployment(&base)
        .context("configuration declares no effects")?;
    // The serving process activates the deployment; wait for it to do so.
    let startup = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    startup.block_on(async {
        let mut remaining = 120;
        loop {
            match delivery.activate().await {
                Err(_) if remaining > 0 => remaining -= 1,
                result => break result,
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }?;
        delivery.settled().await
    })?;
    drop(startup);
    let mut policy = store_policy(config.confinement, &store.confinement()?);
    policy
        .readable
        .extend(effects.secrets.iter().map(|secret| secret.path.clone()));
    policy.tcp_connect.push(effects.tor_proxy.port());
    confine(&policy, "effect worker")?;
    tokio::runtime::Runtime::new()?.block_on(async move {
        let _sidecars = store.hold_sidecars().await?;
        let shutdown = shutdown_signal()?;
        delivery.serve(shutdown).await
    })
}
