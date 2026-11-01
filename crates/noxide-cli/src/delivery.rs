//! Builds effect delivery for the worker and `noxide effects worker-once`. Not
//! included by the server binary.
use super::config::*;
use anyhow::{Context, Result, ensure};
use std::path::Path;

/// Delivery for an approved deployment. Reads no key file and compiles no guest.
pub fn effect_delivery(path: &Path) -> Result<noxide_effect_delivery::EffectDelivery> {
    let (config, base) = config(path)?;
    let approved = decode_digest(&config.approved_contract)?;
    let declarations = read(&base.join(&config.manifest), 32_768)?;
    let manifest = noxide_host::manifest::parse(&declarations)?;
    ensure!(
        config.approval(&manifest)?.digest == approved,
        "deployment did not approve this contract and effective policy"
    );
    noxide_effect_delivery::EffectDelivery::new(
        &read(&base.join(&config.component), 2 * 1024 * 1024)?,
        &declarations,
        approved,
        database(&config.database, &base)?,
        config
            .effect_deployment(&base)
            .context("configuration declares no effects")?,
    )?
    .with_database_statement_limit(config.database_statement_limit)
}
