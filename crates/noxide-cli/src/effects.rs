//! Trusted local effect operations. Only bounded metadata reaches stdout.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_host::{Application, EffectOperatorCommand as Command};
use std::{ffi::OsString, path::Path};
fn text(args: &[OsString], index: usize) -> Result<String> {
    Ok(args
        .get(index)
        .and_then(|v| v.to_str())
        .context("missing or invalid effects argument")?
        .to_owned())
}
pub async fn run(args: &[OsString]) -> Result<()> {
    let command = text(args, 0)?;
    if command == "worker-grants" {
        ensure!(args.len() == 2, "usage: noxide effects worker-grants ROLE");
        let role = text(args, 1)?;
        ensure!(
            noxide_protocol::identifier(&role),
            "role must be a lowercase identifier"
        );
        for grant in noxide_host::POSTGRES_WORKER_GRANTS {
            println!("{};", grant.replace("ROLE", &role));
        }
        return Ok(());
    }
    let count = match command.as_str() {
        "inspect" => 2..=3,
        "cancel" | "retry" | "resume" | "grant-secret" | "revoke-secret" => 3..=3,
        "grant" | "revoke" => 4..=4,
        "worker-once" => 2..=2,
        _ => bail!("unknown effects command"),
    };
    ensure!(
        count.contains(&args.len()),
        "usage: noxide effects inspect CONFIG [AFTER] | cancel CONFIG ID | retry CONFIG ID | resume CONFIG ID | grant CONFIG TENANT ENDPOINT | revoke CONFIG TENANT ENDPOINT | grant-secret CONFIG SLOT | revoke-secret CONFIG SLOT | worker-once CONFIG"
    );
    let path = text(args, 1)?;
    if command == "worker-once" {
        let delivery = super::effect_delivery(Path::new(&path))?;
        delivery.activate().await?;
        println!(
            "{}",
            serde_json::to_string(&delivery.run_effect_once().await?)?
        );
        return Ok(());
    }
    let app = load(Path::new(&path)).await?;
    let operation = match command.as_str() {
        "inspect" => Command::Inspect {
            after: args
                .get(2)
                .map(|_| text(args, 2))
                .transpose()?
                .unwrap_or_default(),
        },
        "cancel" => Command::Cancel { id: text(args, 2)? },
        "retry" => Command::Retry { id: text(args, 2)? },
        "resume" => Command::Resume { id: text(args, 2)? },
        "grant" => Command::GrantEndpoint {
            tenant: text(args, 2)?,
            endpoint: text(args, 3)?,
        },
        "revoke" => Command::RevokeEndpoint {
            tenant: text(args, 2)?,
            endpoint: text(args, 3)?,
        },
        "grant-secret" => Command::GrantSecret {
            slot: text(args, 2)?,
        },
        "revoke-secret" => Command::RevokeSecret {
            slot: text(args, 2)?,
        },
        _ => unreachable!("validated effect command"),
    };
    println!(
        "{}",
        serde_json::to_string(&app.operate_effects(operation).await?)?
    );
    Ok(())
}

async fn load(path: &Path) -> Result<Application> {
    let (config, base) = super::config(path)?;
    let approved: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&config.approved_contract)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid approved contract digest"))?;
    let declarations = super::read(&base.join(&config.manifest), 32_768)?;
    let manifest = noxide_host::manifest::parse(&declarations)?;
    // Validate all operator choices and approval before keys, stores or database
    // opening. The only prior I/O reads the explicit config/manifest for review.
    ensure!(
        config.approval(&manifest)?.digest == approved,
        "deployment did not approve this contract and effective policy"
    );
    let assets = match &config.assets {
        Some(path) => noxide_asset_admission::from_pack(
            &manifest.assets,
            &super::read(
                &base.join(path),
                noxide_host::assets::MAX_ASSET_PACK_BYTES as u64,
            )?,
        )?,
        None => noxide_host::assets::AssetBundle::default(),
    };
    let component = super::read(&base.join(&config.component), 2 * 1024 * 1024)?;
    let keys = super::host_keys(&base.join(&config.keys))?;
    let app = Application::new(
        &component,
        &declarations,
        approved,
        super::database(&config.database, &base)?,
        keys,
        Default::default(),
        noxide_host::DeploymentResources {
            assets,
            blobs: config
                .blobs
                .as_ref()
                .map(|deployment| noxide_host::BlobDeployment {
                    directory: base.join(&deployment.directory),
                    ceilings: deployment.ceilings.clone(),
                }),
            effects: config.effect_deployment(&base),
            jobs: config.jobs.clone(),
        },
    )?
    .with_presentation(config.presentation)?
    .with_signed_in_reserve(config.signed_in_reserve)?
    .with_database_statement_limit(config.database_statement_limit)?
    .with_registration(config.registration);
    app.activate().await?;
    Ok(app)
}
