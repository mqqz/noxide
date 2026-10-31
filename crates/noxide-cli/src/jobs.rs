//! Trusted local operator commands. Output contains metadata, never job inputs,
//! target seals, receipts, rejection details, tokens or configured secrets.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_host::{Application, JobOperatorCommand, JobRunOutcome};
use std::{ffi::OsString, path::Path};

fn text(args: &[OsString], index: usize) -> Result<String> {
    Ok(args
        .get(index)
        .and_then(|arg| arg.to_str())
        .context("missing or invalid jobs argument")?
        .to_owned())
}
pub async fn run(args: &[OsString]) -> Result<()> {
    let command = text(args, 0)?;
    let expected = match command.as_str() {
        "inspect" => 2..=3,
        "cancel" | "reconcile" => 3..=3,
        "grant" | "revoke" => 4..=4,
        "fork" | "worker-once" => 2..=2,
        _ => bail!("unknown jobs command"),
    };
    ensure!(
        expected.contains(&args.len()),
        "usage: noxide jobs inspect CONFIG [AFTER] | cancel CONFIG ID | reconcile CONFIG ID | grant CONFIG TENANT WORKER | revoke CONFIG TENANT WORKER | fork CONFIG | worker-once CONFIG"
    );
    let path = text(args, 1)?;
    let app = load(Path::new(&path)).await?;
    if command == "worker-once" {
        let status = match app.run_job_once().await? {
            None => "idle",
            Some(JobRunOutcome::Completed {
                recovered: true, ..
            }) => "recovered",
            Some(JobRunOutcome::Completed { .. }) => "completed",
            Some(JobRunOutcome::BusinessRejected(_)) => "business_rejected",
            Some(JobRunOutcome::Unavailable) => "unavailable",
            Some(JobRunOutcome::Paused) => "paused",
            Some(JobRunOutcome::Dead) => "dead",
            Some(JobRunOutcome::Retrying(_)) => "retrying",
        };
        println!("{status}");
        return Ok(());
    }
    let operation = match command.as_str() {
        "inspect" => JobOperatorCommand::Inspect {
            after: args
                .get(2)
                .map(|_| text(args, 2))
                .transpose()?
                .unwrap_or_default(),
        },
        "cancel" => JobOperatorCommand::Cancel { id: text(args, 2)? },
        "reconcile" => JobOperatorCommand::Reconcile { id: text(args, 2)? },
        "grant" => JobOperatorCommand::Grant {
            tenant: text(args, 2)?,
            worker: text(args, 3)?,
        },
        "revoke" => JobOperatorCommand::Revoke {
            tenant: text(args, 2)?,
            worker: text(args, 3)?,
        },
        "fork" => JobOperatorCommand::Fork,
        _ => unreachable!("validated command"),
    };
    println!(
        "{}",
        serde_json::to_string(&app.operate_jobs(operation).await?)?
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
        Some(path) => noxide_host::assets::AssetBundle::from_pack(
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
            jobs: config.jobs,
        },
    )?
    .with_presentation(config.presentation)?
    .with_signed_in_reserve(config.signed_in_reserve)?
    .with_database_statement_limit(config.database_statement_limit)?
    .with_registration(config.registration);
    app.activate().await?;
    Ok(app)
}
