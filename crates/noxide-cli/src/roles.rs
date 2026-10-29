use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide::__private::Predicate;
use noxide_host::{RoleScope, manifest};
use std::{ffi::OsString, path::Path};

const USAGE: &str = "usage: noxide role grant|revoke CONFIG.json USER ROLE (--global | --tenant TENANT); noxide role list CONFIG.json USER";

pub async fn run(args: &[OsString]) -> Result<()> {
    let command = args.first().and_then(|s| s.to_str()).context(USAGE)?;
    ensure!(matches!(command, "grant" | "revoke" | "list"), "{USAGE}");
    ensure!(args.len() >= 3, "{USAGE}");
    let user = args[2].to_str().context("invalid user identifier")?;
    ensure!(manifest::identifier(user), "invalid user identifier");
    if command == "list" {
        ensure!(args.len() == 3, "{USAGE}");
        let (config, base) = super::config(Path::new(&args[1]))?;
        let roles = super::database(&config.database, &base)
            .map_err(|_| anyhow::anyhow!("invalid role database configuration"))?
            .list_roles(user)
            .await?;
        println!("ROLE\tSCOPE\tTENANT");
        for role in roles {
            println!(
                "{}\t{}\t{}",
                role.name,
                if role.tenant.is_empty() {
                    "global"
                } else {
                    "tenant"
                },
                if role.tenant.is_empty() {
                    "-"
                } else {
                    &role.tenant
                }
            );
        }
        return Ok(());
    }
    ensure!(args.len() >= 5, "{USAGE}");
    let role = args[3].to_str().context("invalid role identifier")?;
    ensure!(manifest::identifier(role), "invalid role identifier");
    let scope = match args[4].to_str() {
        Some("--global") if args.len() == 5 => RoleScope::Global,
        Some("--tenant") if args.len() == 6 => {
            let tenant = args[5].to_str().context("invalid tenant identifier")?;
            ensure!(manifest::identifier(tenant), "invalid tenant identifier");
            RoleScope::Tenant(tenant)
        }
        _ => bail!("{USAGE}"),
    };
    let (config, base) = super::config(Path::new(&args[1]))?;
    if command == "grant" {
        let contract = manifest::parse(&super::read(&base.join(&config.manifest), 32_768)?)?;
        ensure!(
            URL_SAFE_NO_PAD.encode(manifest::digest(&contract)?) == config.approved_contract,
            "configured manifest is not approved"
        );
        let tenant_scoped = matches!(scope, RoleScope::Tenant(_));
        ensure!(contract.operations.iter().flat_map(|op| &op.policy.any).flatten().any(|p| matches!(p, Predicate::Role { name, tenant_scoped: scoped } if name == role && *scoped == tenant_scoped)), "role and scope are not declared in the approved operation policies");
    }
    let database = super::database(&config.database, &base)
        .map_err(|_| anyhow::anyhow!("invalid role database configuration"))?;
    let changed = if command == "grant" {
        database.grant_role(user, role, scope).await?
    } else {
        database.revoke_role(user, role, scope).await?
    };
    let (kind, tenant) = match scope {
        RoleScope::Global => ("global", "-"),
        RoleScope::Tenant(tenant) => ("tenant", tenant),
    };
    println!(
        "{command} user={user} role={role} scope={kind} tenant={tenant}: {}",
        if changed { "changed" } else { "unchanged" }
    );
    Ok(())
}
