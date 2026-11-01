mod config;
mod deps;
mod effects;
mod jobs;
mod lifecycle;
mod project;
mod roles;
mod scaffold;
mod supervisor;
mod workflow;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
pub(crate) use config::*;
use noxide_host::{HostKeys, runtime::Limits};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let command = args.first().and_then(|s| s.to_str()).unwrap_or("help");
    match command {
        "role" => roles::run(&args[1..]).await?,
        "deps" => deps::run(&args[1..]).await?,
        "build" | "check" | "test" => workflow::build(command, &args[1..]).await?,
        "setup" => project::setup(&args[1..])?,
        "dev" => lifecycle::dev(&args[1..]).await?,
        "approve" => {
            let development = args.get(1).is_some_and(|arg| arg == "--dev");
            ensure!(
                args.len() == if development { 3 } else { 2 },
                "usage: noxide approve [--dev] CONTRACT_DIGEST"
            );
            let digest = args
                .last()
                .and_then(|arg| arg.to_str())
                .context("invalid digest")?;
            let root = project::discover(&std::env::current_dir()?)?;
            let _lock = project::lock(&project::state(&root, development)?)?;
            lifecycle::prepare(&root, development, Some(digest)).await?;
        }
        "schema" => workflow::schema(&args[1..]).await?,
        "new" => {
            ensure!(args.len() == 2, "usage: noxide new NEW_DIRECTORY");
            scaffold::create(Path::new(&args[1]))?;
        }
        "help" | "--help" | "-h" => {
            println!(
                "Noxide {}\n\nCommands:\n  new NEW_DIRECTORY\n  setup [--kernel FILE] [--toolchain DIRECTORY]\n  dev [BUILD_OPTIONS]\n  approve [--dev] CONTRACT_DIGEST\n  check|test|build [--app APP] [--name CRATE] [--output NEW_DIR] [--isolated --kernel KERNEL --toolchain TOOLCHAIN] [--framework CHECKOUT]\n  deps check [--app APP] [BUILD_ENVIRONMENT_OPTIONS]\n  deps resolve [--app APP] --output NEW_DIRECTORY [BUILD_ENVIRONMENT_OPTIONS]\n  schema diff OLD_MANIFEST NEW_MANIFEST NEW_MIGRATION\n  schema check|apply CONFIG MIGRATION\n  schema indexes CONFIG\n  init CONFIG.json\n  account CONFIG.json LOGIN PASSWORD_FILE [TENANT]\n  account-lookup CONFIG.json LOGIN\n  account-disable|account-enable|account-delete CONFIG.json ACCOUNT_ID\n  role grant|revoke CONFIG.json USER ROLE (--global | --tenant TENANT)\n  role list CONFIG.json USER\n  contract-hash MANIFEST.json\n  deployment-hash CONFIG.json\n  jobs inspect CONFIG [AFTER] | cancel|reconcile CONFIG ID\n  jobs grant|revoke CONFIG TENANT WORKER | fork|worker-once CONFIG\n  effects inspect CONFIG [AFTER] | cancel|retry|resume CONFIG ID\n  effects grant|revoke CONFIG TENANT ENDPOINT | grant-secret|revoke-secret CONFIG SLOT\n  effects worker-once CONFIG\n  effects worker-grants ROLE\n  component CORE.wasm COMPONENT.wasm\n  serve [CONFIG.json]\n  assets-compile CONFIG.json\n  maintain CONFIG.json\n  recover-clock CONFIG.json (stop serving first; configure a fresh host key)\n  keygen NEW_KEYS.json\n  edit-key-rotate KEYS.json\n  invite CONFIG.json [--expires-days N]\n\nBUILD_ENVIRONMENT_OPTIONS: --framework CHECKOUT, --cargo-home DIRECTORY, --toolchain DIRECTORY, --seconds N, --isolated [--kernel FILE]. Dependency commands resolve offline without compiling or approving; resolve emits a candidate lock for review.\n\nApplication builds run locally with host access. Use --isolated for untrusted apps or dependencies. Configuration paths are relative to the configuration file. init creates a new host key file; existing keys are never overwritten.",
                env!("CARGO_PKG_VERSION")
            );
        }
        "contract-hash" => {
            ensure!(args.len() == 2, "usage: noxide contract-hash MANIFEST.json");
            let manifest = noxide_host::manifest::parse(&read(Path::new(&args[1]), 32_768)?)?;
            println!(
                "{}",
                URL_SAFE_NO_PAD.encode(noxide_host::manifest::digest(&manifest)?)
            );
        }
        "deployment-hash" => {
            ensure!(args.len() == 2, "usage: noxide deployment-hash CONFIG.json");
            let (config, base) = config(Path::new(&args[1]))?;
            let manifest =
                noxide_host::manifest::parse(&read(&base.join(&config.manifest), 32_768)?)?;
            let approval = config.approval(&manifest)?;
            let effect_disclosures = manifest
                .actions
                .iter()
                .map(|action| {
                    noxide_host::manifest::effect_disclosures(&manifest, action.id)
                        .map(|fields| (action.id, fields))
                })
                .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "manifest_digest": URL_SAFE_NO_PAD.encode(approval.manifest_digest),
                    "requested_blobs": manifest.blobs,
                    "effective_blobs": approval.effective,
                    "requested_jobs": manifest.jobs,
                    "effective_jobs": approval.effective_jobs,
                    "requested_effects": manifest.effects,
                    "effective_effects": approval.effective_effects,
                    "effect_transport": manifest.effects.as_ref().map(|_| "HTTPS POST JSON via Tor SOCKS remote RESOLVE and numeric CONNECT"),
                    "effect_disclosures": effect_disclosures,
                    "deployment_digest": URL_SAFE_NO_PAD.encode(approval.digest),
                }))?
            );
        }
        "keygen" => {
            ensure!(args.len() == 2, "usage: noxide keygen NEW_KEYS.json");
            create(
                Path::new(&args[1]),
                &serde_json::to_vec(&HostKeys::generate()?)?,
                true,
            )?;
        }
        "edit-key-rotate" => {
            ensure!(args.len() == 2, "usage: noxide edit-key-rotate KEYS.json");
            let path = Path::new(&args[1]);
            let mut keys = host_keys(path)?;
            keys.rotate_edit_key()?;
            let temporary = path.with_extension(format!("rotation-{}.tmp", std::process::id()));
            create(&temporary, &serde_json::to_vec(&keys)?, true)?;
            std::fs::rename(&temporary, path)?;
            std::fs::File::open(
                path.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .sync_all()?;
            println!("Added a signing edit key. Previous edit keys remain verify-only.");
        }
        "jobs" => jobs::run(&args[1..]).await?,
        "effects" => effects::run(&args[1..]).await?,
        "recover-clock" => {
            ensure!(
                args.len() == 2,
                "usage: noxide recover-clock CONFIG.json (stop serving first; configure a fresh host key)"
            );
            let (config, base) = config(Path::new(&args[1]))?;
            let keys = host_keys(&base.join(&config.keys))?;
            database(&config.database, &base)?
                .recover_clock(&keys)
                .await?;
            println!(
                "Clock recovered. Sessions and forms retired. Restart with the configured host key."
            );
        }
        "maintain" => {
            ensure!(args.len() == 2, "usage: noxide maintain CONFIG.json");
            let (config, base) = config(Path::new(&args[1]))?;
            database(&config.database, &base)?.maintain().await?;
        }
        "component" => {
            ensure!(
                args.len() == 3,
                "usage: noxide component CORE.wasm COMPONENT.wasm"
            );
            let core = read(Path::new(&args[1]), 2 * 1024 * 1024)?;
            ensure!(
                core.starts_with(b"\0asm\x01\0\0\0"),
                "expected portable core Wasm"
            );
            let bytes = wit_component::ComponentEncoder::default()
                .module(&core)?
                .validate(true)
                .encode()?;
            // Wrapping never grants imports or trusts generated declarations.
            noxide_host::runtime::Runtime::compile(&bytes, Limits::default())?;
            create(Path::new(&args[2]), &bytes, false)?;
        }
        "init" => {
            ensure!(args.len() == 2, "usage: noxide init CONFIG.json");
            let (config, base) = config(Path::new(&args[1]))?;
            ensure!(
                !base.join(&config.keys).try_exists()?,
                "host key file already exists"
            );
            let keys = HostKeys::generate()?;
            database(&config.database, &base)?.initialize().await?;
            create(&base.join(&config.keys), &serde_json::to_vec(&keys)?, true)?;
            println!("Initialized runtime storage and a private host key file.");
        }
        "invite" => {
            ensure!(
                args.len() == 2 || (args.len() == 4 && args[2] == "--expires-days"),
                "usage: noxide invite CONFIG.json [--expires-days N]"
            );
            let (config, base) = config(Path::new(&args[1]))?;
            let days = args
                .get(3)
                .map(|s| {
                    s.to_str()
                        .context("invalid expiry")?
                        .parse::<u64>()
                        .context("invalid expiry")
                })
                .transpose()?;
            let code = database(&config.database, &base)?.mint_invite(days).await?;
            println!("{code}");
        }
        "account-lookup" | "account-disable" | "account-enable" | "account-delete" => {
            ensure!(
                args.len() == 3,
                "usage: noxide account-lookup|account-disable|account-enable|account-delete CONFIG.json ACCOUNT"
            );
            let (config, base) = config(Path::new(&args[1]))?;
            let db = database(&config.database, &base)?;
            let account = args[2].to_str().context("invalid account")?;
            match args[0].to_str().unwrap_or("") {
                "account-lookup" => println!("{}", db.account_id(account).await?),
                "account-disable" => db.disable_account(account).await?,
                "account-enable" => db.enable_account(account).await?,
                _ => db.delete_account(account).await?,
            }
        }
        "account" => {
            ensure!(
                (4..=5).contains(&args.len()),
                "usage: noxide account CONFIG.json USER PASSWORD_FILE [TENANT]"
            );
            let (config, base) = config(Path::new(&args[1]))?;
            let password = String::from_utf8(read(Path::new(&args[3]), 257)?)?;
            let password = password.strip_suffix('\n').unwrap_or(&password);
            let user = args[2].to_str().context("invalid username")?;
            let tenant = args
                .get(4)
                .map(|s| s.to_str().context("invalid tenant"))
                .transpose()?
                .unwrap_or("");
            let id = database(&config.database, &base)?
                .create_account(user, password, tenant)
                .await?;
            println!("{id}");
        }
        "serve" | "validate" => supervisor::run(command, &args).await?,
        "assets-compile" => {
            ensure!(args.len() == 2, "usage: noxide assets-compile CONFIG.json");
            let digest = supervisor::compile_assets(Path::new(&args[1]))?
                .context("configuration declares no assets")?;
            println!("{digest}");
        }
        _ => bail!("unknown command; run noxide --help"),
    }
    Ok(())
}

#[cfg(test)]
mod listen_tests {
    use super::*;
    #[test]
    fn tor_unix_configuration_preserves_existing_listener_shapes() {
        let tor: ListenConfig =
            serde_json::from_str(r#"{"tor_unix":{"path":"run/app.sock","tor_gid":115}}"#).unwrap();
        assert!(
            matches!(tor, ListenConfig::TorUnix { path, tor_gid: 115 } if path == Path::new("run/app.sock"))
        );
        assert!(serde_json::from_str::<ListenConfig>(r#"{"unix":"run/app.sock"}"#).is_ok());
        assert!(serde_json::from_str::<ListenConfig>(r#"{"tcp":"127.0.0.1:8080"}"#).is_ok());
        assert!(
            serde_json::from_str::<ListenConfig>(
                r#"{"tor_unix":{"path":"run/app.sock","tor_gid":115,"extra":true}}"#
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod reserve_tests {
    use super::*;
    #[test]
    fn signed_in_reserve_defaults_and_rejects_nonintegers_or_out_of_range_values() {
        let config = serde_json::json!({"database":{"sqlite":"store.db"}, "keys":"keys.json", "component":"app.wasm", "manifest":"manifest.json", "approved_contract":"", "origin":"http://localhost:8080", "listen":{"tcp":"127.0.0.1:8080"}});
        assert_eq!(
            serde_json::from_value::<Config>(config.clone())
                .unwrap()
                .signed_in_reserve,
            25
        );
        for reserve in [0, 25, 50] {
            let mut value = config.clone();
            value["signed_in_reserve"] = reserve.into();
            assert_eq!(
                serde_json::from_value::<Config>(value)
                    .unwrap()
                    .signed_in_reserve,
                reserve as u8
            );
        }
        for reserve in [
            serde_json::json!(-1),
            serde_json::json!(51),
            serde_json::json!(1.5),
            serde_json::json!("25"),
        ] {
            let mut value = config.clone();
            value["signed_in_reserve"] = reserve;
            assert!(serde_json::from_value::<Config>(value).is_err());
        }
    }
}

#[cfg(test)]
mod registration_config_tests {
    use super::*;
    #[test]
    fn registration_defaults_closed_and_accepts_only_declared_modes() {
        let base = serde_json::json!({"database":{"sqlite":"runtime.db"},"keys":"keys.json","component":"app.wasm","manifest":"manifest.json","approved_contract":"","origin":"http://localhost:8080","listen":{"tcp":"127.0.0.1:8080"}});
        assert!(
            serde_json::from_value::<Config>(base.clone())
                .unwrap()
                .registration
                == noxide_host::Registration::Closed
        );
        for (name, mode) in [
            ("closed", noxide_host::Registration::Closed),
            ("invite", noxide_host::Registration::Invite),
            ("open", noxide_host::Registration::Open),
        ] {
            let mut config = base.clone();
            config["registration"] = name.into();
            assert!(
                serde_json::from_value::<Config>(config)
                    .unwrap()
                    .registration
                    == mode
            );
        }
        let mut config = base;
        config["registration"] = "inviter".into();
        assert!(serde_json::from_value::<Config>(config).is_err());
    }
}

#[cfg(test)]
mod database_statement_config_tests {
    use super::*;

    #[test]
    fn default_ceiling_can_only_be_lowered_with_an_integer() {
        let config = serde_json::json!({"database":{"sqlite":"store.db"}, "keys":"keys.json", "component":"app.wasm", "manifest":"manifest.json", "approved_contract":"", "origin":"http://localhost:8080", "listen":{"tcp":"127.0.0.1:8080"}});
        assert_eq!(
            serde_json::from_value::<Config>(config.clone())
                .unwrap()
                .database_statement_limit,
            256
        );
        for limit in [1_u16, 64, 256] {
            let mut value = config.clone();
            value["database_statement_limit"] = limit.into();
            assert_eq!(
                serde_json::from_value::<Config>(value)
                    .unwrap()
                    .database_statement_limit,
                limit
            );
        }
        for limit in [
            serde_json::json!(0),
            serde_json::json!(257),
            serde_json::json!(65536),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("64"),
            serde_json::Value::Null,
            serde_json::json!(true),
            serde_json::json!({}),
        ] {
            let mut value = config.clone();
            value["database_statement_limit"] = limit;
            assert!(serde_json::from_value::<Config>(value).is_err());
        }
    }
}
