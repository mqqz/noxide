mod deps;
mod lifecycle;
mod project;
mod roles;
mod scaffold;
mod workflow;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_host::{
    Application, Database, HostKeys,
    http::{self, Listener, Origin},
    runtime::Limits,
};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    database: DatabaseConfig,
    keys: PathBuf,
    component: PathBuf,
    manifest: PathBuf,
    approved_contract: String,
    origin: String,
    listen: ListenConfig,
    #[serde(
        default = "default_signed_in_reserve",
        deserialize_with = "signed_in_reserve"
    )]
    signed_in_reserve: u8,
    #[serde(default)]
    registration: noxide_host::Registration,
    #[serde(default)]
    presentation: noxide_host::Presentation,
}
fn default_signed_in_reserve() -> u8 {
    25
}
fn signed_in_reserve<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u8, D::Error> {
    let value = u8::deserialize(deserializer)?;
    if value > 50 {
        return Err(serde::de::Error::custom(
            "signed_in_reserve must be between 0 and 50",
        ));
    }
    Ok(value)
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum DatabaseConfig {
    Sqlite(PathBuf),
    Postgres(String),
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ListenConfig {
    Tcp(std::net::SocketAddr),
    Unix(PathBuf),
    TorUnix { path: PathBuf, tor_gid: u32 },
}

fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.len() <= limit, "file limit");
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "file limit");
    Ok(bytes)
}
fn host_keys(path: &Path) -> Result<HostKeys> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            std::fs::metadata(path)?.permissions().mode() & 0o077 == 0,
            "host key file must be private (mode 0600)"
        );
    }
    Ok(serde_json::from_slice(&read(path, 16_384)?)?)
}

fn create(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if secret { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn config(path: &Path) -> Result<(Config, PathBuf)> {
    Ok((
        serde_json::from_slice(&read(path, 16_384)?)?,
        path.parent().unwrap_or(Path::new(".")).to_owned(),
    ))
}
fn database(config: &DatabaseConfig, base: &Path) -> Result<Database> {
    match config {
        DatabaseConfig::Sqlite(path) => Ok(Database::sqlite(base.join(path))),
        DatabaseConfig::Postgres(url) => Database::postgres(url),
    }
}

fn shutdown_signal() -> Result<impl std::future::Future<Output = ()>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        // Register before binding so both signals are handled as soon as the
        // listener exists, including while deployment activation is pending.
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        Ok(async move {
            tokio::select! {
                _ = interrupt.recv() => {},
                _ = terminate.recv() => {},
            }
        })
    }
    #[cfg(not(unix))]
    Ok(async {
        let _ = tokio::signal::ctrl_c().await;
    })
}

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
                "Noxide {}\n\nCommands:\n  new NEW_DIRECTORY\n  setup [--kernel FILE] [--toolchain DIRECTORY]\n  dev [BUILD_OPTIONS]\n  approve [--dev] CONTRACT_DIGEST\n  check|test|build [--app APP] [--name CRATE] [--output NEW_DIR] [--isolated --kernel KERNEL --toolchain TOOLCHAIN] [--framework CHECKOUT]\n  deps check [--app APP] [BUILD_ENVIRONMENT_OPTIONS]\n  deps resolve [--app APP] --output NEW_DIRECTORY [BUILD_ENVIRONMENT_OPTIONS]\n  schema diff OLD_MANIFEST NEW_MANIFEST NEW_MIGRATION\n  schema check|apply CONFIG MIGRATION\n  init CONFIG.json\n  account CONFIG.json USER PASSWORD_FILE [TENANT]\n  role grant|revoke CONFIG.json USER ROLE (--global | --tenant TENANT)\n  role list CONFIG.json USER\n  contract-hash MANIFEST.json\n  component CORE.wasm COMPONENT.wasm\n  serve [CONFIG.json]\n  maintain CONFIG.json\n  recover-clock CONFIG.json (stop serving first; configure a fresh host key)\n  keygen NEW_KEYS.json\n  edit-key-rotate KEYS.json\n  invite CONFIG.json [--expires-days N]\n\nBUILD_ENVIRONMENT_OPTIONS: --framework CHECKOUT, --cargo-home DIRECTORY, --toolchain DIRECTORY, --seconds N, --isolated [--kernel FILE]. Dependency commands resolve offline without compiling or approving; resolve emits a candidate lock for review.\n\nApplication builds run locally with host access. Use --isolated for untrusted apps or dependencies. Configuration paths are relative to the configuration file. init creates a new host key file; existing keys are never overwritten.",
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
            database(&config.database, &base)?
                .create_account(user, password, tenant)
                .await?;
            println!("Account created.");
        }
        "serve" | "validate" => {
            ensure!(args.len() <= 2, "usage: noxide serve [CONFIG.json]");
            let _lock = if args.len() == 1 {
                Some(project::lock(&project::state(
                    &project::discover(&std::env::current_dir()?)?,
                    false,
                )?)?)
            } else {
                None
            };
            let path = if args.len() == 2 {
                PathBuf::from(&args[1])
            } else {
                lifecycle::prepare(&project::discover(&std::env::current_dir()?)?, false, None)
                    .await?
            };
            let (config, base) = config(&path)?;
            let keys = host_keys(&base.join(&config.keys))?;
            let approved: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&config.approved_contract)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid approved contract digest"))?;
            let app = Arc::new(
                Application::new(
                    &read(&base.join(config.component), 2 * 1024 * 1024)?,
                    &read(&base.join(config.manifest), 32_768)?,
                    approved,
                    database(&config.database, &base)?,
                    keys,
                    Limits::default(),
                )?
                .with_presentation(config.presentation)?
                .with_signed_in_reserve(config.signed_in_reserve)?
                .with_registration(config.registration),
            );
            if command == "validate" {
                app.activate().await?;
                return Ok(());
            }
            let origin = Origin::parse(&config.origin)?;
            let shutdown = shutdown_signal()?;
            let listener = match config.listen {
                ListenConfig::Tcp(address) => Listener::loopback(address).await?,
                #[cfg(unix)]
                ListenConfig::Unix(path) => Listener::unix(&base.join(path))?,
                #[cfg(unix)]
                ListenConfig::TorUnix { path, tor_gid } => {
                    Listener::tor_unix(&base.join(path), tor_gid)?
                }
                #[cfg(not(unix))]
                ListenConfig::Unix(_) | ListenConfig::TorUnix { .. } => {
                    bail!("Unix sockets require Unix")
                }
            };
            app.activate().await?;
            println!("Runtime listening with the approved application contract.");
            http::serve(listener, app, origin, shutdown).await?;
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
