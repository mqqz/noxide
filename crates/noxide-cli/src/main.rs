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
        "help" | "--help" | "-h" => {
            println!(
                "Noxide {}\n\nCommands:\n  init CONFIG.json\n  account CONFIG.json USER PASSWORD_FILE [TENANT]\n  contract-hash MANIFEST.json\n  component CORE.wasm COMPONENT.wasm\n  serve CONFIG.json\n  maintain CONFIG.json\n  keygen NEW_KEYS.json\n\nApplication builds must use the isolated VM recipe. Configuration paths are relative to the configuration file. init creates a new host key file; existing keys are never overwritten.",
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
        "serve" => {
            ensure!(args.len() == 2, "usage: noxide serve CONFIG.json");
            let (config, base) = config(Path::new(&args[1]))?;
            let key_path = base.join(&config.keys);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    std::fs::metadata(&key_path)?.permissions().mode() & 0o077 == 0,
                    "host key file must be private (mode 0600)"
                );
            }
            let keys: HostKeys = serde_json::from_slice(&read(&key_path, 1024)?)?;
            let approved: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&config.approved_contract)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid approved contract digest"))?;
            let app = Arc::new(Application::new(
                &read(&base.join(config.component), 2 * 1024 * 1024)?,
                &read(&base.join(config.manifest), 32_768)?,
                approved,
                database(&config.database, &base)?,
                keys,
                Limits::default(),
            )?);
            let origin = Origin::parse(&config.origin)?;
            let shutdown = shutdown_signal()?;
            let listener = match config.listen {
                ListenConfig::Tcp(address) => Listener::loopback(address).await?,
                #[cfg(unix)]
                ListenConfig::Unix(path) => Listener::unix(&base.join(path))?,
                #[cfg(not(unix))]
                ListenConfig::Unix(_) => bail!("Unix sockets require Unix"),
            };
            app.activate().await?;
            println!("Runtime listening with the approved application contract.");
            http::serve(listener, app, origin, shutdown).await?;
        }
        _ => bail!("unknown command; run noxide --help"),
    }
    Ok(())
}
