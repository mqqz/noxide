//! Runtime configuration shared by the `noxide` command and the deployed processes.
#![allow(dead_code)]
use anyhow::{Context, Result, ensure};
use noxide_host::{Database, HostKeys};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Operator choice for the operating-system confinement of deployed processes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confinement {
    #[default]
    Required,
    BestEffort,
    Disabled,
}
impl Confinement {
    pub fn mode(self) -> noxide_confine::Mode {
        match self {
            Self::Required => noxide_confine::Mode::Required,
            Self::BestEffort => noxide_confine::Mode::BestEffort,
            Self::Disabled => noxide_confine::Mode::Disabled,
        }
    }
    pub fn argument(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::BestEffort => "best_effort",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub confinement: Confinement,
    /// Digest of the compiled asset pack, from `noxide assets-compile`.
    #[serde(default)]
    pub approved_assets: Option<String>,
    pub database: DatabaseConfig,
    pub keys: PathBuf,
    pub component: PathBuf,
    pub manifest: PathBuf,
    #[serde(default)]
    pub assets: Option<PathBuf>,
    #[serde(default)]
    pub blobs: Option<noxide_host::BlobDeployment>,
    #[serde(default)]
    pub jobs: Option<noxide_host::JobDeployment>,
    #[serde(default)]
    pub effects: Option<noxide_host::EffectDeployment>,
    pub approved_contract: String,
    pub origin: String,
    pub listen: ListenConfig,
    #[serde(
        default = "default_signed_in_reserve",
        deserialize_with = "signed_in_reserve"
    )]
    pub signed_in_reserve: u8,
    #[serde(
        default = "default_database_statement_limit",
        deserialize_with = "database_statement_limit"
    )]
    pub database_statement_limit: u16,
    #[serde(default)]
    pub registration: noxide_host::Registration,
    #[serde(default)]
    pub presentation: noxide_host::Presentation,
}
impl Config {
    /// Resolve only host-owned resources after pure approval. Paths and secret
    /// material are excluded from capability summaries and deployment identity.
    pub fn effect_deployment(&self, base: &Path) -> Option<noxide_host::EffectDeployment> {
        self.effects.clone().map(|mut effects| {
            for secret in &mut effects.secrets {
                secret.path = base.join(&secret.path);
            }
            let keys = base.join(&self.keys);
            effects.with_runtime_directory(keys.parent().unwrap_or(base).to_owned())
        })
    }
    pub fn approval(
        &self,
        manifest: &noxide_protocol::Manifest,
    ) -> Result<noxide_host::deployment::DeploymentApproval> {
        noxide_host::deployment::approval(
            manifest,
            self.blobs.as_ref().map(|blobs| &blobs.ceilings),
            self.jobs.as_ref(),
            self.effects.as_ref(),
        )
    }
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
fn default_database_statement_limit() -> u16 {
    256
}
fn database_statement_limit<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u16, D::Error> {
    let value = u16::deserialize(deserializer)?;
    if !(1..=256).contains(&value) {
        return Err(serde::de::Error::custom(
            "database_statement_limit must be between 1 and 256",
        ));
    }
    Ok(value)
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DatabaseConfig {
    Sqlite(PathBuf),
    Postgres(String),
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ListenConfig {
    Tcp(std::net::SocketAddr),
    Unix(PathBuf),
    TorUnix { path: PathBuf, tor_gid: u32 },
}

pub fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.len() <= limit, "file limit");
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "file limit");
    Ok(bytes)
}
pub fn host_keys(path: &Path) -> Result<HostKeys> {
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

pub fn create(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
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
pub fn config(path: &Path) -> Result<(Config, PathBuf)> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let base = std::fs::canonicalize(parent).context("configuration directory unavailable")?;
    Ok((serde_json::from_slice(&read(path, 16_384)?)?, base))
}
pub fn database(config: &DatabaseConfig, base: &Path) -> Result<Database> {
    match config {
        DatabaseConfig::Sqlite(path) => Ok(Database::sqlite(base.join(path))),
        DatabaseConfig::Postgres(url) => Database::postgres(url),
    }
}

pub fn shutdown_signal() -> Result<impl std::future::Future<Output = ()>> {
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

/// Delivery for an approved deployment. Reads no key file and compiles no guest.
pub fn effect_delivery(path: &Path) -> Result<noxide_host::EffectDelivery> {
    let (config, base) = config(path)?;
    let approved = decode_digest(&config.approved_contract)?;
    let declarations = read(&base.join(&config.manifest), 32_768)?;
    let manifest = noxide_host::manifest::parse(&declarations)?;
    ensure!(
        config.approval(&manifest)?.digest == approved,
        "deployment did not approve this contract and effective policy"
    );
    noxide_host::EffectDelivery::new(
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

pub fn decode_digest(encoded: &str) -> Result<[u8; 32]> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(encoded)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid approved contract digest"))
}

/// Stop with the `noxide serve` supervisor rather than outlive it unobserved.
pub fn stop_with_parent() -> Result<()> {
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::TERM))?;
    Ok(())
}

/// A binary installed beside the running executable.
pub fn sibling(name: &str) -> Result<PathBuf> {
    let current = std::env::current_exe()?;
    let path = current.with_file_name(name);
    ensure!(path.is_file(), "missing {}", path.display());
    Ok(path)
}

/// Build a process's confinement policy from what its store needs.
pub fn store_policy(
    mode: Confinement,
    store: &noxide_host::StoreResources,
) -> noxide_confine::Policy {
    noxide_confine::Policy {
        mode: mode.mode(),
        writable: store.files.clone(),
        readable: if store.resolves_host {
            [
                "/etc/hosts",
                "/etc/nsswitch.conf",
                "/etc/resolv.conf",
                "/etc/host.conf",
                "/etc/gai.conf",
            ]
            .iter()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .collect()
        } else {
            Vec::new()
        },
        tcp_connect: store.tcp_port.into_iter().collect(),
        ..Default::default()
    }
}

/// Fail or warn according to the operator's choice.
pub fn confine(policy: &noxide_confine::Policy, process: &str) -> Result<()> {
    // Runtimes used during startup release their threads shortly after shutdown.
    let mut outcome = noxide_confine::apply(policy);
    for _ in 0..50 {
        if outcome.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        outcome = noxide_confine::apply(policy);
    }
    match outcome.with_context(|| format!("{process} confinement"))? {
        noxide_confine::Outcome::Confined => {}
        noxide_confine::Outcome::Partial => {
            eprintln!("warning: {process} confinement is only partially enforced");
        }
        noxide_confine::Outcome::Unconfined => {
            eprintln!("warning: {process} confinement is disabled by configuration");
        }
    }
    Ok(())
}
