use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::process::{Child, Command};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    name: String,
    backend: String,
}

pub async fn prepare(project: &Path, development: bool, approval: Option<&str>) -> Result<PathBuf> {
    let bundle: PathBuf = serde_json::from_slice(
        &super::read(&project.join("target/noxide/latest.json"), 16384)
            .context("no successful project build; run noxide build first")?,
    )?;
    let bundle = bundle
        .canonicalize()
        .context("latest bundle directory missing")?;
    let descriptor: Bundle =
        serde_json::from_slice(&super::read(&bundle.join("bundle.json"), 16384)?)?;
    ensure!(
        !descriptor.name.is_empty()
            && descriptor
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "invalid bundle name"
    );
    ensure!(
        matches!(descriptor.backend.as_str(), "local" | "isolated"),
        "invalid build provenance"
    );
    let manifest_path = bundle.join("manifest.json");
    let bytes = super::read(&manifest_path, 32768)?;
    let manifest = noxide_host::manifest::parse(&bytes)?;
    let digest = URL_SAFE_NO_PAD.encode(noxide_host::manifest::digest(&manifest)?);
    let component = bundle.join(format!("{}.component.wasm", descriptor.name));
    noxide_host::runtime::Runtime::compile(
        &super::read(&component, 2 * 1024 * 1024)?,
        Default::default(),
    )?;
    let state = super::project::state(project, development)?;
    let path = state.join("runtime.json");
    let existing = path.try_exists()?;
    let mut configuration = if existing {
        serde_json::from_slice::<serde_json::Value>(&super::read(&path, 16384)?)?
    } else {
        serde_json::json!({"database":{"sqlite":"application.db"},"keys":"host-keys.json",
            "origin":"http://localhost:8080", "listen":{"tcp":"127.0.0.1:8080"},
            "registration":if development {"open"} else {"closed"}})
    };
    if configuration
        .get("approved_contract")
        .and_then(|v| v.as_str())
        != Some(&digest)
    {
        println!(
            "{} deployment requests this contract:",
            if development {
                "Development"
            } else {
                "Serving"
            }
        );
        // JSON serialization escapes terminal controls in application-provided strings.
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::from_slice::<serde_json::Value>(&bytes)?)?
        );
        println!("Contract: {digest}");
        if development {
            println!(
                "Development binds loopback and allows account registration. Approval applies only to this development deployment."
            );
        }
        if let Some(approval) = approval {
            ensure!(
                approval == digest,
                "approval digest does not match the selected bundle"
            );
        } else {
            ensure!(
                std::io::stdin().is_terminal(),
                "contract approval requires a terminal; run noxide approve {}{}",
                if development { "--dev " } else { "" },
                digest
            );
            print!("Approve this contract for this deployment? Type approve: ");
            std::io::stdout().flush()?;
            let shutdown = super::shutdown_signal()?;
            let mut prompt = Command::new("python3");
            prompt
                .args([
                    "-I",
                    "-c",
                    "import sys; sys.stdout.write(sys.stdin.readline(256))",
                ])
                .stdin(Stdio::inherit())
                .stdout(Stdio::piped())
                .kill_on_drop(true);
            let answer = tokio::select! {
                output = prompt.output() => output?,
                _ = shutdown => bail!("contract approval interrupted"),
            };
            ensure!(
                answer.status.success() && answer.stdout == b"approve\n",
                "contract not approved"
            );
        }
        configuration["approved_contract"] = digest.clone().into();
    }
    if let Some(approval) = approval {
        ensure!(
            approval == digest,
            "approval digest does not match the selected bundle"
        );
    }
    configuration["component"] = serde_json::to_value(component)?;
    configuration["manifest"] = serde_json::to_value(manifest_path)?;
    let parsed: super::Config = serde_json::from_value(configuration.clone())?;
    let keys = state.join(&parsed.keys);
    if !keys.try_exists()? {
        ensure!(
            !existing,
            "configured host keys are missing; refusing to generate a replacement deployment identity"
        );
        super::database(&parsed.database, &state)?
            .initialize()
            .await?;
        super::create(
            &keys,
            &serde_json::to_vec(&noxide_host::HostKeys::generate()?)?,
            true,
        )?;
    }
    super::host_keys(&keys)?;
    let temporary = state.join(format!("runtime-{}.tmp", std::process::id()));
    super::create(
        &temporary,
        &serde_json::to_vec_pretty(&configuration)?,
        true,
    )?;
    fs::rename(temporary, &path)?;
    println!("Runtime configuration: {}", path.display());
    if development {
        println!("Open http://localhost:8080 and register a development account.");
    } else {
        println!(
            "Create accounts with: noxide account {} USER PASSWORD_FILE",
            path.display()
        );
    }
    Ok(path)
}

// This scans metadata only; it never invokes Cargo or application code.
fn fingerprint(project: &Path) -> Result<Vec<u8>> {
    fn walk(path: &Path, hash: &mut Sha256, count: &mut usize, depth: usize) -> Result<()> {
        ensure!(depth <= 32, "watch nesting limit");
        let mut entries = fs::read_dir(path)?
            .take(2049)
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(entries.len() <= 2048, "watch directory entry limit");
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name();
            if name == "target" || name.to_string_lossy().starts_with('.') {
                continue;
            }
            *count += 1;
            ensure!(*count <= 2048, "watch entry limit");
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(!metadata.file_type().is_symlink(), "linked watch input");
            hash.update(entry.path().as_os_str().as_encoded_bytes());
            if metadata.is_dir() {
                walk(&entry.path(), hash, count, depth + 1)?;
            } else {
                ensure!(metadata.is_file(), "nonregular watch input");
                hash.update(metadata.len().to_le_bytes());
                hash.update(
                    metadata
                        .modified()?
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_nanos()
                        .to_le_bytes(),
                );
            }
        }
        Ok(())
    }
    let mut hash = Sha256::new();
    walk(project, &mut hash, &mut 0, 0)?;
    Ok(hash.finalize().to_vec())
}

pub async fn stop(child: &mut Child) -> Result<()> {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .await?;
    }
    match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
        Ok(status) => {
            status?;
        }
        Err(_) => {
            child.kill().await?;
        }
    }
    Ok(())
}

pub async fn dev(args: &[OsString]) -> Result<()> {
    // Keep project discovery and every compilation option in the shared build command.
    ensure!(
        !args.iter().any(|arg| arg == "--output" || arg == "--app"),
        "dev runs in the current project and manages its own output"
    );
    let project = super::project::discover(&std::env::current_dir()?)?;
    let state = super::project::state(&project, true)?;
    let _lock = super::project::lock(&state)?;
    let executable = std::env::current_exe()?;
    let shutdown = super::shutdown_signal()?;
    tokio::pin!(shutdown);
    let mut running: Option<Child> = None;
    let mut previous = Vec::new();
    loop {
        let current = fingerprint(&project)?;
        if current != previous {
            previous = current;
            let mut build = Command::new(&executable)
                .arg("build")
                .args(args)
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let status = tokio::select! {
                _ = &mut shutdown => { stop(&mut build).await?; if let Some(child) = &mut running { stop(child).await?; } return Ok(()); }
                status = build.wait() => status?,
            };
            if status.success() {
                match prepare(&project, true, None).await {
                    Ok(config) => {
                        let valid = Command::new(&executable)
                            .arg("validate")
                            .arg(&config)
                            .status()
                            .await?;
                        if valid.success() {
                            if let Some(child) = &mut running {
                                stop(child).await?;
                            }
                            running = Some(
                                Command::new(&executable)
                                    .arg("serve")
                                    .arg(config)
                                    .stdin(Stdio::null())
                                    .kill_on_drop(true)
                                    .spawn()?,
                            );
                        } else {
                            eprintln!(
                                "Activation failed; previous application remains active. Schema changes require an explicit migration."
                            );
                        }
                    }
                    Err(error) => {
                        if running.is_none() {
                            return Err(error.context("development did not start"));
                        }
                        eprintln!(
                            "Rebuild not activated: {error:#}; previous application remains active."
                        );
                    }
                }
            } else {
                eprintln!(
                    "Build failed; serving the previous successful build, if any. Edit a source file to retry."
                );
            }
        }
        if let Some(child) = &mut running
            && let Some(status) = child.try_wait()?
        {
            bail!("development server exited ({status}); check the port and runtime diagnostics");
        }
        tokio::select! {
            _ = &mut shutdown => { if let Some(child) = &mut running { stop(child).await?; } return Ok(()); }
            _ = tokio::time::sleep(std::time::Duration::from_millis(750)) => {},
        }
    }
}
