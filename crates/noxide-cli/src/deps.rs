//! Dependency-only entry point into the established build executor.
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeSet, ffi::OsString, path::PathBuf};

pub async fn run(args: &[OsString]) -> Result<()> {
    let mode = args.first().and_then(|v| v.to_str()).unwrap_or("");
    ensure!(
        matches!(mode, "check" | "resolve"),
        "usage: noxide deps check|resolve [--app APP] [--output NEW_DIRECTORY] [BUILD_ENVIRONMENT_OPTIONS]"
    );
    let mut seen = BTreeSet::new();
    let mut forwarded = Vec::new();
    let mut framework = None;
    let mut app = None;
    let mut output = None;
    let mut isolated = false;
    let mut iter = args[1..].iter();
    while let Some(arg) = iter.next() {
        let flag = arg.to_str().context("invalid dependency option")?;
        ensure!(seen.insert(flag), "duplicate dependency option");
        if flag == "--isolated" {
            isolated = true;
            continue;
        }
        ensure!(
            matches!(
                flag,
                "--app"
                    | "--output"
                    | "--framework"
                    | "--cargo-home"
                    | "--toolchain"
                    | "--seconds"
                    | "--kernel"
            ),
            "unknown dependency option"
        );
        let value = iter.next().context("dependency option needs a value")?;
        ensure!(
            !value.is_empty() && !value.to_string_lossy().starts_with("--"),
            "dependency option needs a value"
        );
        match flag {
            "--app" => app = Some(PathBuf::from(value)),
            "--framework" => framework = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            _ => forwarded.extend([arg.clone(), value.clone()]),
        }
    }
    ensure!(
        isolated || !seen.contains("--kernel"),
        "--kernel requires --isolated"
    );
    ensure!(
        (mode == "resolve") == output.is_some(),
        "deps resolve requires --output NEW_DIRECTORY; deps check does not accept --output"
    );
    let app = match app {
        Some(path) => std::path::absolute(path)?,
        None => super::project::discover(&std::env::current_dir()?)?,
    };
    super::project::external_state(&app)?;
    let temporary = if mode == "check" {
        Some(tempfile::tempdir()?)
    } else {
        None
    };
    let output = output.unwrap_or_else(|| temporary.as_ref().unwrap().path().join("check"));
    let settings = super::project::settings()?;
    if isolated
        && !seen.contains("--kernel")
        && std::env::var_os("NOXIDE_VM_KERNEL").is_none()
        && let Some(kernel) = settings.kernel
    {
        forwarded.extend([OsString::from("--kernel"), kernel.into_os_string()]);
    }
    if !seen.contains("--toolchain")
        && let Some(toolchain) = settings.toolchain
    {
        forwarded.extend([OsString::from("--toolchain"), toolchain.into_os_string()]);
    }
    let framework = framework.map(Ok).unwrap_or_else(super::project::kit)?;
    let runner = framework.join("tools/build_vm.py");
    ensure!(
        runner.is_file(),
        "trusted framework builder missing; supply --framework CHECKOUT"
    );
    let mut process = tokio::process::Command::new("python3");
    process.kill_on_drop(true);
    process.args(["-I", "-c", "import pathlib,runpy,sys; script=sys.argv.pop(1); sys.path.insert(0,str(pathlib.Path(script).resolve().parent)); sys.argv[0]=script; runpy.run_path(script,run_name='__main__')"])
        .arg(runner).args(forwarded).arg("--app").arg(&app)
        .arg("--output").arg(&output).arg(if mode == "check" { "--deps-check" } else { "--deps-resolve" });
    if !isolated {
        process.arg("--local");
    }
    let shutdown = super::shutdown_signal()?;
    tokio::pin!(shutdown);
    let mut child = process.spawn()?;
    let status = tokio::select! {
        status = child.wait() => status?,
        _ = &mut shutdown => {
            super::lifecycle::stop(&mut child).await?;
            bail!("dependency operation interrupted");
        }
    };
    ensure!(
        status.success(),
        "dependency operation failed; use the same --framework/installed catalog and --toolchain when resolving and checking"
    );
    Ok(())
}
