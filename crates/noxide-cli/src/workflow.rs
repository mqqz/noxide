use anyhow::{Context, Result, bail, ensure};
use noxide::__private::Manifest;
use noxide_host::{manifest, schema};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};

pub async fn build(command: &str, args: &[OsString]) -> Result<()> {
    // Local builds trust native application code; isolation is an explicit option.
    let mut framework = None;
    let mut forwarded = Vec::new();
    let mut isolated = false;
    let mut output = None;
    let mut name = None;
    let mut app = PathBuf::from(".");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let flag = arg.to_str().context("invalid build argument")?;
        if flag == "--isolated" {
            isolated = true;
            continue;
        }
        ensure!(
            matches!(
                flag,
                "--framework"
                    | "--app"
                    | "--kernel"
                    | "--toolchain"
                    | "--cargo-home"
                    | "--output"
                    | "--name"
                    | "--seconds"
            ),
            "unknown build option"
        );
        let value = iter.next().context("build option needs a value")?;
        match flag {
            "--framework" => framework = Some(PathBuf::from(value)),
            "--output" => {
                output = Some(PathBuf::from(value));
                forwarded.extend([arg.clone(), value.clone()]);
            }
            "--name" => {
                name = Some(value.to_str().context("invalid crate name")?.to_owned());
                forwarded.extend([arg.clone(), value.clone()]);
            }
            "--app" => {
                app = PathBuf::from(value);
                forwarded.extend([arg.clone(), value.clone()]);
            }
            _ => forwarded.extend([arg.clone(), value.clone()]),
        }
    }
    ensure!(
        isolated || !args.iter().any(|arg| arg == "--kernel"),
        "--kernel requires --isolated; omit both only for trusted local builds"
    );
    let project = if args.iter().any(|arg| arg == "--app") {
        app.canonicalize()
            .context("application directory missing")?
    } else {
        super::project::discover(&app)?
    };
    super::project::external_state(&project)?;
    if !args.iter().any(|arg| arg == "--app") {
        forwarded.extend([OsString::from("--app"), project.clone().into_os_string()]);
    }
    let name = match name {
        Some(name) => name,
        None => {
            // Parse TOML without invoking Cargo, build scripts, or macros.
            let mut parser = Command::new("python3").args(["-I", "-c", "import sys,tomllib; p=tomllib.loads(sys.stdin.read()); print(p.get('lib',{}).get('name',p['package']['name'].replace('-','_')))"])
                .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn()?;
            use std::io::Write;
            parser
                .stdin
                .take()
                .unwrap()
                .write_all(&super::read(&project.join("Cargo.toml"), 65536)?)?;
            let result = parser.wait_with_output()?;
            ensure!(
                result.status.success(),
                "cannot discover package; supply --app and --name for workspace projects"
            );
            String::from_utf8(result.stdout)?.trim().to_owned()
        }
    };
    if !args.iter().any(|arg| arg == "--name") {
        forwarded.extend([OsString::from("--name"), OsString::from(&name)]);
    }
    let managed = output.is_none();
    let output = output.unwrap_or_else(|| {
        project.join("target/noxide").join(format!(
            "build-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    });
    if managed {
        forwarded.extend([OsString::from("--output"), output.clone().into_os_string()]);
    }
    let settings = super::project::settings()?;
    if isolated
        && !args.iter().any(|arg| arg == "--kernel")
        && std::env::var_os("NOXIDE_VM_KERNEL").is_none()
        && let Some(kernel) = settings.kernel
    {
        forwarded.extend([OsString::from("--kernel"), kernel.into_os_string()]);
    }
    if !args.iter().any(|arg| arg == "--toolchain")
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
    // Ignore Python startup paths supplied by an application or shell. Only
    // the trusted builder directory may supply sibling builder modules.
    process.args(["-I", "-c", "import pathlib,runpy,sys; script=sys.argv.pop(1); sys.path.insert(0,str(pathlib.Path(script).resolve().parent)); sys.argv[0]=script; runpy.run_path(script,run_name='__main__')"])
        .arg(runner).args(forwarded).arg("--metadata");
    if !isolated {
        process.arg("--local");
    }
    if command == "test" {
        process.arg("--test");
    }
    if command == "check" {
        process.arg("--check");
    }
    let shutdown = super::shutdown_signal()?;
    tokio::pin!(shutdown);
    let mut child = process.spawn()?;
    let status = tokio::select! {
        status = child.wait() => status?,
        _ = &mut shutdown => {
            super::lifecycle::stop(&mut child).await?;
            bail!("application build interrupted");
        }
    };
    ensure!(
        status.success(),
        "application build failed; inspect {}",
        output.join("build.log").display()
    );
    let contract = manifest::parse(&super::read(&output.join("manifest.json"), 32768)?)?;
    let digest = manifest::digest(&contract)?;
    if command != "check" {
        let core = super::read(&output.join(format!("{name}.wasm")), 2 * 1024 * 1024)?;
        let component = wit_component::ComponentEncoder::default()
            .module(&core)?
            .validate(true)
            .encode()?;
        noxide_host::runtime::Runtime::compile(&component, Default::default())?;
        super::create(
            &output.join(format!("{name}.component.wasm")),
            &component,
            false,
        )?;
    }
    use base64::Engine;
    println!(
        "Contract: {}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    );
    println!("Schema: {}", schema::digest(&contract.resources)?);
    println!("Bundle: {}", output.display());
    if command != "check" {
        super::create(
            &output.join("bundle.json"),
            &serde_json::to_vec(
                &serde_json::json!({"name":name,"backend":if isolated {"isolated"} else {"local"}}),
            )?,
            false,
        )?;
    }
    if command == "test" {
        let state = tempfile::tempdir()?;
        let database = noxide_host::Database::sqlite(state.path().join("test.db"));
        database.initialize().await?;
        let app = noxide_host::Application::new(
            &super::read(
                &output.join(format!("{name}.component.wasm")),
                2 * 1024 * 1024,
            )?,
            &super::read(&output.join("manifest.json"), 32768)?,
            digest,
            database,
            noxide_host::HostKeys::generate()?,
            Default::default(),
        )?;
        app.activate().await?;
        println!("Runtime admission and activation passed with disposable test storage.");
    }
    if managed && command == "build" {
        let directory = project.join("target/noxide");
        let temporary = directory.join(format!("latest-{}.tmp", std::process::id()));
        super::create(&temporary, &serde_json::to_vec(&output)?, false)?;
        std::fs::rename(temporary, directory.join("latest.json"))?;
    }
    Ok(())
}

fn load(path: &Path) -> Result<Manifest> {
    manifest::parse(&super::read(path, 32768)?)
}

pub async fn schema(args: &[OsString]) -> Result<()> {
    let action = args
        .first()
        .and_then(|value| value.to_str())
        .context("usage: noxide schema diff|check|apply ...")?;
    match action {
        "diff" => {
            ensure!(
                args.len() == 4,
                "usage: noxide schema diff OLD_MANIFEST NEW_MANIFEST NEW_MIGRATION.json"
            );
            let old = load(Path::new(&args[1]))?;
            let new = load(Path::new(&args[2]))?;
            let draft = draft(&old, &new)?;
            super::create(
                Path::new(&args[3]),
                &serde_json::to_vec_pretty(&draft)?,
                false,
            )?;
            println!(
                "Migration draft created. Resolve every null value and confirm every destructive operation before approval."
            );
        }
        "check" | "apply" => {
            ensure!(
                args.len() == 3,
                "usage: noxide schema check|apply CONFIG MIGRATION.json"
            );
            let (config, base) = super::config(Path::new(&args[1]))?;
            let target = load(&base.join(&config.manifest))?;
            use base64::Engine;
            let approved = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&config.approved_contract)?;
            ensure!(
                approved.as_slice() == manifest::digest(&target)?,
                "target contract is not approved"
            );
            let bytes = super::read(Path::new(&args[2]), 65536)?;
            let migration: schema::Migration = serde_json::from_slice(&bytes)
                .context("invalid migration; resolve draft placeholders")?;
            let database = super::database(&config.database, &base)?;
            if action == "apply" {
                database.schema_apply(&target, &migration).await?;
            } else {
                database.schema_check(&target, &migration).await?;
            }
            println!(
                "{}",
                if action == "apply" {
                    "Migration committed. Activate the matching approved bundle."
                } else {
                    "Migration rehearsal passed; all changes were rolled back."
                }
            );
        }
        _ => bail!("unknown schema command"),
    }
    Ok(())
}

fn draft(old: &Manifest, new: &Manifest) -> Result<serde_json::Value> {
    use serde_json::json;
    let from = schema::digest(&old.resources)?;
    let to = schema::digest(&new.resources)?;
    ensure!(from != to, "no persistent schema changes");
    let old = schema::normalized(&old.resources);
    let new = schema::normalized(&new.resources);
    let mut operations = Vec::new();
    for resource in &old {
        if !new.iter().any(|target| target.name == resource.name) {
            operations.push(
                json!({"op":"drop_resource","resource":resource.name,"confirm_removal":null}),
            );
        }
    }
    for target in &new {
        let Some(source) = old.iter().find(|source| source.name == target.name) else {
            operations.push(json!({"op":"add_resource","resource":target.name}));
            continue;
        };
        for field in &source.fields {
            if !target.fields.iter().any(|new| new.name == field.name) {
                operations.push(json!({"op":"drop_field","resource":target.name,"field":field.name,"confirm_removal":null}));
            }
        }
        for field in &target.fields {
            match source.fields.iter().find(|old|old.name==field.name) {
                None=>operations.push(json!({"op":"add_field","resource":target.name,"field":field.name,"value":null})),
                Some(old) if old!=field=>operations.push(json!({"op":null,"resource":target.name,"field":field.name,"choose":"change_field, convert_field, or map_choices"})),
                _=>{}
            }
        }
    }
    Ok(json!({"version":1,"from":from,"to":to,"operations":operations}))
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholders_are_not_executable_migrations() {
        let invalid = serde_json::json!({"version":1,"from":"a".repeat(64),"to":"b".repeat(64),"operations":[{"op":"add_field","resource":"tasks","field":"done","value":null}]});
        assert!(serde_json::from_value::<noxide_host::schema::Migration>(invalid).is_err());
    }
}
