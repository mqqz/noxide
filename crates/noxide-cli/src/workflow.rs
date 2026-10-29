use anyhow::{Context, Result, bail, ensure};
use noxide::__private::Manifest;
use noxide_host::{manifest, schema};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};

pub fn build(command: &str, args: &[OsString]) -> Result<()> {
    // Local builds trust native application code; isolation is an explicit option.
    let mut framework = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut forwarded = Vec::new();
    let mut isolated = false;
    let mut output = None;
    let mut name = "private_notes".to_string();
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
            "--framework" => framework = PathBuf::from(value),
            "--output" => {
                output = Some(PathBuf::from(value));
                forwarded.extend([arg.clone(), value.clone()]);
            }
            "--name" => {
                name = value.to_str().context("invalid crate name")?.into();
                forwarded.extend([arg.clone(), value.clone()]);
            }
            _ => forwarded.extend([arg.clone(), value.clone()]),
        }
    }
    ensure!(
        isolated || !args.iter().any(|arg| arg == "--kernel"),
        "--kernel requires --isolated; omit both only for trusted local builds"
    );
    let output = output.context("--output is required")?;
    let runner = framework.join("tools/build_vm.py");
    ensure!(
        runner.is_file(),
        "trusted framework builder missing; supply --framework CHECKOUT"
    );
    let mut process = Command::new("python3");
    process.arg(runner).args(forwarded).arg("--metadata");
    if !isolated {
        process.arg("--local");
    }
    if command == "check" {
        process.arg("--check");
    }
    ensure!(
        process.status()?.success(),
        "application build failed; inspect build.log"
    );
    let contract = manifest::parse(&super::read(&output.join("manifest.json"), 32768)?)?;
    let digest = manifest::digest(&contract)?;
    if command == "build" {
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
