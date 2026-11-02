//! Holds the host keys for one serving process, over the socket on its stdin.
//! Exits when that process does.
#![cfg_attr(test, allow(clippy::too_many_lines))]
#![forbid(unsafe_code)]
use anyhow::{Context, Result, ensure};
use noxide_keys::KeyMaterial;
use std::os::{fd::AsFd, unix::net::UnixStream};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let (path, mode) = (args.next().context("key file")?, args.next());
    ensure!(args.next().is_none(), "usage: noxide-keyd KEY_FILE [MODE]");
    let material = read(path.as_ref())?;
    let socket = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    // Keep the keys out of core dumps and /proc/PID/mem of the same user.
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    noxide_confine::apply(&noxide_confine::Policy {
        mode: match mode.as_ref().and_then(|mode| mode.to_str()) {
            Some("best_effort") => noxide_confine::Mode::BestEffort,
            Some("disabled") => noxide_confine::Mode::Disabled,
            _ => noxide_confine::Mode::Required,
        },
        ..Default::default()
    })?;
    noxide_keys::serve(&material, socket)
}

fn read(path: &std::path::Path) -> Result<KeyMaterial> {
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        std::fs::metadata(path)?.permissions().mode() & 0o077 == 0,
        "host key file must be private (mode 0600)"
    );
    let bytes = std::fs::read(path)?;
    ensure!(bytes.len() <= 16_384, "host key file limit");
    Ok(serde_json::from_slice(&bytes)?)
}
