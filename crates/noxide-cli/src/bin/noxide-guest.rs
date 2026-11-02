//! Runs one application's guest code, over the socket on its stdin. Holds no keys
//! and no database, and is confined to that socket before any guest code runs.
//! Exits when the socket closes. With `--broker`, runs no guest code at all: it
//! starts workers for a server that can no longer start processes itself. With
//! `--compile`, it admits and compiles the component for the broker, once.
#![cfg_attr(test, allow(clippy::too_many_lines))]
#![forbid(unsafe_code)]
use anyhow::{Context, Result, ensure};
use noxide_confine::{Mode, Policy};
use noxide_sandbox::worker::{Worker, compile_artifact};
use std::{
    ffi::OsString,
    os::{fd::AsFd, unix::net::UnixStream},
    path::PathBuf,
};

/// Where the dynamic linker finds the libraries a new worker needs. Readable, not
/// executable: the broker can run only its own binary and that linker.
const LIBRARIES: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/etc/ld.so.cache",
];

/// Generous for the largest guest memory, its 128 MiB reservation, Wasmtime's own use
/// and a compiled component, and small enough to stop a worker using up the machine.
const WORKER_ADDRESS_SPACE: u64 = 2 * 1024 * 1024 * 1024;
/// Startup and the idle loop.
const WORKER_BASE_CPU_SECONDS: u64 = 30;
/// Far beyond any component a server would accept, in a debug build.
const COMPILE_CPU_SECONDS: u64 = 300;

fn mode(argument: Option<&OsString>) -> Mode {
    match argument.and_then(|mode| mode.to_str()) {
        Some("best_effort") => Mode::BestEffort,
        Some("disabled") => Mode::Disabled,
        _ => Mode::Required,
    }
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    let mut socket = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    if first.as_deref().and_then(|argument| argument.to_str()) == Some("--broker") {
        let selected = args.next();
        ensure!(args.next().is_none(), "usage: noxide-guest --broker [MODE]");
        return broker(socket, selected);
    }
    if first.as_deref().and_then(|argument| argument.to_str()) == Some("--compile") {
        let selected = args.next();
        ensure!(
            args.next().is_none(),
            "usage: noxide-guest --compile [MODE]"
        );
        return compile(socket, selected);
    }
    ensure!(args.next().is_none(), "usage: noxide-guest [MODE]");
    let startup = noxide_guest::pool::read_init(&mut socket).context("startup")?;
    let cpu = cpu_seconds(&startup);
    let memory = startup.limits.memory_bytes as u64;
    // Before confinement: Tokio's drivers make a socket pair, which it then forbids.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    give_up_authority(cpu, memory, first.as_ref())?;
    let worker = Worker::load_from_broker(&startup.code, startup.limits)?;
    drop(startup.code);
    std::io::Write::write_all(&mut socket, b"R")?;
    socket.set_nonblocking(true)?;
    runtime.block_on(async move {
        worker
            .serve(tokio::net::UnixStream::from_std(socket)?)
            .await
    })
}

/// Everything a worker or compile process keeps nothing beyond, before it touches code.
fn give_up_authority(cpu: u64, memory: u64, selected: Option<&OsString>) -> Result<()> {
    limit_resources(cpu, memory)?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    noxide_confine::apply(&Policy {
        mode: mode(selected),
        isolated: true,
        ..Default::default()
    })?;
    Ok(())
}

/// Compile for the broker. Confined first, since this parses and compiles an untrusted
/// component, and limited, since that work is otherwise unbounded. Exits without writing
/// anything if the component is rejected, which the broker reads as a closed socket.
fn compile(mut socket: UnixStream, selected: Option<OsString>) -> Result<()> {
    let startup = noxide_guest::pool::read_init(&mut socket).context("startup")?;
    let memory = startup.limits.memory_bytes as u64;
    give_up_authority(COMPILE_CPU_SECONDS, memory, selected.as_ref())?;
    let artifact = compile_artifact(&startup.code, &startup.limits)?;
    std::io::Write::write_all(&mut socket, &(artifact.len() as u64).to_le_bytes())?;
    std::io::Write::write_all(&mut socket, &artifact)?;
    Ok(())
}

/// Every request it may serve running for its whole time limit. Only an escaped guest
/// could get near this, by spinning between requests.
fn cpu_seconds(startup: &noxide_guest::pool::Startup) -> u64 {
    startup
        .limits
        .wall_time
        .as_secs()
        .saturating_add(1)
        .saturating_mul(u64::from(startup.retire_after))
        .saturating_add(WORKER_BASE_CPU_SECONDS)
}

/// Hard limits, which an escaped guest cannot raise.
fn limit_resources(cpu: u64, memory: u64) -> Result<()> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    for (resource, maximum) in [
        (Resource::As, WORKER_ADDRESS_SPACE),
        (Resource::Cpu, cpu),
        (Resource::Nofile, 32),
        // Wasmtime keeps memory images in memfds; this process can open no other file.
        (Resource::Fsize, memory),
        (Resource::Core, 0),
        (Resource::Memlock, 0),
        (Resource::Locks, 0),
        (Resource::Msgqueue, 0),
    ] {
        setrlimit(
            resource,
            Rlimit {
                current: Some(maximum),
                maximum: Some(maximum),
            },
        )
        .with_context(|| format!("resource limit {resource:?}"))?;
    }
    Ok(())
}

/// The dynamic linker named by this binary, if it has one.
fn interpreter(program: &std::path::Path) -> Result<Option<PathBuf>> {
    let elf = std::fs::read(program)?;
    let field = |offset: usize, size: usize| -> Result<u64> {
        let bytes = elf.get(offset..offset + size).context("ELF header")?;
        let mut value = [0; 8];
        value[..size].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(value))
    };
    ensure!(elf.starts_with(b"\x7fELF\x02\x01"), "expected a 64-bit ELF");
    let table = usize::try_from(field(32, 8)?)?;
    let size = usize::try_from(field(54, 2)?)?;
    for index in 0..usize::try_from(field(56, 2)?)? {
        let header = table + index * size;
        const PT_INTERP: u64 = 3;
        if field(header, 4)? == PT_INTERP {
            let start = usize::try_from(field(header + 8, 8)?)?;
            let length = usize::try_from(field(header + 32, 8)?)?;
            let path = elf.get(start..start + length).context("ELF interpreter")?;
            let path = path.strip_suffix(&[0]).unwrap_or(path);
            return Ok(Some(PathBuf::from(std::str::from_utf8(path)?)));
        }
    }
    Ok(None)
}

fn broker(mut socket: UnixStream, selected: Option<OsString>) -> Result<()> {
    let startup = noxide_guest::pool::read_init(&mut socket).context("startup")?;
    let program = std::env::current_exe()?;
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let mut spawn = vec![program.clone()];
    spawn.extend(interpreter(&program)?);
    noxide_confine::apply(&Policy {
        mode: mode(selected.as_ref()),
        readable: LIBRARIES
            .iter()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .collect(),
        spawn,
        ..Default::default()
    })?;
    let worker_mode = selected
        .and_then(|mode| mode.into_string().ok())
        .unwrap_or_else(|| "required".into());
    noxide_guest::broker::serve(socket, program, worker_mode, startup, null.into())
}
