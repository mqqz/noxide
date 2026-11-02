//! Runs one application's guest code, over the socket on its stdin. Holds no keys
//! and no database, and is confined to that socket before any guest code runs.
//! Exits when the socket closes. With `--broker`, runs no guest code at all: it
//! starts workers for a server that can no longer start processes itself.
#![forbid(unsafe_code)]
use anyhow::{Context, Result, ensure};
use noxide_confine::{Mode, Policy};
use noxide_sandbox::worker::Worker;
use std::{
    ffi::OsString,
    os::{fd::AsFd, unix::net::UnixStream},
    path::PathBuf,
};

/// Where the dynamic linker finds the libraries a new worker needs.
const LIBRARIES: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/etc/ld.so.cache",
];

/// A new worker counts its threads here before confining itself. Landlock stops this
/// process reaching into others under `/proc`, and each worker gives this up too.
const PROCESS_INFORMATION: &str = "/proc";

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
    ensure!(args.next().is_none(), "usage: noxide-guest [MODE]");
    let (limits, component) = noxide_guest::pool::read_init(&mut socket).context("startup")?;
    let worker = Worker::compile(&component, limits)?;
    drop(component);
    std::io::Write::write_all(&mut socket, b"R")?;
    noxide_confine::apply(&Policy {
        mode: mode(first.as_ref()),
        ..Default::default()
    })?;
    socket.set_nonblocking(true)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            worker
                .serve(tokio::net::UnixStream::from_std(socket)?)
                .await
        })
}

fn broker(mut socket: UnixStream, selected: Option<OsString>) -> Result<()> {
    let (limits, component) = noxide_guest::pool::read_init(&mut socket).context("startup")?;
    let program = std::env::current_exe()?;
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let mut readable = vec![program.clone(), PathBuf::from(PROCESS_INFORMATION)];
    readable.extend(
        LIBRARIES
            .iter()
            .map(PathBuf::from)
            .filter(|path| path.exists()),
    );
    noxide_confine::apply(&Policy {
        mode: mode(selected.as_ref()),
        readable,
        spawn: true,
        ..Default::default()
    })?;
    let maximum = limits.concurrency.saturating_mul(2).max(1);
    let worker_mode = selected
        .and_then(|mode| mode.into_string().ok())
        .unwrap_or_else(|| "required".into());
    noxide_guest::broker::serve(
        socket,
        program,
        worker_mode,
        limits,
        component,
        null.into(),
        maximum,
    )
}
