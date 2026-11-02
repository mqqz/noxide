//! Runs one application's guest code, over the socket on its stdin. Holds no keys
//! and no database, and is confined to that socket before any guest code runs.
#![forbid(unsafe_code)]
use anyhow::{Context, Result, ensure};
use noxide_sandbox::worker::Worker;
use std::os::{fd::AsFd, unix::net::UnixStream};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next();
    ensure!(args.next().is_none(), "usage: noxide-guest [MODE]");
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::TERM))?;
    let mut socket = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    let (limits, component) = noxide_guest::pool::read_init(&mut socket).context("startup")?;
    let worker = Worker::compile(&component, limits)?;
    drop(component);
    std::io::Write::write_all(&mut socket, b"R")?;
    noxide_confine::apply(&noxide_confine::Policy {
        mode: match mode.as_ref().and_then(|mode| mode.to_str()) {
            Some("best_effort") => noxide_confine::Mode::BestEffort,
            Some("disabled") => noxide_confine::Mode::Disabled,
            _ => noxide_confine::Mode::Required,
        },
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
