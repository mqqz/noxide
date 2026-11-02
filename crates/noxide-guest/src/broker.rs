//! Starts workers for a server that has confined itself and can no longer start
//! processes. The broker holds the component and its right to start one program, and
//! hands each new worker's socket to the server. It runs no guest code and never
//! reads a worker's messages.
use crate::{Limits, pool::write_init};
use anyhow::{Context, Result, bail, ensure};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use std::{
    collections::HashMap,
    io::{IoSlice, IoSliceMut, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

const START: u8 = b'S';
const KILL: u8 = b'K';
const READY: u8 = 1;
const FAILED: u8 = 0;

/// The server's side. Asking and collecting are separate so a slow compile does not
/// stop other workers from starting.
pub struct BrokerClient {
    child: Mutex<Child>,
    requests: Mutex<UnixStream>,
    replies: Mutex<UnixStream>,
}

impl BrokerClient {
    pub fn start(program: &Path, mode: &str, component: &[u8], limits: &Limits) -> Result<Self> {
        let (mut ours, theirs) = UnixStream::pair()?;
        let child = Command::new(program)
            .args(["--broker", mode])
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear()
            .spawn()
            .with_context(|| format!("cannot start {}", program.display()))?;
        write_init(&mut ours, component, limits)?;
        let replies = ours.try_clone()?;
        Ok(Self {
            child: Mutex::new(child),
            requests: Mutex::new(ours),
            replies: Mutex::new(replies),
        })
    }

    /// Ask for a worker and wait for one. Replies are interchangeable, so whichever
    /// finishes first answers whoever is waiting. Blocks; not for an async task.
    pub fn worker(&self) -> Result<(u32, UnixStream)> {
        self.requests.lock().unwrap().write_all(&[START])?;
        let replies = self.replies.lock().unwrap();
        let mut message = [0; 5];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let received = recvmsg(
            replies.as_fd(),
            &mut [IoSliceMut::new(&mut message)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        ensure!(received.bytes == message.len(), "broker reply");
        let mut socket = None;
        for item in ancillary.drain() {
            if let RecvAncillaryMessage::ScmRights(mut descriptors) = item {
                socket = descriptors.next();
            }
        }
        ensure!(message[0] == READY, "worker did not start");
        let socket = socket.context("broker sent no worker socket")?;
        let id = u32::from_le_bytes(message[1..].try_into()?);
        Ok((id, UnixStream::from(socket)))
    }

    /// Ask the broker to kill a worker the server no longer trusts. The socket is
    /// already closed by then, so a refused request leaves only an idle process.
    pub fn kill(&self, id: u32) {
        let mut message = [KILL, 0, 0, 0, 0];
        message[1..].copy_from_slice(&id.to_le_bytes());
        let _ = self.requests.lock().unwrap().write_all(&message);
    }
}

impl Drop for BrokerClient {
    /// The broker exits when its socket closes, and workers when theirs do.
    fn drop(&mut self) {
        let child = self.child.get_mut().unwrap();
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn reply(socket: &Mutex<UnixStream>, status: u8, id: u32, worker: Option<OwnedFd>) -> Result<()> {
    let mut message = [status, 0, 0, 0, 0];
    message[1..].copy_from_slice(&id.to_le_bytes());
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let descriptors;
    if let Some(worker) = &worker {
        descriptors = [worker.as_fd()];
        ensure!(
            ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)),
            "ancillary space"
        );
    }
    let socket = socket.lock().unwrap();
    let sent = sendmsg(
        socket.as_fd(),
        &[IoSlice::new(&message)],
        &mut ancillary,
        SendFlags::empty(),
    )?;
    ensure!(sent == message.len(), "broker reply");
    Ok(())
}

struct Broker {
    program: PathBuf,
    mode: String,
    component: Vec<u8>,
    limits: Limits,
    /// Opened before confinement, which leaves `/dev/null` out of reach.
    null: OwnedFd,
    children: Mutex<HashMap<u32, Child>>,
    /// Workers being started, counted before their thread runs.
    starting: AtomicUsize,
    /// Refuses a server asking for more than it can ever use.
    maximum: usize,
}

impl Broker {
    fn start(&self, id: u32) -> Result<(Child, OwnedFd)> {
        let (mut ours, theirs) = UnixStream::pair()?;
        let mut child = Command::new(&self.program)
            .arg(&self.mode)
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::from(self.null.try_clone()?))
            .stderr(Stdio::from(self.null.try_clone()?))
            .env_clear()
            .spawn()
            .with_context(|| format!("cannot start worker {id}"))?;
        let started = (|| {
            write_init(&mut ours, &self.component, &self.limits)?;
            let mut ready = [0];
            ours.read_exact(&mut ready)?;
            ensure!(&ready == b"R", "worker did not start");
            Ok(())
        })();
        if let Err(error) = started {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok((child, ours.into()))
    }

    /// Reap workers that exited after their socket closed.
    fn sweep(&self) -> usize {
        let mut children = self.children.lock().unwrap();
        children.retain(|_, child| matches!(child.try_wait(), Ok(None)));
        children.len()
    }
}

/// Serve one server until its socket closes. `limits` and `component` come from
/// [`read_init`](crate::pool::read_init), read before this process confined itself.
pub fn serve(
    socket: UnixStream,
    program: PathBuf,
    mode: String,
    limits: Limits,
    component: Vec<u8>,
    null: OwnedFd,
    maximum: usize,
) -> Result<()> {
    let broker = Arc::new(Broker {
        program,
        mode,
        component,
        limits,
        null,
        children: Mutex::new(HashMap::new()),
        starting: AtomicUsize::new(0),
        maximum,
    });
    let mut requests = socket.try_clone()?;
    let replies = Arc::new(Mutex::new(socket));
    let mut next = 0u32;
    loop {
        let mut kind = [0];
        if requests.read_exact(&mut kind).is_err() {
            return Ok(());
        }
        match kind[0] {
            START => {
                next = next.wrapping_add(1);
                let id = next;
                let (broker, replies) = (broker.clone(), replies.clone());
                if broker.sweep() + broker.starting.load(Ordering::Acquire) >= broker.maximum {
                    reply(&replies, FAILED, id, None)?;
                    continue;
                }
                broker.starting.fetch_add(1, Ordering::AcqRel);
                std::thread::spawn(move || {
                    let started = broker.start(id);
                    let reported = match started {
                        Ok((child, socket)) => {
                            broker.children.lock().unwrap().insert(id, child);
                            reply(&replies, READY, id, Some(socket))
                        }
                        Err(_) => reply(&replies, FAILED, id, None),
                    };
                    broker.starting.fetch_sub(1, Ordering::AcqRel);
                    drop(reported);
                });
            }
            KILL => {
                let mut id = [0; 4];
                requests.read_exact(&mut id)?;
                let child = broker
                    .children
                    .lock()
                    .unwrap()
                    .remove(&u32::from_le_bytes(id));
                if let Some(mut child) = child {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                broker.sweep();
            }
            _ => bail!("unknown broker request"),
        }
    }
}
