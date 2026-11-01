use super::*;

trait Transport: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Transport for T {}

pub struct Listener(pub(super) ListenerKind);

/// A socket bound without a runtime, so a process can bind it before confining
/// itself and creating the threads that serve it.
pub struct BoundListener(BoundKind);
enum BoundKind {
    Tcp(std::net::TcpListener),
    #[cfg(unix)]
    Unix {
        listener: std::os::unix::net::UnixListener,
        socket: SocketFile,
        tor: bool,
    },
}

/// Removes its own socket path on drop, and no pre-existing or replacement file.
#[cfg(unix)]
pub(super) struct SocketFile {
    path: std::path::PathBuf,
    identity: (u64, u64),
}
#[cfg(unix)]
impl Drop for SocketFile {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && (metadata.dev(), metadata.ino()) == self.identity
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(super) enum ListenerKind {
    #[cfg(test)]
    AcceptError(Arc<tokio::sync::Notify>),
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix {
        listener: tokio::net::UnixListener,
        _socket: SocketFile,
        tor: bool,
    },
}
impl BoundListener {
    pub fn loopback(address: std::net::SocketAddr) -> Result<Self> {
        ensure!(address.ip().is_loopback(), "listener must bind loopback");
        let listener = std::net::TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Ok(Self(BoundKind::Tcp(listener)))
    }
    #[cfg(unix)]
    pub fn unix(path: &std::path::Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let path = std::path::absolute(path)?;
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        Ok(Self(BoundKind::Unix {
            listener,
            socket: SocketFile {
                path,
                identity: (metadata.dev(), metadata.ino()),
            },
            tor: false,
        }))
    }
    #[cfg(unix)]
    pub fn tor_unix(path: &std::path::Path, tor_gid: u32) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path = std::path::absolute(path)?;
        let directory = std::fs::File::open(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("socket parent missing"))?,
        )?;
        let parent = directory.metadata()?;
        ensure!(
            parent.is_dir() && parent.mode() & 0o7777 == 0o2750 && parent.gid() == tor_gid,
            "Tor socket directory must have mode 2750 and the configured group"
        );
        let mut bound = Self::unix(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let BoundKind::Unix { socket, tor, .. } = &mut bound.0 else {
            unreachable!()
        };
        ensure!(
            (metadata.dev(), metadata.ino()) == socket.identity
                && metadata.uid() == parent.uid()
                && metadata.gid() == tor_gid
                && metadata.mode() & 0o777 == 0o660,
            "Tor socket ownership or permissions differ"
        );
        *tor = true;
        Ok(bound)
    }
    /// Register with the current runtime.
    pub fn start(self) -> Result<Listener> {
        Ok(Listener(match self.0 {
            BoundKind::Tcp(listener) => {
                ListenerKind::Tcp(tokio::net::TcpListener::from_std(listener)?)
            }
            #[cfg(unix)]
            BoundKind::Unix {
                listener,
                socket,
                tor,
            } => ListenerKind::Unix {
                listener: tokio::net::UnixListener::from_std(listener)?,
                _socket: socket,
                tor,
            },
        }))
    }
}
impl Listener {
    #[cfg(test)]
    pub(crate) fn test_accept_error(release: Arc<tokio::sync::Notify>) -> Self {
        Self(ListenerKind::AcceptError(release))
    }
    pub async fn loopback(address: std::net::SocketAddr) -> Result<Self> {
        BoundListener::loopback(address)?.start()
    }
    #[cfg(unix)]
    pub fn unix(path: &std::path::Path) -> Result<Self> {
        BoundListener::unix(path)?.start()
    }
    #[cfg(unix)]
    pub fn tor_unix(path: &std::path::Path, tor_gid: u32) -> Result<Self> {
        BoundListener::tor_unix(path, tor_gid)?.start()
    }
    async fn accept(&self) -> std::io::Result<(Box<dyn Transport>, bool)> {
        match &self.0 {
            #[cfg(test)]
            ListenerKind::AcceptError(release) => {
                release.notified().await;
                Err(std::io::Error::other("test listener stopped"))
            }
            ListenerKind::Tcp(l) => Ok((Box::new(l.accept().await?.0), false)),
            #[cfg(unix)]
            ListenerKind::Unix { listener, tor, .. } => {
                Ok((Box::new(listener.accept().await?.0), *tor))
            }
        }
    }
}

pub(super) struct Prefixed<T> {
    prefix: Vec<u8>,
    offset: usize,
    inner: T,
}
impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Prefixed<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let n = buffer.remaining().min(self.prefix.len() - self.offset);
            buffer.put_slice(&self.prefix[self.offset..self.offset + n]);
            self.offset += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}
impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Prefixed<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, buffers)
    }
}

pub(super) fn parse_proxy_line(line: &[u8]) -> Result<Peer> {
    ensure!(
        line.len() <= PROXY_LINE_MAX && line.is_ascii(),
        "invalid PROXY line"
    );
    let line = line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| anyhow::anyhow!("PROXY line missing CRLF"))?;
    let tokens: Vec<_> = std::str::from_utf8(line)?.split(' ').collect();
    ensure!(
        tokens.len() == 6 && tokens[0] == "PROXY" && tokens[1] == "TCP6",
        "invalid PROXY line"
    );
    let source: std::net::Ipv6Addr = tokens[2].parse()?;
    let _: std::net::Ipv6Addr = tokens[3].parse()?;
    ensure!(
        u128::from(source) >> 64 == 0xfc00_dead_beef_4dad,
        "invalid Tor source prefix"
    );
    for port in &tokens[4..] {
        ensure!(
            (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit()),
            "invalid PROXY port"
        );
        let _: u16 = port.parse()?;
    }
    Ok(Peer::Circuit(u128::from(source) as u32))
}

pub(super) async fn read_proxy<T: tokio::io::AsyncRead + Unpin>(
    mut stream: T,
) -> Result<(Prefixed<T>, Peer)> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(PROXY_LINE_TIMEOUT, async {
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let n = stream.read(&mut buffer).await?;
            ensure!(n != 0, "incomplete PROXY line");
            bytes.extend_from_slice(&buffer[..n]);
            if let Some(at) = bytes.windows(2).position(|pair| pair == b"\r\n") {
                let peer = parse_proxy_line(&bytes[..at + 2])?;
                return Ok((
                    Prefixed {
                        prefix: bytes[at + 2..].to_vec(),
                        offset: 0,
                        inner: stream,
                    },
                    peer,
                ));
            }
            ensure!(bytes.len() < PROXY_LINE_MAX, "PROXY line too long");
        }
    })
    .await?
}

pub(super) type CircuitCounts = Arc<Mutex<HashMap<u32, usize>>>;
pub(super) struct CircuitConnection {
    counts: CircuitCounts,
    id: u32,
}
impl CircuitConnection {
    pub(super) fn acquire(counts: CircuitCounts, id: u32) -> Option<Self> {
        let mut open = counts.lock().unwrap_or_else(|e| e.into_inner());
        let count = open.entry(id).or_default();
        if *count == MAX_CONNECTIONS_PER_CIRCUIT {
            return None;
        }
        *count += 1;
        drop(open);
        Some(Self { counts, id })
    }
}
impl Drop for CircuitConnection {
    fn drop(&mut self) {
        let mut open = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = open.get_mut(&self.id) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.id);
            }
        }
    }
}

pub async fn serve(
    listener: Listener,
    app: Arc<Application>,
    origin: Origin,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let checkpoint = app.start_clock_service()?;
    let jobs = match app.start_job_service() {
        Ok(jobs) => jobs,
        Err(error) => {
            checkpoint.shutdown().await?;
            return Err(error);
        }
    };
    let effects = match app.start_effect_service() {
        Ok(effects) => effects,
        Err(error) => {
            let jobs_stopped = if let Some(jobs) = jobs {
                jobs.shutdown().await
            } else {
                Ok(())
            };
            let clock_stopped = checkpoint.shutdown().await;
            jobs_stopped?;
            clock_stopped?;
            return Err(error);
        }
    };
    let ordinary = app.request_lifecycle();
    let router = router(app, origin);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let circuits: CircuitCounts = Arc::new(Mutex::new(HashMap::new()));
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    let mut accept_error = None;
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            Some(_)=connections.join_next(),if !connections.is_empty()=>{},
            accepted=listener.accept()=>{
                let (stream, tor)=match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => { accept_error = Some(error); break; }
                };
                let Ok(permit)=slots.clone().try_acquire_owned() else {drop(stream);continue};
                let router = router.clone();
                let circuits = circuits.clone();
                connections.spawn(async move {
                    let _permit=permit;
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
                    let _=tokio::time::timeout_at(deadline, async move {
                        let (stream, peer): (Box<dyn Transport>, Peer) = if tor {
                            let Ok((stream, peer)) = read_proxy(stream).await else { return };
                            (Box::new(stream), peer)
                        } else { (stream, Peer::Local) };
                        let _circuit = match peer {
                            Peer::Local => None,
                            Peer::Circuit(id) => {
                                let Some(guard) = CircuitConnection::acquire(circuits, id) else { return };
                                Some(guard)
                            }
                        };
                        let service=hyper_util::service::TowerToHyperService::new(router.layer(axum::Extension(peer)).layer(axum::Extension(super::TransportDeadline(deadline))));
                        let mut http=hyper::server::conn::http1::Builder::new();
                        http.auto_date_header(false).timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT).max_headers(64).max_buf_size(32*1024);
                        let _=http.serve_connection(hyper_util::rt::TokioIo::new(stream),service).await;
                    }).await;
                });
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    let effects_stopped = if let Some(effects) = effects {
        effects.shutdown().await
    } else {
        Ok(())
    };
    let jobs_stopped = if let Some(jobs) = jobs {
        jobs.shutdown().await
    } else {
        Ok(())
    };
    let ordinary_stopped = ordinary.shutdown().await;
    let clock_stopped = checkpoint.shutdown().await;
    effects_stopped?;
    jobs_stopped?;
    ordinary_stopped?;
    clock_stopped?;
    if let Some(error) = accept_error {
        return Err(error.into());
    }
    Ok(())
}

use tokio::sync::Semaphore;
