//! Key service: a blocking request-response loop over one inherited Unix socket.
//!
//! The client treats the service as part of its request budget. One stalled or
//! malformed reply disables the handle permanently, so no request waits twice and
//! nothing proceeds without its check.
use crate::{KeyMaterial, TokenDomain};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};

const MAX_MESSAGE: usize = 64 * 1024;
const REPLY_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Serialize, Deserialize)]
enum Request {
    Identity,
    Seal(TokenDomain, Vec<u8>),
    Open(TokenDomain, Vec<u8>),
    Csrf(String),
    EditMac {
        key: u32,
        resource: u32,
        id: u64,
        version: u64,
    },
}

#[derive(Serialize, Deserialize)]
enum Reply {
    Identity {
        incarnation: String,
        signing_edit_key: Option<u32>,
    },
    Bytes(Vec<u8>),
    Mac([u8; 32]),
    /// No detail crosses: failures here are invalid tokens or unknown keys.
    Refused,
}

fn write_message<T: Serialize>(socket: &mut UnixStream, message: &T) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    ensure!(bytes.len() <= MAX_MESSAGE, "key message limit");
    socket.write_all(&(bytes.len() as u32).to_le_bytes())?;
    socket.write_all(&bytes)?;
    Ok(())
}
fn read_message<T: for<'a> Deserialize<'a>>(socket: &mut UnixStream) -> Result<T> {
    let mut length = [0; 4];
    socket.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    ensure!(length <= MAX_MESSAGE, "key message limit");
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Answer one client until it disconnects.
pub fn serve(material: &KeyMaterial, mut socket: UnixStream) -> Result<()> {
    loop {
        let request = match read_message::<Request>(&mut socket) {
            Ok(request) => request,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let reply = match request {
            Request::Identity => Reply::Identity {
                incarnation: material.incarnation().to_owned(),
                signing_edit_key: material.signing_edit_key().ok(),
            },
            Request::Seal(domain, plaintext) => bytes(material.seal(domain, &plaintext)),
            Request::Open(domain, envelope) => bytes(material.open(domain, &envelope)),
            Request::Csrf(subject) => Reply::Mac(material.csrf(&subject)),
            Request::EditMac {
                key,
                resource,
                id,
                version,
            } => material
                .edit_mac(key, resource, id, version)
                .map_or(Reply::Refused, Reply::Mac),
        };
        write_message(&mut socket, &reply)?;
    }
}
fn bytes(result: Result<Vec<u8>>) -> Reply {
    result.map_or(Reply::Refused, Reply::Bytes)
}

/// Handle to a running key service.
pub struct KeyClient {
    socket: Mutex<Option<UnixStream>>,
    incarnation: String,
    signing_edit_key: Option<u32>,
    _service: Option<Child>,
}

impl KeyClient {
    /// Start `program KEY_FILE ARGUMENTS...` with the service socket as its stdin.
    /// Call before this process confines itself; afterwards it could not exec.
    pub fn spawn(program: &Path, key_file: &Path, arguments: &[&str]) -> Result<Self> {
        let (ours, theirs) = UnixStream::pair()?;
        let child = Command::new(program)
            .arg(key_file)
            .args(arguments)
            .env_clear()
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .spawn()
            .with_context(|| format!("cannot start key service {}", program.display()))?;
        Self::connect(ours, Some(child))
    }
    /// Use an already connected service socket.
    pub fn connect_socket(socket: UnixStream) -> Result<Self> {
        Self::connect(socket, None)
    }
    fn connect(mut socket: UnixStream, service: Option<Child>) -> Result<Self> {
        socket.set_read_timeout(Some(REPLY_TIMEOUT))?;
        socket.set_write_timeout(Some(REPLY_TIMEOUT))?;
        write_message(&mut socket, &Request::Identity)?;
        let Reply::Identity {
            incarnation,
            signing_edit_key,
        } = read_message(&mut socket).context("key service did not start")?
        else {
            anyhow::bail!("invalid key service identity");
        };
        Ok(Self {
            socket: Mutex::new(Some(socket)),
            incarnation,
            signing_edit_key,
            _service: service,
        })
    }
    pub fn incarnation(&self) -> &str {
        &self.incarnation
    }
    pub fn signing_edit_key(&self) -> Result<u32> {
        self.signing_edit_key.context("no signing edit key")
    }
    fn call(&self, request: &Request) -> Result<Reply> {
        let mut guard = self.socket.lock().unwrap_or_else(|e| e.into_inner());
        let socket = guard.as_mut().context("key service unavailable")?;
        let reply = write_message(socket, request).and_then(|()| read_message(socket));
        if reply.is_err() {
            // Replies are positional: after any failure the stream cannot be trusted.
            *guard = None;
        }
        reply.context("key service unavailable")
    }
    pub fn seal(&self, domain: TokenDomain, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.bytes(&Request::Seal(domain, plaintext.to_vec()))
    }
    pub fn open(&self, domain: TokenDomain, envelope: &[u8]) -> Result<Vec<u8>> {
        self.bytes(&Request::Open(domain, envelope.to_vec()))
    }
    fn bytes(&self, request: &Request) -> Result<Vec<u8>> {
        match self.call(request)? {
            Reply::Bytes(bytes) => Ok(bytes),
            _ => anyhow::bail!("key operation refused"),
        }
    }
    pub fn csrf(&self, subject: &str) -> Result<[u8; 32]> {
        self.mac(&Request::Csrf(subject.to_owned()))
    }
    pub fn edit_mac(&self, key: u32, resource: u32, id: u64, version: u64) -> Result<[u8; 32]> {
        self.mac(&Request::EditMac {
            key,
            resource,
            id,
            version,
        })
    }
    fn mac(&self, request: &Request) -> Result<[u8; 32]> {
        match self.call(request)? {
            Reply::Mac(mac) => Ok(mac),
            _ => anyhow::bail!("key operation refused"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn pair() -> (KeyMaterial, KeyClient, std::thread::JoinHandle<Result<()>>) {
        let (client, server) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let material: KeyMaterial = serde_json::from_slice(MATERIAL.get().unwrap()).unwrap();
            serve(&material, server)
        });
        let local = serde_json::from_slice(MATERIAL.get().unwrap()).unwrap();
        (local, KeyClient::connect_socket(client).unwrap(), handle)
    }
    static MATERIAL: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    fn material() {
        MATERIAL.get_or_init(|| serde_json::to_vec(&KeyMaterial::generate().unwrap()).unwrap());
    }

    #[test]
    fn remote_operations_match_local_material() {
        material();
        let (local, client, service) = pair();
        assert_eq!(client.incarnation(), local.incarnation());
        assert_eq!(
            client.signing_edit_key().unwrap(),
            local.signing_edit_key().unwrap()
        );
        assert_eq!(client.csrf("subject").unwrap(), local.csrf("subject"));
        assert_eq!(
            client.edit_mac(1, 2, 3, 4).unwrap(),
            local.edit_mac(1, 2, 3, 4).unwrap()
        );
        assert!(client.edit_mac(99, 2, 3, 4).is_err());
        let sealed = client.seal(TokenDomain::Token, b"plain").unwrap();
        assert_eq!(local.open(TokenDomain::Token, &sealed).unwrap(), b"plain");
        assert_eq!(client.open(TokenDomain::Token, &sealed).unwrap(), b"plain");
        // A refused operation leaves the stream usable; domains stay separate.
        assert!(client.open(TokenDomain::Cursor, &sealed).is_err());
        assert_eq!(client.csrf("subject").unwrap(), local.csrf("subject"));
        drop(client);
        service.join().unwrap().unwrap();
    }

    #[test]
    fn dead_service_fails_closed_and_permanently() {
        let (client, server) = UnixStream::pair().unwrap();
        let service = std::thread::spawn(move || {
            let material = KeyMaterial::generate().unwrap();
            let mut server = server;
            let request: Request = read_message(&mut server).unwrap();
            assert!(matches!(request, Request::Identity));
            write_message(
                &mut server,
                &Reply::Identity {
                    incarnation: material.incarnation().into(),
                    signing_edit_key: None,
                },
            )
            .unwrap();
        });
        let client = KeyClient::connect_socket(client).unwrap();
        service.join().unwrap();
        assert!(client.csrf("one").is_err());
        assert!(client.seal(TokenDomain::Token, b"two").is_err());
    }

    #[test]
    fn stalled_service_is_bounded() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let material = KeyMaterial::generate().unwrap();
        let _: () = {
            let reader = std::thread::spawn(move || {
                let _: Request = read_message(&mut server).unwrap();
                write_message(
                    &mut server,
                    &Reply::Identity {
                        incarnation: material.incarnation().into(),
                        signing_edit_key: None,
                    },
                )
                .unwrap();
                // Holds the socket open without replying again.
                server
            });
            let client = KeyClient::connect_socket(client).unwrap();
            let _held = reader.join().unwrap();
            let started = std::time::Instant::now();
            assert!(client.csrf("one").is_err());
            assert!(started.elapsed() < REPLY_TIMEOUT * 2);
            let started = std::time::Instant::now();
            assert!(client.csrf("two").is_err());
            assert!(started.elapsed() < Duration::from_millis(100));
        };
    }

    #[test]
    fn serialized_form_exists_only_for_local_material() {
        let keys = Keys::Local(KeyMaterial::generate().unwrap());
        let bytes = serde_json::to_vec(&keys).unwrap();
        let restored: Keys = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.incarnation(), keys.incarnation());
        let (client, server) = UnixStream::pair().unwrap();
        let service = std::thread::spawn(move || {
            serve(&KeyMaterial::generate().unwrap(), server).unwrap();
        });
        let remote = Keys::Remote(KeyClient::connect_socket(client).unwrap());
        assert!(serde_json::to_vec(&remote).is_err());
        drop(remote);
        service.join().unwrap();
    }
}
