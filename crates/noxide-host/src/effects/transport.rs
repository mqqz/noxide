//! Unregistered P11 preparation. No guest API, worker, endpoint grant or outbox is
//! enabled by this leaf. Future admission must supply current endpoint/disclosure
//! authority and invoke it outside every database transaction.
#[path = "transport/config.rs"]
mod config;
#[path = "transport/http.rs"]
mod http;
#[path = "transport/socks.rs"]
mod socks;

pub(crate) use config::{BearerSecret, Endpoint, IdempotencyKey, JsonBody, TorProxy};
use std::{fmt, sync::Arc, time::Duration};
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};
use tokio_rustls::TlsConnector;

const CONNECT_LIMIT: Duration = Duration::from_secs(10);
const ATTEMPT_LIMIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Endpoint,
    ProxyConfig,
    Json,
    BodyLimit,
    Header,
    Busy,
    ProxyIo,
    Socks,
    Address,
    Tls,
    Http,
    ResponseLimit,
    Redirect(u16),
    Deadline,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Endpoint => "invalid canonical endpoint",
            Self::ProxyConfig => "invalid local Tor proxy",
            Self::Json => "invalid JSON body",
            Self::BodyLimit => "request body limit",
            Self::Header => "invalid host header value",
            Self::Busy => "effect transport busy",
            Self::ProxyIo => "Tor proxy I/O failed",
            Self::Socks => "Tor SOCKS negotiation failed",
            Self::Address => "Tor returned a forbidden address",
            Self::Tls => "endpoint TLS failed",
            Self::Http => "invalid endpoint HTTP response",
            Self::ResponseLimit => "endpoint response limit",
            Self::Redirect(_) => "endpoint redirect rejected",
            Self::Deadline => "effect transport deadline",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Discard {
    Complete,
    LimitExceeded,
    Invalid,
    Deadline,
}

/// No remote body or arbitrary header is returned to a guest or stored by this
/// adapter. Retry/admission/window decisions belong to the future outbox worker.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) retry_after_seconds: Option<u32>,
    pub(crate) discard: Discard,
}

pub(crate) struct Transport {
    proxy: TorProxy,
    tls: Arc<rustls::ClientConfig>,
    slots: Arc<Semaphore>,
}
impl Transport {
    pub(crate) fn new(proxy: TorProxy) -> Self {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(proxy, roots)
    }
    fn with_roots(proxy: TorProxy, roots: rustls::RootCertStore) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("compiled TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.resumption = rustls::client::Resumption::disabled();
        tls.enable_early_data = false;
        Self {
            proxy,
            tls: Arc::new(tls),
            slots: Arc::new(Semaphore::new(2)),
        }
    }

    pub(crate) async fn post(
        &self,
        endpoint: &Endpoint,
        body: &JsonBody,
        key: &IdempotencyKey,
        secret: Option<&BearerSecret>,
        caller_deadline: Instant,
    ) -> Result<Response, Error> {
        let started = Instant::now();
        let deadline = caller_deadline.min(started + ATTEMPT_LIMIT);
        if deadline <= started {
            return Err(Error::Deadline);
        }
        let _slot = self.slots.try_acquire().map_err(|_| Error::Busy)?;
        let name = rustls::pki_types::ServerName::try_from(endpoint.host().to_owned())
            .map_err(|_| Error::Endpoint)?;
        let connected = timeout_at(deadline.min(started + CONNECT_LIMIT), async {
            let stream = socks::connect(self.proxy, endpoint).await?;
            TlsConnector::from(self.tls.clone())
                .connect(name, stream)
                .await
                .map_err(|_| Error::Tls)
        })
        .await
        .map_err(|_| Error::Deadline)??;
        // Certificate verification, SNI and Host retain the exact approved name;
        // only the proxy sees the numeric address validated from remote RESOLVE.
        http::post(connected, endpoint, body, key, secret, deadline).await
    }
}

#[cfg(test)]
#[path = "transport/tests.rs"]
mod tests;
