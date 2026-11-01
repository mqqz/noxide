//! Effect transport preparation. No guest API, worker, endpoint grant or outbox is
//! enabled by this module. Future admission must supply current endpoint/disclosure
//! authority and invoke it outside every database transaction.
#[path = "transport/http.rs"]
mod http;
#[path = "transport/socks.rs"]
mod socks;

pub use noxide_effects::transport::*;
mod config {
    pub use noxide_effects::transport::*;
}
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};
use tokio_rustls::TlsConnector;

const CONNECT_LIMIT: Duration = Duration::from_secs(10);
const ATTEMPT_LIMIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discard {
    Complete,
    LimitExceeded,
    Invalid,
    Deadline,
}

/// No remote body or arbitrary header is returned to a guest or stored by this
/// adapter. Retry/admission/window decisions belong to the future outbox worker.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub retry_after_seconds: Option<u32>,
    pub discard: Discard,
}

pub struct Transport {
    proxy: TorProxy,
    tls: Arc<rustls::ClientConfig>,
    slots: Arc<Semaphore>,
}
impl Transport {
    pub fn new(proxy: TorProxy) -> Self {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(proxy, roots)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_test_roots(proxy: TorProxy, roots: rustls::RootCertStore) -> Self {
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

    pub async fn post(
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
