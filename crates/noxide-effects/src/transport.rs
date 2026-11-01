//! Validated values for effect endpoints, proxies and request parts. Opens no
//! socket; the transport that uses them lives in noxide-effect-delivery.
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

pub const MAX_BODY: usize = 65_536;
pub const MAX_RESPONSE: usize = 16_384;
pub const MAX_HEADERS: usize = 8_192;

/// Canonical shape, not an authorization grant. Future admission must intersect
/// the named endpoint/operator policy with current outbox and disclosure scope.
pub struct Endpoint {
    host: String,
    port: u16,
    path: String,
}
impl Endpoint {
    pub fn checked(host: &str, port: u16, path: &str) -> Result<Self, Error> {
        if host.len() > 253 || path.len() > 1_024 {
            return Err(Error::Endpoint);
        }
        let labels: Vec<_> = host.split('.').collect();
        if host.len() > 253
            || labels.len() < 2
            || port == 0
            || !matches!(url::Host::parse(host), Ok(url::Host::Domain(domain)) if domain == host)
            || labels.iter().any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    || !label.as_bytes()[0].is_ascii_alphanumeric()
                    || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            })
            || !labels
                .last()
                .unwrap()
                .bytes()
                .any(|b| b.is_ascii_lowercase())
            || ["onion", "localhost", "local", "invalid", "test", "example"]
                .contains(labels.last().unwrap())
        {
            return Err(Error::Endpoint);
        }
        // Do not silently normalize escapes, dot segments or duplicate slashes.
        // This first transport accepts only an exact ASCII origin path.
        if path.is_empty()
            || path.len() > 1_024
            || !path.starts_with('/')
            || path.contains("//")
            || path.split('/').any(|s| matches!(s, "." | ".."))
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-._~!$&'()*+,;=:@".contains(&b))
        {
            return Err(Error::Endpoint);
        }
        Ok(Self {
            host: host.into(),
            port,
            path: path.into(),
        })
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}
impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Endpoint([redacted])")
    }
}

#[derive(Clone, Copy)]
pub struct TorProxy(SocketAddr);
impl TorProxy {
    pub fn loopback(address: SocketAddr) -> Result<Self, Error> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(Error::ProxyConfig);
        }
        Ok(Self(address))
    }
    pub fn address(self) -> SocketAddr {
        self.0
    }
}
impl fmt::Debug for TorProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TorProxy([redacted])")
    }
}

pub struct JsonBody(Box<[u8]>);
impl JsonBody {
    pub fn checked(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() > MAX_BODY {
            return Err(Error::BodyLimit);
        }
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_| Error::Json)?;
        Ok(Self(bytes.into_boxed_slice()))
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for JsonBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JsonBody([redacted])")
    }
}

pub struct IdempotencyKey(String);
impl IdempotencyKey {
    pub fn from_host(value: String) -> Result<Self, Error> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(Error::Header);
        }
        Ok(Self(value))
    }
    pub fn value(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdempotencyKey([redacted])")
    }
}

/// Host-resolved slot material, never a manifest or guest payload field.
pub struct BearerSecret(String);
impl BearerSecret {
    pub fn from_host(value: String) -> Result<Self, Error> {
        if value.is_empty() || value.len() > 2_048 {
            return Err(Error::Header);
        }
        let token = value.trim_end_matches('=');
        if token.is_empty()
            || value.len() > 2_048
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
        {
            return Err(Error::Header);
        }
        Ok(Self(value))
    }
    pub fn value(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for BearerSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerSecret([redacted])")
    }
}

/// Conservative global-unicast policy: deny every special-purpose registry block,
/// including special anycast exceptions. IANA registry snapshot: 2026-10-31.
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let n = u32::from(ip);
            let denied = [
                (0x00000000, 8),
                (0x0a000000, 8),
                (0x64400000, 10),
                (0x7f000000, 8),
                (0xa9fe0000, 16),
                (0xac100000, 12),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc01fc400, 24),
                (0xc034c100, 24),
                (0xc0586300, 24),
                (0xc0a80000, 16),
                (0xc0af3000, 24),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 3),
            ];
            !denied
                .iter()
                .any(|&(base, bits)| n >> (32 - bits) == base >> (32 - bits))
        }
        IpAddr::V6(ip) => {
            let n = u128::from(ip);
            if n >> 125 != 1 {
                return false;
            } // Only 2000::/3 global unicast.
            let denied = [
                (0x2001u128 << 112, 23),
                ((0x2001u128 << 112) | (0xdb8u128 << 96), 32),
                (0x2002u128 << 112, 16),
                (
                    (0x2620u128 << 112) | (0x4fu128 << 96) | (0x8000u128 << 80),
                    48,
                ),
                (0x3fffu128 << 112, 20),
            ];
            !denied
                .iter()
                .any(|&(base, bits)| n >> (128 - bits) == base >> (128 - bits))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
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
