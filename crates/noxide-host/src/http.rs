use crate::{
    Application, RequestError,
    render::{CSP, Rendered},
};
use anyhow::{Result, ensure};
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::Router,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

const SESSION: &str = "noxide_session";
const LOGIN: &str = "noxide_login";
const STYLE: &str = "html{color-scheme:light dark;font:1.1rem/1.6 system-ui}body{margin:2rem auto;max-width:48rem;padding:0 1rem}label{display:block;margin:1rem 0}input,textarea,button{font:inherit}textarea{display:block;width:100%;min-height:8rem;box-sizing:border-box}button{padding:.5rem 1rem}article{border-block-end:1px solid;padding-block:1rem}pre{white-space:pre-wrap;overflow-wrap:anywhere}a{overflow-wrap:anywhere}:focus-visible{outline:3px solid Highlight;outline-offset:3px}";

#[derive(Clone)]
pub struct Origin {
    serialized: String,
    authority: String,
    secure: bool,
}
impl Origin {
    pub fn parse(value: &str) -> Result<Self> {
        let url = url::Url::parse(value)?;
        ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "invalid public origin"
        );
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("origin host missing"))?;
        let loopback = host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|a| a.is_loopback());
        ensure!(
            loopback || host.ends_with(".onion") || host.ends_with(".i2p"),
            "public origin must be local, Tor, or I2P"
        );
        let serialized = url.origin().ascii_serialization();
        let authority = serialized
            .split_once("://")
            .expect("HTTP origin")
            .1
            .to_string();
        Ok(Self {
            serialized,
            authority,
            secure: url.scheme() == "https",
        })
    }
}

struct Gateway {
    app: Arc<Application>,
    origin: Origin,
}

pub fn router(app: Arc<Application>, origin: Origin) -> Router {
    Router::new()
        .fallback(dispatch)
        .with_state(Arc::new(Gateway { app, origin }))
}

fn cookie(headers: &HeaderMap, name: &str) -> Result<String> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        let text = header.to_str()?;
        ensure!(text.len() <= 8192, "cookie limit");
        for item in text.split(';') {
            if let Some((key, value)) = item.trim().split_once('=')
                && key == name
            {
                ensure!(found.is_none(), "duplicate cookie");
                found = Some(value.to_owned());
            }
        }
    }
    found.ok_or_else(|| anyhow::anyhow!("cookie missing"))
}

fn set_cookie(name: &str, value: &str, secure: bool, age: u32) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{}",
        if secure { "; Secure" } else { "" }
    ))
    .expect("host encoded cookie")
}

fn finish(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // Fetch makes navigation POST Origin opaque under no-referrer. same-origin
    // preserves strict Origin checks and still suppresses cross-origin referrers.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    response
}

fn rendered(value: Rendered) -> Response {
    let mut response = (
        StatusCode::from_u16(value.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        value.body,
    )
        .into_response();
    if let Some(location) = value.location {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&location).expect("resolved route"),
        );
    }
    response
}
fn redirect(location: &'static str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}
fn error(error: RequestError) -> Response {
    let status = match error {
        RequestError::Authentication => return redirect("/login"),
        RequestError::InvalidRequest => StatusCode::BAD_REQUEST,
        RequestError::Rejected => StatusCode::UNPROCESSABLE_ENTITY,
        RequestError::Busy | RequestError::OutcomeUnknown => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        error.to_string(),
    )
        .into_response()
}

// Browser newline normalization can double the admitted 8 KiB of field values;
// percent encoding can triple that to 48 KiB. The rest of this cap covers eight
// field names, the 2 KiB token limit, CSRF, and separators. Check the separate
// canonical-input budget after decoding and normalization.
const MAX_ENCODED_FORM_BYTES: usize = 64 * 1024;

fn decode_form(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    fn decode(bytes: &[u8]) -> Result<String> {
        let mut output = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => output.push(b' '),
                b'%' => {
                    ensure!(i + 2 < bytes.len(), "truncated escape");
                    let a = (bytes[i + 1] as char)
                        .to_digit(16)
                        .ok_or_else(|| anyhow::anyhow!("invalid escape"))?;
                    let b = (bytes[i + 2] as char)
                        .to_digit(16)
                        .ok_or_else(|| anyhow::anyhow!("invalid escape"))?;
                    output.push((a * 16 + b) as u8);
                    i += 2;
                }
                byte => output.push(byte),
            }
            i += 1;
        }
        Ok(String::from_utf8(output)?
            .replace("\r\n", "\n")
            .replace('\r', "\n"))
    }
    ensure!(bytes.len() <= MAX_ENCODED_FORM_BYTES, "form limit");
    let mut result = BTreeMap::new();
    let mut decoded_bytes = 0;
    for pair in bytes.split(|b| *b == b'&') {
        ensure!(result.len() < 12, "field count");
        let Some(at) = pair.iter().position(|b| *b == b'=') else {
            anyhow::bail!("field missing value")
        };
        let key = decode(&pair[..at])?;
        let value = decode(&pair[at + 1..])?;
        decoded_bytes += key.len() + value.len();
        ensure!(
            decoded_bytes <= noxide_protocol::MAX_INPUT_BYTES,
            "decoded form limit"
        );
        ensure!(
            key.len() <= 32 && result.insert(key, value).is_none(),
            "duplicate field"
        );
    }
    Ok(result)
}

async fn dispatch(State(gateway): State<Arc<Gateway>>, request: Request) -> Response {
    finish(dispatch_inner(gateway, request).await)
}
async fn dispatch_inner(gateway: Arc<Gateway>, request: Request) -> Response {
    let headers = request.headers();
    if headers.get_all(header::HOST).iter().count() != 1
        || headers.get(header::HOST).and_then(|h| h.to_str().ok())
            != Some(&gateway.origin.authority)
    {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    if request.uri().path().len() > 256 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let cursor = match request.uri().query() {
        None => None,
        Some(query) => match query
            .strip_prefix("before=")
            .and_then(|s| s.parse::<u64>().ok())
        {
            Some(id) if id > 0 && id <= i64::MAX as u64 => Some(id),
            _ => return StatusCode::BAD_REQUEST.into_response(),
        },
    };
    let path = request.uri().path().to_owned();
    if request.method() == axum::http::Method::GET {
        if path == "/_noxide/style.css" {
            return ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLE).into_response();
        }
        if path == "/login" {
            return match gateway.app.login_challenge().await {
                Err(e) => error(e),
                Ok(challenge) => {
                    let html = format!(
                        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Sign in</title><link rel=\"stylesheet\" href=\"/_noxide/style.css\"></head><body><main><h1>Sign in</h1><form method=\"post\" action=\"/login\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><label>Username<input name=\"username\" autocomplete=\"username\" maxlength=\"32\" required></label><label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" maxlength=\"256\" required></label><button>Sign in</button></form></main></body></html>",
                        challenge.csrf
                    );
                    let mut response = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
                        .into_response();
                    response.headers_mut().insert(
                        header::SET_COOKIE,
                        set_cookie(LOGIN, &challenge.cookie, gateway.origin.secure, 900),
                    );
                    response
                }
            };
        }
        let session = match cookie(headers, SESSION) {
            Ok(s) => s,
            Err(_) => return redirect("/login"),
        };
        let route = gateway.app.manifest.routes.iter().find_map(|r| {
            if !r.record && r.path == path {
                Some((r.id, None))
            } else if r.record {
                path.strip_prefix(&format!("{}/", r.path.trim_end_matches('/')))
                    .and_then(|id| id.parse::<u64>().ok())
                    .map(|id| (r.id, Some(id)))
            } else {
                None
            }
        });
        return match route {
            Some((route, target)) => {
                match gateway.app.view_page(&session, route, target, cursor).await {
                    Ok(r) => rendered(r),
                    Err(e) => error(e),
                }
            }
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    if request.method() != axum::http::Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if cursor.is_some() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get(header::ORIGIN).and_then(|h| h.to_str().ok())
            != Some(&gateway.origin.serialized)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .is_none_or(|v| {
                !matches!(
                    v,
                    "application/x-www-form-urlencoded"
                        | "application/x-www-form-urlencoded; charset=UTF-8"
                        | "application/x-www-form-urlencoded; charset=utf-8"
                )
            })
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let session = cookie(headers, SESSION);
    let login = cookie(headers, LOGIN);
    let bytes = match tokio::time::timeout(
        Duration::from_secs(30),
        to_bytes(request.into_body(), MAX_ENCODED_FORM_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let mut form = match decode_form(&bytes) {
        Ok(form) => form,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Some(csrf) = form.remove("_csrf") else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if path == "/login" {
        let (Some(username), Some(password)) = (form.remove("username"), form.remove("password"))
        else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        if !form.is_empty() {
            return StatusCode::BAD_REQUEST.into_response();
        }
        return match gateway
            .app
            .login(&login.unwrap_or_default(), &csrf, &username, &password)
            .await
        {
            Ok(signed) => {
                let mut response = redirect("/");
                response.headers_mut().append(
                    header::SET_COOKIE,
                    set_cookie(SESSION, &signed, gateway.origin.secure, 3600),
                );
                response.headers_mut().append(
                    header::SET_COOKIE,
                    set_cookie(LOGIN, "", gateway.origin.secure, 0),
                );
                response
            }
            Err(_) => (
                StatusCode::UNAUTHORIZED,
                "Sign-in failed. Return to the sign-in page and try again.",
            )
                .into_response(),
        };
    }
    let Ok(session) = session else {
        return redirect("/login");
    };
    if path == "/logout" {
        if !form.is_empty() {
            return StatusCode::BAD_REQUEST.into_response();
        }
        return match gateway.app.logout(&session, &csrf).await {
            Ok(()) => {
                let mut r = redirect("/login");
                r.headers_mut().insert(
                    header::SET_COOKIE,
                    set_cookie(SESSION, "", gateway.origin.secure, 0),
                );
                r
            }
            Err(e) => error(e),
        };
    }
    let Some(action) = path
        .strip_prefix("/_noxide/action/")
        .and_then(|n| n.parse::<u32>().ok())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(submission) = form.remove("_submission") else {
        return StatusCode::FORBIDDEN.into_response();
    };
    match gateway
        .app
        .submit(&session, action, &submission, &csrf, form.clone())
        .await
    {
        Ok(r) => rendered(r),
        Err(e) => {
            let unknown = matches!(e, RequestError::OutcomeUnknown);
            match gateway
                .app
                .recover_form(&session, action, &submission, &csrf, &form, unknown)
                .await
            {
                Ok(r) => rendered(r),
                Err(_) => error(e),
            }
        }
    }
}

trait Transport: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Transport for T {}

pub struct Listener(ListenerKind);

enum ListenerKind {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix {
        listener: tokio::net::UnixListener,
        path: std::path::PathBuf,
        identity: (u64, u64),
    },
}
impl Listener {
    pub async fn loopback(address: std::net::SocketAddr) -> Result<Self> {
        ensure!(address.ip().is_loopback(), "listener must bind loopback");
        Ok(Self(ListenerKind::Tcp(
            tokio::net::TcpListener::bind(address).await?,
        )))
    }
    #[cfg(unix)]
    pub fn unix(path: &std::path::Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let path = std::path::absolute(path)?;
        let listener = tokio::net::UnixListener::bind(&path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        Ok(Self(ListenerKind::Unix {
            listener,
            path,
            identity: (metadata.dev(), metadata.ino()),
        }))
    }
    async fn accept(&self) -> std::io::Result<Box<dyn Transport>> {
        match &self.0 {
            ListenerKind::Tcp(l) => Ok(Box::new(l.accept().await?.0)),
            #[cfg(unix)]
            ListenerKind::Unix { listener, .. } => Ok(Box::new(listener.accept().await?.0)),
        }
    }
}

#[cfg(unix)]
impl Drop for Listener {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if let ListenerKind::Unix { path, identity, .. } = &self.0
            && let Ok(metadata) = std::fs::symlink_metadata(path)
            && metadata.file_type().is_socket()
            && (metadata.dev(), metadata.ino()) == *identity
        {
            // Only remove our own socket. Never remove a pre-existing or
            // replacement file, including after a failed deployment activation.
            let _ = std::fs::remove_file(path);
        }
    }
}

pub async fn serve(
    listener: Listener,
    app: Arc<Application>,
    origin: Origin,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let router = router(app, origin);
    let slots = Arc::new(Semaphore::new(64));
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            Some(_)=connections.join_next(),if !connections.is_empty()=>{},
            accepted=listener.accept()=>{
                let stream=accepted?;
                let Ok(permit)=slots.clone().try_acquire_owned() else {drop(stream);continue};
                let service=hyper_util::service::TowerToHyperService::new(router.clone());
                connections.spawn(async move {
                    let _permit=permit;
                    let mut http=hyper::server::conn::http1::Builder::new();
                    http.timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(30)).max_headers(64).max_buf_size(32*1024);
                    let connection=http.serve_connection(hyper_util::rt::TokioIo::new(stream),service);
                    let _=tokio::time::timeout(Duration::from_secs(60),connection).await;
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
    Ok(())
}

use tokio::sync::Semaphore;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_listener_cleans_up_only_its_own_socket() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("runtime.sock");
        let listener = Listener::unix(&path).unwrap();
        assert!(Listener::unix(&path).is_err());
        assert!(path.exists());
        drop(listener);
        assert!(!path.exists());
        let listener = Listener::unix(&path).unwrap();
        std::fs::rename(&path, temp.path().join("old.sock")).unwrap();
        std::fs::write(&path, "replacement").unwrap();
        drop(listener);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
        assert!(Listener::unix(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
    }
    #[test]
    fn strict_form_canonicalization() {
        assert_eq!(
            decode_form(b"body=hello+world%0D%0A").unwrap()["body"],
            "hello world\n"
        );
        for invalid in [
            b"body=a&body=b".as_slice(),
            b"body=%FF",
            b"body=%",
            b"body=%GG",
        ] {
            assert!(decode_form(invalid).is_err());
        }
        assert!(
            decode_form(
                format!("body={}", "x".repeat(noxide_protocol::MAX_INPUT_BYTES)).as_bytes()
            )
            .is_err()
        );
    }
    #[test]
    fn origin_has_no_clearnet_default() {
        assert!(Origin::parse("https://example.com").is_err());
        assert!(Origin::parse("http://localhost:8080").is_ok());
        assert!(Origin::parse("http://user@localhost/").is_err());
        assert!(Origin::parse("http://localhost/path").is_err());
    }
}
