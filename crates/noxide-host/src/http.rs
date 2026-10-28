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
fn redirect(location: &str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}
fn error(error: RequestError, login_path: &str) -> Response {
    let status = match error {
        RequestError::Authentication => return redirect(login_path),
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
    let presentation = &gateway.app.presentation;
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
        if path == presentation.stylesheet_path
            && let Some(css) = &presentation.stylesheet
        {
            return (
                [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                css.clone(),
            )
                .into_response();
        }
        if path == presentation.login_path {
            return match gateway.app.login_challenge().await {
                Err(e) => error(e, &presentation.login_path),
                Ok(challenge) => {
                    let html = format!(
                        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Sign in</title>{}</head><body><main><h1>Sign in</h1><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><label>Username<input name=\"username\" autocomplete=\"username\" maxlength=\"32\" required></label><label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" maxlength=\"256\" required></label><button>Sign in</button></form></main></body></html>",
                        if presentation.stylesheet.is_some() {
                            format!(
                                "<link rel=\"stylesheet\" href=\"{}\">",
                                presentation.stylesheet_path
                            )
                        } else {
                            String::new()
                        },
                        presentation.login_path,
                        challenge.csrf
                    );
                    let mut response = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
                        .into_response();
                    response.headers_mut().insert(
                        header::SET_COOKIE,
                        set_cookie(
                            &presentation.login_cookie,
                            &challenge.cookie,
                            gateway.origin.secure,
                            900,
                        ),
                    );
                    response
                }
            };
        }
        let session = match cookie(headers, &presentation.session_cookie) {
            Ok(s) => s,
            Err(_) => return redirect(&presentation.login_path),
        };
        let route = gateway.app.manifest.routes.iter().find_map(|route| {
            crate::render::match_path(route, &path).map(|target| (route.id, target))
        });
        return match route {
            Some((route, target)) => {
                match gateway.app.view_page(&session, route, target, cursor).await {
                    Ok(r) => rendered(r),
                    Err(e) => error(e, &presentation.login_path),
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
    let session = cookie(headers, &presentation.session_cookie);
    let login = cookie(headers, &presentation.login_cookie);
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
    if path == presentation.login_path {
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
                    set_cookie(
                        &presentation.session_cookie,
                        &signed,
                        gateway.origin.secure,
                        3600,
                    ),
                );
                response.headers_mut().append(
                    header::SET_COOKIE,
                    set_cookie(&presentation.login_cookie, "", gateway.origin.secure, 0),
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
        return redirect(&presentation.login_path);
    };
    if path == presentation.logout_path {
        if !form.is_empty() {
            return StatusCode::BAD_REQUEST.into_response();
        }
        return match gateway.app.logout(&session, &csrf).await {
            Ok(()) => {
                let mut r = redirect(&presentation.login_path);
                r.headers_mut().insert(
                    header::SET_COOKIE,
                    set_cookie(&presentation.session_cookie, "", gateway.origin.secure, 0),
                );
                r
            }
            Err(e) => error(e, &presentation.login_path),
        };
    }
    let Some(action) = path
        .strip_prefix(&format!("{}/", presentation.action_path))
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
                Err(_) => error(e, &presentation.login_path),
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
    let checkpoint_app = app.clone();
    let checkpoint = tokio::spawn(async move { checkpoint_app.checkpoint_clocks().await });
    // Abort on normal shutdown, errors, and cancellation of serve itself.
    struct Checkpoint(tokio::task::JoinHandle<()>);
    impl Drop for Checkpoint {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _checkpoint = Checkpoint(checkpoint);
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
                    http.auto_date_header(false).timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(30)).max_headers(64).max_buf_size(32*1024);
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
    async fn exchange(address: std::net::SocketAddr, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8(bytes).unwrap();
        let headers = response
            .split_once("\r\n\r\n")
            .unwrap()
            .0
            .to_ascii_lowercase();
        assert!(!headers.contains("\r\ndate:"), "{headers}");
        assert!(!headers.contains("\r\nserver:"), "{headers}");
        assert!(!response.contains("noxide"), "{response}");
        response
    }

    #[tokio::test]
    async fn socket_responses_use_deployment_presentation_without_clock_headers() {
        use crate::{
            Database, HostKeys, Presentation, manifest, runtime::Limits, test_support as fixture,
        };
        for custom in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let db = Database::sqlite(temp.path().join("http.db"));
            db.initialize().await.unwrap();
            db.create_account("alice", "socket test password", "")
                .await
                .unwrap();
            let m = fixture::manifest();
            let p = if custom {
                Presentation {
                    session_cookie: "account".into(),
                    login_cookie: "challenge".into(),
                    login_path: "/signin".into(),
                    logout_path: "/signout".into(),
                    action_path: "/submit".into(),
                    stylesheet_path: "/theme.css".into(),
                    stylesheet: Some("body { color: #123; margin: 1rem }".into()),
                }
            } else {
                Presentation::default()
            };
            let app = Arc::new(
                Application::new(
                    &fixture::component(Some("trap")),
                    &serde_json::to_vec(&m).unwrap(),
                    manifest::digest(&m).unwrap(),
                    db,
                    HostKeys::generate().unwrap(),
                    Limits::default(),
                )
                .unwrap()
                .with_presentation(p.clone())
                .unwrap(),
            );
            app.activate().await.unwrap();
            let listener = Listener::loopback("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = match &listener.0 {
                ListenerKind::Tcp(tcp) => tcp.local_addr().unwrap(),
                #[cfg(unix)]
                _ => unreachable!(),
            };
            let origin = format!("http://{address}");
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let serving = tokio::spawn(serve(
                listener,
                app,
                Origin::parse(&origin).unwrap(),
                async {
                    let _ = stopped.await;
                },
            ));
            let get = |path: &str, cookie: &str| {
                format!(
                    "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nCookie: {cookie}\r\n\r\n"
                )
            };
            let post = |path: &str, cookie: &str, body: &str| {
                format!(
                    "POST {path} HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: {cookie}\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
            };
            let cookie = |response: &str, name: &str| {
                response
                    .split_once(&format!("set-cookie: {name}="))
                    .unwrap()
                    .1
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned()
            };
            let redirected = exchange(address, &get("/", "")).await;
            assert!(redirected.starts_with("HTTP/1.1 303"));
            assert!(redirected.contains(&format!("location: {}\r\n", p.login_path)));
            if !custom {
                let absent_css = exchange(address, &get(&p.stylesheet_path, "")).await;
                // An unconfigured asset must behave like any unknown path,
                // rather than retaining a distinctive anonymous 404 endpoint.
                assert_eq!(absent_css, redirected);
            }
            let login = exchange(address, &get(&p.login_path, "")).await;
            assert!(login.starts_with("HTTP/1.1 200"));
            assert!(login.contains("HttpOnly; SameSite=Strict"));
            assert_eq!(login.contains("rel=\"stylesheet\""), custom);
            let csrf = fixture::hidden(&login, "_csrf");
            let challenge = cookie(&login, &p.login_cookie);
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("_csrf", &csrf)
                .append_pair("username", "alice")
                .append_pair("password", "socket test password")
                .finish();
            let signed = exchange(
                address,
                &post(
                    &p.login_path,
                    &format!("{}={challenge}", p.login_cookie),
                    &body,
                ),
            )
            .await;
            assert!(signed.starts_with("HTTP/1.1 303"));
            let session = cookie(&signed, &p.session_cookie);
            let cookie_header = format!("{}={session}", p.session_cookie);
            let page = exchange(address, &get("/", &cookie_header)).await;
            assert!(page.starts_with("HTTP/1.1 200"));
            assert!(page.contains(&format!("action=\"{}/1\"", p.action_path)));
            assert!(page.contains(&format!("action=\"{}\"", p.logout_path)));
            assert_eq!(page.contains("rel=\"stylesheet\""), custom);
            let submission = fixture::hidden(&page, "_submission");
            // The account navigation has a CSRF field too; it uses the same session token.
            let csrf = fixture::hidden(&page, "_csrf");
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("_csrf", &csrf)
                .append_pair("_submission", &submission)
                .append_pair("body", "a note")
                .finish();
            let recovery = exchange(
                address,
                &post(&format!("{}/1", p.action_path), &cookie_header, &body),
            )
            .await;
            assert!(recovery.starts_with("HTTP/1.1 422"));
            assert!(recovery.contains(&format!("action=\"{}/1\"", p.action_path)));
            assert_eq!(recovery.contains("rel=\"stylesheet\""), custom);
            let css = exchange(address, &get(&p.stylesheet_path, &cookie_header)).await;
            if custom {
                assert!(css.starts_with("HTTP/1.1 200"));
                assert!(css.ends_with(p.stylesheet.as_ref().unwrap()));
            } else {
                assert!(css.starts_with("HTTP/1.1 404"));
            }
            let missing = exchange(address, &get("/missing", &cookie_header)).await;
            assert!(missing.starts_with("HTTP/1.1 404"));
            let logout = exchange(
                address,
                &post(&p.logout_path, &cookie_header, &format!("_csrf={csrf}")),
            )
            .await;
            assert!(logout.starts_with("HTTP/1.1 303"));
            assert!(logout.contains(&format!("set-cookie: {}=;", p.session_cookie)));
            let malformed = exchange(address, "GET / HTTP/1.1\r\nbad header\r\n\r\n").await;
            assert!(malformed.starts_with("HTTP/1.1 400"));
            stop.send(()).unwrap();
            serving.await.unwrap().unwrap();
        }
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
