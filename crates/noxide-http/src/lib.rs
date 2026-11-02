pub(crate) use noxide_admission::{Presentation, manifest, routing};
#[cfg(test)]
pub(crate) use noxide_admission::{assets, policy, query_plan, schema};
#[cfg(test)]
pub(crate) use noxide_authority::auth;
pub(crate) use noxide_authority::auth::{Registration, account_id};
pub(crate) use noxide_authority::{limiter, security};
pub(crate) use noxide_host::application;
#[cfg(test)]
pub(crate) use noxide_host::{
    BlobDeployment, DeploymentResources, HostKeys, deployment, repository, runtime, test_account,
};
pub(crate) use noxide_render as render;
#[cfg(test)]
pub(crate) use noxide_store::Database;
pub(crate) use noxide_store::database;
#[cfg(test)]
pub(crate) use noxide_store::lifecycle_clock;
#[cfg(test)]
use noxide_test_support as test_support;
#[cfg(test)]
mod action_meter_tests;
#[cfg(test)]
mod anonymous_tests;
#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod parameter_tests;
#[cfg(test)]
mod public_tests;
#[cfg(test)]
mod registration_tests;
#[cfg(test)]
use crate::auth::AccountAdmin as _;
mod blobs;
mod transport;
use crate::{
    limiter::{
        HEADER_READ_TIMEOUT, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_CIRCUIT, PROXY_LINE_MAX,
        PROXY_LINE_TIMEOUT,
    },
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
pub(crate) use noxide_host::{Application, RequestError};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};
#[cfg(test)]
use transport::*;
pub use transport::{BoundListener, Listener, reclaim_stale_socket, serve};

pub(crate) use crate::limiter::Peer;

const BUSY_HTML: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Service busy</title></head><body><main><h1>Service busy</h1><p>The service is busy. Retry this request.</p></main></body></html>";
fn busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        BUSY_HTML,
    )
        .into_response()
}

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

pub(crate) use crate::limiter::TransportDeadline;

struct Gateway {
    app: Arc<Application>,
    origin: Origin,
}

pub fn router(app: Arc<Application>, origin: Origin) -> Router {
    Router::new()
        .fallback(dispatch)
        .with_state(Arc::new(Gateway { app, origin }))
}

pub(crate) fn parse_query(
    m: &noxide_protocol::Manifest,
    route: &noxide_protocol::Route,
    raw: Option<&str>,
) -> Result<(Option<String>, noxide_protocol::Fields)> {
    let raw = raw.unwrap_or("");
    const INPUT_BYTES: usize = 1024;
    const CURSOR_COMPONENT_BYTES: usize = "cursor=".len() + crate::security::MAX_TOKEN_BYTES;
    ensure!(
        raw.len() <= INPUT_BYTES + CURSOR_COMPONENT_BYTES + 1,
        "query string limit"
    );
    let bytes = raw.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'%' {
            ensure!(
                bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit),
                "invalid query encoding"
            );
        }
    }
    let mut values = noxide_protocol::Fields::new();
    let mut cursor_component = None;
    for component in raw.split('&') {
        for (key, value) in url::form_urlencoded::parse(component.as_bytes()) {
            if key == "cursor" {
                ensure!(
                    component.len() <= CURSOR_COMPONENT_BYTES
                        && value.len() <= crate::security::MAX_TOKEN_BYTES,
                    "cursor transport limit"
                );
                cursor_component = Some(component.len());
            }
            ensure!(
                values
                    .insert(key.into_owned(), value.into_owned())
                    .is_none(),
                "duplicate query parameter"
            );
        }
    }
    // Only one bounded opaque cursor component, plus its separator, is outside
    // the unchanged raw input allowance. Padding and encoded ordinary controls
    // still count against the original limit.
    let input_bytes = cursor_component.map_or(raw.len(), |length| {
        raw.len() - length - usize::from(raw.len() > length)
    });
    ensure!(input_bytes <= INPUT_BYTES, "query string limit");
    for key in values.keys() {
        ensure!(
            key == "cursor" || route.params.iter().any(|name| name == key),
            "unknown query parameter"
        );
    }
    let cursor = values.remove("cursor");
    crate::manifest::validate_params(m, route, &values)?;
    Ok((cursor, values))
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
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(CSP));
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

fn rendered(value: Rendered, secure: bool, presentation: &crate::Presentation) -> Response {
    let mut response = (
        StatusCode::from_u16(value.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        value.body,
    )
        .into_response();
    if let Some(cookie) = value.anonymous_cookie {
        response.headers_mut().append(
            header::SET_COOKIE,
            set_cookie(
                &presentation.anonymous_cookie,
                &cookie,
                secure,
                crate::security::ANONYMOUS_TTL as u32,
            ),
        );
    }
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
fn cursor_error(restart: &str) -> Response {
    let escaped = restart
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    (StatusCode::BAD_REQUEST,[(header::CONTENT_TYPE,"text/html; charset=utf-8")],format!("<!doctype html><p>This pagination link is invalid or has expired.</p><a href=\"{escaped}\">Restart pagination</a>")).into_response()
}

fn error(error: RequestError, login_path: &str) -> Response {
    let status = match error {
        RequestError::Authentication => return redirect(login_path),
        RequestError::Busy => return busy(),
        RequestError::InvalidRequest | RequestError::InvalidCursor => StatusCode::BAD_REQUEST,
        RequestError::Rejected => StatusCode::UNPROCESSABLE_ENTITY,
        RequestError::OutcomeUnknown => StatusCode::SERVICE_UNAVAILABLE,
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
        // Scalar inputs retain their existing 32-field schema plus three host
        // credentials. Up to four separately bounded target handles are envelope
        // proofs; they still share the same encoded/decoded byte limits.
        ensure!(result.len() < 39, "field count");
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
        let selection = key.starts_with("_target_");
        ensure!(
            key.len() <= if selection { 40 } else { 32 },
            "field name limit"
        );
        let count = result
            .keys()
            .filter(|name: &&String| name.starts_with("_target_") == selection)
            .count();
        ensure!(count < if selection { 4 } else { 35 }, "field count");
        ensure!(result.insert(key, value).is_none(), "duplicate field");
    }
    Ok(result)
}

fn capability_path(path: &str, presentation: &crate::Presentation) -> Option<(u32, u64)> {
    let (resource, id) = path
        .strip_prefix(&format!("{}/", presentation.capability_path))?
        .split_once('/')?;
    let r: u32 = resource.parse().ok()?;
    let n: u64 = id.parse().ok()?;
    (r > 0 && n > 0 && n <= i64::MAX as u64 && r.to_string() == resource && n.to_string() == id)
        .then_some((r, n))
}

fn registration_failed(presentation: &crate::Presentation) -> Response {
    (StatusCode::UNPROCESSABLE_ENTITY, [(header::CONTENT_TYPE,"text/html; charset=utf-8")], format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Registration failed</title></head><body><main><h1>Registration failed</h1><p>Registration failed. Return to registration and try again.</p><a href=\"{}\">Return to registration</a></main></body></html>", presentation.registration_path)).into_response()
}

fn request_class(
    app: &Application,
    method: &axum::http::Method,
    path: &str,
) -> crate::limiter::RequestClass {
    use crate::limiter::RequestClass;
    if method == axum::http::Method::GET {
        RequestClass::Get
    } else if path == app.presentation.login_path || path == app.presentation.registration_path {
        RequestClass::PasswordHash
    } else if capability_path(path, &app.presentation).is_some()
        || path
            .strip_prefix(&format!("{}/", app.presentation.action_path))
            .and_then(|s| s.parse().ok())
            .and_then(|id| crate::manifest::web_action(&app.manifest, id).ok())
            .and_then(|a| crate::manifest::operation(&app.manifest, a.steps[0].operation).ok())
            .is_some_and(crate::manifest::anonymous_action)
    {
        RequestClass::AnonymousAction
    } else {
        RequestClass::AuthenticatedAction
    }
}

async fn dispatch(State(gateway): State<Arc<Gateway>>, request: Request) -> Response {
    use crate::limiter::{AdmissionContext, AdmissionIdentity, RequestClass};
    let app = gateway.app.clone();
    let peer = request
        .extensions()
        .get::<Peer>()
        .copied()
        .unwrap_or(Peer::Local);
    let path = request.uri().path();
    let class = request_class(&app, request.method(), path);
    let scope = app.http_request_scope(
        class,
        path,
        request.extensions().get::<TransportDeadline>().copied(),
    );
    scope
        .run(async {
            let path = request.uri().path();
            let presentation = &app.presentation;
            let mut context = AdmissionContext {
                peer,
                class,
                identity: AdmissionIdentity::Anonymous,
            };
            if !app
                .admission_limits
                .charge_circuit(context.peer, context.class)
            {
                return finish(busy());
            }
            if request.method() == axum::http::Method::GET
                && let Some(route) = app
                    .manifest
                    .routes
                    .iter()
                    .find(|r| crate::routing::match_path(r, path).is_some())
                && parse_query(&app.manifest, route, request.uri().query()).is_err()
            {
                let Ok(_permit) = app.admission_limits.requests.request().await else {
                    return finish(busy());
                };
                return finish(StatusCode::NOT_FOUND.into_response());
            }
            let public = path.starts_with(noxide_protocol::assets::ASSET_PATH_PREFIX)
                || (path == presentation.registration_path
                    && app.registration == crate::Registration::Closed)
                || app
                    .manifest
                    .routes
                    .iter()
                    .find(|r| crate::render::match_path(r, path).is_some())
                    .is_some_and(|r| r.access == noxide_protocol::Access::Public);
            if !public
                && !matches!(class, RequestClass::PasswordHash)
                && let Ok(cookie) = cookie(request.headers(), &app.presentation.session_cookie)
                && app.session_envelope(&cookie)
            {
                context.identity = AdmissionIdentity::Candidate;
                match app.session_candidate(&cookie).await {
                    Ok(Some(principal)) => {
                        context.identity = AdmissionIdentity::Verified { principal }
                    }
                    Ok(None) => {
                        app.admission_limits.failed_session(peer);
                        context.identity = AdmissionIdentity::Anonymous;
                    }
                    Err(e) => return finish(error(e, &app.presentation.login_path)),
                }
            }
            if let AdmissionIdentity::Verified { principal } = &context.identity
                && matches!(class, RequestClass::AuthenticatedAction)
                && !app.admission_limits.principal_action(principal)
            {
                return finish(busy());
            }
            app.admission_limits
                .context(context, async {
                    let Ok(permit) = app.admission_limits.requests().request().await else {
                        return finish(busy());
                    };
                    finish(
                        app.admission_limits
                            .scope(permit, dispatch_inner(gateway, request))
                            .await,
                    )
                })
                .await
        })
        .await
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
    let path = request.uri().path().to_owned();
    if path == "/_noxide/download" {
        return blobs::download(gateway, request).await;
    }
    if path.starts_with(noxide_protocol::assets::ASSET_PATH_PREFIX) {
        if headers.contains_key(header::TRANSFER_ENCODING)
            || headers
                .get_all(header::CONTENT_LENGTH)
                .iter()
                .any(|value| value.as_bytes() != b"0")
        {
            return (StatusCode::BAD_REQUEST, [(header::CONNECTION, "close")]).into_response();
        }
        if request.method() != axum::http::Method::GET || request.uri().query().is_some() {
            return StatusCode::NOT_FOUND.into_response();
        }
        let Some(asset) = gateway.app.assets.at_path(&path) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let Ok(permit) = gateway.app.asset_responses.clone().try_acquire_owned() else {
            return busy();
        };
        struct AssetBody {
            bytes: Arc<[u8]>,
            _permit: tokio::sync::OwnedSemaphorePermit,
        }
        impl AsRef<[u8]> for AssetBody {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        let bytes = axum::body::Bytes::from_owner(AssetBody {
            bytes: asset.shared_bytes(),
            _permit: permit,
        });
        return (
            [(header::CONTENT_TYPE, asset.declaration().media_type.mime())],
            bytes,
        )
            .into_response();
    }

    if path == presentation.registration_path
        && gateway.app.registration == crate::Registration::Closed
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if request.method() == axum::http::Method::GET {
        if path == presentation.account_path {
            let session =
                cookie(request.headers(), &presentation.session_cookie).unwrap_or_default();
            return match gateway.app.account_identity(&session).await {
                Ok(id) if crate::account_id(&id) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Your account</title><nav><a href=\"/\">Home</a></nav><main><h1>Your account ID</h1><p>Share this ID with someone who needs to address you.</p><code>{id}</code></main></html>")).into_response(),
                Ok(_) => redirect(&presentation.login_path),
                Err(e) => error(e, &presentation.login_path),
            };
        }
        if path == presentation.registration_path {
            return match gateway.app.login_challenge().await {
                Err(e) => error(e, &presentation.login_path),
                Ok(challenge) => {
                    let invite = if gateway.app.registration == crate::Registration::Invite {
                        "<label>Invite code<input type=\"password\" name=\"invite\" autocomplete=\"off\" maxlength=\"43\" required></label>"
                    } else {
                        ""
                    };
                    let html = format!(
                        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Create account</title></head><body><main><h1>Create account</h1><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"{}\" value=\"{}\"><label>Username<input name=\"username\" autocomplete=\"username\" maxlength=\"32\" required></label><label>Password<input type=\"password\" name=\"password\" autocomplete=\"new-password\" maxlength=\"256\" required></label>{invite}<button>Create account</button></form></main></body></html>",
                        presentation.registration_path, presentation.csrf_field, challenge.csrf
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
                        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Sign in</title>{}</head><body><main><h1>Sign in</h1><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"{}\" value=\"{}\"><label>Username<input name=\"username\" autocomplete=\"username\" maxlength=\"32\" required></label><label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" maxlength=\"256\" required></label><button>Sign in</button></form></main></body></html>",
                        if presentation.stylesheet.is_some() {
                            format!(
                                "<link rel=\"stylesheet\" href=\"{}\">",
                                presentation.stylesheet_path
                            )
                        } else {
                            String::new()
                        },
                        presentation.login_path,
                        presentation.csrf_field,
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
        if let Some((resource, id)) = capability_path(&path, presentation) {
            return match gateway
                .app
                .capability_page(
                    resource,
                    id,
                    cookie(headers, &presentation.anonymous_cookie)
                        .ok()
                        .as_deref(),
                )
                .await
            {
                Ok(page) => rendered(page, gateway.origin.secure, presentation),
                Err(e) => error(e, &presentation.login_path),
            };
        }
        let route = gateway.app.manifest.routes.iter().find_map(|route| {
            crate::render::match_path(route, &path).map(|target| (route, target))
        });
        return match route {
            Some((route, target)) => {
                let Ok((cursor, params)) =
                    parse_query(&gateway.app.manifest, route, request.uri().query())
                else {
                    return StatusCode::NOT_FOUND.into_response();
                };

                let session = match route.access {
                    noxide_protocol::Access::Public => None,
                    noxide_protocol::Access::Authenticated => {
                        match cookie(headers, &presentation.session_cookie) {
                            Ok(session) => Some(session),
                            Err(_) => return redirect(&presentation.login_path),
                        }
                    }
                    noxide_protocol::Access::PublicOptional => {
                        cookie(headers, &presentation.session_cookie).ok()
                    }
                };
                match gateway
                    .app
                    .view_page_parameters(
                        session.as_deref(),
                        cookie(headers, &presentation.anonymous_cookie)
                            .ok()
                            .as_deref(),
                        route.id,
                        target,
                        cursor.as_deref(),
                        params.clone(),
                    )
                    .await
                {
                    Ok(r) => rendered(r, gateway.origin.secure, presentation),
                    Err(RequestError::InvalidCursor) => {
                        // Resolve the restart URL from the current route, never token data.
                        let restart = crate::routing::resolve(
                            &gateway.app.manifest,
                            &noxide_protocol::RouteRef {
                                params: params.clone(),
                                route: route.id,
                                target,
                            },
                        );
                        match restart {
                            Ok(url) => cursor_error(&url),
                            Err(_) => error(RequestError::InvalidRequest, &presentation.login_path),
                        }
                    }
                    Err(e) => error(e, &presentation.login_path),
                }
            }
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    if request.method() != axum::http::Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if request.uri().query().is_some() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get(header::ORIGIN).and_then(|h| h.to_str().ok())
            != Some(&gateway.origin.serialized)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if headers.get_all(header::CONTENT_TYPE).iter().count() == 1
        && headers
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|v| v.starts_with("multipart/form-data"))
    {
        return blobs::upload(gateway, request).await;
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
    let anonymous = cookie(headers, &presentation.anonymous_cookie);
    let body_deadline = crate::database::lifecycle::RequestScope::current_work_deadline()
        .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(30));
    let bytes = match tokio::time::timeout_at(
        body_deadline,
        to_bytes(request.into_body(), MAX_ENCODED_FORM_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let mut form = match decode_form(&bytes) {
        Ok(form) => form,
        Err(_) if path == presentation.registration_path => {
            return registration_failed(presentation);
        }
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Some(csrf) = form.remove(&presentation.csrf_field) else {
        return if path == presentation.registration_path {
            registration_failed(presentation)
        } else {
            StatusCode::FORBIDDEN.into_response()
        };
    };
    if path == presentation.registration_path {
        let (Some(username), Some(password)) = (form.remove("username"), form.remove("password"))
        else {
            return registration_failed(presentation);
        };
        let invite = if gateway.app.registration == crate::Registration::Invite {
            form.remove("invite")
        } else {
            None
        };
        if !form.is_empty()
            || (gateway.app.registration == crate::Registration::Invite && invite.is_none())
        {
            return registration_failed(presentation);
        }
        return match gateway
            .app
            .register(
                &login.unwrap_or_default(),
                &csrf,
                &username,
                &password,
                invite.as_deref(),
            )
            .await
        {
            Ok(()) => {
                let mut response = redirect(&presentation.login_path);
                response.headers_mut().insert(
                    header::SET_COOKIE,
                    set_cookie(&presentation.login_cookie, "", gateway.origin.secure, 0),
                );
                response
            }
            Err(RequestError::Busy) => busy(),
            Err(RequestError::OutcomeUnknown) => {
                error(RequestError::OutcomeUnknown, &presentation.login_path)
            }
            Err(_) => registration_failed(presentation),
        };
    }
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
            Err(RequestError::Busy) => busy(),
            Err(RequestError::OutcomeUnknown) => {
                error(RequestError::OutcomeUnknown, &presentation.login_path)
            }
            Err(_) => (
                StatusCode::UNAUTHORIZED,
                "Sign-in failed. Return to the sign-in page and try again.",
            )
                .into_response(),
        };
    }
    if let Some((resource, id)) = capability_path(&path, presentation) {
        let (Some(submission), Some(secret)) = (
            form.remove(&presentation.submission_field),
            form.remove(&presentation.capability_field),
        ) else {
            return StatusCode::FORBIDDEN.into_response();
        };
        if !form.is_empty() {
            return StatusCode::BAD_REQUEST.into_response();
        }
        return match gateway
            .app
            .rotate_capability(
                resource,
                id,
                &anonymous.unwrap_or_default(),
                &csrf,
                &submission,
                &secret,
            )
            .await
        {
            Ok(page) => rendered(page, gateway.origin.secure, presentation),
            Err(e) => error(e, &presentation.login_path),
        };
    }
    if path == presentation.logout_path {
        let Ok(session) = session else {
            return redirect(&presentation.login_path);
        };
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
    let op = match crate::manifest::web_action(&gateway.app.manifest, action)
        .and_then(|a| crate::manifest::operation(&gateway.app.manifest, a.steps[0].operation))
    {
        Ok(op) => op,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let capability = form.remove(&presentation.capability_field);
    if capability.is_some() && !crate::manifest::is_capability(op) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let session = if crate::manifest::anonymous_action(op) {
        anonymous.unwrap_or_default()
    } else {
        match session {
            Ok(session) => session,
            Err(_) => return redirect(&presentation.login_path),
        }
    };
    let Some(submission) = form.remove(&presentation.submission_field) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    match gateway
        .app
        .submit_with_capability(
            &session,
            action,
            &submission,
            &csrf,
            form.clone(),
            capability.as_deref(),
        )
        .await
    {
        Ok(r) => rendered(r, gateway.origin.secure, presentation),
        Err(RequestError::Busy) => busy(),
        Err(e) => {
            let unknown = matches!(e, RequestError::OutcomeUnknown);
            let recovered = if let Some(capability) = capability.as_deref() {
                gateway
                    .app
                    .recover_form_with_capability(
                        &session,
                        action,
                        &submission,
                        &csrf,
                        &form,
                        unknown,
                        Some(capability),
                    )
                    .await
            } else {
                gateway
                    .app
                    .recover_form(&session, action, &submission, &csrf, &form, unknown)
                    .await
            };
            match recovered {
                Ok(r) => rendered(r, gateway.origin.secure, presentation),
                Err(_) => error(e, &presentation.login_path),
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod admission_tests;

#[cfg(test)]
mod cursor_recovery_tests;
#[cfg(test)]
mod endpoint_tests;

#[cfg(test)]
mod parent_redirect_disconnect_tests;

#[cfg(test)]
mod binding_tests;

#[cfg(test)]
mod cursor_query_tests;

#[cfg(test)]
mod picker_form_tests;
