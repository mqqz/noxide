#![cfg_attr(test, allow(clippy::too_many_lines))]
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
mod endpoint;
mod forms;
mod pages;
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
use endpoint::Endpoint;
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

fn registration_failed(presentation: &crate::Presentation) -> Response {
    (StatusCode::UNPROCESSABLE_ENTITY, [(header::CONTENT_TYPE,"text/html; charset=utf-8")], format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Registration failed</title></head><body><main><h1>Registration failed</h1><p>Registration failed. Return to registration and try again.</p><a href=\"{}\">Return to registration</a></main></body></html>", presentation.registration_path)).into_response()
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
    let is_get = request.method() == axum::http::Method::GET;
    let endpoint = Endpoint::classify(&app, is_get, path);
    let class = endpoint.class(is_get);
    let scope = app.http_request_scope(
        endpoint.deadline(class),
        request.extensions().get::<TransportDeadline>().copied(),
    );
    scope
        .run(async {
            let path = request.uri().path();
            let presentation = &app.web.presentation;
            let mut context = AdmissionContext {
                peer,
                class,
                identity: AdmissionIdentity::Anonymous,
            };
            if !app
                .limits
                .admission
                .charge_circuit(context.peer, context.class)
            {
                return finish(busy());
            }
            if request.method() == axum::http::Method::GET
                && let Some(route) = app
                    .identity
                    .manifest
                    .routes
                    .iter()
                    .find(|r| crate::routing::match_path(r, path).is_some())
                && parse_query(&app.identity.manifest, route, request.uri().query()).is_err()
            {
                let Ok(_permit) = app.limits.admission.requests.request().await else {
                    return finish(busy());
                };
                return finish(StatusCode::NOT_FOUND.into_response());
            }
            let public = path.starts_with(noxide_protocol::assets::ASSET_PATH_PREFIX)
                || (path == presentation.registration_path
                    && app.web.registration == crate::Registration::Closed)
                || app
                    .identity
                    .manifest
                    .routes
                    .iter()
                    .find(|r| crate::render::match_path(r, path).is_some())
                    .is_some_and(|r| r.access == noxide_protocol::Access::Public);
            if !public
                && !matches!(class, RequestClass::PasswordHash)
                && let Ok(cookie) = cookie(request.headers(), &app.web.presentation.session_cookie)
                && app.session_envelope(&cookie)
            {
                context.identity = AdmissionIdentity::Candidate;
                match app.session_candidate(&cookie).await {
                    Ok(Some(principal)) => {
                        context.identity = AdmissionIdentity::Verified { principal }
                    }
                    Ok(None) => {
                        app.limits.admission.failed_session(peer);
                        context.identity = AdmissionIdentity::Anonymous;
                    }
                    Err(e) => return finish(error(e, &app.web.presentation.login_path)),
                }
            }
            if let AdmissionIdentity::Verified { principal } = &context.identity
                && matches!(class, RequestClass::AuthenticatedAction)
                && !app.limits.admission.principal_action(principal)
            {
                return finish(busy());
            }
            app.limits
                .admission
                .context(context, async {
                    let Ok(permit) = app.limits.admission.requests().request().await else {
                        return finish(busy());
                    };
                    finish(
                        app.limits
                            .admission
                            .scope(permit, dispatch_inner(gateway, request, endpoint))
                            .await,
                    )
                })
                .await
        })
        .await
}
async fn dispatch_inner(
    gateway: Arc<Gateway>,
    request: Request,
    endpoint: Endpoint<'_>,
) -> Response {
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
    match endpoint {
        Endpoint::Download => return blobs::download(gateway, request).await,
        Endpoint::Asset => return pages::asset(&gateway, &request),
        Endpoint::ClosedRegistration => return StatusCode::NOT_FOUND.into_response(),
        _ => {}
    }
    if request.method() != axum::http::Method::GET {
        return forms::post(gateway, request, endpoint).await;
    }
    match endpoint {
        Endpoint::Account => pages::account(&gateway, headers).await,
        Endpoint::Registration => pages::registration(&gateway).await,
        Endpoint::Stylesheet(css) => pages::stylesheet(css),
        Endpoint::Login => pages::login(&gateway).await,
        Endpoint::Capability { resource, id } => {
            pages::capability(&gateway, headers, resource, id).await
        }
        Endpoint::Page { route, target } => {
            pages::route_page(&gateway, headers, request.uri().query(), route, target).await
        }
        _ => StatusCode::NOT_FOUND.into_response(),
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
