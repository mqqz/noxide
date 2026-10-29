mod transport;
use crate::{
    Application, RequestError,
    render::{CSP, Rendered},
    runtime::limiter::{
        HEADER_READ_TIMEOUT, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_CIRCUIT, PROXY_LINE_MAX,
        PROXY_LINE_TIMEOUT,
    },
};
use anyhow::{Result, ensure};
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::Router,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};
#[cfg(test)]
use transport::*;
pub use transport::{Listener, serve};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Peer {
    Local,
    Circuit(u32),
}

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
fn error(error: RequestError, login_path: &str) -> Response {
    let status = match error {
        RequestError::Authentication => return redirect(login_path),
        RequestError::Busy => return busy(),
        RequestError::InvalidRequest => StatusCode::BAD_REQUEST,
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

async fn dispatch(State(gateway): State<Arc<Gateway>>, request: Request) -> Response {
    let presentation = &gateway.app.presentation;
    use crate::runtime::limiter::{AdmissionContext, AdmissionIdentity, RequestClass};
    let app = gateway.app.clone();
    let peer = request
        .extensions()
        .get::<Peer>()
        .copied()
        .unwrap_or(Peer::Local);
    let path = request.uri().path();
    let class = if request.method() == axum::http::Method::GET {
        RequestClass::Get
    } else if path == app.presentation.login_path || path == presentation.registration_path {
        RequestClass::PasswordHash
    } else if capability_path(path, &app.presentation).is_some()
        || path
            .strip_prefix(&format!("{}/", app.presentation.action_path))
            .and_then(|s| s.parse().ok())
            .and_then(|id| crate::manifest::action(&app.manifest, id).ok())
            .and_then(|a| crate::manifest::operation(&app.manifest, a.operation).ok())
            .is_some_and(crate::manifest::anonymous_action)
    {
        RequestClass::AnonymousAction
    } else {
        RequestClass::AuthenticatedAction
    };
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
    let public = (path == presentation.registration_path
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
            Ok(Some(principal)) => context.identity = AdmissionIdentity::Verified { principal },
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
    if path == presentation.registration_path
        && gateway.app.registration == crate::Registration::Closed
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if request.method() == axum::http::Method::GET {
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
                    .view_page_anonymous(
                        session.as_deref(),
                        cookie(headers, &presentation.anonymous_cookie)
                            .ok()
                            .as_deref(),
                        route.id,
                        target,
                        cursor,
                    )
                    .await
                {
                    Ok(r) => rendered(r, gateway.origin.secure, presentation),
                    Err(e) => error(e, &presentation.login_path),
                }
            }
            None => {
                // Preserve the existing unknown-path response after route lookup.
                if cookie(headers, &presentation.session_cookie).is_err() {
                    redirect(&presentation.login_path)
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }
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
    let anonymous = cookie(headers, &presentation.anonymous_cookie);
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
    let op = match crate::manifest::action(&gateway.app.manifest, action)
        .and_then(|a| crate::manifest::operation(&gateway.app.manifest, a.operation))
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
mod tests {
    #[tokio::test]
    async fn browser_encoded_maximum_fields_save_and_recover() {
        use crate::{
            Application, Database, HostKeys, manifest, runtime::Limits, test_support as fixture,
        };
        use noxide_protocol::{Fields, Manifest, TextField};
        use std::sync::Arc;

        async fn app(db: Database, m: Manifest) -> Arc<Application> {
            db.initialize().await.unwrap();
            db.create_account("alice", "review test password", "")
                .await
                .unwrap();
            let app = Arc::new(
                Application::new(
                    &fixture::component(None),
                    &serde_json::to_vec(&m).unwrap(),
                    manifest::digest(&m).unwrap(),
                    db,
                    HostKeys::generate().unwrap(),
                    Limits::default(),
                )
                .unwrap(),
            );
            app.activate().await.unwrap();
            app
        }

        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let temp = tempfile::tempdir().unwrap();
        let mut m = fixture::manifest();
        m.resources[0].fields.push(TextField {
            kind: noxide_protocol::FieldKind::Text,
            optional: false,
            initial: None,
            name: "extra".into(),
            label: "Extra".into(),
            max_bytes: 4096,
        });
        m.actions[0].fields.push("extra".into());
        let app = app(Database::sqlite(temp.path().join("forms.db")), m).await;
        let challenge = app.login_challenge().await.unwrap();
        let session = app
            .login(
                &challenge.cookie,
                &challenge.csrf,
                "alice",
                "review test password",
            )
            .await
            .unwrap();
        let page = String::from_utf8(app.view(&session, 1, None).await.unwrap().body).unwrap();
        let token = fixture::hidden(&page, "_submission");
        let csrf = fixture::hidden(&page, "_csrf");
        let router = crate::http::router(
            app.clone(),
            crate::http::Origin::parse("http://localhost:8080").unwrap(),
        );
        let request = |body| {
            Request::builder()
                .method("POST")
                .uri("/actions/1")
                .header("Host", "localhost:8080")
                .header("Origin", "http://localhost:8080")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", format!("session={session}"))
                .body(Body::from(body))
                .unwrap()
        };
        let encoded = |tail: &str, token: &str| {
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("_csrf", &csrf)
                .append_pair("_submission", token)
                .append_pair("body", &format!("{}{tail}", "\r\n".repeat(4095)))
                .append_pair("extra", &format!("{}x", "\r\n".repeat(4095)))
                .finish()
        };
        let body = encoded("x", &token);
        assert!(body.len() > 49_000);
        let saved = router.clone().oneshot(request(body)).await.unwrap();
        assert_eq!(saved.status(), StatusCode::SEE_OTHER);
        // An equivalent non-CRLF encoding has the same canonical receipt identity.
        let canonical = Fields::from([
            ("body".into(), format!("{}x", "\n".repeat(4095))),
            ("extra".into(), format!("{}x", "\n".repeat(4095))),
        ]);
        let replay = app
            .submit(&session, 1, &token, &csrf, canonical)
            .await
            .unwrap();
        assert_eq!(saved.headers()["Location"], replay.location.unwrap());
        let page = String::from_utf8(app.view(&session, 1, None).await.unwrap().body).unwrap();
        let fresh = fixture::hidden(&page, "_submission");
        let invalid = router
            .clone()
            .oneshot(request(encoded("xx", &fresh)))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let html = String::from_utf8(
            to_bytes(invalid.into_body(), noxide_protocol::MAX_OUTPUT_BYTES)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("aria-invalid=\"true\"") && html.contains(&fresh));
        assert!(html.contains(&format!(">{}xx</textarea>", "\n".repeat(4096))));
        let oversized = router.oneshot(request("x".repeat(65_537))).await.unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

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
                    csrf_field: "check".into(),
                    submission_field: "ticket".into(),
                    ..Presentation::default()
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
            let csrf = fixture::hidden(&login, &p.csrf_field);
            let challenge = cookie(&login, &p.login_cookie);
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair(&p.csrf_field, &csrf)
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
            let submission = fixture::hidden(&page, &p.submission_field);
            // The account navigation has a CSRF field too; it uses the same session token.
            let csrf = fixture::hidden(&page, &p.csrf_field);
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair(&p.csrf_field, &csrf)
                .append_pair(&p.submission_field, &submission)
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
                &post(
                    &p.logout_path,
                    &cookie_header,
                    &format!("{}={csrf}", p.csrf_field),
                ),
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

#[cfg(test)]
mod admission_tests;
