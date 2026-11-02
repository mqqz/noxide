//! Responses to GET requests, and static assets for any method.
use super::*;

pub(super) fn asset(gateway: &Gateway, request: &Request) -> Response {
    let headers = request.headers();
    let path = request.uri().path();
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
    let Some(asset) = gateway.app.web.assets.at_path(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(permit) = gateway.app.web.asset_responses.clone().try_acquire_owned() else {
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
    (
        [(header::CONTENT_TYPE, asset.declaration().media_type.mime())],
        bytes,
    )
        .into_response()
}

pub(super) async fn account(gateway: &Gateway, headers: &HeaderMap) -> Response {
    let presentation = &gateway.app.web.presentation;
    let session = cookie(headers, &presentation.session_cookie).unwrap_or_default();
    match gateway.app.account_identity(&session).await {
                Ok(id) if crate::account_id(&id) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Your account</title><nav><a href=\"/\">Home</a></nav><main><h1>Your account ID</h1><p>Share this ID with someone who needs to address you.</p><code>{id}</code></main></html>")).into_response(),
                Ok(_) => redirect(&presentation.login_path),
                Err(e) => error(e, &presentation.login_path),
            }
}

pub(super) async fn registration(gateway: &Gateway) -> Response {
    let presentation = &gateway.app.web.presentation;
    match gateway.app.login_challenge().await {
        Err(e) => error(e, &presentation.login_path),
        Ok(challenge) => {
            let invite = if gateway.app.web.registration == crate::Registration::Invite {
                "<label>Invite code<input type=\"password\" name=\"invite\" autocomplete=\"off\" maxlength=\"43\" required></label>"
            } else {
                ""
            };
            let html = format!(
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Create account</title></head><body><main><h1>Create account</h1><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"{}\" value=\"{}\"><label>Username<input name=\"username\" autocomplete=\"username\" maxlength=\"32\" required></label><label>Password<input type=\"password\" name=\"password\" autocomplete=\"new-password\" maxlength=\"256\" required></label>{invite}<button>Create account</button></form></main></body></html>",
                presentation.registration_path, presentation.csrf_field, challenge.csrf
            );
            let mut response =
                ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response();
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
    }
}

pub(super) fn stylesheet(css: &str) -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        css.to_owned(),
    )
        .into_response()
}

pub(super) async fn login(gateway: &Gateway) -> Response {
    let presentation = &gateway.app.web.presentation;
    match gateway.app.login_challenge().await {
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
            let mut response =
                ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response();
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
    }
}

pub(super) async fn capability(
    gateway: &Gateway,
    headers: &HeaderMap,
    resource: u32,
    id: u64,
) -> Response {
    let presentation = &gateway.app.web.presentation;
    match gateway
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
    }
}

pub(super) async fn route_page(
    gateway: &Gateway,
    headers: &HeaderMap,
    query: Option<&str>,
    route: &noxide_protocol::Route,
    target: Option<u64>,
) -> Response {
    let presentation = &gateway.app.web.presentation;
    let Ok((cursor, params)) = parse_query(&gateway.app.identity.manifest, route, query) else {
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
                &gateway.app.identity.manifest,
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
