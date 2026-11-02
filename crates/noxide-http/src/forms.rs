//! Responses to POST requests. Every form passes the same origin, content type,
//! body size and CSRF presence checks before its handler runs.
use super::{endpoint::Endpoint, *};

/// A decoded form body, its CSRF field and the cookies it arrived with.
struct Submitted {
    form: BTreeMap<String, String>,
    csrf: String,
    session: Result<String>,
    login: Result<String>,
    anonymous: Result<String>,
}

pub(super) async fn post(
    gateway: Arc<Gateway>,
    request: Request,
    endpoint: Endpoint<'_>,
) -> Response {
    let headers = request.headers();
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
    let registering = matches!(endpoint, Endpoint::Registration);
    let submitted = match read_form(&gateway, request, registering).await {
        Ok(submitted) => submitted,
        Err(response) => return *response,
    };
    match endpoint {
        Endpoint::Registration => registration(&gateway, submitted).await,
        Endpoint::Login => login(&gateway, submitted).await,
        Endpoint::Capability { resource, id } => {
            capability(&gateway, submitted, resource, id).await
        }
        Endpoint::Logout => logout(&gateway, submitted).await,
        Endpoint::Action { id, operation } => action(&gateway, submitted, id, operation).await,
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn read_form(
    gateway: &Gateway,
    request: Request,
    registering: bool,
) -> std::result::Result<Submitted, Box<Response>> {
    let presentation = &gateway.app.web.presentation;
    let headers = request.headers();
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
        return Err(Box::new(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()));
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
        _ => return Err(Box::new(StatusCode::PAYLOAD_TOO_LARGE.into_response())),
    };
    let mut form = match decode_form(&bytes) {
        Ok(form) => form,
        Err(_) if registering => {
            return Err(Box::new(registration_failed(presentation)));
        }
        Err(_) => return Err(Box::new(StatusCode::BAD_REQUEST.into_response())),
    };
    let Some(csrf) = form.remove(&presentation.csrf_field) else {
        return Err(Box::new(if registering {
            registration_failed(presentation)
        } else {
            StatusCode::FORBIDDEN.into_response()
        }));
    };
    Ok(Submitted {
        form,
        csrf,
        session,
        login,
        anonymous,
    })
}

async fn registration(gateway: &Gateway, submitted: Submitted) -> Response {
    let presentation = &gateway.app.web.presentation;
    let Submitted {
        mut form,
        csrf,
        login,
        ..
    } = submitted;
    let (Some(username), Some(password)) = (form.remove("username"), form.remove("password"))
    else {
        return registration_failed(presentation);
    };
    let invite = if gateway.app.web.registration == crate::Registration::Invite {
        form.remove("invite")
    } else {
        None
    };
    if !form.is_empty()
        || (gateway.app.web.registration == crate::Registration::Invite && invite.is_none())
    {
        return registration_failed(presentation);
    }
    match gateway
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
    }
}

async fn login(gateway: &Gateway, submitted: Submitted) -> Response {
    let presentation = &gateway.app.web.presentation;
    let Submitted {
        mut form,
        csrf,
        login,
        ..
    } = submitted;
    let (Some(username), Some(password)) = (form.remove("username"), form.remove("password"))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !form.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match gateway
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
    }
}

async fn capability(gateway: &Gateway, submitted: Submitted, resource: u32, id: u64) -> Response {
    let presentation = &gateway.app.web.presentation;
    let Submitted {
        mut form,
        csrf,
        anonymous,
        ..
    } = submitted;
    let (Some(submission), Some(secret)) = (
        form.remove(&presentation.submission_field),
        form.remove(&presentation.capability_field),
    ) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !form.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match gateway
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
    }
}

async fn logout(gateway: &Gateway, submitted: Submitted) -> Response {
    let presentation = &gateway.app.web.presentation;
    let Submitted {
        form,
        csrf,
        session,
        ..
    } = submitted;
    let Ok(session) = session else {
        return redirect(&presentation.login_path);
    };
    if !form.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match gateway.app.logout(&session, &csrf).await {
        Ok(()) => {
            let mut r = redirect(&presentation.login_path);
            r.headers_mut().insert(
                header::SET_COOKIE,
                set_cookie(&presentation.session_cookie, "", gateway.origin.secure, 0),
            );
            r
        }
        Err(e) => error(e, &presentation.login_path),
    }
}

async fn action(
    gateway: &Gateway,
    submitted: Submitted,
    action: u32,
    op: &noxide_protocol::Operation,
) -> Response {
    let presentation = &gateway.app.web.presentation;
    let Submitted {
        mut form,
        csrf,
        session,
        anonymous,
        ..
    } = submitted;
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
