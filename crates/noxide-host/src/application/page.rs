//! Running a page's guest handler and rendering the result.
use super::*;

pub(super) fn cursor_scope(
    identity: (&str, &str),
    route: u32,
    target: Option<u64>,
    scope_incarnation: Option<String>,
    list: Option<&Operation>,
    subject: &str,
    params: &Fields,
) -> serde_json::Result<String> {
    let (contract, deployment) = identity;
    if params.is_empty() {
        serde_json::to_string(&(
            contract,
            deployment,
            route,
            target,
            scope_incarnation,
            list,
            subject,
        ))
    } else {
        serde_json::to_string(&(
            contract,
            deployment,
            route,
            target,
            scope_incarnation,
            list,
            subject,
            params,
        ))
    }
}

impl Application {
    /// Without HTTP, for tests; a request reaches `view_page_parameters`.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn view(
        &self,
        cookie: &str,
        route: u32,
        target: Option<u64>,
    ) -> std::result::Result<Rendered, RequestError> {
        self.view_page(Some(cookie), route, target, None).await
    }

    /// Without HTTP, for tests; a request reaches `view_page_parameters`.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn view_page(
        &self,
        cookie: Option<&str>,
        route: u32,
        target: Option<u64>,
        cursor: Option<&str>,
    ) -> std::result::Result<Rendered, RequestError> {
        self.view_page_anonymous(cookie, None, route, target, cursor)
            .await
    }

    /// Without HTTP, for tests; a request reaches `view_page_parameters`.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn view_page_anonymous(
        &self,
        cookie: Option<&str>,
        anonymous_cookie: Option<&str>,
        route: u32,
        target: Option<u64>,
        cursor: Option<&str>,
    ) -> std::result::Result<Rendered, RequestError> {
        self.view_page_parameters(
            cookie,
            anonymous_cookie,
            route,
            target,
            cursor,
            Fields::new(),
        )
        .await
    }

    #[allow(clippy::too_many_lines)]
    pub async fn view_page_parameters(
        &self,
        cookie: Option<&str>,
        anonymous_cookie: Option<&str>,
        route: u32,
        target: Option<u64>,
        cursor: Option<&str>,
        params: Fields,
    ) -> std::result::Result<Rendered, RequestError> {
        let entry_scope = self.request_scope(self.runtime.limits().wall_time);
        entry_scope.run(async {
        let _request = self
            .limits.admission
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::deadline())?;
        let _database = self
            .limits.admission
            .database()
            .acquire()
            .await
            .map_err(|_| RequestError::deadline())?;
        if cursor.is_some_and(|c| c.len() > 4096) {
            return Err(RequestError::InvalidCursor);
        }
        let params = self.canonical_route_params(route, params)?;
        let reference = RouteRef {
            params: params.clone(),
            route,
            target,
        };
        render::resolve(&self.identity.manifest, &reference).map_err(|_| RequestError::InvalidRequest)?;
        let owner = self.owned_request(
            _request,
            Arc::new(_database),
            None,
            self.runtime.limits().wall_time,
        );
        let deadline = owner.work_deadline();
        owner.run(async {

        timeout_at(deadline, async {
            let mut tx = self
                .database
                .begin_read(deadline.into_std())
                .await
                .map_err(|_| RequestError::deadline())?;
            self.admission(&mut tx, false)
                .await
                .map_err(RequestError::database)?;
            let now = security::now().map_err(|_| RequestError::Rejected)?;
            let now = security::observe_clock_read(&mut tx, now, &self.time.observed)
                .await
                .map_err(RequestError::database)?;
            self.time.observed.fetch_max(now, Ordering::Relaxed);

            let access = &manifest::route(&self.identity.manifest, route)
                .map_err(|_| RequestError::InvalidRequest)?
                .access;
            let authenticated = self.route_identity(&mut tx, access, cookie, now).await?;
            let (session, principal) = match authenticated {
                Some((token, principal)) => (Some(token), principal),
                None => (None, auth::Principal::Anonymous),
            };
            let mut database_calls = crate::repository::MAX_LIST_DATABASE_CALLS;
            let time = if crate::authority::uses_time(&self.identity.manifest) {
                database_calls = database_calls.checked_sub(1).ok_or(RequestError::Busy)?;
                Some(self.temporal_after_admission(&mut tx).await?)
            } else { None };
            let mut authority = self.authority_context(time).map_err(RequestError::database)?;
            let list = manifest::route(&self.identity.manifest,route).map_err(|_| RequestError::InvalidRequest)?.operations.iter().filter_map(|id| manifest::operation(&self.identity.manifest,*id).ok()).find(|op| op.kind==OperationKind::List && !manifest::is_preview(op));
            let scope = self.cursor_scope_digest(&mut tx, route, target, list, &principal, &params, &mut database_calls).await?;
            let preview_only = list.is_none() && manifest::route(&self.identity.manifest, route).map_err(|_| RequestError::InvalidRequest)?.operations.iter().any(|id| manifest::operation(&self.identity.manifest,*id).is_ok_and(manifest::is_preview));
            if preview_only && cursor.is_some() { return Err(RequestError::InvalidCursor); }
            let cursor = cursor.map(|encoded| self.verified_cursor(encoded, now, &scope, list)).transpose()?;
            let (anonymous, new_cookie) = self.page_anonymous_token(route, anonymous_cookie, now)?;
            let mut forms = self.forms(&mut tx, &mut authority, &mut database_calls, route, target, session.as_ref(), anonymous.as_ref(), &principal, now).await.map_err(|_| RequestError::Rejected)?;
            let request = RequestView {
                params: params.clone(),
                available_forms: forms
                    .iter()
                    .filter_map(|(id, form)| form.as_ref().map(|_| *id))
                    .collect(),
                version: VERSION,
                kind: RequestKind::Route(route),
                target,
                input: Fields::new(),
                inspection: BTreeMap::new(),
            };
            let effects = Effects {
                authority,
                upload: None,
                blob_reads: Default::default(),
                provenance: Default::default(),
                follow_sources: Vec::new(),
                invoked: Default::default(),
                list_bytes: 0,
                list_calls: database_calls,
                result_limit: noxide_protocol::MAX_RESULT_BYTES,
                truncated: false,
                see_all: Vec::new(),
                plans: self.identity.plans.clone(),
                tx,
                manifest: self.identity.manifest.clone(),
                principal,
                request: request.clone(),
                grants: BTreeMap::new(),
                target_rows: BTreeMap::new(),
                written_rows: Default::default(),
                capability_grant: None,
                calls: 16,
                cursor,
                more: None,
            };
            let _wasm = self
                .limits.admission
                .wasm()
                .acquire()
                .await
                .map_err(|_| RequestError::deadline())?;
            let attempt = self
                .runtime
                .run(
                    request,
                    Some(effects),
                    self.runtime.limits().fuel,
                    self.runtime.limits().host_calls,
                    deadline,
                )
                .await;
            let mut effects = attempt.effects.ok_or(RequestError::Rejected)?;
            let response = attempt
                .result
                .map_err(|error| RequestError::database(guest_error(error)))?;
            if !matches!(
                response,
                ResponseIntent::Page(_) | ResponseIntent::NotFound(_) | ResponseIntent::Redirect(_)
            ) {
                return Err(RequestError::Rejected);
            }
            let next_page = effects.more.take().map(|after| {
                let (_,encoded)=self.keys.issue(TokenKind::Cursor {scope:scope.clone(),after},"",now,900).map_err(|_|RequestError::Rejected)?;
                let path = crate::routing::resolve(&self.identity.manifest,&reference).expect("validated route");
                Ok(format!("{path}{}cursor={encoded}", if params.is_empty() { "?" } else { "&" }))
            }).transpose()?;
            self.complete_target_forms(&mut effects, &response, &mut forms, session.as_ref(), anonymous.as_ref(), now).await.map_err(RequestError::database)?;
            let mut rendered = render::render(
                &response,
                &RenderContext {
                    checkpoint: RequestScope::checkpoint_current,
                    presentation: &self.web.presentation,
                    assets: &self.web.assets,
                    manifest: Some(&self.identity.manifest),
                    forms,
                    logout_csrf: session
                        .as_ref()
                        .map(|session| self.keys.csrf(&session.nonce))
                        .transpose()
                        .map_err(|_| RequestError::Busy)?,
                    next_page,
                    preview_links: effects.see_all.clone(),
                    downloads: self.download_links(&effects, session.as_ref(), now).map_err(RequestError::database)?,
                },
            )
            .map_err(RequestError::database)?;
            if let ResponseIntent::Page(doc) | ResponseIntent::NotFound(doc) = &response
                && doc.nodes.iter().any(|n| matches!(n, Instruction::Form { action } if self.is_anonymous_form(*action))) { rendered.anonymous_cookie = new_cookie; }
            Self::finish_commit(&mut effects.tx, rendered).await
        })
        .await
        .map_err(|_| RequestError::deadline())?
        }).await
        }).await
    }

    /// Validate a route's parameters and normalize its search terms.
    fn canonical_route_params(
        &self,
        route: u32,
        params: Fields,
    ) -> std::result::Result<Fields, RequestError> {
        let mut params = params;
        let route_definition = manifest::route(&self.identity.manifest, route)
            .map_err(|_| RequestError::InvalidRequest)?;
        manifest::validate_params(&self.identity.manifest, route_definition, &params)
            .map_err(|_| RequestError::InvalidRequest)?;
        for (name, field) in manifest::parameter_fields(&self.identity.manifest, route_definition)
            .map_err(|_| RequestError::InvalidRequest)?
        {
            if matches!(field, manifest::ParameterField::Search) {
                let raw = params.get(&name).ok_or(RequestError::InvalidRequest)?;
                let tokens =
                    crate::search::canonical_query(raw, &mut RequestScope::checkpoint_current)
                        .map_err(|_| RequestError::InvalidRequest)?;
                params.insert(name, tokens.tokens().join(" "));
            }
        }
        Ok(params)
    }

    /// What a cursor is bound to. A fixed-size digest binds every approved setting
    /// without exposing it in URLs.
    #[allow(clippy::too_many_arguments)]
    async fn cursor_scope_digest(
        &self,
        tx: &mut Transaction,
        route: u32,
        target: Option<u64>,
        list: Option<&Operation>,
        principal: &auth::Principal,
        params: &Fields,
        database_calls: &mut usize,
    ) -> std::result::Result<String, RequestError> {
        let scope_incarnation = if let (Some(target), Some(op)) = (target, list) {
            if let Some(parent) = op
                .scope
                .as_deref()
                .map(|field| {
                    manifest::reference_resource(&self.identity.manifest, op.resource, field)
                })
                .transpose()
                .map_err(|_| RequestError::Rejected)?
                .flatten()
            {
                *database_calls = database_calls.checked_sub(2).ok_or(RequestError::Busy)?;
                crate::repository::load(tx, &self.identity.manifest, parent.id, target)
                    .await
                    .map_err(RequestError::database)?
                    .map(|r| r.incarnation)
            } else {
                None
            }
        } else {
            None
        };
        let subject = principal.user().map(|u| u.id.as_str()).unwrap_or("");
        let scope = cursor_scope(
            (&self.identity.contract, &self.identity.deployment),
            route,
            target,
            scope_incarnation,
            list,
            subject,
            params,
        )
        .map_err(|_| RequestError::Rejected)?;
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(scope.as_bytes())))
    }

    fn verified_cursor(
        &self,
        encoded: &str,
        now: i64,
        scope: &str,
        list: Option<&Operation>,
    ) -> std::result::Result<noxide_protocol::query::CursorKey, RequestError> {
        let token = self
            .keys
            .verify_cursor(encoded, now)
            .map_err(|_| RequestError::InvalidCursor)?;
        let TokenKind::Cursor {
            scope: bound,
            after,
        } = token.kind
        else {
            return Err(RequestError::InvalidCursor);
        };
        let op = list.ok_or(RequestError::InvalidCursor)?;
        if bound != *scope {
            return Err(RequestError::InvalidCursor);
        }
        self.identity
            .plans
            .get(&op.id)
            .ok_or(RequestError::InvalidCursor)?
            .validate_cursor(&self.identity.manifest, &after)
            .map_err(|_| RequestError::InvalidCursor)?;
        Ok(after)
    }

    /// The anonymous token this page's forms need, and a cookie if it had to be issued.
    fn page_anonymous_token(
        &self,
        route: u32,
        anonymous_cookie: Option<&str>,
        now: i64,
    ) -> std::result::Result<(Option<Token>, Option<String>), RequestError> {
        let needs_anonymous = manifest::route(&self.identity.manifest, route)
            .map_err(|_| RequestError::InvalidRequest)?
            .forms
            .iter()
            .any(|id| self.is_anonymous_form(*id));
        Ok(if needs_anonymous {
            if let Some(token) = anonymous_cookie.and_then(|c| self.keys.anonymous(c, now).ok()) {
                (Some(token), None)
            } else {
                let (token, cookie) = self
                    .keys
                    .issue(TokenKind::Anonymous, "", now, security::ANONYMOUS_TTL)
                    .map_err(|_| RequestError::Rejected)?;
                (Some(token), Some(cookie))
            }
        } else {
            (None, None)
        })
    }

    fn is_anonymous_form(&self, id: u32) -> bool {
        manifest::web_action(&self.identity.manifest, id)
            .ok()
            .and_then(|a| ActionCore::of(a.core).ok())
            .and_then(|a| manifest::operation(&self.identity.manifest, a.first_operation()).ok())
            .is_some_and(manifest::anonymous_action)
    }
}

#[cfg(test)]
mod query_compatibility_tests;
