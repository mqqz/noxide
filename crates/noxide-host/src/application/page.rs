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
        entry_scope
            .run(async {
                let _request = self
                    .limits
                    .admission
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let _database = self
                    .limits
                    .admission
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
                render::resolve(&self.identity.manifest, &reference)
                    .map_err(|_| RequestError::InvalidRequest)?;
                let owner = self.owned_request(
                    _request,
                    Arc::new(_database),
                    None,
                    self.runtime.limits().wall_time,
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        timeout_at(deadline, async {
                            self.page_attempt(
                                cookie,
                                anonymous_cookie,
                                cursor,
                                &reference,
                                deadline,
                            )
                            .await
                        })
                        .await
                        .map_err(|_| RequestError::deadline())?
                    })
                    .await
            })
            .await
    }

    /// One read transaction: authenticate, build forms, run the guest and render.
    async fn page_attempt(
        &self,
        cookie: Option<&str>,
        anonymous_cookie: Option<&str>,
        cursor: Option<&str>,
        reference: &RouteRef,
        deadline: Instant,
    ) -> std::result::Result<Rendered, RequestError> {
        let (route, target, params) = (reference.route, reference.target, &reference.params);
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
        } else {
            None
        };
        let mut authority = self
            .authority_context(time)
            .map_err(RequestError::database)?;
        let (scope, cursor) = self
            .page_cursor(
                &mut tx,
                reference,
                &principal,
                cursor,
                now,
                &mut database_calls,
            )
            .await?;
        let (anonymous, new_cookie) = self.page_anonymous_token(route, anonymous_cookie, now)?;
        let mut forms = self
            .forms(
                &mut tx,
                &mut authority,
                &mut database_calls,
                route,
                target,
                session.as_ref(),
                anonymous.as_ref(),
                &principal,
                now,
            )
            .await
            .map_err(|_| RequestError::Rejected)?;
        let request = Self::page_request(params, &forms, route, target);
        let effects = self.page_effects(
            tx,
            authority,
            principal,
            request.clone(),
            database_calls,
            cursor,
        );
        let _wasm = self
            .limits
            .admission
            .wasm()
            .acquire()
            .await
            .map_err(|_| RequestError::deadline())?;
        let (mut effects, response) = self.run_page_guest(request, effects, deadline).await?;
        let next_page = self.next_page_link(effects.more.take(), &scope, reference, now)?;
        self.complete_target_forms(
            &mut effects,
            &response,
            &mut forms,
            session.as_ref(),
            anonymous.as_ref(),
            now,
        )
        .await
        .map_err(RequestError::database)?;
        let rendered = self.render_page(
            &effects,
            &response,
            forms,
            session.as_ref(),
            now,
            next_page,
            new_cookie,
        )?;
        Self::finish_commit(&mut effects.tx, rendered).await
    }

    /// Verify the request's cursor against what it was issued for. Returns that scope,
    /// which signs the next cursor, with the verified position.
    async fn page_cursor(
        &self,
        tx: &mut Transaction,
        reference: &RouteRef,
        principal: &auth::Principal,
        cursor: Option<&str>,
        now: i64,
        database_calls: &mut usize,
    ) -> std::result::Result<(String, Option<noxide_protocol::query::CursorKey>), RequestError>
    {
        let (route, target, params) = (reference.route, reference.target, &reference.params);
        let list = manifest::route(&self.identity.manifest, route)
            .map_err(|_| RequestError::InvalidRequest)?
            .operations
            .iter()
            .filter_map(|id| manifest::operation(&self.identity.manifest, *id).ok())
            .find(|op| op.kind == OperationKind::List && !manifest::is_preview(op));
        let scope = self
            .cursor_scope_digest(tx, route, target, list, principal, params, database_calls)
            .await?;
        let preview_only = list.is_none()
            && manifest::route(&self.identity.manifest, route)
                .map_err(|_| RequestError::InvalidRequest)?
                .operations
                .iter()
                .any(|id| {
                    manifest::operation(&self.identity.manifest, *id)
                        .is_ok_and(manifest::is_preview)
                });
        if preview_only && cursor.is_some() {
            return Err(RequestError::InvalidCursor);
        }
        let cursor = cursor
            .map(|encoded| self.verified_cursor(encoded, now, &scope, list))
            .transpose()?;
        Ok((scope, cursor))
    }

    /// A signed link to the page after `after`, when there is one.
    fn next_page_link(
        &self,
        after: Option<noxide_protocol::query::CursorKey>,
        scope: &str,
        reference: &RouteRef,
        now: i64,
    ) -> std::result::Result<Option<String>, RequestError> {
        let params = &reference.params;
        after
            .map(|after| {
                let (_, encoded) = self
                    .keys
                    .issue(
                        TokenKind::Cursor {
                            scope: scope.to_owned(),
                            after,
                        },
                        "",
                        now,
                        900,
                    )
                    .map_err(|_| RequestError::Rejected)?;
                let path = crate::routing::resolve(&self.identity.manifest, reference)
                    .expect("validated route");
                Ok(format!(
                    "{path}{}cursor={encoded}",
                    if params.is_empty() { "?" } else { "&" }
                ))
            })
            .transpose()
    }

    fn page_request(
        params: &Fields,
        forms: &BTreeMap<u32, Option<FormCredentials>>,
        route: u32,
        target: Option<u64>,
    ) -> RequestView {
        RequestView {
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
        }
    }

    /// What the guest may touch while it builds this page.
    fn page_effects(
        &self,
        tx: Transaction,
        authority: crate::authority::Authority,
        principal: auth::Principal,
        request: RequestView,
        database_calls: usize,
        cursor: Option<noxide_protocol::query::CursorKey>,
    ) -> Effects {
        Effects {
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
            request,
            grants: BTreeMap::new(),
            target_rows: BTreeMap::new(),
            written_rows: Default::default(),
            capability_grant: None,
            calls: 16,
            cursor,
            more: None,
        }
    }

    async fn run_page_guest(
        &self,
        request: RequestView,
        effects: Effects,
        deadline: Instant,
    ) -> std::result::Result<(Effects, ResponseIntent), RequestError> {
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
        let effects = attempt.effects.ok_or(RequestError::Rejected)?;
        let response = attempt
            .result
            .map_err(|error| RequestError::database(guest_error(error)))?;
        if !matches!(
            response,
            ResponseIntent::Page(_) | ResponseIntent::NotFound(_) | ResponseIntent::Redirect(_)
        ) {
            return Err(RequestError::Rejected);
        }
        Ok((effects, response))
    }

    /// Render the guest's response. The anonymous cookie is sent only with a page that
    /// has an anonymous form.
    #[allow(clippy::too_many_arguments)]
    fn render_page(
        &self,
        effects: &Effects,
        response: &ResponseIntent,
        forms: BTreeMap<u32, Option<FormCredentials>>,
        session: Option<&Token>,
        now: i64,
        next_page: Option<String>,
        new_cookie: Option<String>,
    ) -> std::result::Result<Rendered, RequestError> {
        let mut rendered = render::render(
            response,
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
                downloads: self
                    .download_links(effects, session, now)
                    .map_err(RequestError::database)?,
            },
        )
        .map_err(RequestError::database)?;
        if let ResponseIntent::Page(doc) | ResponseIntent::NotFound(doc) = response
            && doc.nodes.iter().any(
                |n| matches!(n, Instruction::Form { action } if self.is_anonymous_form(*action)),
            )
        {
            rendered.anonymous_cookie = new_cookie;
        }
        Ok(rendered)
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
