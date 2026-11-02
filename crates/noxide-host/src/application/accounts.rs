//! Registration, login, logout and session identity.
use super::*;

pub(crate) fn authentication_error(error: auth::AuthError) -> RequestError {
    match error {
        auth::AuthError::Invalid => RequestError::Authentication,
        auth::AuthError::Unavailable => RequestError::Busy,
    }
}

pub struct LoginChallenge {
    pub cookie: String,
    pub csrf: String,
}

impl Application {
    pub async fn register(
        &self,
        challenge: &str,
        csrf: &str,
        username: &str,
        password: &str,
        invite: Option<&str>,
    ) -> std::result::Result<(), RequestError> {
        let entry_scope = self.request_scope(std::time::Duration::from_secs(3));
        entry_scope
            .run(async {
                if self.registration == auth::Registration::Closed {
                    return Err(RequestError::InvalidRequest);
                }
                let request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let database = Arc::new(
                    self.admission_limits
                        .database()
                        .acquire()
                        .await
                        .map_err(|_| RequestError::deadline())?,
                );
                let owner = self.owned_request(
                    request.clone(),
                    database.clone(),
                    None,
                    std::time::Duration::from_secs(3),
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        timeout_at(deadline, async {
                            let mut tx = self
                                .database
                                .begin(deadline.into_std())
                                .await
                                .map_err(|_| RequestError::deadline())?;
                            self.admission(&mut tx, false)
                                .await
                                .map_err(RequestError::database)?;
                            let now = self
                                .observe_clock_write(
                                    &mut tx,
                                    security::now().map_err(|_| RequestError::Rejected)?,
                                )
                                .await
                                .map_err(RequestError::database)?;
                            let token = self
                                .keys
                                .verify(challenge, now)
                                .map_err(|_| RequestError::InvalidRequest)?;
                            if token.kind != TokenKind::Login {
                                return Err(RequestError::InvalidRequest);
                            }
                            self.keys
                                .verify_csrf(&token.nonce, csrf)
                                .map_err(|_| RequestError::InvalidRequest)?;
                            if !self.admission_limits.argon2_attempts.allow() {
                                return Err(RequestError::Busy);
                            }
                            let permit = self
                                .admission_limits
                                .argon2
                                .acquire()
                                .await
                                .map_err(|_| RequestError::deadline())?;
                            let permits = self.admission_limits.hash_permits(
                                permit,
                                request.clone(),
                                database.clone(),
                            );
                            auth::register(
                                &mut tx,
                                self.registration,
                                username,
                                password,
                                invite,
                                now,
                                permits,
                            )
                            .await
                            .map_err(|error| {
                                if error.is::<crate::database::lifecycle::meter::StatementLimit>() {
                                    RequestError::Busy
                                } else {
                                    RequestError::Rejected
                                }
                            })?;
                            Self::finish_commit(&mut tx, ()).await
                        })
                        .await
                        .map_err(|_| RequestError::deadline())?
                    })
                    .await
            })
            .await
    }

    /// Authenticate host-owned account content through normal request admission.
    /// Scheduling preflight must never authorize a response.
    pub async fn account_identity(
        &self,
        cookie: &str,
    ) -> std::result::Result<String, RequestError> {
        let entry_scope = self.request_scope(self.runtime.limits().wall_time);
        entry_scope
            .run(async {
                let _request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let _database = self
                    .admission_limits
                    .database()
                    .acquire()
                    .await
                    .map_err(|_| RequestError::deadline())?;
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
                            let mut tx = self
                                .database
                                .begin_read(deadline.into_std())
                                .await
                                .map_err(|_| RequestError::deadline())?;
                            self.admission(&mut tx, false)
                                .await
                                .map_err(RequestError::database)?;
                            let wall = security::now().map_err(|_| RequestError::Rejected)?;
                            let now = security::observe_clock_read(&mut tx, wall, &self.clock)
                                .await
                                .map_err(RequestError::database)?;
                            self.clock.fetch_max(now, Ordering::Relaxed);
                            let (_, principal) = self
                                .route_identity(&mut tx, &Access::Authenticated, Some(cookie), now)
                                .await?
                                .ok_or(RequestError::Authentication)?;
                            let id = principal
                                .user()
                                .map_err(|_| RequestError::Authentication)?
                                .id
                                .clone();
                            Self::finish_commit(&mut tx, id).await
                        })
                        .await
                        .map_err(|_| RequestError::deadline())?
                    })
                    .await
            })
            .await
    }

    pub async fn session_candidate(
        &self,
        cookie: &str,
    ) -> std::result::Result<Option<String>, RequestError> {
        let entry_scope = self.request_scope(std::time::Duration::from_secs(1));
        entry_scope
            .run(async {
                let scope = self.request_scope(std::time::Duration::from_secs(1));
                let deadline = scope.work_deadline();
                timeout_at(deadline, async {
                    let _request = self
                        .admission_limits
                        .session_requests()
                        .acquire()
                        .await
                        .map_err(|_| RequestError::deadline())?;
                    let _database = self
                        .admission_limits
                        .session_database()
                        .acquire()
                        .await
                        .map_err(|_| RequestError::deadline())?;
                    let owner =
                        AdmissionOwner::new(scope, Arc::new(_request), Arc::new(_database), None);
                    owner
                        .run(async {
                            let mut tx = self
                                .database
                                .begin_read(deadline.into_std())
                                .await
                                .map_err(|_| RequestError::deadline())?;
                            // Scheduling preflight only; the request repeats admission and
                            // authorization inside its own transaction.
                            let now = security::now()
                                .map_err(|_| RequestError::Rejected)?
                                .max(self.clock.load(Ordering::Relaxed));
                            let principal =
                                match auth::authenticate(&mut tx, &self.keys, cookie, now).await {
                                    Ok((_, auth::Principal::User(user))) => Some(user.id),
                                    Err(auth::AuthError::Invalid) => None,
                                    _ => return Err(RequestError::Busy),
                                };
                            Self::finish_commit(&mut tx, principal).await
                        })
                        .await
                })
                .await
                .map_err(|_| RequestError::deadline())?
            })
            .await
    }

    pub fn session_envelope(&self, cookie: &str) -> bool {
        security::now()
            .ok()
            .and_then(|now| {
                self.keys
                    .verify(cookie, now.max(self.clock.load(Ordering::Relaxed)))
                    .ok()
            })
            .is_some_and(|t| t.kind == TokenKind::Session)
    }

    pub async fn login_challenge(&self) -> std::result::Result<LoginChallenge, RequestError> {
        let entry_scope = self.request_scope(std::time::Duration::from_secs(2));
        entry_scope
            .run(async {
                let _request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let _database = self
                    .admission_limits
                    .database()
                    .acquire()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let owner = self.owned_request(
                    _request,
                    Arc::new(_database),
                    None,
                    std::time::Duration::from_secs(2),
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        let mut tx = self
                            .database
                            .begin_read(deadline.into_std())
                            .await
                            .map_err(|_| RequestError::deadline())?;
                        self.admission(&mut tx, false)
                            .await
                            .map_err(RequestError::database)?;
                        let now = security::now().map_err(|_| RequestError::Rejected)?;
                        let now = security::observe_clock_read(&mut tx, now, &self.clock)
                            .await
                            .map_err(RequestError::database)?;
                        self.clock.fetch_max(now, Ordering::Relaxed);

                        let (token, cookie) = self
                            .keys
                            .issue(TokenKind::Login, "", now, 900)
                            .map_err(|_| RequestError::Busy)?;
                        Self::finish_commit(
                            &mut tx,
                            LoginChallenge {
                                cookie,
                                csrf: self
                                    .keys
                                    .csrf(&token.nonce)
                                    .map_err(|_| RequestError::Busy)?,
                            },
                        )
                        .await
                    })
                    .await
            })
            .await
    }

    pub async fn login(
        &self,
        challenge: &str,
        csrf: &str,
        username: &str,
        password: &str,
    ) -> std::result::Result<String, RequestError> {
        let entry_scope = self.request_scope(std::time::Duration::from_secs(3));
        entry_scope
            .run(async {
                let request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let database = Arc::new(
                    self.admission_limits
                        .database()
                        .acquire()
                        .await
                        .map_err(|_| RequestError::deadline())?,
                );
                let owner = self.owned_request(
                    request.clone(),
                    database.clone(),
                    None,
                    std::time::Duration::from_secs(3),
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        timeout_at(deadline, async {
                            let mut tx = self
                                .database
                                .begin(deadline.into_std())
                                .await
                                .map_err(|_| RequestError::deadline())?;
                            self.admission(&mut tx, false)
                                .await
                                .map_err(RequestError::database)?;
                            let now = security::now().map_err(|_| RequestError::Rejected)?;
                            let now = self
                                .observe_clock_write(&mut tx, now)
                                .await
                                .map_err(RequestError::database)?;
                            let token = self
                                .keys
                                .verify(challenge, now)
                                .map_err(|_| RequestError::InvalidRequest)?;
                            if token.kind != TokenKind::Login {
                                return Err(RequestError::InvalidRequest);
                            }
                            self.keys
                                .verify_csrf(&token.nonce, csrf)
                                .map_err(|_| RequestError::InvalidRequest)?;

                            if !self.admission_limits.argon2_attempts.allow() {
                                return Err(RequestError::Busy);
                            }
                            let permit = self
                                .admission_limits
                                .argon2
                                .acquire()
                                .await
                                .map_err(|_| RequestError::deadline())?;
                            let permits = self.admission_limits.hash_permits(
                                permit,
                                request.clone(),
                                database.clone(),
                            );
                            let signed = auth::login(
                                &mut tx, &self.keys, username, password, now, permits,
                            )
                            .await
                            .map_err(|error| {
                                if error.is::<crate::database::lifecycle::meter::StatementLimit>() {
                                    RequestError::Busy
                                } else {
                                    RequestError::Authentication
                                }
                            })?;
                            Self::finish_commit(&mut tx, signed).await
                        })
                        .await
                        .map_err(|_| RequestError::deadline())?
                    })
                    .await
            })
            .await
    }

    pub async fn logout(&self, cookie: &str, csrf: &str) -> std::result::Result<(), RequestError> {
        let entry_scope = self.request_scope(std::time::Duration::from_secs(2));
        entry_scope
            .run(async {
                let _request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let _database = self
                    .admission_limits
                    .database()
                    .acquire()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let owner = self.owned_request(
                    _request,
                    Arc::new(_database),
                    None,
                    std::time::Duration::from_secs(2),
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        let mut tx = self
                            .database
                            .begin(deadline.into_std())
                            .await
                            .map_err(|_| RequestError::deadline())?;
                        self.admission(&mut tx, false)
                            .await
                            .map_err(RequestError::database)?;
                        let now = security::now().map_err(|_| RequestError::Rejected)?;
                        let now = self
                            .observe_clock_write(&mut tx, now)
                            .await
                            .map_err(RequestError::database)?;
                        let (session, _) = auth::authenticate(&mut tx, &self.keys, cookie, now)
                            .await
                            .map_err(authentication_error)?;

                        self.keys
                            .verify_csrf(&session.nonce, csrf)
                            .map_err(|_| RequestError::InvalidRequest)?;
                        tx.run(
                            &noxide_store::statements::accounts::DELETE_SESSION,
                            &[session.nonce.into()],
                        )
                        .await
                        .map_err(|_| RequestError::Rejected)?;
                        Self::finish_commit(&mut tx, ()).await
                    })
                    .await
            })
            .await
    }

    pub(super) async fn route_identity(
        &self,
        tx: &mut Transaction,
        access: &Access,
        cookie: Option<&str>,
        now: i64,
    ) -> std::result::Result<Option<(Token, auth::Principal)>, RequestError> {
        Ok(match access {
            Access::Public => None,
            Access::Authenticated => Some(
                auth::authenticate(
                    tx,
                    &self.keys,
                    cookie.ok_or(RequestError::Authentication)?,
                    now,
                )
                .await
                .map_err(authentication_error)?,
            ),
            Access::PublicOptional => match cookie {
                None => None,
                Some(cookie) => match auth::authenticate(tx, &self.keys, cookie, now).await {
                    Ok(authenticated) => Some(authenticated),
                    Err(auth::AuthError::Invalid) => None,
                    Err(auth::AuthError::Unavailable) => return Err(RequestError::Busy),
                },
            },
        })
    }
}
