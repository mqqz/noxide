use crate::{
    Database, HostKeys, auth,
    database::{Param, Transaction, retryable},
    manifest,
    render::{self, FormCredentials, RenderContext, Rendered},
    repository::Effects,
    runtime::{Limits, Runtime},
    security::{self, Token, TokenKind},
};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_protocol::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};

#[derive(Debug)]
pub enum RequestError {
    Authentication,
    InvalidRequest,
    Rejected,
    Busy,
    OutcomeUnknown,
}
impl RequestError {
    fn database(error: anyhow::Error) -> Self {
        if retryable(&error) {
            Self::Busy
        } else {
            Self::Rejected
        }
    }
}
impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Authentication => "Sign in to continue.",
                Self::InvalidRequest => "This request is invalid or has expired.",
                Self::Rejected => "The request could not be completed.",
                Self::Busy => "The service is busy. Retry this request.",
                Self::OutcomeUnknown =>
                    "The save result is not yet confirmed. Retry the same submission to recover it.",
            }
        )
    }
}
impl std::error::Error for RequestError {}

pub struct Application {
    pub(crate) manifest: Arc<Manifest>,
    pub(crate) keys: Arc<HostKeys>,
    database: Database,
    runtime: Runtime,
    contract: String,
    deployment: String,
    generation: OnceLock<String>,
    permits: Semaphore,
    login_permits: Arc<Semaphore>,
}

pub struct LoginChallenge {
    pub cookie: String,
    pub csrf: String,
}

impl Application {
    /// Validate persisted schema compatibility before accepting any traffic.
    /// Data requests repeat this fence inside their transaction.
    pub async fn activate(&self) -> Result<()> {
        let mut tx = self
            .database
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await?;
        tx.bind_schema(&self.manifest).await?;
        let generation = tx
            .deployment(&self.deployment, self.keys.incarnation(), true)
            .await?;
        ensure!(
            self.generation.get().is_none_or(|g| g == &generation),
            "application generation retired"
        );
        tx.commit().await?;
        ensure!(
            self.generation.get_or_init(|| generation.clone()) == &generation,
            "concurrent activation differs"
        );
        Ok(())
    }

    async fn admission(&self, tx: &mut Transaction, activate: bool) -> Result<()> {
        tx.bind_schema(&self.manifest).await?;
        let generation = tx
            .deployment(&self.deployment, self.keys.incarnation(), activate)
            .await?;
        ensure!(
            self.generation.get() == Some(&generation),
            "application is unactivated or retired"
        );
        Ok(())
    }

    fn submission_contract(&self) -> String {
        format!(
            "{}:{}",
            self.contract,
            self.generation.get().expect("admission precedes token use")
        )
    }
    /// The approval digest comes from operator policy, separately from the
    /// application bundle. Compilation retains immutable admitted bytes.
    pub fn new(
        component: &[u8],
        declarations: &[u8],
        approved: [u8; 32],
        database: Database,
        keys: HostKeys,
        limits: Limits,
    ) -> Result<Self> {
        let m = manifest::parse(declarations)?;
        let digest = manifest::digest(&m)?;
        ensure!(
            digest == approved,
            "deployment did not approve this contract"
        );
        let concurrency = limits.concurrency;
        let mut identity = Sha256::new();
        identity.update(digest);
        identity.update(Sha256::digest(component));
        let deployment = URL_SAFE_NO_PAD.encode(identity.finalize());
        let runtime = Runtime::compile(component, limits)?;
        Ok(Self {
            manifest: Arc::new(m),
            keys: Arc::new(keys),
            database,
            runtime,
            contract: URL_SAFE_NO_PAD.encode(digest),
            deployment,
            generation: OnceLock::new(),
            permits: Semaphore::new(concurrency),
            login_permits: Arc::new(Semaphore::new(2)),
        })
    }

    pub async fn login_challenge(&self) -> std::result::Result<LoginChallenge, RequestError> {
        let mut tx = self
            .database
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .map_err(|_| RequestError::Busy)?;
        self.admission(&mut tx, false)
            .await
            .map_err(|_| RequestError::Rejected)?;
        let now = security::now().map_err(|_| RequestError::Rejected)?;
        security::observe_clock(&mut tx, now)
            .await
            .map_err(RequestError::database)?;
        let (token, cookie) = self
            .keys
            .issue(TokenKind::Login, "", now, 900)
            .map_err(|_| RequestError::Rejected)?;
        tx.commit().await.map_err(|_| RequestError::Busy)?;
        Ok(LoginChallenge {
            cookie,
            csrf: self.keys.csrf(&token.nonce),
        })
    }

    pub async fn login(
        &self,
        challenge: &str,
        csrf: &str,
        username: &str,
        password: &str,
    ) -> std::result::Result<String, RequestError> {
        let permit = self
            .login_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| RequestError::Busy)?;
        let deadline = Instant::now() + std::time::Duration::from_secs(3);
        timeout_at(deadline, async {
            let mut tx = self
                .database
                .begin(deadline.into_std())
                .await
                .map_err(|_| RequestError::Busy)?;
            self.admission(&mut tx, false)
                .await
                .map_err(|_| RequestError::Rejected)?;
            let now = security::now().map_err(|_| RequestError::Rejected)?;
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
            security::observe_clock(&mut tx, now)
                .await
                .map_err(RequestError::database)?;
            let signed = auth::login(&mut tx, &self.keys, username, password, now, permit)
                .await
                .map_err(|_| RequestError::Authentication)?;
            tx.commit().await.map_err(|_| RequestError::Busy)?;
            Ok(signed)
        })
        .await
        .map_err(|_| RequestError::Busy)?
    }

    pub async fn logout(&self, cookie: &str, csrf: &str) -> std::result::Result<(), RequestError> {
        let mut tx = self
            .database
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .map_err(|_| RequestError::Busy)?;
        self.admission(&mut tx, false)
            .await
            .map_err(|_| RequestError::Rejected)?;
        let now = security::now().map_err(|_| RequestError::Rejected)?;
        let (session, _) = auth::authenticate(&mut tx, &self.keys, cookie, now)
            .await
            .map_err(|_| RequestError::Authentication)?;
        security::observe_clock(&mut tx, now)
            .await
            .map_err(RequestError::database)?;
        self.keys
            .verify_csrf(&session.nonce, csrf)
            .map_err(|_| RequestError::InvalidRequest)?;
        tx.execute(
            "DELETE FROM nx_sessions WHERE id=$1",
            &[session.nonce.into()],
        )
        .await
        .map_err(|_| RequestError::Rejected)?;
        tx.commit().await.map_err(|_| RequestError::Busy)
    }

    fn forms(
        &self,
        route: u32,
        session: &Token,
        principal: &auth::Principal,
        now: i64,
    ) -> Result<BTreeMap<u32, Option<FormCredentials>>> {
        let mut forms = BTreeMap::new();
        for id in &manifest::route(&self.manifest, route)?.forms {
            let action = manifest::action(&self.manifest, *id)?;
            let operation = manifest::operation(&self.manifest, action.operation)?;
            if !crate::repository::allowed(
                &operation.policy,
                principal,
                &principal.id,
                &principal.tenant,
            ) {
                forms.insert(*id, None);
                continue;
            }
            let (_, submission) = self.keys.issue(
                TokenKind::Submission {
                    contract: self.submission_contract(),
                    action: *id,
                    version: action.version,
                },
                &session.nonce,
                now,
                900,
            )?;
            forms.insert(
                *id,
                Some(FormCredentials {
                    csrf: self.keys.csrf(&session.nonce),
                    submission,
                }),
            );
        }
        Ok(forms)
    }

    pub async fn view(
        &self,
        cookie: &str,
        route: u32,
        target: Option<u64>,
    ) -> std::result::Result<Rendered, RequestError> {
        self.view_page(cookie, route, target, None).await
    }

    pub async fn view_page(
        &self,
        cookie: &str,
        route: u32,
        target: Option<u64>,
        cursor: Option<u64>,
    ) -> std::result::Result<Rendered, RequestError> {
        let _permit = self.permits.try_acquire().map_err(|_| RequestError::Busy)?;
        if cursor.is_some_and(|c| c == 0 || c > i64::MAX as u64 || target.is_some()) {
            return Err(RequestError::InvalidRequest);
        }
        let reference = RouteRef { route, target };
        render::resolve(&self.manifest, &reference).map_err(|_| RequestError::InvalidRequest)?;
        let deadline = Instant::now() + self.runtime.limits().wall_time;
        timeout_at(deadline, async {
            let mut tx = self
                .database
                .begin(deadline.into_std())
                .await
                .map_err(|_| RequestError::Busy)?;
            self.admission(&mut tx, false)
                .await
                .map_err(|_| RequestError::Rejected)?;
            let now = security::now().map_err(|_| RequestError::Rejected)?;
            security::observe_clock(&mut tx, now)
                .await
                .map_err(RequestError::database)?;
            let (session, principal) = auth::authenticate(&mut tx, &self.keys, cookie, now)
                .await
                .map_err(|_| RequestError::Authentication)?;
            let forms = self
                .forms(route, &session, &principal, now)
                .map_err(|_| RequestError::Rejected)?;
            let request = RequestView {
                version: VERSION,
                kind: RequestKind::Route(route),
                target,
                input: Fields::new(),
            };
            let effects = Effects {
                tx,
                manifest: self.manifest.clone(),
                principal,
                request: request.clone(),
                created: None,
                calls: 16,
                cursor,
                more: None,
            };
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
            let response = attempt.result.map_err(|_| RequestError::Rejected)?;
            if matches!(response, ResponseIntent::Created { .. }) {
                return Err(RequestError::Rejected);
            }
            let next_page = effects.more.map(|id| {
                format!(
                    "{}?before={id}",
                    manifest::route(&self.manifest, route)
                        .expect("validated route")
                        .path
                )
            });
            let rendered = render::render(
                &response,
                &RenderContext {
                    manifest: Some(&self.manifest),
                    forms,
                    logout_csrf: Some(self.keys.csrf(&session.nonce)),
                    next_page,
                },
            )
            .map_err(|_| RequestError::Rejected)?;
            effects.tx.commit().await.map_err(|_| RequestError::Busy)?;
            Ok(rendered)
        })
        .await
        .map_err(|_| RequestError::Busy)?
    }

    pub async fn submit(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        input: Fields,
    ) -> std::result::Result<Rendered, RequestError> {
        let _permit = self.permits.try_acquire().map_err(|_| RequestError::Busy)?;
        let a =
            manifest::action(&self.manifest, action).map_err(|_| RequestError::InvalidRequest)?;
        let op = manifest::operation(&self.manifest, a.operation)
            .map_err(|_| RequestError::InvalidRequest)?;
        manifest::validate_fields(
            manifest::resource(&self.manifest, op.resource)
                .map_err(|_| RequestError::InvalidRequest)?,
            &input,
        )
        .map_err(|_| RequestError::InvalidRequest)?;
        let input_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(
            serde_json::to_vec(&(VERSION, a.version, &input))
                .map_err(|_| RequestError::InvalidRequest)?,
        ));
        let deadline = Instant::now() + self.runtime.limits().wall_time;
        let mut fuel = self.runtime.limits().fuel;
        let mut calls = self.runtime.limits().host_calls;
        let mut db_calls = 16;
        for _ in 0..3 {
            let prepared = timeout_at(
                deadline,
                self.prepare(
                    cookie,
                    action,
                    submission,
                    csrf,
                    &input,
                    &input_hash,
                    &mut fuel,
                    &mut calls,
                    &mut db_calls,
                    deadline,
                ),
            )
            .await;
            let (mut tx, response) = match prepared {
                Err(_) => return Err(RequestError::Rejected),
                Ok(Err(error)) if retryable(&error) && Instant::now() < deadline => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Ok(Err(error)) => {
                    return Err(error
                        .downcast::<RequestError>()
                        .unwrap_or(RequestError::Rejected));
                }
                Ok(Ok(prepared)) => prepared,
            };
            match timeout_at(deadline, tx.commit()).await {
                Ok(Ok(())) => return Ok(response),
                Ok(Err(error)) if retryable(&error) => {
                    // SQLite busy can leave COMMIT's transaction active. A new
                    // attempt is legal only after this rollback succeeds.
                    if tx.rollback().await.is_err() {
                        return Err(RequestError::OutcomeUnknown);
                    }
                }
                _ => return Err(RequestError::OutcomeUnknown),
            }
        }
        Err(RequestError::Busy)
    }

    pub(crate) async fn recover_form(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        input: &Fields,
        unknown: bool,
    ) -> Result<Rendered> {
        let _permit = self.permits.try_acquire()?;
        let deadline = Instant::now() + self.runtime.limits().wall_time;
        timeout_at(deadline,async {
            let a=manifest::action(&self.manifest,action)?;
            let mut tx=self.database.begin(deadline.into_std()).await?;
            self.admission(&mut tx,false).await?;
            let now=security::now()?;
            let token=self.keys.verify(submission,now)?;
            security::observe_clock(&mut tx,now).await?;
            ensure!(token.kind==TokenKind::Submission{contract:self.submission_contract(),action,version:a.version},"retired submission");
            let (session,_)=auth::authenticate(&mut tx,&self.keys,cookie,now).await?;
            ensure!(session.nonce==token.subject,"submission subject");
            self.keys.verify_csrf(&session.nonce,csrf)?;
            let sql=format!("SELECT subject,contract,input,{} FROM nx_receipts WHERE nonce=$1",tx.bounded_text("outcome",1024));
            let rows=tx.fetch::<4>(&sql,&[token.nonce.into()]).await?;
            if let Some([subject,contract,digest,outcome])=rows.first() {
                ensure!(*subject==session.nonce && *contract==self.contract,"receipt scope differs");
                let expected=URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&(VERSION,a.version,input))?));
                let response=if digest==&expected {
                    let intent:ResponseIntent=serde_json::from_str(outcome)?;
                    ensure!(matches!(intent,ResponseIntent::Created{..}),"invalid receipt");
                    render::render(&intent,&RenderContext{manifest:Some(&self.manifest),..RenderContext::empty()})?
                } else {
                    let mut response=render::render(&ResponseIntent::Page(Document::new("Form already used",vec![Instruction::Text("This form already saved different content. Return home to start a new form.".into()),Instruction::Link{destination:RouteRef{route:self.manifest.routes.iter().find(|r|r.path=="/").expect("index route").id,target:None},text:"Return home".into()}])),&RenderContext{manifest:Some(&self.manifest),..RenderContext::empty()})?;
                    response.status=409;response
                };
                tx.commit().await?;
                return Ok(response);
            }
            let rendered=render::recovery(&self.manifest,action,&FormCredentials{csrf:csrf.into(),submission:submission.into()},input,unknown)?;
            tx.commit().await?;
            Ok(rendered)
        }).await?
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        input: &Fields,
        input_hash: &str,
        fuel: &mut u64,
        calls: &mut u32,
        db_calls: &mut u32,
        deadline: Instant,
    ) -> Result<(Transaction, Rendered)> {
        let a = manifest::action(&self.manifest, action)?;
        let mut tx = self.database.begin(deadline.into_std()).await?;
        self.admission(&mut tx, false).await?;
        let now = security::now()?;
        let token = self
            .keys
            .verify(submission, now)
            .map_err(|_| RequestError::InvalidRequest)?;
        ensure!(
            token.kind
                == TokenKind::Submission {
                    contract: self.submission_contract(),
                    action,
                    version: a.version
                },
            RequestError::InvalidRequest
        );
        security::observe_clock(&mut tx, now).await?;
        let (session, principal) = auth::authenticate(&mut tx, &self.keys, cookie, now)
            .await
            .map_err(|_| RequestError::Authentication)?;
        ensure!(token.subject == session.nonce, RequestError::InvalidRequest);
        self.keys
            .verify_csrf(&session.nonce, csrf)
            .map_err(|_| RequestError::InvalidRequest)?;
        let claimed=tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES($1,$2,$3,$4,$5,'',$6) ON CONFLICT(nonce) DO NOTHING",&[
            token.nonce.as_str().into(),session.nonce.as_str().into(),self.contract.as_str().into(),Param::Number(action.into()),input_hash.into(),Param::Number(token.expires)
        ]).await?;
        if claimed == 0 {
            let sql = format!(
                "SELECT subject,contract,input,{} FROM nx_receipts WHERE nonce=$1",
                tx.bounded_text("outcome", 1024)
            );
            let rows = tx.fetch::<4>(&sql, &[token.nonce.into()]).await?;
            let [subject, contract, digest, outcome] = rows
                .first()
                .ok_or_else(|| anyhow::anyhow!("receipt unavailable"))?;
            ensure!(
                *subject == session.nonce && *contract == self.contract && digest == input_hash,
                RequestError::InvalidRequest
            );
            let intent: ResponseIntent = serde_json::from_str(outcome)?;
            ensure!(
                matches!(intent, ResponseIntent::Created { .. }),
                "invalid receipt"
            );
            let response = render::render(
                &intent,
                &RenderContext {
                    manifest: Some(&self.manifest),
                    ..RenderContext::empty()
                },
            )?;
            return Ok((tx, response));
        }
        let request = RequestView {
            version: VERSION,
            kind: RequestKind::Action(action),
            target: None,
            input: input.clone(),
        };
        let effects = Effects {
            tx,
            manifest: self.manifest.clone(),
            principal,
            request: request.clone(),
            created: None,
            calls: *db_calls,
            cursor: None,
            more: None,
        };
        let attempt = self
            .runtime
            .run(request, Some(effects), *fuel, *calls, deadline)
            .await;
        *fuel = attempt.fuel_left;
        *calls = attempt.calls_left;
        let mut effects = attempt
            .effects
            .ok_or_else(|| anyhow::anyhow!("missing request state"))?;
        *db_calls = effects.calls;
        let outcome = match attempt.result {
            Ok(value) => value,
            Err(error) => {
                effects.tx.rollback().await?;
                return Err(error);
            }
        };
        let expected = effects
            .created
            .as_ref()
            .map(|record| ResponseIntent::Created {
                resource: record.resource,
                id: record.id,
                destination: RouteRef {
                    route: a.redirect,
                    target: Some(record.id),
                },
            });
        ensure!(
            expected.as_ref() == Some(&outcome),
            "action outcome differs from granted mutation"
        );
        let response = render::render(
            &outcome,
            &RenderContext {
                manifest: Some(&self.manifest),
                ..RenderContext::empty()
            },
        )?;
        effects
            .tx
            .execute(
                "UPDATE nx_receipts SET outcome=$1 WHERE nonce=$2",
                &[serde_json::to_string(&outcome)?.into(), token.nonce.into()],
            )
            .await?;
        ensure!(Instant::now() < deadline, "request deadline");
        Ok((effects.tx, response))
    }
}
