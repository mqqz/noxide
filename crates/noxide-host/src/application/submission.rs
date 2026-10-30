use super::*;

impl Application {
    pub async fn submit(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        input: Fields,
    ) -> std::result::Result<Rendered, RequestError> {
        self.submit_with_capability(cookie, action, submission, csrf, input, None)
            .await
    }
    pub(crate) async fn submit_with_capability(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        input: Fields,
        capability: Option<&str>,
    ) -> std::result::Result<Rendered, RequestError> {
        let _request = self
            .admission_limits
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::Busy)?;
        let op = manifest::action(&self.manifest, action)
            .and_then(|a| manifest::operation(&self.manifest, a.steps[0].operation))
            .map_err(|_| RequestError::InvalidRequest)?;
        let _anonymous_write = self.anonymous_write(manifest::anonymous_action(op)).await?;
        let _database = self
            .admission_limits
            .database()
            .acquire()
            .await
            .map_err(|_| RequestError::Busy)?;
        let a =
            manifest::action(&self.manifest, action).map_err(|_| RequestError::InvalidRequest)?;
        let input = manifest::canonical_input(&self.manifest, a, &input)
            .map_err(|_| RequestError::InvalidRequest)?;
        manifest::validate_input(&self.manifest, a, &input)
            .map_err(|_| RequestError::InvalidRequest)?;
        let input_hash = input_digest(a, &input).map_err(|_| RequestError::InvalidRequest)?;
        let deadline = Instant::now() + self.runtime.limits().wall_time;
        let mut budget = ExecutionBudget::new(self.runtime.limits(), deadline);
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
                    capability,
                    &mut budget,
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
            let Some(mut tx) = tx.take() else {
                return Ok(response.fallback);
            };
            match timeout_at(deadline, tx.commit()).await {
                Ok(Ok(())) => return Ok(self.finish_navigation(response, deadline).await),
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
        self.recover_form_with_capability(cookie, action, submission, csrf, input, unknown, None)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn recover_form_with_capability(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        input: &Fields,
        unknown: bool,
        capability: Option<&str>,
    ) -> Result<Rendered> {
        let _request = self
            .admission_limits
            .requests()
            .request()
            .await
            .map_err(|_| RequestError::Busy)?;
        let _database = self
            .admission_limits
            .database()
            .acquire()
            .await
            .map_err(|_| RequestError::Busy)?;
        let deadline = Instant::now() + self.runtime.limits().wall_time;
        let prepared = timeout_at(deadline, async {
            let a = manifest::action(&self.manifest, action)?;
            let mut tx = self.database.begin(deadline.into_std()).await?;
            self.admission(&mut tx, false).await?;
            let now = security::now()?;
            let now = self.observe_clock_write(&mut tx, now).await?;
            let (token, session, principal) = self.submission_identity(&mut tx, a, cookie, submission, csrf, now).await?;
            let target = self.submission_target(&token, a)?;
            let receipt = self.load_receipt(&mut tx, &token.nonce, &session.nonce).await?;
            if let Some([digest, outcome]) = receipt.as_ref() {
                let canonical = manifest::canonical_input(&self.manifest, a, input).ok();
                let expected = canonical.as_ref().map(|input| input_digest(a, input)).transpose()?;

                let response = if expected.as_ref() == Some(digest) { self.prepare_response(&mut tx, a, target.as_ref(), outcome, &principal).await.or_else(|_| self.committed_recovery(a, submission, csrf, input))? } else {
                    let mut response = render::render(&ResponseIntent::Page(Document::new("Form already used", vec![
                        Instruction::Text("This form already committed different input. Return home to start a new form.".into()),
                        Instruction::Link { destination: RouteRef { params: Default::default(),
                        route: self.manifest.routes.iter().find(|r| r.path == "/").expect("index route").id, target: None }, text: "Return home".into() },
                    ])), &RenderContext { presentation: &self.presentation, manifest: Some(&self.manifest), ..RenderContext::empty() })?;
                    response.status = 409; navigation::Prepared::ready(response)
                };
                if tx.commit().await.is_err() {
                    return self.committed_recovery(a, submission, csrf, input);
                }
                return Ok(response);
            }
            if let Some(target) = target {
                let Some(stored) = self.authorized_target(&mut tx, a, &target, &principal, capability).await? else { return render::unavailable(&self.presentation, &self.manifest).map(navigation::Prepared::ready); };
                if a.revision == Revision::Exact && stored.revision != target.revision && !unknown {
                    return self.conflict(a, &session, now, target, &stored, input).map(navigation::Prepared::ready);
                }
            } else {
                self.authorize_create(a, &principal)?;
            }
            let credentials = FormCredentials { csrf: csrf.into(), submission: submission.into(), values: Fields::new() };
            let rendered = render::recovery(&self.presentation, &self.manifest, action, &credentials, input, render::Recovery::Retry { unknown })?;
            tx.commit().await?;
            Ok(navigation::Prepared::ready(rendered))
        }).await??;
        Ok(self.finish_navigation(prepared, deadline).await)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn prepare(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        input: &Fields,
        input_hash: &str,
        capability: Option<&str>,
        budget: &mut ExecutionBudget,
    ) -> Result<(Option<Transaction>, navigation::Prepared)> {
        let a = manifest::action(&self.manifest, action)?;
        let attempt = self
            .attempt_action(
                cookie, action, submission, csrf, input, input_hash, capability, budget,
            )
            .await;
        let _wasm = budget.wasm.take();
        let (mut tx, receipt, nonce) = match attempt? {
            action::Attempt::Settled(outcome) => {
                return Ok((
                    None,
                    navigation::Prepared::ready(self.settle(a, outcome, submission, csrf, input)?),
                ));
            }
            action::Attempt::Commit { tx, receipt, nonce } => (tx, receipt, Some(nonce)),
            action::Attempt::Replay { tx, receipt } => (tx, receipt, None),
        };
        let response = self
            .prepare_response(
                &mut tx,
                a,
                receipt.target.as_ref(),
                &receipt.payload,
                &receipt.principal,
            )
            .await;
        let response = if nonce.is_none() {
            response.or_else(|_| self.committed_recovery(a, submission, csrf, input))?
        } else {
            response?
        };
        if let Some(nonce) = nonce {
            Self::write_receipt(&mut tx, &nonce, &receipt.payload, budget.deadline).await?;
        }
        Ok((Some(tx), response))
    }

    fn settle(
        &self,
        a: &Action,
        outcome: action::Settled,
        submission: &str,
        csrf: &str,
        input: &Fields,
    ) -> Result<Rendered> {
        use action::Settled;
        let (errors, message) = match outcome {
            Settled::Unavailable => return render::unavailable(&self.presentation, &self.manifest),
            Settled::Conflict {
                target,
                stored,
                session,
                now,
            } => return self.conflict(a, &session, now, target, &stored, input),
            Settled::Rejected {
                field_errors,
                message,
            } => (field_errors, message),
            Settled::GuardRejected { input, message } => (
                Fields::from([(input, message)]),
                "Review the highlighted fields.".into(),
            ),
        };
        render::recovery(
            &self.presentation,
            &self.manifest,
            a.id,
            &FormCredentials {
                csrf: csrf.into(),
                submission: submission.into(),
                values: Fields::new(),
            },
            input,
            render::Recovery::Rejected {
                errors: &errors,
                message: &message,
            },
        )
    }
}

pub(super) fn input_digest(action: &Action, input: &Fields) -> Result<String> {
    ensure!(
        input.len() == action.inputs.len(),
        "unexpected digest input"
    );
    let input: Fields = action
        .inputs
        .iter()
        .map(|schema| {
            let value = input
                .get(&schema.name)
                .ok_or_else(|| anyhow::anyhow!("missing digest input"))?;
            Ok((
                schema.name.clone(),
                schema.canonical(value).map_err(anyhow::Error::msg)?,
            ))
        })
        .collect::<Result<_>>()?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&(
        VERSION,
        action.version,
        &action.inputs,
        input,
    ))?)))
}

impl Application {
    pub(super) async fn load_receipt(
        &self,
        tx: &mut Transaction,
        nonce: &str,
        subject: &str,
    ) -> Result<Option<[String; 2]>> {
        let sql = format!(
            "SELECT subject,contract,input,{} FROM nx_receipts WHERE nonce=$1",
            tx.bounded_text("outcome", 4096)
        );
        let rows = tx.fetch::<4>(&sql, &[nonce.into()]).await?;
        let Some([stored_subject, contract, digest, outcome]) = rows.into_iter().next() else {
            return Ok(None);
        };
        ensure!(
            stored_subject == subject && contract == self.contract,
            RequestError::InvalidRequest
        );
        Ok(Some([digest, outcome]))
    }
}

// One budget survives every transaction retry; admission waits and bounded
// transaction cleanup are separate from this execution deadline.
pub(super) struct ExecutionBudget {
    pub(super) deadline: Instant,
    pub(super) fuel: u64,
    pub(super) host_calls: u32,
    pub(super) database_calls: u32,
    parent_navigation_reserved: bool,
    pub(super) wasm: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl ExecutionBudget {
    pub(super) fn parent_redirect_attempt(&mut self, gated: bool) -> Result<()> {
        // Navigation runs once after the successful commit, outside all retries.
        // Its quota covers begin/commit, the target lookup and its optional gate.
        if !self.parent_navigation_reserved {
            self.database_calls = self
                .database_calls
                .checked_sub(4 + 2 * u32::from(gated))
                .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
            self.parent_navigation_reserved = true;
        }
        // Each attempt actually captures the parent with storage_resource + load.
        // Charge before calling it so errors and rolled-back work stay charged.
        self.database_calls = self
            .database_calls
            .checked_sub(2)
            .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
        Ok(())
    }
    pub(super) fn new(limits: &Limits, deadline: Instant) -> Self {
        Self {
            deadline,
            fuel: limits.fuel,
            host_calls: limits.host_calls,
            database_calls: 16,
            parent_navigation_reserved: false,
            wasm: None,
        }
    }
}

impl Application {
    pub(super) fn authorize_create(
        &self,
        action: &Action,
        principal: &auth::Principal,
    ) -> Result<()> {
        for step in &action.steps {
            let op = manifest::operation(&self.manifest, step.operation)?;
            if op.kind != OperationKind::Create {
                continue;
            }
            ensure!(
                manifest::is_public(op)
                    || principal.user().is_ok_and(|user| repository::allowed(
                        &op.policy,
                        principal,
                        crate::policy::Row {
                            owner: &user.id,
                            tenant: &user.tenant,
                            fields: &Default::default()
                        }
                    )),
                repository::ReferenceUnavailable
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod parent_redirect_budget_tests {
    use super::*;
    use crate::{parent_tests, test_support as fixture};

    #[tokio::test]
    async fn rolled_back_parent_mutations_reuse_navigation_reservation() {
        let tmp = tempfile::tempdir().unwrap();
        retry_case(Database::sqlite(tmp.path().join("redirect-retries.db"))).await;
    }
    async fn retry_case(db: Database) {
        let (app, m) = parent_tests::redirect_app(db.clone()).await;
        let form = app.view_page(None, 3, Some(10), None).await.unwrap();
        let cookie = form.anonymous_cookie.unwrap();
        let html = String::from_utf8(form.body).unwrap();
        let submission = fixture::hidden(&html, "_submission");
        let csrf = fixture::hidden(&html, "_csrf");
        let input = Fields::from([
            ("body".into(), "retried reply".into()),
            ("published".into(), "true".into()),
        ]);
        let digest = input_digest(&m.actions[0], &input).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut budget = ExecutionBudget::new(app.runtime.limits(), deadline);
        // Complete capture, mutation and response preparation on every attempt.
        // Rollbacks deterministically reproduce two known-aborted transactions
        // without relying on database lock timing or a provider-specific error.
        for attempt in 0..3 {
            let (tx, prepared) = app
                .prepare(
                    &cookie,
                    1,
                    &submission,
                    &csrf,
                    &input,
                    &digest,
                    None,
                    &mut budget,
                )
                .await
                .unwrap();
            let mut tx = tx.unwrap();
            assert_eq!(budget.database_calls, 16 - 4 - (attempt + 1) * 3);
            if attempt < 2 {
                tx.rollback().await.unwrap();
            } else {
                tx.commit().await.unwrap();
                let response = app.finish_navigation(prepared, deadline).await;
                let body = String::from_utf8(response.body).unwrap();
                assert!(body.contains("<pre>"));
                assert!(body.contains("href=\"/threads/10\""));
            }
        }
        let mut tx = db.begin_read(deadline.into_std()).await.unwrap();
        let storage = tx.storage_resource(&m, 1).await.unwrap();
        assert_eq!(
            tx.fetch::<1>(
                "SELECT CAST(COUNT(*) AS TEXT) FROM nx_records WHERE resource=$1 AND id>12",
                &[storage.into()]
            )
            .await
            .unwrap()[0][0],
            "1"
        );
        assert_eq!(
            tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_receipts", &[])
                .await
                .unwrap()[0][0],
            "1"
        );
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
    async fn postgres_rolled_back_parent_mutations_reuse_navigation_reservation() {
        use sqlx::Connection;
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "nx_redirect_retry_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut case_url = url::Url::parse(&url).unwrap();
        case_url.set_path(&format!("/{name}"));
        retry_case(Database::postgres(case_url.as_str()).unwrap()).await;
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }

    #[test]
    fn exhausted_capture_budget_never_refreshes_on_retry() {
        let mut budget = ExecutionBudget::new(&Limits::default(), Instant::now());
        for _ in 0..6 {
            budget.parent_redirect_attempt(false).unwrap();
        }
        assert_eq!(budget.database_calls, 0);
        assert!(budget.parent_redirect_attempt(false).is_err());
        assert_eq!(budget.database_calls, 0);
    }
}
