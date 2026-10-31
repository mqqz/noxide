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
        let binding = manifest::web_action(&self.manifest, action)
            .map_err(|_| RequestError::InvalidRequest)?;
        let op = manifest::operation(&self.manifest, binding.steps[0].operation)
            .map_err(|_| RequestError::InvalidRequest)?;
        let _admission = self
            .admit_invocation(manifest::anonymous_action(op))
            .await?;
        let a = manifest::web_action(&self.manifest, action)
            .map_err(|_| RequestError::InvalidRequest)?;
        let canonical = self
            .canonical_action_input(a.core.id, &input)
            .map_err(|_| RequestError::InvalidRequest)?;
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
                    &canonical,
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
            let a = manifest::web_action(&self.manifest, action)?;
            let core = ActionCore::of(a.core)?;
            let binding = manifest::web_binding(&self.manifest, action)?;
            let mut tx = self.database.begin(deadline.into_std()).await?;
            self.admission(&mut tx, false).await?;
            let now = security::now()?;
            let now = self.observe_clock_write(&mut tx, now).await?;
            let (token, session, principal) = self
                .submission_identity(&mut tx, core, cookie, submission, csrf, now)
                .await?;
            let (_, selections) = self.action_input(a.core, input)?;
            let grants = self.web_target_grants(
                &token,
                core,
                binding,
                &selections,
                &session,
                &principal,
                now,
            )?;
            let targets: BTreeMap<_, _> = grants
                .iter()
                .map(|(name, grant)| (name.clone(), grant.identity().clone()))
                .collect();
            let receipt = self
                .load_receipt(&mut tx, &token.nonce, &session.nonce)
                .await?;
            if let Some([digest, outcome]) = receipt.as_ref() {
                let canonical = self.canonical_action_input(a.core.id, input).ok();
                let expected = canonical
                    .as_ref()
                    .map(|input| {
                        self.web_invocation_identity(
                            binding,
                            &token,
                            &session,
                            &principal,
                            input.digest(),
                            &targets,
                        )
                    })
                    .transpose()?;

                let response = if expected.as_ref() == Some(digest) {
                    self.prepare_response(&mut tx, &a, &targets, outcome, &principal)
                        .await
                        .or_else(|_| self.committed_recovery(&a, submission, csrf, input))?
                } else {
                    navigation::Prepared::ready(render::form_already_used(
                        &self.presentation,
                        &self.manifest,
                    )?)
                };
                if tx.commit().await.is_err() {
                    return self.committed_recovery(&a, submission, csrf, input);
                }
                return Ok(response);
            }
            let mut budget = ExecutionBudget::new(self.runtime.limits(), deadline);
            match self
                .resolve_action_targets(
                    &mut tx,
                    core,
                    &grants,
                    &principal,
                    capability,
                    now,
                    &mut budget,
                )
                .await
            {
                Ok(_) => self.authorize_create(core, &principal)?,
                Err(error) if error.is::<action::ReviewConflict>() && unknown => {}
                Err(error) if error.is::<action::ReviewConflict>() => {
                    if a.targets.len() == 1
                        && matches!(a.targets[0].source, TargetSource::Page { .. })
                    {
                        let target = targets[&a.targets[0].name].clone();
                        let stored =
                            repository::load(&mut tx, &self.manifest, target.resource, target.id)
                                .await?
                                .ok_or(repository::ReferenceUnavailable)?;
                        return self
                            .settle(
                                &a,
                                action::Settled::Conflict { target, stored },
                                submission,
                                csrf,
                                input,
                                Some((&session, now)),
                            )
                            .map(navigation::Prepared::ready);
                    }
                    return Ok(navigation::Prepared::ready(render::target_conflict()));
                }
                Err(error) if error.is::<repository::ReferenceUnavailable>() => {
                    return self
                        .settle(
                            &a,
                            action::Settled::Unavailable,
                            submission,
                            csrf,
                            input,
                            None,
                        )
                        .map(navigation::Prepared::ready);
                }
                Err(error) => return Err(error),
            }
            let credentials = FormCredentials {
                selections: Default::default(),
                selected: Default::default(),
                csrf: csrf.into(),
                submission: submission.into(),
                values: Fields::new(),
            };
            let rendered = render::recovery(
                &self.presentation,
                &self.manifest,
                action,
                &credentials,
                input,
                render::Recovery::Retry { unknown },
            )?;
            tx.commit().await?;
            Ok(navigation::Prepared::ready(rendered))
        })
        .await??;
        Ok(self.finish_navigation(prepared, deadline).await)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn prepare(
        &self,
        cookie: &str,
        action: u32,
        submission: &str,
        csrf: &str,
        canonical: &CanonicalActionInput,
        capability: Option<&str>,
        budget: &mut ExecutionBudget,
    ) -> Result<(Option<Transaction>, navigation::Prepared)> {
        let a = manifest::web_action(&self.manifest, action)?;
        let input = canonical.web_fields();
        let input = &input;
        let binding = manifest::web_binding(&self.manifest, action)?;
        let mut tx = self.database.begin(budget.deadline.into_std()).await?;
        self.admission(&mut tx, false).await?;
        let (context, session, now) = self
            .admit_web_invocation(
                &mut tx, binding.id, cookie, submission, csrf, canonical, capability,
            )
            .await?;
        let attempt = self.attempt_action(tx, context, budget).await;
        let _wasm = budget.wasm.take();
        let (mut tx, receipt, nonce) = match attempt? {
            action::Attempt::Settled(outcome) => {
                return Ok((
                    None,
                    navigation::Prepared::ready(self.settle(
                        &a,
                        outcome,
                        submission,
                        csrf,
                        input,
                        Some((&session, now)),
                    )?),
                ));
            }
            action::Attempt::Commit { tx, receipt, nonce } => (tx, receipt, Some(nonce)),
            action::Attempt::Replay { tx, receipt } => (tx, receipt, None),
        };
        let response = self
            .prepare_response(
                &mut tx,
                &a,
                &receipt.targets,
                &receipt.payload,
                &receipt.principal,
            )
            .await;
        let response = if nonce.is_none() {
            response.or_else(|_| self.committed_recovery(&a, submission, csrf, input))?
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
        a: &manifest::WebAction<'_>,
        outcome: action::Settled,
        submission: &str,
        csrf: &str,
        input: &Fields,
        refresh: Option<(&Token, i64)>,
    ) -> Result<Rendered> {
        use action::Settled;
        let (errors, message) = match outcome {
            Settled::Unavailable => return render::unavailable(&self.presentation, &self.manifest),
            Settled::TargetConflict => return Ok(render::target_conflict()),
            Settled::Conflict { target, stored } => {
                let (session, now) =
                    refresh.ok_or_else(|| anyhow::anyhow!("missing web refresh identity"))?;
                return self.conflict(a, session, now, target, &stored, input);
            }
            Settled::Rejected {
                field_errors,
                message,
            } => (field_errors, message),
            Settled::GuardRejected {
                input: Some(input),
                message,
            } => (
                Fields::from([(input, message)]),
                "Review the highlighted fields.".into(),
            ),
            Settled::GuardRejected {
                input: None,
                message,
            } => (Fields::new(), message),
        };
        render::recovery(
            &self.presentation,
            &self.manifest,
            a.id,
            &FormCredentials {
                selections: Default::default(),
                selected: Default::default(),
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
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut budget = ExecutionBudget::new(app.runtime.limits(), deadline);
        let canonical = app.canonical_action_input(m.actions[0].id, &input).unwrap();
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
                    &canonical,
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
