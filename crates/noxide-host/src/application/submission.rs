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
            .and_then(|a| manifest::operation(&self.manifest, a.operation))
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
                return Ok(response);
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
        timeout_at(deadline, async {
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

                let response = if expected.as_ref() == Some(digest) { self.receipt_response(&mut tx, a, target.as_ref(), outcome).await? } else {
                    let mut response = render::render(&ResponseIntent::Page(Document::new("Form already used", vec![
                        Instruction::Text("This form already committed different input. Return home to start a new form.".into()),
                        Instruction::Link { destination: RouteRef { route: self.manifest.routes.iter().find(|r| r.path == "/").expect("index route").id, target: None }, text: "Return home".into() },
                    ])), &RenderContext { presentation: &self.presentation, manifest: Some(&self.manifest), ..RenderContext::empty() })?;
                    response.status = 409; response
                };
                tx.commit().await?;
                return Ok(response);
            }
            if let Some(target) = target {
                let Some(stored) = self.authorized_target(&mut tx, a, &target, &principal, capability).await? else { return render::unavailable(&self.presentation, &self.manifest); };
                if stored.revision != target.revision && !unknown {
                    return self.conflict(a, &session, now, target, &stored, input);
                }
            } else {
                self.authorize_create(a, &principal)?;
            }
            let credentials = FormCredentials { csrf: csrf.into(), submission: submission.into(), values: Fields::new() };
            let rendered = render::recovery(&self.presentation, &self.manifest, action, &credentials, input, render::Recovery::Retry { unknown })?;
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
        capability: Option<&str>,
        budget: &mut ExecutionBudget,
    ) -> Result<(Option<Transaction>, Rendered)> {
        let deadline = budget.deadline;
        let a = manifest::action(&self.manifest, action)?;
        let mut tx = self.database.begin(deadline.into_std()).await?;
        self.admission(&mut tx, false).await?;
        let now = security::now()?;
        let now = self.observe_clock_write(&mut tx, now).await?;
        let (token, session, principal) = self
            .submission_identity(&mut tx, a, cookie, submission, csrf, now)
            .await?;
        let target = self.submission_target(&token, a)?;
        let claimed = tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES($1,$2,$3,$4,$5,'',$6) ON CONFLICT(nonce) DO NOTHING", &[
            token.nonce.as_str().into(), session.nonce.as_str().into(), self.contract.as_str().into(), Param::Number(action.into()), input_hash.into(), Param::Number(token.expires),
        ]).await?;
        if claimed == 0 {
            let [digest, outcome] = self
                .load_receipt(&mut tx, &token.nonce, &session.nonce)
                .await?
                .ok_or_else(|| anyhow::anyhow!("receipt unavailable"))?;
            ensure!(digest == input_hash, RequestError::InvalidRequest);
            let response = self
                .receipt_response(&mut tx, a, target.as_ref(), &outcome)
                .await?;
            return Ok((Some(tx), response));
        }
        let record = if let Some(target) = &target {
            let Some(stored) = self
                .authorized_target(&mut tx, a, target, &principal, capability)
                .await?
            else {
                let response = render::unavailable(&self.presentation, &self.manifest)?;
                tx.rollback().await?;
                return Ok((None, response));
            };
            if stored.revision != target.revision {
                let response = self.conflict(a, &session, now, target.clone(), &stored, input)?;
                tx.rollback().await?;
                return Ok((None, response));
            }
            Some(stored)
        } else {
            self.authorize_create(a, &principal)?;
            None
        };
        let inspection = a.inspect.as_ref().map(|inspect| {
            let stored = record
                .as_ref()
                .expect("validated inspection requires a target");
            inspect
                .fields
                .iter()
                .map(|name| (name.clone(), stored.record.fields[name].clone()))
                .collect()
        });
        let request = RequestView {
            available_forms: Vec::new(),
            version: VERSION,
            kind: RequestKind::Action(action),
            target: target.as_ref().map(|t| t.id),
            input: input.clone(),
            inspection,
        };
        let effects = Effects {
            tx,
            manifest: self.manifest.clone(),
            principal,
            request: request.clone(),
            outcome: None,
            capability_grant: if manifest::is_capability(manifest::operation(
                &self.manifest,
                a.operation,
            )?) {
                target.clone()
            } else {
                None
            },
            grant: target,
            record,
            calls: budget.database_calls,
            cursor: None,
            more: None,
        };
        let _wasm = self
            .admission_limits
            .wasm()
            .acquire()
            .await
            .map_err(|_| RequestError::Busy)?;
        let attempt = self
            .runtime
            .run(
                request,
                Some(effects),
                budget.fuel,
                budget.host_calls,
                deadline,
            )
            .await;
        budget.fuel = attempt.fuel_left;
        budget.host_calls = attempt.calls_left;
        let mut effects = attempt
            .effects
            .ok_or_else(|| anyhow::anyhow!("missing request state"))?;
        budget.database_calls = effects.calls;
        let outcome = match attempt.result {
            Ok(value) => value,
            Err(error) => {
                effects.tx.rollback().await?;
                return Err(error);
            }
        };
        if let ResponseIntent::Rejected {
            field_errors,
            message,
        } = &outcome
        {
            let response = render::recovery(
                &self.presentation,
                &self.manifest,
                action,
                &FormCredentials {
                    csrf: csrf.into(),
                    submission: submission.into(),
                    values: Fields::new(),
                },
                input,
                render::Recovery::Rejected {
                    errors: field_errors,
                    message,
                },
            )?;
            effects.tx.rollback().await?;
            return Ok((None, response));
        }
        let public_create = manifest::is_public(manifest::operation(&self.manifest, a.operation)?)
            && manifest::operation(&self.manifest, a.operation)?.kind == OperationKind::Create;
        if public_create {
            match (&effects.outcome, &outcome) {
                (
                    Some(ResponseIntent::Created {
                        resource: actual_resource,
                        id: actual_id,
                        ..
                    }),
                    ResponseIntent::Created { resource, id, .. },
                ) => ensure!(
                    resource == actual_resource && id == actual_id,
                    "create outcome differs"
                ),
                _ => anyhow::bail!("public create outcome differs"),
            }
        } else {
            ensure!(
                effects.outcome.as_ref() == Some(&outcome),
                "action outcome differs from granted mutation"
            );
        }
        let receipt = if public_create {
            let Some(ResponseIntent::Created { resource, id, .. }) = &effects.outcome else {
                anyhow::bail!("public create outcome")
            };
            serde_json::to_string(&EditReceipt {
                resource: *resource,
                id: *id,
                cap_version: 1,
                key_id: self.keys.signing_edit_key()?,
            })?
        } else {
            serde_json::to_string(&outcome)?
        };
        let response = self
            .receipt_response(&mut effects.tx, a, None, &receipt)
            .await?;
        effects
            .tx
            .execute(
                "UPDATE nx_receipts SET outcome=$1 WHERE nonce=$2",
                &[receipt.into(), token.nonce.into()],
            )
            .await?;
        ensure!(Instant::now() < deadline, "request deadline");
        Ok((Some(effects.tx), response))
    }
}

fn input_digest(action: &Action, input: &Fields) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&(
        VERSION,
        action.version,
        input,
    ))?)))
}

impl Application {
    async fn load_receipt(
        &self,
        tx: &mut Transaction,
        nonce: &str,
        subject: &str,
    ) -> Result<Option<[String; 2]>> {
        let sql = format!(
            "SELECT subject,contract,input,{} FROM nx_receipts WHERE nonce=$1",
            tx.bounded_text("outcome", 1024)
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
struct ExecutionBudget {
    deadline: Instant,
    fuel: u64,
    host_calls: u32,
    database_calls: u32,
}
impl ExecutionBudget {
    fn new(limits: &Limits, deadline: Instant) -> Self {
        Self {
            deadline,
            fuel: limits.fuel,
            host_calls: limits.host_calls,
            database_calls: 16,
        }
    }
}

impl Application {
    pub(super) fn authorize_create(
        &self,
        action: &Action,
        principal: &auth::Principal,
    ) -> Result<()> {
        let op = manifest::operation(&self.manifest, action.operation)?;
        ensure!(
            manifest::is_public(op)
                || principal.user().is_ok_and(|user| repository::allowed(
                    &op.policy,
                    principal,
                    &user.id,
                    &user.tenant
                )),
            "policy denied"
        );
        Ok(())
    }
}
