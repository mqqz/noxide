use super::*;

impl Application {
    fn capability_route(&self, resource: u32) -> Result<u32> {
        self.manifest
            .routes
            .iter()
            .find(|r| r.resource == Some(resource))
            .map(|r| r.id)
            .ok_or_else(|| anyhow::anyhow!(RequestError::InvalidRequest))
    }

    pub(crate) async fn capability_page(
        &self,
        resource: u32,
        id: u64,
        cookie: Option<&str>,
    ) -> Result<Rendered, RequestError> {
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
                    std::sync::Arc::new(_database),
                    None,
                    std::time::Duration::from_secs(2),
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        let mut budget = ExecutionBudget::new(self.runtime.limits(), deadline);
                        timeout_at(deadline, async {
                            let mut tx = self
                                .database
                                .begin_read(deadline.into_std())
                                .await
                                .map_err(|_| RequestError::deadline())?;
                            self.admission(&mut tx, false)
                                .await
                                .map_err(RequestError::database)?;
                            let now = security::observe_clock_read(
                                &mut tx,
                                security::now().map_err(|_| RequestError::Rejected)?,
                                &self.clock,
                            )
                            .await
                            .map_err(RequestError::database)?;
                            let route = self
                                .capability_route(resource)
                                .map_err(|_| RequestError::InvalidRequest)?;
                            let time = if crate::authority::uses_time(&self.manifest) {
                                budget.spend(1).map_err(RequestError::database)?;
                                Some(self.temporal_after_admission(&mut tx).await?)
                            } else {
                                None
                            };
                            let record = repository::load(&mut tx, &self.manifest, resource, id)
                                .await
                                .map_err(RequestError::database)?;
                            let Some(record) = record.filter(|r| r.cap_version.is_some()) else {
                                return render::unavailable(&self.presentation, &self.manifest)
                                    .map_err(|_| RequestError::Rejected);
                            };
                            if !crate::expiry::available(
                                manifest::resource(&self.manifest, resource)
                                    .map_err(RequestError::database)?,
                                &record.record.fields,
                                time,
                            )
                            .map_err(RequestError::database)?
                            {
                                return render::unavailable(&self.presentation, &self.manifest)
                                    .map_err(|_| RequestError::Rejected);
                            }
                            let (anonymous, new_cookie) =
                                match cookie.and_then(|c| self.keys.anonymous(c, now).ok()) {
                                    Some(token) => (token, None),
                                    None => {
                                        let (token, cookie) = self
                                            .keys
                                            .issue(
                                                TokenKind::Anonymous,
                                                "",
                                                now,
                                                security::ANONYMOUS_TTL,
                                            )
                                            .map_err(|_| RequestError::Rejected)?;
                                        (token, Some(cookie))
                                    }
                                };
                            let target = RecordTarget {
                                resource,
                                id,
                                route: Some(route),
                                incarnation: record.incarnation,
                                revision: record.revision,
                            };
                            let (_, submission) = self
                                .keys
                                .issue(
                                    TokenKind::AnonymousSubmission {
                                        contract: self.submission_contract(),
                                        action: 0,
                                        version: 1,
                                        targets: BTreeMap::from([("target".into(), target)]),
                                    },
                                    &anonymous.nonce,
                                    now,
                                    security::ANONYMOUS_TTL,
                                )
                                .map_err(|_| RequestError::Rejected)?;
                            let mut page = render::capability_rotation(
                                &self.presentation,
                                &FormCredentials {
                                    selections: Default::default(),
                                    selected: Default::default(),
                                    csrf: self.keys.csrf(&anonymous.nonce),
                                    submission,
                                    values: Fields::new(),
                                },
                                resource,
                                id,
                            )
                            .map_err(|_| RequestError::Rejected)?;
                            page.anonymous_cookie = new_cookie;
                            Self::finish_commit(&mut tx, page).await
                        })
                        .await
                        .map_err(|_| RequestError::deadline())?
                    })
                    .await
            })
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn rotate_capability(
        &self,
        resource: u32,
        id: u64,
        cookie: &str,
        csrf: &str,
        submission: &str,
        secret: &str,
    ) -> Result<Rendered, RequestError> {
        let entry_scope = self.request_scope(self.runtime.limits().wall_time);
        entry_scope
            .run(async {
                let _request = self
                    .admission_limits
                    .requests()
                    .request()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let _anonymous_write = self.anonymous_write(true).await?;
                let _database = self
                    .admission_limits
                    .database()
                    .acquire()
                    .await
                    .map_err(|_| RequestError::deadline())?;
                let owner = self.owned_request(
                    _request,
                    std::sync::Arc::new(_database),
                    _anonymous_write,
                    self.runtime.limits().wall_time,
                );
                let deadline = owner.work_deadline();
                owner
                    .run(async {
                        let mut budget = ExecutionBudget::new(self.runtime.limits(), deadline);
                        let mut receipt_commit = false;
                        for _ in 0..3 {
                            let prepared = timeout_at(
                                deadline,
                                self.prepare_rotation(
                                    resource,
                                    id,
                                    cookie,
                                    csrf,
                                    submission,
                                    secret,
                                    deadline,
                                    &mut budget,
                                    &mut receipt_commit,
                                ),
                            )
                            .await;
                            let (mut tx, page) = match prepared {
                                Err(_) | Ok(Err(_)) if receipt_commit => {
                                    return Ok(navigation::success());
                                }
                                Err(_) => return Err(RequestError::Busy),
                                Ok(Err(error))
                                    if retryable(&error) && Instant::now() < deadline =>
                                {
                                    continue;
                                }
                                Ok(Err(error)) => {
                                    return Err(error
                                        .downcast::<RequestError>()
                                        .unwrap_or_else(RequestError::database));
                                }
                                Ok(Ok(value)) => value,
                            };
                            match timeout_at(deadline, tx.commit()).await {
                                Ok(Ok(())) => return Ok(page),
                                _ if tx.commit_acknowledged() || receipt_commit => return Ok(page),
                                Ok(Err(error)) if !tx.commit_may_have_succeeded() && error.is::<crate::database::lifecycle::meter::StatementLimit>() => {
                                    if tx.rollback().await.is_err() {return Err(RequestError::OutcomeUnknown);}
                                    return Err(RequestError::Busy);
                                }
                                Ok(Err(error))
                                    if !tx.commit_may_have_succeeded() && retryable(&error) =>
                                {
                                    if tx.rollback().await.is_err() {
                                        return Err(RequestError::OutcomeUnknown);
                                    }
                                }
                                _ => return Err(RequestError::OutcomeUnknown),
                            }
                        }
                        Err(RequestError::Busy)
                    })
                    .await
            })
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_rotation(
        &self,
        resource: u32,
        id: u64,
        cookie: &str,
        csrf: &str,
        submission: &str,
        secret: &str,
        deadline: Instant,
        budget: &mut ExecutionBudget,
        receipt_commit: &mut bool,
    ) -> Result<(Transaction, Rendered)> {
        let mut tx = self.database.begin(deadline.into_std()).await?;
        self.admission(&mut tx, false).await?;
        let now = self.observe_clock_write(&mut tx, security::now()?).await?;
        let anonymous = self
            .keys
            .anonymous(cookie, now)
            .map_err(|_| RequestError::InvalidRequest)?;
        self.keys
            .verify_csrf(&anonymous.nonce, csrf)
            .map_err(|_| RequestError::InvalidRequest)?;
        let token = self
            .keys
            .verify(submission, now)
            .map_err(|_| RequestError::InvalidRequest)?;
        let TokenKind::AnonymousSubmission {
            contract,
            action: 0,
            version: 1,
            targets,
        } = &token.kind
        else {
            anyhow::bail!(RequestError::InvalidRequest);
        };
        ensure!(targets.len() == 1, RequestError::InvalidRequest);
        let target = targets.get("target").ok_or(RequestError::InvalidRequest)?;
        ensure!(
            contract == &self.submission_contract()
                && token.subject == anonymous.nonce
                && target.resource == resource
                && target.id == id
                && Some(self.capability_route(resource)?) == target.route,
            RequestError::InvalidRequest
        );
        ensure!(secret.len() <= 128, RequestError::InvalidRequest);
        let input = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&(
            VERSION, resource, id, secret,
        ))?));
        let claimed = tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES($1,$2,$3,0,$4,'',$5) ON CONFLICT(nonce) DO NOTHING", &[token.nonce.as_str().into(), anonymous.nonce.as_str().into(), self.contract.as_str().into(), input.as_str().into(), token.expires.into()]).await?;
        if claimed == 0 {
            let sql = format!(
                "SELECT subject,contract,input,{} FROM nx_receipts WHERE nonce=$1",
                tx.bounded_text("outcome", 1024)
            );
            let rows = tx.fetch::<4>(&sql, &[token.nonce.as_str().into()]).await?;
            let [subject, contract, digest, outcome] =
                rows.first().ok_or(RequestError::InvalidRequest)?;
            ensure!(
                subject == &anonymous.nonce && contract == &self.contract && digest == &input,
                RequestError::InvalidRequest
            );
            let receipt: EditReceipt = serde_json::from_str(outcome)?;
            ensure!(
                receipt.resource == resource
                    && receipt.id == id
                    && receipt.incarnation == target.incarnation,
                RequestError::InvalidRequest
            );
            // Verified original receipt proves commitment; current target checks
            // still exclusively govern whether a secret handover can be emitted.
            *receipt_commit = true;
            let page = self.edit_handover(&mut tx, &receipt, target.route).await?;
            return Ok((tx, page));
        }
        let time = if crate::authority::uses_time(&self.manifest) {
            budget.spend(1)?;
            Some(self.temporal_after_admission(&mut tx).await?)
        } else {
            None
        };
        let stored = repository::load(&mut tx, &self.manifest, resource, id)
            .await?
            .ok_or(RequestError::InvalidRequest)?;
        ensure!(
            stored.incarnation == target.incarnation,
            RequestError::InvalidRequest
        );
        ensure!(
            crate::expiry::available(
                manifest::resource(&self.manifest, resource)?,
                &stored.record.fields,
                time
            )?,
            RequestError::InvalidRequest
        );
        let current = stored.cap_version.ok_or(RequestError::InvalidRequest)?;
        let storage = tx.storage_resource(&self.manifest, resource).await?;
        self.keys
            .verify_edit(secret, u32::try_from(storage)?, id, current)
            .map_err(|_| RequestError::InvalidRequest)?;
        let next = current.checked_add(1).ok_or(RequestError::Rejected)?;
        ensure!(tx.execute("UPDATE nx_records SET cap_version=$1 WHERE resource=$2 AND id=$3 AND cap_version=$4", &[next.into(), storage.into(), (id as i64).into(), current.into()]).await? == 1, "capability changed");
        let receipt = EditReceipt {
            resource,
            id,
            incarnation: stored.incarnation.clone(),
            cap_version: next as u64,
            key_id: self.keys.signing_edit_key()?,
        };
        tx.execute(
            "UPDATE nx_receipts SET outcome=$1 WHERE nonce=$2",
            &[serde_json::to_string(&receipt)?.into(), token.nonce.into()],
        )
        .await?;
        let page = self.edit_handover(&mut tx, &receipt, target.route).await?;
        Ok((tx, page))
    }
}
