//! Submission identity and the forms a rendered page offers.
use super::*;

impl Application {
    pub(super) async fn submission_identity(
        &self,
        tx: &mut Transaction,
        action: ActionCore<'_>,
        cookie: &str,
        submission: &str,
        csrf: &str,
        now: i64,
    ) -> Result<(Token, Token, auth::Principal)> {
        let op = manifest::operation(&self.identity.manifest, action.first_operation())?;
        if manifest::anonymous_action(op) {
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
            ensure!(
                matches!(token.kind, TokenKind::AnonymousSubmission { .. })
                    && token.subject == anonymous.nonce,
                RequestError::InvalidRequest
            );
            Ok((token, anonymous, auth::Principal::Anonymous))
        } else {
            let token = self
                .keys
                .verify(submission, now)
                .map_err(|_| RequestError::InvalidRequest)?;
            ensure!(
                matches!(token.kind, TokenKind::Submission { .. }),
                RequestError::InvalidRequest
            );
            let (session, principal) = auth::authenticate(tx, &self.keys, cookie, now)
                .await
                .map_err(accounts::authentication_error)?;
            ensure!(token.subject == session.nonce, RequestError::InvalidRequest);
            self.keys
                .verify_csrf(&session.nonce, csrf)
                .map_err(|_| RequestError::InvalidRequest)?;
            Ok((token, session, principal))
        }
    }

    pub(super) async fn edit_handover(
        &self,
        tx: &mut Transaction,
        receipt: &EditReceipt,
        route: Option<u32>,
    ) -> Result<Rendered> {
        let record =
            repository::load(tx, &self.identity.manifest, receipt.resource, receipt.id).await?;
        if record
            .as_ref()
            .is_none_or(|r| r.incarnation != receipt.incarnation)
            || receipt.cap_version == 0
            || record
                .as_ref()
                .and_then(|r| r.cap_version)
                .and_then(|v| u64::try_from(v).ok())
                != Some(receipt.cap_version)
        {
            return render::capability_handover(None, None);
        }
        let storage = u32::try_from(
            tx.storage_resource(&self.identity.manifest, receipt.resource)
                .await?,
        )?;
        let Ok(secret) =
            self.keys
                .edit_secret(receipt.key_id, storage, receipt.id, receipt.cap_version)
        else {
            return render::capability_handover(None, None);
        };
        let link = route
            .map(|route| {
                render::resolve(
                    &self.identity.manifest,
                    &RouteRef {
                        params: Default::default(),
                        route,
                        target: Some(receipt.id),
                    },
                )
            })
            .transpose()?;
        render::capability_handover(Some(&secret), link.as_deref())
    }

    pub(super) fn credentials(
        &self,
        action: &manifest::WebAction<'_>,
        session: &Token,
        now: i64,
        targets: BTreeMap<String, RecordTarget>,
        values: Fields,
    ) -> Result<FormCredentials> {
        let kind = if session.kind == TokenKind::Anonymous {
            TokenKind::AnonymousSubmission {
                contract: self.submission_contract(),
                action: action.id,
                version: action.version,
                targets,
            }
        } else {
            TokenKind::Submission {
                contract: self.submission_contract(),
                action: action.id,
                version: action.version,
                targets,
            }
        };
        let (_, submission) = self.keys.issue(kind, &session.nonce, now, 900)?;
        let upload_ticket = self
            .services
            .blobs
            .as_ref()
            .filter(|blobs| {
                blobs
                    .policy()
                    .uploads
                    .iter()
                    .any(|u| u.web_binding == action.id)
            })
            .map(|_| self.upload_ticket(action.id, &submission))
            .transpose()?;
        Ok(FormCredentials {
            upload_ticket,
            selections: Default::default(),
            selected: Default::default(),
            csrf: self.keys.csrf(&session.nonce)?,
            submission,
            values,
        })
    }

    pub(super) async fn target_allowed(
        &self,
        context: &mut repository::ReadContext<'_>,
        action: ActionCore<'_>,
        route: Option<u32>,
        stored: &StoredRecord,
    ) -> Result<bool> {
        if !context.unexpired(stored)? {
            return Ok(false);
        }
        let route = route
            .map(|id| manifest::route(&self.identity.manifest, id))
            .transpose()?;
        for target in action
            .targets
            .iter()
            .filter(|target| matches!(target.source, TargetSource::Page { .. }))
        {
            let TargetSource::Page { reads } = &target.source else {
                unreachable!()
            };
            if target.resource != stored.record.resource {
                return Ok(false);
            }
            let mut permitted = false;
            for id in reads
                .iter()
                .filter(|id| route.is_none_or(|route| route.operations.contains(id)))
            {
                if repository::authorize_stored_read(
                    context,
                    manifest::operation(&self.identity.manifest, *id)?,
                    stored,
                )
                .await?
                {
                    permitted = true;
                    break;
                }
            }
            if !permitted {
                return Ok(false);
            }
            for projection in [target.projection.as_ref(), target.inspect.as_ref()]
                .into_iter()
                .flatten()
            {
                if !repository::authorize_stored_read(
                    context,
                    manifest::operation(&self.identity.manifest, projection.operation)?,
                    stored,
                )
                .await?
                {
                    return Ok(false);
                }
            }
            for step in action.steps {
                let op = manifest::operation(&self.identity.manifest, step.operation)?;
                if matches!(&step.target, Target::Named(name) if name == &target.name)
                    && !manifest::is_capability(op)
                    && !context.authorize(op, stored).await?
                {
                    return Ok(false);
                }
                for assignment in step.assign.iter().filter(|_| action.steps.len() == 1) {
                    if matches!(&assignment.change, Change::Set(Value::Target(name)) if name == &target.name)
                    {
                        let eligible = manifest::operation(
                            &self.identity.manifest,
                            *op.bind
                                .get(&assignment.field)
                                .ok_or(repository::ReferenceUnavailable)?,
                        )?;
                        if !repository::authorize_stored_read(context, eligible, stored).await?
                            || manifest::resource(&self.identity.manifest, op.resource)?
                                .gate
                                .as_ref()
                                .is_some_and(|gate| gate.field == assignment.field)
                                && !manifest::gate_permits(
                                    manifest::resource(&self.identity.manifest, op.resource)?,
                                    &stored.record.fields,
                                    true,
                                )
                        {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        Ok(route.is_none_or(|route| route.resource == Some(stored.record.resource)))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn forms(
        &self,
        tx: &mut Transaction,
        authority: &mut crate::authority::Authority,
        database_calls: &mut usize,
        route: u32,
        target: Option<u64>,
        session: Option<&Token>,
        anonymous: Option<&Token>,
        principal: &auth::Principal,
        now: i64,
    ) -> Result<BTreeMap<u32, Option<FormCredentials>>> {
        let r = manifest::route(&self.identity.manifest, route)?;
        let stored = match (r.resource, target) {
            (Some(resource), Some(id)) => {
                *database_calls = database_calls
                    .checked_sub(2)
                    .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
                repository::load(tx, &self.identity.manifest, resource, id).await?
            }
            _ => None,
        };
        let mut forms = BTreeMap::new();
        for id in &r.forms {
            let action = manifest::web_action(&self.identity.manifest, *id)?;
            let op = manifest::operation(
                &self.identity.manifest,
                ActionCore::of(action.core)?.first_operation(),
            )?;
            let subject = if manifest::anonymous_action(op) {
                anonymous
            } else {
                session
            };
            let principal = if manifest::anonymous_action(op) {
                &auth::Principal::Anonymous
            } else {
                principal
            };
            let Some(subject) = subject else {
                forms.insert(*id, None);
                continue;
            };
            let credentials =
                if manifest::signed_resource(&self.identity.manifest, &action)?.is_some() {
                    if let Some(record) = &stored {
                        if crate::expiry::available(
                            manifest::resource(&self.identity.manifest, record.record.resource)?,
                            &record.record.fields,
                            authority.time(),
                        )? && ((manifest::is_capability(op) && record.cap_version.is_some())
                            || self
                                .target_allowed(
                                    &mut repository::ReadContext {
                                        tx,
                                        manifest: &self.identity.manifest,
                                        principal,
                                        authority,
                                        budget: repository::ReadBudget::Query(database_calls),
                                    },
                                    ActionCore::of(action.core)?,
                                    Some(route),
                                    record,
                                )
                                .await?)
                        {
                            let grant = RecordTarget {
                                resource: record.record.resource,
                                id: record.record.id,
                                incarnation: record.incarnation.clone(),
                                revision: record.revision,
                                route: Some(route),
                            };
                            let values = if manifest::is_capability(op) {
                                Fields::new()
                            } else {
                                self.action_values(&action, &record.record.fields)
                            };
                            Some(self.credentials(
                                &action,
                                subject,
                                now,
                                Self::page_grants(action.core, &grant),
                                values,
                            )?)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else if self
                    .authorize_create(ActionCore::of(action.core)?, principal)
                    .is_ok()
                {
                    Some(self.credentials(&action, subject, now, BTreeMap::new(), Fields::new())?)
                } else {
                    None
                };
            forms.insert(*id, credentials);
        }
        Ok(forms)
    }

    pub(super) fn action_values(
        &self,
        action: &manifest::WebAction<'_>,
        fields: &Fields,
    ) -> Fields {
        action
            .steps
            .iter()
            .filter(|step| matches!(&step.target, Target::Named(name) if action.targets.iter().any(|target| target.name == *name && matches!(target.source, TargetSource::Page { .. }))))
            .flat_map(|step| &step.assign)
            .filter_map(|assignment| {
                let Change::Set(Value::Input(name)) = &assignment.change else {
                    return None;
                };
                fields
                    .get(&assignment.field)
                    .map(|value| (name.clone(), value.clone()))
            })
            .collect()
    }

    pub(super) fn conflict(
        &self,
        action: &manifest::WebAction<'_>,
        session: &Token,
        now: i64,
        mut target: RecordTarget,
        stored: &StoredRecord,
        input: &Fields,
    ) -> Result<Rendered> {
        target.revision = stored.revision;
        let credentials = self.credentials(
            action,
            session,
            now,
            Self::page_grants(action.core, &target),
            Fields::new(),
        )?;
        let operation = manifest::operation(
            &self.identity.manifest,
            ActionCore::of(action.core)?.first_operation(),
        )?;
        let current = if manifest::is_capability(operation) {
            Fields::new()
        } else if operation.kind == OperationKind::Delete {
            stored.record.fields.clone()
        } else {
            self.action_values(action, &stored.record.fields)
        };
        render::recovery(
            &self.web.presentation,
            &self.identity.manifest,
            action.id,
            &credentials,
            input,
            render::Recovery::Conflict { current: &current },
        )
    }
}
