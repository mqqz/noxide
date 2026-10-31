//! Host-only target provenance, canonical identity and per-alias authorization.
use super::*;
use noxide_protocol::{MAX_INPUT_BYTES, Target, TargetSource};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub(in crate::application) struct ReviewConflict;
impl std::fmt::Display for ReviewConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("target review conflict")
    }
}
impl std::error::Error for ReviewConflict {}

impl Application {
    pub(in crate::application) fn canonical_action_input(
        &self,
        action: u32,
        raw: &Fields,
    ) -> Result<CanonicalActionInput> {
        let action = manifest::action(&self.manifest, action)?;
        let (scalar, selections) = self.action_input(action, raw)?;
        let fields = manifest::canonical_input(&self.manifest, action, &scalar)
            .map_err(|_| RequestError::InvalidRequest)?;
        manifest::validate_input(&self.manifest, action, &fields)
            .map_err(|_| RequestError::InvalidRequest)?;
        let digest = input_digest(ActionCore::of(action)?, &fields)?;
        Ok(CanonicalActionInput {
            action: action.id,
            version: action.version,
            contract: self.contract.clone(),
            fields,
            selections,
            digest,
        })
    }

    pub(in crate::application) fn action_input(
        &self,
        action: &Action,
        input: &Fields,
    ) -> Result<(Fields, BTreeMap<String, String>)> {
        ensure!(
            input.len() <= action.inputs.len() + 4
                && input.values().map(String::len).sum::<usize>() <= MAX_INPUT_BYTES,
            RequestError::InvalidRequest
        );
        let mut scalar = input.clone();
        let mut selections = BTreeMap::new();
        for target in action
            .targets
            .iter()
            .filter(|target| matches!(target.source, TargetSource::Selected { .. }))
        {
            if let Some(handle) = scalar.remove(&format!("_target_{}", target.name)) {
                ensure!(
                    !handle.is_empty() && handle.len() <= 2048,
                    RequestError::InvalidRequest
                );
                selections.insert(target.name.clone(), handle);
            }
        }
        ensure!(
            scalar.values().map(String::len).sum::<usize>() <= MAX_INPUT_BYTES,
            RequestError::InvalidRequest
        );
        Ok((scalar, selections))
    }

    fn selection_subject(&self, session: &Token, principal: &auth::Principal) -> Result<String> {
        use base64::Engine;
        use sha2::Digest;
        let identity = match principal {
            auth::Principal::Anonymous => ("anonymous", session.nonce.as_str(), ""),
            auth::Principal::User(user) => ("user", user.id.as_str(), user.tenant.as_str()),
        };
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(serde_json::to_vec(&identity)?)))
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::application) fn web_target_grants(
        &self,
        token: &Token,
        action: ActionCore<'_>,
        binding: &noxide_protocol::WebBinding,
        selections: &BTreeMap<String, String>,
        session: &Token,
        principal: &auth::Principal,
        now: i64,
    ) -> Result<BTreeMap<String, TargetGrant>> {
        let (security::TokenKind::Submission {
            contract,
            action: id,
            version,
            targets,
        }
        | security::TokenKind::AnonymousSubmission {
            contract,
            action: id,
            version,
            targets,
        }) = &token.kind
        else {
            anyhow::bail!(RequestError::InvalidRequest)
        };
        ensure!(
            contract == &self.submission_contract()
                && *id == binding.id
                && *version == binding.version,
            RequestError::InvalidRequest
        );
        let mut grants = BTreeMap::new();
        for (name, target) in targets {
            let declaration = manifest::action_target(action.targets, name)?;
            let page = match &declaration.source {
                TargetSource::Page { .. } => true,
                TargetSource::Reference { target, .. } => matches!(
                    manifest::action_target(action.targets, target)?.source,
                    TargetSource::Page { .. }
                ),
                _ => false,
            };
            ensure!(
                page && Self::valid_target_identity(declaration, target),
                RequestError::InvalidRequest
            );
            if matches!(declaration.source, TargetSource::Page { .. }) {
                let route = manifest::route(
                    &self.manifest,
                    target.route.ok_or(RequestError::InvalidRequest)?,
                )?;
                ensure!(
                    route.resource == Some(declaration.resource)
                        && route.forms.contains(&binding.id),
                    RequestError::InvalidRequest
                );
            } else {
                ensure!(target.route.is_none(), RequestError::InvalidRequest);
            }
            grants.insert(
                name.clone(),
                TargetGrant {
                    target: target.clone(),
                    expires: None,
                },
            );
        }
        let subject = self.selection_subject(session, principal)?;
        for declaration in action
            .targets
            .iter()
            .filter(|target| matches!(target.source, TargetSource::Selected { .. }))
        {
            let handle = selections
                .get(&declaration.name)
                .ok_or(RequestError::InvalidRequest)?;
            let proof = self
                .keys
                .verify_selection(handle, now)
                .map_err(|_| RequestError::InvalidRequest)?;
            let security::TokenKind::Selection {
                contract,
                action: id,
                binding: bound,
                name,
                query,
                eligible,
                targets,
            } = proof.kind
            else {
                anyhow::bail!(RequestError::InvalidRequest)
            };
            let TargetSource::Selected {
                query: expected_query,
                eligible: expected_read,
                ..
            } = declaration.source
            else {
                unreachable!()
            };
            ensure!(
                contract == self.submission_contract()
                    && id == action.id
                    && bound == binding.id
                    && name == declaration.name
                    && query == expected_query
                    && eligible == expected_read
                    && proof.subject == subject
                    && proof.expires - proof.issued <= 600,
                RequestError::InvalidRequest
            );
            let expected: BTreeSet<_> = action.targets.iter().filter(|target| target.name == declaration.name || matches!(&target.source, TargetSource::Reference { target, .. } if target == &declaration.name)).map(|target| target.name.as_str()).collect();
            ensure!(
                targets.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected,
                RequestError::InvalidRequest
            );
            for (name, target) in targets {
                ensure!(
                    target.route.is_none()
                        && Self::valid_target_identity(
                            manifest::action_target(action.targets, &name)?,
                            &target
                        )
                        && !grants.contains_key(&name),
                    RequestError::InvalidRequest
                );
                grants.insert(
                    name,
                    TargetGrant {
                        target,
                        expires: Some(proof.expires),
                    },
                );
            }
        }
        ensure!(
            grants.len() == action.targets.len()
                && action
                    .targets
                    .iter()
                    .all(|target| grants.contains_key(&target.name)),
            RequestError::InvalidRequest
        );
        Ok(grants)
    }

    fn valid_target_identity(declaration: &ActionTarget, target: &RecordTarget) -> bool {
        target.resource == declaration.resource
            && target.id > 0
            && target.id <= i64::MAX as u64
            && target.revision > 0
            && !target.incarnation.is_empty()
            && target.incarnation.len() <= 64
    }

    async fn target_read(
        &self,
        tx: &mut Transaction,
        authority: &mut crate::authority::Authority,
        principal: &auth::Principal,
        operation: u32,
        stored: &StoredRecord,
        budget: &mut ExecutionBudget,
    ) -> Result<bool> {
        let read = manifest::operation(&self.manifest, operation)?;
        repository::authorize_stored_read(
            &mut repository::ReadContext {
                tx,
                manifest: &self.manifest,
                principal,
                authority,
                budget: repository::ReadBudget::Action(&mut budget.database_calls),
            },
            read,
            stored,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::application) async fn resolve_action_targets(
        &self,
        tx: &mut Transaction,
        authority: &mut crate::authority::Authority,
        action: ActionCore<'_>,
        grants: &BTreeMap<String, TargetGrant>,
        principal: &auth::Principal,
        capability: Option<&str>,
        now: i64,
        budget: &mut ExecutionBudget,
    ) -> Result<(BTreeMap<(u32, u64), StoredRecord>, Option<RecordTarget>)> {
        let mut records = BTreeMap::new();
        let mut reviewed = BTreeMap::new();
        let mut capability_grant = None;
        let mut conflicting_reviews = false;
        for declaration in action.targets {
            let proof = grants
                .get(&declaration.name)
                .ok_or(repository::ReferenceUnavailable)?;
            ensure!(
                proof.expires.is_none_or(|expires| now < expires),
                repository::ReferenceUnavailable
            );
            let target = &proof.target;
            let key = (target.resource, target.id);
            if let std::collections::btree_map::Entry::Vacant(entry) = records.entry(key) {
                let original_page = action
                    .targets
                    .iter()
                    .filter(|target| matches!(target.source, TargetSource::Page { .. }))
                    .any(|target| {
                        grants
                            .get(&target.name)
                            .is_some_and(|proof| (proof.target.resource, proof.target.id) == key)
                    });
                if !original_page {
                    budget.spend(2)?;
                }
                entry.insert(
                    repository::load(tx, &self.manifest, target.resource, target.id)
                        .await?
                        .ok_or(repository::ReferenceUnavailable)?,
                );
            }
            let stored = &records[&key];
            ensure!(
                crate::expiry::available(
                    manifest::resource(&self.manifest, stored.record.resource)?,
                    &stored.record.fields,
                    authority.time()
                )?,
                repository::ReferenceUnavailable
            );
            ensure!(
                stored.incarnation == target.incarnation,
                repository::ReferenceUnavailable
            );
            if declaration.revision == Revision::Exact
                && let Some(previous) = reviewed.insert(key, target.revision)
            {
                conflicting_reviews |= previous != target.revision;
            }
            let edit = action.steps.iter().any(|step| {
                matches!(&step.target, Target::Named(name) if name == &declaration.name)
                    && manifest::operation(&self.manifest, step.operation)
                        .is_ok_and(manifest::is_capability)
            });
            if edit {
                let storage =
                    u32::try_from(tx.storage_resource(&self.manifest, target.resource).await?)?;
                let (Some(secret), Some(version)) = (capability, stored.cap_version) else {
                    anyhow::bail!(repository::ReferenceUnavailable)
                };
                ensure!(
                    self.keys
                        .verify_edit(secret, storage, target.id, version)
                        .is_ok(),
                    repository::ReferenceUnavailable
                );
                capability_grant = Some(target.clone());
            }
            match &declaration.source {
                TargetSource::Page { reads } if !edit => {
                    let route = manifest::route(
                        &self.manifest,
                        target.route.ok_or(repository::ReferenceUnavailable)?,
                    )?;
                    let mut permitted = false;
                    let mut reads: Vec<_> = reads
                        .iter()
                        .copied()
                        .filter(|read| route.operations.contains(read))
                        .collect();
                    reads.sort_by_key(|id| {
                        (
                            manifest::operation(&self.manifest, *id).is_ok_and(manifest::is_public),
                            *id,
                        )
                    });
                    for read in reads {
                        if self
                            .target_read(tx, authority, principal, read, stored, budget)
                            .await?
                        {
                            permitted = true;
                            break;
                        }
                    }
                    ensure!(permitted, repository::ReferenceUnavailable);
                }
                TargetSource::Page { .. } => {}
                TargetSource::Selected { .. } | TargetSource::Reference { .. } => {
                    // The mandatory projection names the single current eligible
                    // read. Picker query selection is checked when minting proof.
                }
            }
            for projection in [
                declaration.projection.as_ref(),
                declaration.inspect.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                ensure!(
                    self.target_read(
                        tx,
                        authority,
                        principal,
                        projection.operation,
                        stored,
                        budget
                    )
                    .await?,
                    repository::ReferenceUnavailable
                );
            }
        }
        // Check each alias's mutation and field-binding authority before exposing
        // review conflicts. Sharing a row never shares another alias's policy.
        for declaration in action.targets {
            let proof = &grants[&declaration.name].target;
            let stored = &records[&(proof.resource, proof.id)];
            for step in action.steps {
                let operation = manifest::operation(&self.manifest, step.operation)?;
                if matches!(&step.target, Target::Named(name) if name == &declaration.name)
                    && !manifest::is_capability(operation)
                {
                    ensure!(
                        repository::ReadContext {
                            tx,
                            manifest: &self.manifest,
                            principal,
                            authority,
                            budget: repository::ReadBudget::Action(&mut budget.database_calls)
                        }
                        .authorize(operation, stored)
                        .await?,
                        repository::ReferenceUnavailable
                    );
                }
                // An earlier transaction step may open a gate or change state
                // used by a later reference's eligibility. The executor checks
                // those bindings at their actual step, after preceding writes.
                for assignment in step.assign.iter().filter(|_| action.steps.len() == 1) {
                    if matches!(&assignment.change, noxide_protocol::Change::Set(noxide_protocol::Value::Target(name)) if name == &declaration.name)
                    {
                        let eligible = *operation
                            .bind
                            .get(&assignment.field)
                            .ok_or(repository::ReferenceUnavailable)?;
                        ensure!(
                            self.target_read(tx, authority, principal, eligible, stored, budget)
                                .await?,
                            repository::ReferenceUnavailable
                        );
                        let resource = manifest::resource(&self.manifest, operation.resource)?;
                        ensure!(
                            resource.gate.as_ref().is_none_or(|gate| gate.field
                                != assignment.field
                                || manifest::gate_permits(resource, &stored.record.fields, true)),
                            repository::ReferenceUnavailable
                        );
                    }
                }
            }
        }
        // The reference comes from an approved source projection; aliases never
        // reuse that source's policy as authority for the destination.
        for declaration in action.targets {
            if let TargetSource::Reference {
                target: source,
                field,
                ..
            } = &declaration.source
            {
                let source = &grants[source].target;
                let destination = &grants[&declaration.name].target;
                let source = &records[&(source.resource, source.id)];
                ensure!(
                    source
                        .record
                        .fields
                        .get(field)
                        .and_then(|value| value.parse::<u64>().ok())
                        == Some(destination.id),
                    repository::ReferenceUnavailable
                );
            }
        }
        ensure!(
            !conflicting_reviews
                && reviewed
                    .iter()
                    .all(|(key, revision)| records[key].revision == *revision),
            ReviewConflict
        );
        Ok((records, capability_grant))
    }
}

impl Application {
    pub(in crate::application) fn page_grants(
        action: &Action,
        page: &RecordTarget,
    ) -> BTreeMap<String, RecordTarget> {
        action
            .targets
            .iter()
            .filter(|target| matches!(target.source, TargetSource::Page { .. }))
            .map(|target| (target.name.clone(), page.clone()))
            .collect()
    }

    async fn form_target_row(
        effects: &mut Effects,
        resource: u32,
        id: u64,
        picker: bool,
    ) -> Result<StoredRecord> {
        if let Some(row) = effects.target_rows.get(&(resource, id)) {
            ensure!(
                effects.row_unexpired(row)?,
                repository::ReferenceUnavailable
            );
            return Ok(row.clone());
        }
        if picker {
            effects.charge_list_calls(2)?;
        } else {
            ensure!(effects.calls >= 2, "database call budget");
            effects.calls -= 2;
        }
        let stored = repository::load(&mut effects.tx, &effects.manifest, resource, id)
            .await?
            .ok_or(repository::ReferenceUnavailable)?;
        ensure!(
            effects.row_unexpired(&stored)?,
            repository::ReferenceUnavailable
        );
        effects.target_rows.insert((resource, id), stored.clone());
        Ok(stored)
    }

    async fn form_projection(
        effects: &mut Effects,
        declaration: &ActionTarget,
        stored: &StoredRecord,
        picker: bool,
    ) -> Result<bool> {
        for projection in [
            declaration.projection.as_ref(),
            declaration.inspect.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            let read = manifest::operation(&effects.manifest, projection.operation)?.clone();
            let budget = if picker {
                repository::ReadBudget::Query(&mut effects.list_calls)
            } else {
                repository::ReadBudget::Action(&mut effects.calls)
            };
            if !repository::authorize_stored_read(
                &mut repository::ReadContext {
                    tx: &mut effects.tx,
                    manifest: &effects.manifest,
                    principal: &effects.principal,
                    authority: &mut effects.authority,
                    budget,
                },
                &read,
                stored,
            )
            .await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn seal_derived(
        effects: &mut Effects,
        action: &Action,
        sealed: &mut BTreeMap<String, RecordTarget>,
        picker: bool,
    ) -> Result<()> {
        for declaration in &action.targets {
            let TargetSource::Reference {
                target: source,
                field,
                ..
            } = &declaration.source
            else {
                continue;
            };
            let Some(proof) = sealed.get(source) else {
                continue;
            };
            let parent = manifest::action_target(&action.targets, source)?;
            let source = Self::form_target_row(effects, proof.resource, proof.id, picker).await?;
            ensure!(
                source.incarnation == proof.incarnation,
                repository::ReferenceUnavailable
            );
            ensure!(
                Self::form_projection(effects, parent, &source, picker).await?,
                repository::ReferenceUnavailable
            );
            let id = source
                .record
                .fields
                .get(field)
                .ok_or(repository::ReferenceUnavailable)?
                .parse()?;
            let stored = Self::form_target_row(effects, declaration.resource, id, picker).await?;
            ensure!(
                Self::form_projection(effects, declaration, &stored, picker).await?,
                repository::ReferenceUnavailable
            );
            sealed.insert(
                declaration.name.clone(),
                RecordTarget {
                    resource: declaration.resource,
                    id,
                    incarnation: stored.incarnation,
                    revision: stored.revision,
                    route: None,
                },
            );
        }
        Ok(())
    }

    pub(in crate::application) async fn complete_target_forms(
        &self,
        effects: &mut Effects,
        response: &ResponseIntent,
        forms: &mut BTreeMap<u32, Option<crate::render::FormCredentials>>,
        session: Option<&Token>,
        anonymous: Option<&Token>,
        now: i64,
    ) -> Result<()> {
        let document = match response {
            ResponseIntent::Page(document) | ResponseIntent::NotFound(document) => document,
            _ => return Ok(()),
        };
        let bindings: BTreeSet<_> = document
            .nodes
            .iter()
            .filter_map(|node| {
                if let noxide_protocol::Instruction::Form { action } = node {
                    Some(*action)
                } else {
                    None
                }
            })
            .collect();
        ensure!(bindings.len() <= 8, "form limit");
        for id in bindings {
            let entry = forms
                .get_mut(&id)
                .ok_or_else(|| anyhow::anyhow!("form outside route grant"))?;
            let Some(form) = entry else { continue };
            let binding = manifest::web_binding(&self.manifest, id)?;
            let action = manifest::action(&self.manifest, binding.action)?;
            if !action.targets.iter().any(|target| {
                !matches!(target.source, TargetSource::Page { .. }) || target.projection.is_some()
            }) {
                continue;
            }
            let first = manifest::operation(&self.manifest, action.steps[0].operation)?;
            let subject = if manifest::anonymous_action(first) {
                anonymous
            } else {
                session
            }
            .ok_or(RequestError::Authentication)?;
            effects.authority.invalidate();
            let principal = effects.principal.clone();
            if manifest::anonymous_action(first) {
                effects.principal = auth::Principal::Anonymous;
            }
            let completed = self
                .complete_target_form(effects, action, binding, form, subject, now)
                .await;
            effects.principal = principal;
            effects.authority.invalidate();
            // Cached rows contain no authority, and no picker authority survives
            // into another binding or the guest route context.
            effects.target_rows.clear();
            if !completed? {
                *entry = None;
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    async fn complete_target_form(
        &self,
        effects: &mut Effects,
        action: &Action,
        binding: &noxide_protocol::WebBinding,
        form: &mut crate::render::FormCredentials,
        subject: &Token,
        now: i64,
    ) -> Result<bool> {
        let issued = self.keys.verify(&form.submission, now)?;
        let (security::TokenKind::Submission { mut targets, .. }
        | security::TokenKind::AnonymousSubmission { mut targets, .. }) = issued.kind
        else {
            anyhow::bail!("invalid form proof")
        };
        if let Err(error) = Self::seal_derived(effects, action, &mut targets, false).await {
            if error.is::<repository::ReferenceUnavailable>() {
                return Ok(false);
            }
            return Err(error);
        }
        for declaration in action
            .targets
            .iter()
            .filter(|target| matches!(target.source, TargetSource::Selected { .. }))
        {
            let TargetSource::Selected {
                query, eligible, ..
            } = declaration.source
            else {
                unreachable!()
            };
            let candidates = effects
                .picker_records(binding.id, &declaration.name)
                .await?;
            ensure!(candidates.len() <= 20, "picker result limit");
            let mut options = Vec::new();
            for candidate in candidates {
                let stored =
                    Self::form_target_row(effects, declaration.resource, candidate.id, true)
                        .await?;
                if !Self::form_projection(effects, declaration, &stored, true).await? {
                    continue;
                }
                let mut proof = BTreeMap::from([(
                    declaration.name.clone(),
                    RecordTarget {
                        resource: declaration.resource,
                        id: candidate.id,
                        incarnation: stored.incarnation.clone(),
                        revision: stored.revision,
                        route: None,
                    },
                )]);
                if let Err(error) = Self::seal_derived(effects, action, &mut proof, true).await {
                    if error.is::<repository::ReferenceUnavailable>() {
                        continue;
                    }
                    return Err(error);
                }
                let (_, handle) = self.keys.issue(
                    security::TokenKind::Selection {
                        contract: self.submission_contract(),
                        action: action.id,
                        binding: binding.id,
                        name: declaration.name.clone(),
                        query,
                        eligible,
                        targets: proof,
                    },
                    &self.selection_subject(subject, &effects.principal)?,
                    now,
                    600,
                )?;
                let TargetSource::Selected { label: fields, .. } = &declaration.source else {
                    unreachable!()
                };
                let label = fields
                    .iter()
                    .filter_map(|field| stored.record.fields.get(field))
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" / ")
                    .chars()
                    .take(64)
                    .collect::<String>();
                options.push((
                    handle,
                    if label.is_empty() {
                        format!("Record {}", options.len() + 1)
                    } else {
                        label
                    },
                ));
            }
            form.selections.insert(declaration.name.clone(), options);
        }
        let renewed = self.credentials(
            &manifest::web_action(&self.manifest, binding.id)?,
            subject,
            now,
            targets,
            form.values.clone(),
        )?;
        form.submission = renewed.submission;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
