//! Headless adapter to the existing action executor, and its transactional schedules.
use super::*;
use crate::jobs::{
    CapturedJob, Claim, Execution, Failure, FailureResult, JobScope, QueueContext, SealedTarget,
};
use noxide_protocol::{jobs::ScheduledTarget, time::Timestamp};

pub enum JobRunOutcome {
    Completed {
        outcomes: Vec<MutationOutcome>,
        recovered: bool,
    },
    BusinessRejected(ValidatedActionRejection),
    Unavailable,
    Paused,
    Dead,
    Retrying(Timestamp),
}

impl Application {
    fn job_receipt(&self, job: &CapturedJob, payload: &str) -> Result<navigation::SemanticReceipt> {
        let (id, version) = job.action();
        let action = manifest::action(&self.manifest, id)?;
        ensure!(
            action.version == version,
            "job receipt action version differs"
        );
        let targets = job
            .targets()
            .iter()
            .map(|(name, target)| {
                (
                    name.clone(),
                    RecordTarget {
                        resource: target.resource,
                        id: target.id,
                        incarnation: target.incarnation.clone(),
                        revision: target.revision,
                        route: None,
                    },
                )
            })
            .collect();
        let receipt = self.validate_core_receipt(ActionCore::of(action)?, &targets, payload)?;
        ensure!(
            receipt.source.is_none() && receipt.destination.is_none() && receipt.handover.is_none(),
            "headless receipt contains browser state"
        );
        Ok(receipt)
    }

    #[cfg(test)]
    pub(crate) async fn invoke_job(
        &self,
        claim: &Claim,
    ) -> std::result::Result<JobRunOutcome, RequestError> {
        self.invoke_job_with_calls(claim, 16).await
    }

    /// A claim is not authority. Each attempt obtains the current queue proof in
    /// its mutation transaction, then enters exactly the same guest/core path as web.
    pub(crate) async fn invoke_job_with_calls(
        &self,
        claim: &Claim,
        remaining: u32,
    ) -> std::result::Result<JobRunOutcome, RequestError> {
        if remaining > 16 {
            return Err(RequestError::InvalidRequest);
        }
        let entry = self.job_request_scope()?;
        entry
            .run(async {
                let admission = self.admit_job_invocation_work().await?;
                let owner = admission.owner;
                owner
                    .run(async {
                        let deadline = owner.work_deadline();
                        let mut budget = ExecutionBudget::new(self.runtime.limits(), deadline);
                        budget.database_calls = remaining;
                        let result =
                            timeout_at(deadline, self.invoke_job_owned(claim, &mut budget)).await;
                        match result {
                            Ok(Ok(value)) => Ok(value),
                            Ok(Err(error)) => Err(error
                                .downcast::<RequestError>()
                                .unwrap_or_else(RequestError::database)),
                            Err(_) => Err(RequestError::OutcomeUnknown),
                        }
                    })
                    .await
            })
            .await
    }

    async fn invoke_job_owned(
        &self,
        claim: &Claim,
        budget: &mut ExecutionBudget,
    ) -> Result<JobRunOutcome> {
        let mut fixed_capture = None;
        for attempt_index in 0..3 {
            let mut tx = self.database.begin(budget.deadline.into_std()).await?;
            self.admission(&mut tx, false).await?;
            let mut admitted_time = None;
            let (capture, execution) = QueueContext {
                tx: &mut tx,
                calls: &mut budget.database_calls,
            }
            .lock_execution_with_time(
                claim,
                async |tx: &mut Transaction, calls: &mut u32| {
                    *calls = calls
                        .checked_sub(1)
                        .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
                    let time = self.temporal_after_admission(tx).await?;
                    admitted_time = Some(time);
                    Ok(time.timestamp())
                },
                |job, payload| self.job_receipt(job, payload).map(|_| ()),
            )
            .await?;
            if let Some(original) = &fixed_capture {
                ensure!(
                    original == &capture,
                    "captured invocation changed during retry"
                );
            } else {
                fixed_capture = Some(capture.clone());
            }
            let verified = match execution {
                Execution::Ready(verified) => verified,
                Execution::Recovered(payload) => {
                    let outcomes = self.job_receipt(&capture, &payload)?.outcomes;
                    tx.commit().await?;
                    return Ok(JobRunOutcome::Completed {
                        outcomes,
                        recovered: true,
                    });
                }
                Execution::Paused => {
                    tx.commit().await?;
                    return Ok(JobRunOutcome::Paused);
                }
                Execution::Dead => {
                    tx.commit().await?;
                    return Ok(JobRunOutcome::Dead);
                }
            };
            let time = admitted_time
                .ok_or_else(|| anyhow::anyhow!("missing admitted lifecycle snapshot"))?;
            ensure!(
                verified.captured() == &capture,
                "captured invocation changed during retry"
            );
            let context = match self.admit_job_invocation(&verified, time) {
                Ok(context) => context,
                Err(_) => {
                    tx.rollback().await?;
                    return self
                        .finish_job_failure(
                            claim,
                            &capture,
                            time.timestamp(),
                            Failure::Rejected,
                            budget,
                        )
                        .await;
                }
            };
            let attempt = self.attempt_action(tx, context, budget).await;
            let _wasm = budget.wasm.take();
            // Only the explicit core proof permits retry/backoff. Raw errors can
            // contain uncertain provider cleanup and leave Running for recovery.
            let attempt = attempt?;
            let (mut tx, receipt, nonce, recovered) = match attempt {
                action::Attempt::Aborted { error } => {
                    if attempt_index < 2
                        && crate::database::retryable(&error)
                        && Instant::now() < budget.deadline
                    {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    return self
                        .finish_job_failure(
                            claim,
                            &capture,
                            time.timestamp(),
                            Failure::Transient,
                            budget,
                        )
                        .await;
                }
                action::Attempt::Settled(settled) => {
                    let failure = match settled {
                        action::Settled::Rejected(rejection) => {
                            Failure::BusinessRejected(rejection)
                        }
                        action::Settled::Unavailable
                        | action::Settled::Conflict { .. }
                        | action::Settled::TargetConflict => Failure::Rejected,
                    };
                    return self
                        .finish_job_failure(claim, &capture, time.timestamp(), failure, budget)
                        .await;
                }
                action::Attempt::Commit { tx, receipt, nonce } => (tx, receipt, Some(nonce), false),
                action::Attempt::Replay { tx, receipt } => (tx, receipt, None, true),
            };
            let validated = self.job_receipt(&capture, &receipt.payload)?;
            if let Some(nonce) = nonce {
                Self::write_receipt(&mut tx, &nonce, &receipt.payload, budget.deadline).await?;
            }
            QueueContext {
                tx: &mut tx,
                calls: &mut budget.database_calls,
            }
            .succeed(&verified, |payload| {
                self.job_receipt(&capture, payload).map(|_| ())
            })
            .await?;
            ensure!(Instant::now() < budget.deadline, "request deadline");
            match tx.commit().await {
                Ok(()) => {
                    return Ok(JobRunOutcome::Completed {
                        outcomes: validated.outcomes,
                        recovered,
                    });
                }
                Err(_) if tx.commit_acknowledged() => {
                    return Ok(JobRunOutcome::Completed {
                        outcomes: validated.outcomes,
                        recovered,
                    });
                }
                Err(error) if !tx.commit_may_have_succeeded() => {
                    tx.rollback()
                        .await
                        .map_err(|_| RequestError::OutcomeUnknown)?;
                    if attempt_index < 2
                        && crate::database::retryable(&error)
                        && Instant::now() < budget.deadline
                    {
                        continue;
                    }
                    return self
                        .finish_job_failure(
                            claim,
                            &capture,
                            time.timestamp(),
                            Failure::Transient,
                            budget,
                        )
                        .await;
                }
                Err(_) => return Err(RequestError::OutcomeUnknown.into()),
            }
        }
        Err(RequestError::Busy.into())
    }

    async fn finish_job_failure(
        &self,
        claim: &Claim,
        capture: &CapturedJob,
        now: Timestamp,
        failure: Failure,
        budget: &mut ExecutionBudget,
    ) -> Result<JobRunOutcome> {
        let mut tx = self.database.begin(budget.deadline.into_std()).await?;
        self.admission(&mut tx, false).await?;
        let outcome = QueueContext {
            tx: &mut tx,
            calls: &mut budget.database_calls,
        }
        .fail(claim, now, failure, |payload| {
            self.job_receipt(capture, payload).map(|_| ())
        })
        .await?;
        let outcome = match outcome {
            FailureResult::Recovered(payload) => JobRunOutcome::Completed {
                outcomes: self.job_receipt(capture, &payload)?.outcomes,
                recovered: true,
            },
            FailureResult::BusinessRejected(rejection) => {
                JobRunOutcome::BusinessRejected(rejection)
            }
            FailureResult::Rejected => JobRunOutcome::Unavailable,
            FailureResult::Paused => JobRunOutcome::Paused,
            FailureResult::Dead => JobRunOutcome::Dead,
            FailureResult::Retrying(at) => JobRunOutcome::Retrying(at),
        };
        tx.commit()
            .await
            .map_err(|_| RequestError::OutcomeUnknown)?;
        Ok(outcome)
    }

    pub(crate) fn canonical_job_input(&self, id: u32, input: &Fields) -> Result<Fields> {
        let action = manifest::action(&self.manifest, id)?;
        let canonical = manifest::canonical_input(&self.manifest, action, input)?;
        manifest::validate_input(&self.manifest, action, &canonical)?;
        Ok(canonical)
    }

    /// Resolve candidate identities in this transaction before current service
    /// authorization. Existing captures may be explicitly reconciled, never copied.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn seal_job_targets(
        &self,
        tx: &mut Transaction,
        locked: &crate::jobs::VerifiedScheduleGrant,
        id: u32,
        candidates: &BTreeMap<String, SealedTarget>,
        time: crate::lifecycle_clock::AttemptTime,
        calls: &mut u32,
    ) -> Result<BTreeMap<String, SealedTarget>> {
        let rows = self
            .load_job_target_rows(tx, candidates, &mut BTreeMap::new(), calls)
            .await?;
        let principal = crate::jobs::locked_grant_principal(locked);
        let mut authority = self.authority_context(Some(time))?;
        self.seal_job_target_rows(
            &mut repository::ReadContext {
                tx,
                manifest: &self.manifest,
                principal: &principal,
                authority: &mut authority,
                budget: repository::ReadBudget::Action(calls),
            },
            locked,
            id,
            &rows,
        )
        .await
    }

    async fn load_job_target_rows(
        &self,
        tx: &mut Transaction,
        candidates: &BTreeMap<String, SealedTarget>,
        cache: &mut BTreeMap<(u32, u64), StoredRecord>,
        calls: &mut u32,
    ) -> Result<BTreeMap<String, StoredRecord>> {
        ensure!(candidates.len() <= 4, repository::ReferenceUnavailable);
        let mut rows = BTreeMap::new();
        for (alias, candidate) in candidates {
            ensure!(
                candidate.id > 0
                    && candidate.id <= i64::MAX as u64
                    && !candidate.incarnation.is_empty()
                    && candidate.incarnation.len() <= 64,
                repository::ReferenceUnavailable
            );
            let key = (candidate.resource, candidate.id);
            if let std::collections::btree_map::Entry::Vacant(entry) = cache.entry(key) {
                *calls = calls
                    .checked_sub(2)
                    .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
                entry.insert(
                    repository::load(tx, &self.manifest, candidate.resource, candidate.id)
                        .await?
                        .ok_or(repository::ReferenceUnavailable)?,
                );
            }
            let stored = &cache[&key];
            ensure!(
                stored.incarnation == candidate.incarnation,
                repository::ReferenceUnavailable
            );
            rows.insert(alias.clone(), stored.clone());
        }
        Ok(rows)
    }

    /// Host-only row boundary for canonical query candidates and final action rows.
    /// Callers must obtain every row from this same transaction, with no intervening
    /// resource mutation. Sharing row data never shares an alias's read authority.
    pub(crate) async fn seal_job_target_rows(
        &self,
        context: &mut repository::ReadContext<'_>,
        locked: &crate::jobs::VerifiedScheduleGrant,
        id: u32,
        rows: &BTreeMap<String, StoredRecord>,
    ) -> Result<BTreeMap<String, SealedTarget>> {
        let grant = locked.grant();
        ensure!(
            Some(&grant.scope.deployment) == self.generation.get()
                && grant.contract == self.contract,
            repository::ReferenceUnavailable
        );
        let action = manifest::action(&self.manifest, id)?;
        let rule = grant
            .worker
            .actions
            .iter()
            .find(|rule| rule.action == id)
            .ok_or(repository::ReferenceUnavailable)?;
        ensure!(
            rows.len() == action.targets.len() && rule.targets.len() == action.targets.len(),
            repository::ReferenceUnavailable
        );
        ensure!(
            context.principal.authority_key()
                == crate::jobs::locked_grant_principal(locked).authority_key()
                && std::ptr::eq(context.manifest, self.manifest.as_ref()),
            repository::ReferenceUnavailable
        );
        let mut targets = BTreeMap::new();
        for target in &action.targets {
            let stored = rows
                .get(&target.name)
                .ok_or(repository::ReferenceUnavailable)?;
            let binding = rule
                .targets
                .get(&target.name)
                .ok_or(repository::ReferenceUnavailable)?;
            let eligible = match target.source {
                TargetSource::Service { eligible } | TargetSource::Reference { eligible, .. } => {
                    eligible
                }
                _ => anyhow::bail!(repository::ReferenceUnavailable),
            };
            ensure!(
                target.resource == stored.record.resource
                    && binding.resource == stored.record.resource
                    && binding.eligible == eligible
                    && stored.record.id > 0
                    && stored.record.id <= i64::MAX as u64
                    && !stored.incarnation.is_empty()
                    && stored.incarnation.len() <= 64
                    && stored.revision > 0,
                repository::ReferenceUnavailable
            );
            let read = manifest::operation(&self.manifest, eligible)?;
            ensure!(
                repository::authorize_stored_read(context, read, stored).await?,
                repository::ReferenceUnavailable
            );
            targets.insert(
                target.name.clone(),
                SealedTarget {
                    resource: stored.record.resource,
                    id: stored.record.id,
                    incarnation: stored.incarnation.clone(),
                    revision: if target.revision == Revision::Identity {
                        0
                    } else {
                        stored.revision
                    },
                },
            );
        }
        for target in &action.targets {
            if let TargetSource::Reference {
                target: parent,
                field,
                ..
            } = &target.source
            {
                ensure!(
                    rows.get(parent)
                        .and_then(|row| row.record.fields.get(field))
                        .and_then(|raw| raw.parse::<u64>().ok())
                        == targets.get(&target.name).map(|seal| seal.id),
                    repository::ReferenceUnavailable
                );
            }
        }
        Ok(targets)
    }

    /// Fixed schedule effects share the mutation transaction and receipt. Scalar
    /// values come from initial snapshots; Created supplies identities only.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn enqueue_action_jobs(
        &self,
        effects: &mut Effects,
        action: ActionCore<'_>,
        snapshots: &BTreeMap<(u32, u64), StoredRecord>,
        outcomes: &[MutationOutcome],
        time: Option<crate::lifecycle_clock::AttemptTime>,
        origin: &str,
    ) -> Result<()> {
        let Some(contract) = &self.manifest.jobs else {
            return Ok(());
        };
        let schedules: Vec<_> = contract
            .schedules
            .iter()
            .filter(|schedule| schedule.source_action == action.id)
            .collect();
        if schedules.is_empty() {
            return Ok(());
        }
        ensure!(
            schedules.len() <= noxide_protocol::jobs::MAX_SCHEDULES_PER_ACTION,
            "schedule count limit"
        );
        let time = time.ok_or(repository::CalculationUnavailable)?;
        let scope = JobScope {
            deployment: self
                .generation
                .get()
                .ok_or_else(|| anyhow::anyhow!("application is not activated"))?
                .clone(),
            tenant: match &effects.principal {
                auth::Principal::Anonymous => String::new(),
                auth::Principal::User(user) => user.tenant.clone(),
                auth::Principal::Service(service) => service.tenant().to_owned(),
            },
        };
        // Only queue bookkeeping follows; no resource row can change while these
        // two fixed effects are sealed. Deduplicate data loads, never authorization:
        // rows this transaction wrote are already final and write-locked.
        let mut final_rows = effects.written_rows.clone();
        #[cfg(test)]
        for ((resource, id), row) in &final_rows {
            let loaded = repository::load(&mut effects.tx, &self.manifest, *resource, *id).await?;
            assert_eq!(loaded.as_ref(), Some(row), "reused job target row diverged");
        }
        // These are authoritative row-lock proofs within this transaction, not
        // configuration metadata. No resource writes occur between fixed effects.
        let mut locked_grants = BTreeMap::new();
        for schedule in schedules {
            let destination = manifest::action(&self.manifest, schedule.action)?;
            let (due, raw) = {
                let values = repository::ScheduleValues {
                    manifest: &self.manifest,
                    input: &effects.request.input,
                    principal: &effects.principal,
                    grants: &effects.grants,
                    snapshots,
                    outcomes,
                    time: Some(time),
                    current: None,
                };
                let repository::ScheduleScalar::Timestamp(due) =
                    values.value(&schedule.due_at, action)?
                else {
                    anyhow::bail!(repository::CalculationUnavailable);
                };
                let mut raw = Fields::new();
                for (name, value) in &schedule.inputs {
                    raw.insert(name.clone(), values.value(value, action)?.encode());
                }
                (due, raw)
            };
            let input = manifest::canonical_input(&self.manifest, destination, &raw)?;
            manifest::validate_input(&self.manifest, destination, &input)?;
            if let std::collections::btree_map::Entry::Vacant(entry) =
                locked_grants.entry(schedule.worker.as_str())
            {
                entry.insert(
                    QueueContext {
                        tx: &mut effects.tx,
                        calls: &mut effects.calls,
                    }
                    .schedule_grant(&scope, &schedule.worker, &self.contract)
                    .await?,
                );
            }
            let locked = &locked_grants[schedule.worker.as_str()];
            let mut candidates = BTreeMap::new();
            for (alias, source) in &schedule.targets {
                let (resource, id, incarnation) = match source {
                    ScheduledTarget::Target(name) => {
                        let target = effects
                            .grants
                            .get(name)
                            .ok_or(repository::ReferenceUnavailable)?;
                        (target.resource, target.id, target.incarnation.clone())
                    }
                    ScheduledTarget::Created(index) => {
                        let outcome = outcomes
                            .get(usize::from(*index))
                            .ok_or(repository::ReferenceUnavailable)?;
                        ensure!(
                            outcome.kind == MutationKind::Created,
                            repository::ReferenceUnavailable
                        );
                        (outcome.resource, outcome.id, outcome.incarnation.clone())
                    }
                };
                candidates.insert(
                    alias.clone(),
                    SealedTarget {
                        resource,
                        id,
                        incarnation,
                        revision: 0,
                    },
                );
            }
            let rows = self
                .load_job_target_rows(
                    &mut effects.tx,
                    &candidates,
                    &mut final_rows,
                    &mut effects.calls,
                )
                .await?;
            let principal = crate::jobs::locked_grant_principal(locked);
            let mut authority = self.authority_context(Some(time))?;
            let targets = self
                .seal_job_target_rows(
                    &mut repository::ReadContext {
                        tx: &mut effects.tx,
                        manifest: &self.manifest,
                        principal: &principal,
                        authority: &mut authority,
                        budget: repository::ReadBudget::Action(&mut effects.calls),
                    },
                    locked,
                    destination.id,
                    &rows,
                )
                .await?;
            let grant = locked.grant();
            let job = CapturedJob::capture(
                schedule,
                origin.to_owned(),
                grant,
                destination.version,
                due,
                time.timestamp(),
                input,
                targets,
            )?;
            QueueContext {
                tx: &mut effects.tx,
                calls: &mut effects.calls,
            }
            .enqueue(
                &job,
                time.timestamp(),
                noxide_protocol::jobs::MAX_PENDING_JOBS,
            )
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests;
