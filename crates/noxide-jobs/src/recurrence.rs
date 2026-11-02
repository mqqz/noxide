//! Resumable operator recurrence bookkeeping. Query execution/authorization uses
//! the existing query adapter; this module stores its bounded internal frontier.
use super::{store::QueueContext, types::*};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{
    Fields,
    jobs::*,
    time::{Duration, Timestamp},
};
use noxide_store::statements::jobs as stmt;
use std::collections::BTreeMap;

/// What `QueueContext::emit_recurrence` may spend, including its enqueue: at most nine
/// actual statements and two logical calls. `finish_recurrence` uses one of each.
pub const EMIT_STATEMENTS: u16 = 9;

pub struct RecurrenceCursor {
    pub(super) scope: JobScope,
    pub(super) name: String,
    pub(super) version: i64,
    pub(super) cutoff: Timestamp,
    pub(super) cutoff_seq: i64,
    pub(super) cursor: String,
}
pub struct RecurrenceBatch {
    pub(super) position: RecurrenceCursor,
    pub(super) declaration: RecurringSchedule,
    pub(super) grant: Grant,
    pub(super) emitted: u8,
    pub(super) now: Timestamp,
}
impl RecurrenceBatch {
    pub fn cutoff(&self) -> Timestamp {
        self.position.cutoff
    }
    pub fn cutoff_seq(&self) -> i64 {
        self.position.cutoff_seq
    }
    pub fn cursor(&self) -> Option<&str> {
        (!self.position.cursor.is_empty()).then_some(self.position.cursor.as_str())
    }
    pub fn remaining(&self) -> u8 {
        MAX_RECURRENCE_FANOUT - self.emitted
    }
}

/// Ordinary occurrences include the fixed scan cutoff; expiry repair deliberately
/// excludes it, deduplicating by schedule/target incarnation/expiry/contract.
pub fn occurrence_key(
    scope: &JobScope,
    name: &str,
    cutoff: Timestamp,
    cutoff_seq: i64,
    targets: &BTreeMap<String, SealedTarget>,
    expiry: Option<Timestamp>,
    contract: &str,
) -> Result<String> {
    let identities: BTreeMap<_, _> = targets
        .iter()
        .map(|(name, target)| (name, (target.resource, target.id, &target.incarnation)))
        .collect();
    let occurrence = if expiry.is_some() {
        None
    } else {
        Some((cutoff, cutoff_seq))
    };
    Ok(format!(
        "r1_{}",
        digest(&(
            1,
            "recurrence",
            scope,
            name,
            occurrence,
            identities,
            expiry,
            contract
        ))?
    ))
}

impl QueueContext<'_> {
    /// Operator has installed this schedule row under the reviewed contract.
    /// Keep this transaction through query, enqueue and finish; cursor progress
    /// commits atomically with all jobs emitted by this bounded batch.
    pub async fn begin_recurrence(
        &mut self,
        scope: &JobScope,
        declaration: &RecurringSchedule,
        now: Timestamp,
    ) -> Result<Option<RecurrenceBatch>> {
        self.charge()?;
        scope.validate()?;
        ensure!(
            declaration.interval.as_millis() >= MIN_RECURRENCE_MILLIS
                && declaration.interval.as_millis() <= MAX_SCHEDULE_HORIZON_MILLIS,
            "recurring interval limit"
        );
        let (contract, epoch, runtime_state) = self.lock_runtime(scope).await?;
        let (grant, grant_state) = self.lock_grant(scope, &declaration.worker).await?;
        let changed = self
            .tx
            .run(
                &stmt::LOCK_RECURRING,
                &[
                    scope.deployment.as_str().into(),
                    scope.tenant.as_str().into(),
                    declaration.name.as_str().into(),
                ],
            )
            .await?;
        ensure!(changed == 1, "recurring schedule not installed");
        let query = stmt::recurring_schedule(self.tx);
        let rows = self
            .tx
            .rows(
                &query,
                &[
                    scope.deployment.as_str().into(),
                    scope.tenant.as_str().into(),
                    declaration.name.as_str().into(),
                ],
            )
            .await?;
        let [
            stored_contract,
            stored_epoch,
            grant_version,
            version,
            state,
            next,
            cutoff,
            cutoff_seq,
            cursor,
        ] = rows.first().context("recurring schedule unavailable")?;
        let version = integer(version)?;
        ensure!(
            version > 0 && integer(grant_version)? > 0,
            "invalid recurrence version"
        );
        if runtime_state != "active"
            || grant_state != "active"
            || state != "active"
            || stored_contract != &contract
            || stored_epoch != &epoch
            || grant.contract != contract
            || grant.epoch != epoch
            || grant.version != integer(grant_version)?
        {
            self.tx
                .run(
                    &stmt::PAUSE_RECURRING,
                    &[
                        scope.deployment.as_str().into(),
                        scope.tenant.as_str().into(),
                        declaration.name.as_str().into(),
                    ],
                )
                .await?;
            return Ok(None);
        }
        if now.unix_millis() < integer(next)? {
            return Ok(None);
        }
        ensure!(
            grant
                .worker
                .actions
                .iter()
                .any(|action| action.action == declaration.action),
            "recurring action not granted"
        );
        let mut cutoff = Timestamp::from_unix_millis(integer(cutoff)?)?;
        let mut cutoff_seq = integer(cutoff_seq)?;
        let rows = self.tx.rows(&stmt::CREATION_COUNTER, &[]).await?;
        let current_seq = integer(&rows.first().context("creation counter unavailable")?[0])?;
        if cursor.is_empty() {
            cutoff = now;
            cutoff_seq = current_seq;
        } else {
            ensure!(
                cutoff <= now && cutoff_seq <= current_seq,
                "recurring cutoff is in the future"
            );
        }
        cpu_checkpoint(self.tx)?;
        Ok(Some(RecurrenceBatch {
            position: RecurrenceCursor {
                scope: scope.clone(),
                name: declaration.name.clone(),
                version,
                cutoff,
                cutoff_seq,
                cursor: cursor.clone(),
            },
            declaration: declaration.clone(),
            grant,
            emitted: 0,
            now,
        }))
    }
    /// Caller has freshly authorized this query result and supplied its sealed
    /// target plus fixed literal canonical inputs. No picker tokens are accepted.
    /// A duplicate still consumes fanout work, preventing unbounded dedup scans.
    pub async fn emit_recurrence(
        &mut self,
        batch: &mut RecurrenceBatch,
        action_version: u32,
        input: Fields,
        targets: BTreeMap<String, SealedTarget>,
        expiry: Option<Timestamp>,
        tenant_limit: u16,
    ) -> Result<bool> {
        self.charge()?;
        ensure!(
            batch.emitted < MAX_RECURRENCE_FANOUT,
            "recurring fanout limit"
        );
        batch.emitted += 1;
        ensure!(
            batch.declaration.inputs.keys().eq(input.keys()),
            "recurring input aliases differ"
        );
        match &batch.declaration.selection {
            Some(selection) => {
                ensure!(
                    !targets.is_empty()
                        && targets.len() <= 4
                        && targets.contains_key(&selection.target)
                        && batch
                            .grant
                            .worker
                            .actions
                            .iter()
                            .find(|action| action.action == batch.declaration.action)
                            .is_some_and(|action| action.targets.keys().eq(targets.keys()))
                        && selection.expiry_repair == expiry.is_some(),
                    "recurring target or expiry mismatch"
                );
                if let Some(expiry) = expiry {
                    ensure!(
                        expiry <= batch.position.cutoff,
                        "expiry repair target not expired at cutoff"
                    );
                }
            }
            None => ensure!(
                targets.is_empty() && expiry.is_none(),
                "unexpected recurring target"
            ),
        }
        let occurrence = occurrence_key(
            &batch.position.scope,
            &batch.position.name,
            batch.position.cutoff,
            batch.position.cutoff_seq,
            &targets,
            expiry,
            &batch.grant.contract,
        )?;
        let seen = self
            .tx
            .rows(
                &stmt::OCCURRENCE_JOB,
                &[
                    batch.position.scope.deployment.as_str().into(),
                    batch.position.scope.tenant.as_str().into(),
                    batch.position.name.as_str().into(),
                    occurrence.as_str().into(),
                ],
            )
            .await?;
        if !seen.is_empty() {
            return Ok(false);
        }
        let job = CapturedJob {
            scope: batch.position.scope.clone(),
            origin: occurrence.clone(),
            ordinal: 0,
            source_action: batch.declaration.action,
            worker: batch.declaration.worker.clone(),
            action: batch.declaration.action,
            action_version,
            contract: batch.grant.contract.clone(),
            grant_version: batch.grant.version,
            epoch: batch.grant.epoch.clone(),
            due: batch.now,
            input,
            targets,
            reconciled_from: None,
        };
        job.validate()?;
        batch.grant.permits(&job)?;
        let inserted = self.enqueue(&job, batch.now, tenant_limit).await?;
        self.tx
            .run(
                &stmt::INSERT_OCCURRENCE,
                &[
                    batch.position.scope.deployment.as_str().into(),
                    batch.position.scope.tenant.as_str().into(),
                    batch.position.name.as_str().into(),
                    occurrence.into(),
                    job.id()?.into(),
                ],
            )
            .await?;
        Ok(inserted)
    }
    /// `next_cursor` is a canonical INTERNAL query frontier, never a browser
    /// credential with an expiry. None completes this scan. A continued scan
    /// retains both cutoffs, even across arbitrarily many missed intervals.
    pub async fn finish_recurrence(
        &mut self,
        batch: RecurrenceBatch,
        next_cursor: Option<&str>,
    ) -> Result<()> {
        self.charge()?;
        if let Some(cursor) = next_cursor {
            ensure!(
                !cursor.is_empty() && cursor.len() <= 4096 && cursor != batch.position.cursor,
                "recurring scan must advance"
            );
        }
        let next = batch.now.checked_add(Duration::from_millis(
            batch.declaration.interval.as_millis(),
        )?)?;
        let continued = next_cursor.is_some();
        let changed = self
            .tx
            .run(
                &stmt::ADVANCE_RECURRING_CURSOR,
                &[
                    next.unix_millis().into(),
                    (if continued {
                        batch.position.cutoff.unix_millis()
                    } else {
                        0
                    })
                    .into(),
                    (if continued {
                        batch.position.cutoff_seq
                    } else {
                        0
                    })
                    .into(),
                    next_cursor.unwrap_or("").into(),
                    batch.position.scope.deployment.as_str().into(),
                    batch.position.scope.tenant.as_str().into(),
                    batch.position.name.as_str().into(),
                    batch.position.version.into(),
                ],
            )
            .await?;
        ensure!(changed == 1, "recurring cursor changed");
        Ok(())
    }

    /// A resumed scan could not afford another row under this request's budget.
    /// Give other due schedules a turn without changing its frontier/cutoffs or
    /// pretending that an occurrence completed. This is a scan-work retry, not
    /// a new recurring occurrence or an interval shorter than its declaration.
    pub async fn defer_recurrence(&mut self, batch: RecurrenceBatch) -> Result<()> {
        self.charge()?;
        ensure!(
            !batch.position.cursor.is_empty(),
            "recurring deferral requires a persisted scan frontier"
        );
        let next = batch.now.checked_add(Duration::from_millis(1_000)?)?;
        let changed = self
            .tx
            .run(
                &stmt::ADVANCE_RECURRING_DUE,
                &[
                    next.unix_millis().into(),
                    batch.position.scope.deployment.as_str().into(),
                    batch.position.scope.tenant.as_str().into(),
                    batch.position.name.as_str().into(),
                    batch.position.version.into(),
                    batch.position.cutoff.unix_millis().into(),
                    batch.position.cutoff_seq.into(),
                    batch.position.cursor.as_str().into(),
                ],
            )
            .await?;
        ensure!(changed == 1, "recurring scan changed before deferral");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
