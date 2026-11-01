use super::types::*;
use crate::sql::sql;
use crate::{
    action_contract::ValidatedActionRejection,
    database::{Transaction, lifecycle::RequestScope},
    query_plan::NativeProvider,
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{
    jobs::*,
    time::{Duration, Timestamp},
};

pub struct QueueContext<'a> {
    pub tx: &'a mut Transaction,
    pub calls: &'a mut u32,
}

pub enum Execution {
    Ready(Box<VerifiedJob>),
    /// Complete receipt has been validated by the existing semantic decoder.
    Recovered(String),
    Paused,
    Dead,
}
pub enum Failure {
    Transient,
    Rejected,
    BusinessRejected(ValidatedActionRejection),
}
pub enum FailureResult {
    Retrying(Timestamp),
    Rejected,
    BusinessRejected(ValidatedActionRejection),
    Dead,
    Paused,
    Recovered(String),
}

/// An active enqueue grant read and locked in the originating transaction.
/// It is not execution authority and cannot be constructed by an adapter.
pub struct VerifiedScheduleGrant {
    grant: Grant,
}
impl VerifiedScheduleGrant {
    pub fn grant(&self) -> &Grant {
        &self.grant
    }
}

struct RuntimeSnapshot {
    contract: String,
    epoch: String,
    state: String,
    pending_limit: u16,
    tenant_limit: u16,
    concurrency: u8,
}

struct Row {
    job: CapturedJob,
    state: String,
    attempts: i64,
    first_eligible: Timestamp,
    fence: i64,
    lease_until: Timestamp,
}
impl QueueContext<'_> {
    fn checkpoint(&self) -> Result<()> {
        cpu_checkpoint(self.tx)
    }
    pub(super) fn charge(&mut self) -> Result<()> {
        self.checkpoint()?;
        *self.calls = self.calls.checked_sub(1).context("database call budget")?;
        Ok(())
    }
    pub(super) async fn lock_runtime(
        &mut self,
        scope: &JobScope,
    ) -> Result<(String, String, String)> {
        let runtime = self.runtime_snapshot(scope).await?;
        Ok((runtime.contract, runtime.epoch, runtime.state))
    }
    async fn runtime_snapshot(&mut self, scope: &JobScope) -> Result<RuntimeSnapshot> {
        self.checkpoint()?;
        let suffix = match self.tx.query_provider()? {
            NativeProvider::Postgres => " FOR SHARE",
            NativeProvider::Sqlite => "",
        };
        let query = sql!(
            "SELECT deployment,contract,epoch,state,CAST(pending_limit AS TEXT),CAST(tenant_limit AS TEXT),CAST(concurrency AS TEXT) FROM nx_job_runtime WHERE singleton=1 AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=nx_job_runtime.deployment){suffix}"
        );
        let rows = self.tx.fetch::<7>(&query, &[]).await?;
        let [
            deployment,
            contract,
            epoch,
            state,
            pending,
            tenant,
            concurrency,
        ] = rows.first().context("job runtime unavailable")?;
        let pending_limit = u16::try_from(integer(pending)?)?;
        let tenant_limit = u16::try_from(integer(tenant)?)?;
        let concurrency = u8::try_from(integer(concurrency)?)?;
        ensure!(
            (1..=MAX_PENDING_JOBS).contains(&pending_limit)
                && (1..=pending_limit).contains(&tenant_limit)
                && (1..=MAX_WORKERS_PER_APP).contains(&concurrency),
            "invalid authoritative queue limits"
        );
        Ok(RuntimeSnapshot {
            contract: contract.clone(),
            epoch: epoch.clone(),
            state: if deployment == &scope.deployment {
                state.clone()
            } else {
                "changed".into()
            },
            pending_limit,
            tenant_limit,
            concurrency,
        })
    }
    pub(super) async fn lock_grant(
        &mut self,
        scope: &JobScope,
        worker: &str,
    ) -> Result<(Grant, String)> {
        self.checkpoint()?;
        let payload = self.tx.bounded_text("declaration", MAX_JOB_BYTES);
        let suffix = match self.tx.query_provider()? {
            NativeProvider::Postgres => " FOR SHARE",
            NativeProvider::Sqlite => "",
        };
        let query = sql!(
            "SELECT {payload},state,CAST(version AS TEXT),contract,epoch FROM nx_job_grants WHERE deployment=$1 AND tenant=$2 AND worker=$3{suffix}"
        );
        let rows = self
            .tx
            .fetch::<5>(
                &query,
                &[
                    scope.deployment.as_str().into(),
                    scope.tenant.as_str().into(),
                    worker.into(),
                ],
            )
            .await?;
        let [payload, state, version, contract, epoch] =
            rows.first().context("service grant unavailable")?;
        let grant: Grant = serde_json::from_str(payload)?;
        grant.validate()?;
        ensure!(
            &grant.scope == scope
                && grant.worker.name == worker
                && grant.version == integer(version)?
                && &grant.contract == contract
                && &grant.epoch == epoch,
            "service grant storage mismatch"
        );
        self.checkpoint()?;
        Ok((grant, state.clone()))
    }
    async fn row(&mut self, claim: &Claim, lock: bool) -> Result<Row> {
        self.checkpoint()?;
        if lock {
            let changed = self.tx.execute("UPDATE nx_jobs SET fence=fence WHERE id=$1 AND deployment=$2 AND tenant=$3 AND fence=$4", &[claim.id.as_str().into(), claim.scope.deployment.as_str().into(), claim.scope.tenant.as_str().into(), claim.fence.into()]).await?;
            ensure!(changed == 1, "job claim superseded");
        }
        let payload = self.tx.bounded_text("payload", MAX_JOB_BYTES);
        let rows = self.tx.fetch::<17>(&sql!("SELECT {payload},payload_digest,state,CAST(attempts AS TEXT),CAST(first_eligible_ms AS TEXT),CAST(fence AS TEXT),CAST(lease_until_ms AS TEXT),contract,epoch,worker,CAST(action AS TEXT),CAST(grant_version AS TEXT),CAST(due_ms AS TEXT),CAST(eligible_ms AS TEXT),origin,CAST(ordinal AS TEXT),COALESCE(reconciled_from,'') FROM nx_jobs WHERE id=$1 AND deployment=$2 AND tenant=$3"), &[claim.id.as_str().into(), claim.scope.deployment.as_str().into(), claim.scope.tenant.as_str().into()]).await?;
        let [
            payload,
            digest,
            state,
            attempts,
            first_eligible,
            fence,
            lease_until,
            contract,
            epoch,
            worker,
            action,
            grant_version,
            due,
            eligible,
            origin,
            ordinal,
            reconciled_from,
        ] = rows.first().context("job unavailable")?;
        let job: CapturedJob = serde_json::from_str(payload)?;
        job.validate()?;
        ensure!(
            job.id()? == claim.id
                && job.scope == claim.scope
                && job.invocation_digest()? == *digest
                && job.contract == *contract
                && job.epoch == *epoch,
            "job storage identity mismatch"
        );
        ensure!(
            job.worker == *worker
                && i64::from(job.action) == integer(action)?
                && job.grant_version == integer(grant_version)?
                && job.due.unix_millis() == integer(due)?
                && job.origin == *origin
                && i64::from(job.ordinal) == integer(ordinal)?
                && job.reconciled_from().unwrap_or("") == reconciled_from,
            "job indexed metadata differs from capture"
        );
        ensure!(
            integer(first_eligible)? >= integer(due)?
                && integer(eligible)? >= integer(first_eligible)?,
            "job retry time precedes eligibility"
        );
        let row = Row {
            job,
            state: state.clone(),
            attempts: integer(attempts)?,
            first_eligible: Timestamp::from_unix_millis(integer(first_eligible)?)?,
            fence: integer(fence)?,
            lease_until: Timestamp::from_unix_millis(integer(lease_until)?)?,
        };
        ensure!(
            row.attempts <= i64::from(MAX_JOB_ATTEMPTS)
                && row.fence == claim.fence
                && (row.state != "running" || row.lease_until == claim.lease_until),
            "invalid or superseded job claim"
        );
        ensure!(
            match row.state.as_str() {
                "running" => row.lease_until.unix_millis() > 0 && row.fence > 0 && row.attempts > 0,
                "pending" =>
                    row.lease_until == Timestamp::UNIX_EPOCH
                        && row.attempts < i64::from(MAX_JOB_ATTEMPTS),
                "succeeded" | "rejected" | "dead" | "paused" =>
                    row.lease_until == Timestamp::UNIX_EPOCH,
                _ => false,
            },
            "invalid job state shape"
        );
        self.checkpoint()?;
        Ok(row)
    }
    /// Authoritative bound receipt lookup after acquiring the claimed row lock.
    /// The callback MUST be the existing core's semantic receipt decoder.
    async fn receipt(
        &mut self,
        row: &Row,
        validate: &impl Fn(&str) -> Result<()>,
    ) -> Result<Option<String>> {
        let outcome = self
            .tx
            .bounded_text("outcome", noxide_protocol::MAX_RESULT_BYTES);
        let receipts = self.tx.fetch::<5>(&sql!("SELECT subject,contract,CAST(action AS TEXT),input,{outcome} FROM nx_receipts WHERE nonce=$1"), &[row.job.id()?.into()]).await?;
        let Some([subject, contract, action, input, outcome]) = receipts.first() else {
            return Ok(None);
        };
        ensure!(
            *subject == row.job.receipt_subject()?
                && *contract == row.job.contract
                && integer(action)? == i64::from(row.job.action)
                && *input == row.job.invocation_digest()?
                && !outcome.is_empty(),
            "job receipt is incomplete or mismatched"
        );
        validate(outcome)?;
        self.checkpoint()?;
        Ok(Some(outcome.clone()))
    }
    async fn transition(
        &mut self,
        claim: &Claim,
        state: &str,
        reason: &str,
        eligible: Timestamp,
    ) -> Result<()> {
        self.checkpoint()?;
        let changed = self.tx.execute("UPDATE nx_jobs SET state=$1,reason=$2,eligible_ms=$3,lease_until_ms=0 WHERE id=$4 AND deployment=$5 AND tenant=$6 AND state='running' AND fence=$7", &[state.into(), reason.into(), eligible.unix_millis().into(), claim.id.as_str().into(), claim.scope.deployment.as_str().into(), claim.scope.tenant.as_str().into(), claim.fence.into()]).await?;
        ensure!(changed == 1, "job finalization superseded");
        Ok(())
    }
    /// Current operator intersection for a fixed admitted transactional schedule.
    pub async fn schedule_grant(
        &mut self,
        scope: &JobScope,
        worker: &str,
        contract: &str,
    ) -> Result<VerifiedScheduleGrant> {
        self.charge()?;
        let (current_contract, epoch, state) = self.lock_runtime(scope).await?;
        ensure!(
            state == "active" && current_contract == contract,
            "job runtime changed"
        );
        let (grant, state) = self.lock_grant(scope, worker).await?;
        ensure!(
            state == "active" && grant.contract == contract && grant.epoch == epoch,
            "service grant changed"
        );
        Ok(VerifiedScheduleGrant { grant })
    }

    /// Caller has separately authorized the originating schedule declaration and
    /// evaluated/canonicalized every input and resolved target in this transaction.
    /// Enqueue and action mutations/receipt commit together. Never commits here.
    pub async fn enqueue(
        &mut self,
        job: &CapturedJob,
        now: Timestamp,
        tenant_limit: u16,
    ) -> Result<bool> {
        self.charge()?;
        self.checkpoint()?;
        job.validate()?;
        ensure!(
            (1..=MAX_PENDING_JOBS).contains(&tenant_limit),
            "invalid tenant queue limit"
        );
        ensure!(
            job.due <= now.checked_add(Duration::from_millis(MAX_SCHEDULE_HORIZON_MILLIS)?)?,
            "job schedule horizon"
        );
        // Lock the singleton only during queue admission/claim, not action work.
        let runtime = self.runtime_snapshot(&job.scope).await?;
        ensure!(
            runtime.state == "active"
                && runtime.contract == job.contract
                && runtime.epoch == job.epoch,
            "job runtime paused or changed"
        );
        let changed = self
            .tx
            .execute(
                "UPDATE nx_job_queue SET claim_seq=claim_seq WHERE singleton=1",
                &[],
            )
            .await?;
        ensure!(changed == 1, "job queue unavailable");
        let (grant, state) = self.lock_grant(&job.scope, &job.worker).await?;
        ensure!(state == "active", "service grant revoked");
        grant.permits(job)?;
        let id = job.id()?;
        let digest = job.invocation_digest()?;
        let existing = self
            .tx
            .fetch::<1>(
                "SELECT payload_digest FROM nx_jobs WHERE id=$1",
                &[id.as_str().into()],
            )
            .await?;
        if let Some([stored]) = existing.first() {
            ensure!(
                *stored == digest,
                "origin effect ordinal reused with different capture"
            );
            return Ok(false);
        }
        // The queue write lock serializes both quota checks and insertion.
        // Old paused contracts count until explicitly reconciled by the operator.
        let counts = self.tx.fetch::<2>("SELECT CAST(COUNT(*) AS TEXT),CAST(COALESCE(SUM(CASE WHEN tenant=$1 THEN 1 ELSE 0 END),0) AS TEXT) FROM (SELECT tenant FROM nx_jobs WHERE state IN ('pending','running','paused') LIMIT 1001) AS active_jobs", &[job.scope.tenant.as_str().into()]).await?;
        ensure!(
            integer(&counts[0][0])? < i64::from(runtime.pending_limit)
                && integer(&counts[0][1])? < i64::from(tenant_limit.min(runtime.tenant_limit)),
            "job queue full"
        );
        self.tx.execute("INSERT INTO nx_job_tenants(deployment,tenant,claim_seq) VALUES($1,$2,0) ON CONFLICT(deployment,tenant) DO NOTHING", &[job.scope.deployment.as_str().into(), job.scope.tenant.as_str().into()]).await?;
        let payload = serde_json::to_string(job)?;
        self.tx.execute("INSERT INTO nx_jobs(id,deployment,tenant,origin,ordinal,worker,action,contract,epoch,grant_version,payload,payload_digest,due_ms,eligible_ms,first_eligible_ms,attempts,fence,lease_until_ms,state,reason,reconciled_from) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14,0,0,0,'pending','',NULLIF($15,''))", &[id.into(), job.scope.deployment.as_str().into(), job.scope.tenant.as_str().into(), job.origin.as_str().into(), i64::from(job.ordinal).into(), job.worker.as_str().into(), i64::from(job.action).into(), job.contract.as_str().into(), job.epoch.as_str().into(), job.grant_version.into(), payload.into(), digest.into(), job.due.unix_millis().into(), now.max(job.due).unix_millis().into(), job.reconciled_from().unwrap_or("").into()]).await?;
        Ok(true)
    }
    /// One fair bounded claim. Commit this short transaction before launching
    /// the existing executor. A lost claim acknowledgement is checked by the
    /// later execution lock; it never grants authority itself.
    pub async fn claim(&mut self, deployment: &str, now: Timestamp) -> Result<Option<Claim>> {
        self.charge()?;
        self.checkpoint()?;
        ensure!(opaque(deployment), "invalid job deployment");
        let runtime = self
            .runtime_snapshot(&JobScope {
                deployment: deployment.into(),
                tenant: String::new(),
            })
            .await?;
        ensure!(runtime.state == "active", "job runtime unavailable");
        let changed = self.tx.execute("UPDATE nx_job_queue SET claim_seq=claim_seq+1 WHERE singleton=1 AND claim_seq<9223372036854775807 AND EXISTS(SELECT 1 FROM nx_job_runtime WHERE singleton=1 AND deployment=$1 AND state='active' AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=nx_job_runtime.deployment))", &[deployment.into()]).await?;
        ensure!(changed == 1, "job runtime unavailable");
        // Counting all running rows prevents lease expiry from freeing capacity
        // while an old execution transaction might still be alive.
        let running = self.tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM (SELECT id FROM nx_jobs WHERE state='running' LIMIT 3) AS running_jobs", &[]).await?;
        let capacity = integer(&running[0][0])? < i64::from(runtime.concurrency);
        // Never wait on a job row while retaining the queue lock: an existing
        // action may hold that row and enqueue its own admitted next action.
        let suffix = match self.tx.query_provider()? {
            NativeProvider::Postgres => " FOR UPDATE OF j SKIP LOCKED",
            NativeProvider::Sqlite => "",
        };
        let rows = self.tx.fetch::<5>(&sql!("SELECT j.id,j.tenant,CAST(j.fence AS TEXT),CAST(j.attempts AS TEXT),j.state FROM nx_jobs j JOIN nx_job_tenants t ON t.deployment=j.deployment AND t.tenant=j.tenant WHERE j.deployment=$1 AND ((j.state='running' AND j.lease_until_ms<=$2) OR (j.state='pending' AND j.eligible_ms<=$2 AND $3=1)) ORDER BY t.claim_seq,j.eligible_ms,j.id LIMIT 1{suffix}"), &[deployment.into(), now.unix_millis().into(), i64::from(capacity).into()]).await?;
        let Some([id, tenant, fence, attempts, state]) = rows.first() else {
            return Ok(None);
        };
        let next_fence = integer(fence)?
            .checked_add(1)
            .context("job fence exhausted")?;
        let attempts = integer(attempts)?;
        ensure!(
            attempts <= i64::from(MAX_JOB_ATTEMPTS),
            "invalid job attempts"
        );
        let lease = now.checked_add(Duration::from_millis(JOB_LEASE_MILLIS)?)?;
        let changed = self.tx.execute("UPDATE nx_jobs SET state='running',fence=$1,lease_until_ms=$2,attempts=$3 WHERE id=$4 AND deployment=$5 AND fence=$6 AND state=$7", &[next_fence.into(), lease.unix_millis().into(), (attempts + i64::from(attempts < i64::from(MAX_JOB_ATTEMPTS))).into(), id.as_str().into(), deployment.into(), integer(fence)?.into(), state.as_str().into()]).await?;
        ensure!(changed == 1, "job claim raced");
        self.tx.execute("UPDATE nx_job_tenants SET claim_seq=(SELECT claim_seq FROM nx_job_queue WHERE singleton=1) WHERE deployment=$1 AND tenant=$2", &[deployment.into(), tenant.as_str().into()]).await?;
        Ok(Some(Claim {
            id: id.clone(),
            scope: JobScope {
                deployment: deployment.into(),
                tenant: tenant.clone(),
            },
            fence: next_fence,
            lease_until: lease,
            exhausted: attempts >= i64::from(MAX_JOB_ATTEMPTS),
        }))
    }
    /// Locks authoritative runtime/grant plus claimed row in this execution
    /// transaction. Restores/revocations take conflicting locks. No current
    /// authorization is inferred from a captured grant or record identity.
    pub async fn lock_execution_with_time(
        &mut self,
        claim: &Claim,
        sample_time: impl AsyncFnOnce(&mut Transaction, &mut u32) -> Result<Timestamp>,
        validate_receipt: impl Fn(&CapturedJob, &str) -> Result<()>,
    ) -> Result<(CapturedJob, Execution)> {
        self.charge()?;
        self.checkpoint()?;
        let deadline = RequestScope::current_work_deadline()
            .context("job execution requires existing request scope")?;
        ensure!(
            deadline
                < tokio::time::Instant::now()
                    + std::time::Duration::from_millis(JOB_LEASE_MILLIS as u64),
            "action deadline must be below job lease"
        );
        let (contract, epoch, runtime_state) = self.lock_runtime(&claim.scope).await?;
        // Lock order is runtime -> grant -> job -> receipt throughout this module.
        let preview = self.row(claim, false).await?;
        let (grant, grant_state) = self.lock_grant(&claim.scope, &preview.job.worker).await?;
        let row = self.row(claim, true).await?;
        let capture = row.job.clone();
        if let Some(outcome) = self
            .receipt(&row, &|payload| validate_receipt(&row.job, payload))
            .await?
        {
            if row.state == "running" {
                self.transition(claim, "succeeded", "", row.first_eligible)
                    .await?;
            } else {
                ensure!(
                    row.state == "succeeded",
                    "receipt with inconsistent job state"
                );
            }
            return Ok((capture, Execution::Recovered(outcome)));
        }
        // This host callback consumes the existing lifecycle snapshot and charges
        // its logical call. Receipt recovery never invokes a fresh time guard.
        let now = sample_time(&mut *self.tx, &mut *self.calls).await?;
        ensure!(
            row.state == "running" && now < row.lease_until,
            "job claim expired or settled"
        );
        if runtime_state != "active"
            || row.job.contract != contract
            || row.job.epoch != epoch
            || grant_state != "active"
            || grant.permits(&row.job).is_err()
        {
            self.transition(claim, "paused", "authority_changed", now)
                .await?;
            return Ok((capture, Execution::Paused));
        }
        let window = row
            .first_eligible
            .checked_add(Duration::from_millis(JOB_RETRY_WINDOW_MILLIS)?)?;
        if now >= window || claim.exhausted {
            self.transition(claim, "dead", "retry_window", now).await?;
            return Ok((capture, Execution::Dead));
        }
        ensure!(row.attempts > 0, "job has no claimed attempt");
        Ok((
            capture,
            Execution::Ready(Box::new(VerifiedJob {
                claim: claim.clone(),
                job: row.job,
                grant,
            })),
        ))
    }
    #[cfg(any(test, feature = "test-support"))]
    pub async fn lock_execution(
        &mut self,
        claim: &Claim,
        now: Timestamp,
        validate_receipt: impl Fn(&str) -> Result<()>,
    ) -> Result<Execution> {
        // A supplied fixture timestamp performs no lifecycle database read.
        self.lock_execution_with_time(
            claim,
            async |_, _| Ok(now),
            |_, payload| validate_receipt(payload),
        )
        .await
        .map(|(_, execution)| execution)
    }

    /// Existing executor must first persist a complete semantic receipt. This
    /// completion write participates in that exact same mutation transaction.
    pub async fn succeed(
        &mut self,
        verified: &VerifiedJob,
        validate_receipt: impl Fn(&str) -> Result<()>,
    ) -> Result<()> {
        self.charge()?;
        let (contract, epoch, state) = self.lock_runtime(&verified.job.scope).await?;
        let (grant, grant_state) = self
            .lock_grant(&verified.job.scope, &verified.job.worker)
            .await?;
        ensure!(
            state == "active"
                && contract == verified.job.contract
                && epoch == verified.job.epoch
                && grant_state == "active",
            "job authority changed before completion"
        );
        grant.permits(&verified.job)?;
        let row = self.row(&verified.claim, true).await?;
        ensure!(
            row.state == "running" && row.job == verified.job,
            "job execution changed"
        );
        ensure!(
            self.receipt(&row, &validate_receipt).await?.is_some(),
            "job success requires complete bound receipt"
        );
        self.transition(&verified.claim, "succeeded", "", row.lease_until)
            .await
    }
    /// Only call in a fresh short transaction after the prior transaction has
    /// terminated. Row locking and authoritative receipt recovery precede every
    /// retry/rejection. An uncertain COMMIT is never classified by its error.
    pub async fn fail(
        &mut self,
        claim: &Claim,
        now: Timestamp,
        failure: Failure,
        validate_receipt: impl Fn(&str) -> Result<()>,
    ) -> Result<FailureResult> {
        self.charge()?;
        self.checkpoint()?;
        let (contract, epoch, runtime_state) = self.lock_runtime(&claim.scope).await?;
        let preview = self.row(claim, false).await?;
        let (grant, grant_state) = self.lock_grant(&claim.scope, &preview.job.worker).await?;
        let row = self.row(claim, true).await?;
        if let Some(outcome) = self.receipt(&row, &validate_receipt).await? {
            if row.state == "running" {
                self.transition(claim, "succeeded", "", now).await?;
            } else {
                ensure!(
                    row.state == "succeeded",
                    "receipt with inconsistent job state"
                );
            }
            return Ok(FailureResult::Recovered(outcome));
        }
        ensure!(row.state == "running", "job already settled");
        if runtime_state != "active"
            || row.job.contract != contract
            || row.job.epoch != epoch
            || grant_state != "active"
            || grant.permits(&row.job).is_err()
        {
            self.transition(claim, "paused", "authority_changed", now)
                .await?;
            return Ok(FailureResult::Paused);
        }
        match failure {
            Failure::Rejected => {
                self.transition(claim, "rejected", "business_or_authority", now)
                    .await?;
                return Ok(FailureResult::Rejected);
            }
            Failure::BusinessRejected(rejection) => {
                ensure!(
                    rejection.action() == row.job.action(),
                    "rejection belongs to another action"
                );
                self.transition(claim, "rejected", rejection.stored_json(), now)
                    .await?;
                return Ok(FailureResult::BusinessRejected(rejection));
            }
            Failure::Transient => {}
        }
        let end = row
            .first_eligible
            .checked_add(Duration::from_millis(JOB_RETRY_WINDOW_MILLIS)?)?;
        if row.attempts >= i64::from(MAX_JOB_ATTEMPTS) || now >= end {
            self.transition(claim, "dead", "retry_exhausted", now)
                .await?;
            return Ok(FailureResult::Dead);
        }
        let delay = retry_delay(&row.job.id()?, row.attempts)?;
        let next = now.checked_add(Duration::from_millis(delay)?)?;
        if next >= end {
            self.transition(claim, "dead", "retry_window", now).await?;
            return Ok(FailureResult::Dead);
        }
        self.transition(claim, "pending", "transient", next).await?;
        Ok(FailureResult::Retrying(next))
    }
}

fn retry_delay(id: &str, attempts: i64) -> Result<i64> {
    use sha2::{Digest, Sha256};
    let base = match attempts {
        1 => 60_000,
        2 => 300_000,
        3 => 1_800_000,
        4 => 7_200_000,
        _ => anyhow::bail!("invalid retry attempt"),
    };
    // Stable bounded additive jitter [0,10%], requiring no caller randomness.
    let hash = Sha256::digest(format!("noxide/job-retry/v1/{id}/{attempts}"));
    let sample = u16::from_be_bytes([hash[0], hash[1]]);
    Ok(base + i64::from(sample) % (base / 10 + 1))
}
