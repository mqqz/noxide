//! Operator changes share the execution lock order: clock (when held), runtime,
//! grant, job. No operation commits its caller's transaction.
use super::types::*;
use crate::{database::Transaction, job_deployment::EffectiveJobDeployment};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{jobs::JobContract, time::Timestamp};
use serde::Serialize;

pub enum JobOperatorCommand {
    Inspect { after: String },
    Cancel { id: String },
    Revoke { tenant: String, worker: String },
    Grant { tenant: String, worker: String },
    Reconcile { id: String },
    Fork,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobOperatorResult {
    Jobs(Vec<JobSummary>),
    Reconciled { id: String },
    Granted { recurring_resumed: usize },
    Done,
}

#[derive(Debug, Serialize)]
pub struct JobSummary {
    pub id: String,
    pub deployment: String,
    pub tenant: String,
    pub worker: String,
    pub action: u32,
    pub state: String,
    pub attempts: u8,
    pub due: Timestamp,
    pub eligible: Timestamp,
}

impl Transaction {
    pub(crate) async fn reconciliation_source(
        &mut self,
        generation: &str,
        id: &str,
    ) -> Result<CapturedJob> {
        self.lock_job_operator_runtime(generation).await?;
        ensure!(opaque(id), "invalid reconciliation identity");
        let payload = self.bounded_text("payload", noxide_protocol::jobs::MAX_JOB_BYTES);
        let rows = self
            .fetch::<3>(
                &format!("SELECT {payload},payload_digest,state FROM nx_jobs WHERE id=$1"),
                &[id.into()],
            )
            .await?;
        let [payload, stored_digest, state] =
            rows.first().context("reconciliation source missing")?;
        ensure!(
            matches!(state.as_str(), "paused" | "dead" | "rejected"),
            "only settled operator-reviewed work can be reconciled"
        );
        let source: CapturedJob = serde_json::from_str(payload)?;
        source.validate()?;
        ensure!(
            source.id()? == id && source.invocation_digest()? == *stored_digest,
            "reconciliation source differs from capture"
        );
        Ok(source)
    }
    async fn lock_job_operator_runtime(
        &mut self,
        generation: &str,
    ) -> Result<(String, String, String)> {
        cpu_checkpoint(self)?;
        ensure!(opaque(generation), "invalid job deployment");
        let changed = self.execute("UPDATE nx_job_runtime SET state=state WHERE singleton=1 AND deployment=$1 AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=$1)", &[generation.into()]).await?;
        ensure!(changed == 1, "job runtime retired or unavailable");
        let rows = self
            .fetch::<3>(
                "SELECT contract,epoch,state FROM nx_job_runtime WHERE singleton=1",
                &[],
            )
            .await?;
        let [contract, epoch, state] = rows.first().context("job runtime missing")?;
        ensure!(
            opaque(contract) && opaque(epoch),
            "invalid job runtime identity"
        );
        Ok((contract.clone(), epoch.clone(), state.clone()))
    }

    /// Called while the startup MaintenanceLease already holds the clock lock.
    /// The following lifecycle tick commits activation and its durable heartbeat
    /// together. Same-approval restart never rotates or revives paused work.
    pub(crate) async fn activate_jobs(
        &mut self,
        generation: &str,
        contract: &str,
        effective: Option<&EffectiveJobDeployment>,
        declarations: Option<&JobContract>,
        effects_enabled: bool,
    ) -> Result<()> {
        self.maintenance_checkpoint()?;
        ensure!(
            opaque(generation) && opaque(contract),
            "invalid job runtime identity"
        );
        let epoch = crate::security::random_id()?;
        let limits = effective.map(|e| e.limits).unwrap_or_default();
        limits.validate()?;
        self.execute("INSERT INTO nx_job_runtime(singleton,deployment,contract,epoch,state,pending_limit,tenant_limit,concurrency) VALUES(1,$1,$2,$3,$4,$5,$6,$7) ON CONFLICT(singleton) DO NOTHING", &[generation.into(), contract.into(), epoch.into(), if effective.is_some() || effects_enabled { "active" } else { "paused" }.into(), i64::from(limits.pending_per_app).into(), i64::from(limits.pending_per_tenant).into(), i64::from(limits.worker_concurrency).into()]).await?;
        // Deployment changes are allowed only here, after central deployment
        // admission; ordinary operator commands remain generation-fenced.
        self.execute(
            "UPDATE nx_job_runtime SET state=state WHERE singleton=1",
            &[],
        )
        .await?;
        let rows = self
            .fetch::<7>(
                "SELECT deployment,contract,epoch,state,CAST(pending_limit AS TEXT),CAST(tenant_limit AS TEXT),CAST(concurrency AS TEXT) FROM nx_job_runtime WHERE singleton=1",
                &[],
            )
            .await?;
        let [
            old_generation,
            old_contract,
            old_epoch,
            old_state,
            pending_limit,
            tenant_limit,
            concurrency,
        ] = rows.first().context("job runtime missing")?;
        let generation_changed = old_generation != generation;
        let changed = generation_changed || old_contract != contract;
        // Clock recovery and copied-storage fencing retire a generation while
        // paused. Rebinding to the new deployment must preserve that operator
        // pause until an explicit current-generation grant, even when approval
        // bytes are unchanged.
        let preserve_pause = generation_changed && old_state == "paused";
        let runtime_state = if (effective.is_some() || effects_enabled) && !preserve_pause {
            "active"
        } else {
            "paused"
        };
        let grant_state = if preserve_pause { "revoked" } else { "active" };
        let recurring_state = if preserve_pause { "paused" } else { "active" };
        if !changed {
            ensure!(
                integer(pending_limit)? == i64::from(limits.pending_per_app)
                    && integer(tenant_limit)? == i64::from(limits.pending_per_tenant)
                    && integer(concurrency)? == i64::from(limits.worker_concurrency),
                "same approval has different job limits"
            );
        }
        let epoch = if changed {
            crate::security::random_id()?
        } else {
            old_epoch.clone()
        };
        if changed {
            self.pause_effects_for_epoch().await?;
            self.execute("UPDATE nx_jobs SET state='paused',reason='approval_changed',lease_until_ms=0 WHERE state IN ('pending','running')", &[]).await?;
            self.execute(
                "UPDATE nx_job_recurring SET state='paused' WHERE state='active'",
                &[],
            )
            .await?;
            self.execute(
                "UPDATE nx_job_grants SET state='revoked' WHERE state='active'",
                &[],
            )
            .await?;
            self.execute("UPDATE nx_job_runtime SET deployment=$1,contract=$2,epoch=$3,state=$4,pending_limit=$5,tenant_limit=$6,concurrency=$7 WHERE singleton=1", &[generation.into(), contract.into(), epoch.as_str().into(), runtime_state.into(), i64::from(limits.pending_per_app).into(), i64::from(limits.pending_per_tenant).into(), i64::from(limits.worker_concurrency).into()]).await?;
        }
        self.execute("INSERT INTO nx_job_queue(singleton,claim_seq) VALUES(1,0) ON CONFLICT(singleton) DO NOTHING", &[]).await?;
        let Some(effective) = effective else {
            return Ok(());
        };
        let declarations = declarations.context("operator job approval has no declaration")?;
        effective.limits.validate()?;
        for configured in &effective.grants {
            self.maintenance_checkpoint()?;
            let scope = JobScope {
                deployment: generation.into(),
                tenant: configured.tenant.clone(),
            };
            scope.validate()?;
            let rows = self.fetch::<3>("SELECT CAST(version AS TEXT),declaration,state FROM nx_job_grants WHERE deployment=$1 AND tenant=$2 AND worker=$3", &[generation.into(), scope.tenant.as_str().into(), configured.worker.name.as_str().into()]).await?;
            let version = match rows.first() {
                None => 1,
                Some([version, _, _]) if changed => integer(version)?
                    .checked_add(1)
                    .context("service grant version exhausted")?,
                Some([version, payload, state]) => {
                    let stored: Grant = serde_json::from_str(payload)?;
                    stored.validate()?;
                    ensure!(
                        stored.worker == configured.worker
                            && stored.scope == scope
                            && stored.contract == contract
                            && stored.version == integer(version)?
                            && (stored.epoch == epoch || state == "revoked"),
                        "same approval has different grant"
                    );
                    continue;
                }
            };
            let grant = Grant {
                scope: scope.clone(),
                worker: configured.worker.clone(),
                version,
                contract: contract.into(),
                epoch: epoch.clone(),
            };
            grant.validate()?;
            self.execute("INSERT INTO nx_job_grants(deployment,tenant,worker,version,contract,epoch,state,declaration) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(deployment,tenant,worker) DO UPDATE SET version=$4,contract=$5,epoch=$6,state=$7,declaration=$8", &[generation.into(), scope.tenant.as_str().into(), grant.worker.name.as_str().into(), version.into(), contract.into(), epoch.as_str().into(), grant_state.into(), serde_json::to_string(&grant)?.into()]).await?;
            for schedule in declarations.recurring.iter().filter(|s| {
                s.worker == grant.worker.name
                    && grant.worker.actions.iter().any(|a| a.action == s.action)
            }) {
                self.execute("INSERT INTO nx_job_recurring(deployment,tenant,name,contract,epoch,grant_version,version,state,next_ms,cutoff_ms,cutoff_seq,cursor) VALUES($1,$2,$3,$4,$5,$6,1,$7,0,0,0,'') ON CONFLICT(deployment,tenant,name) DO UPDATE SET contract=$4,epoch=$5,grant_version=$6,version=nx_job_recurring.version+1,state=$7,next_ms=0,cutoff_ms=0,cutoff_seq=0,cursor=''", &[generation.into(), scope.tenant.as_str().into(), schedule.name.as_str().into(), contract.into(), epoch.as_str().into(), version.into(), recurring_state.into()]).await?;
            }
        }
        Ok(())
    }

    /// Serialize revocation with every execution commit. Existing receipts and
    /// terminal outcomes remain available; pending/running work requires review.
    pub(crate) async fn revoke_job_grant(
        &mut self,
        generation: &str,
        tenant: &str,
        worker: &str,
    ) -> Result<()> {
        self.lock_job_operator_runtime(generation).await?;
        let scope = JobScope {
            deployment: generation.into(),
            tenant: tenant.into(),
        };
        scope.validate()?;
        ensure!(
            noxide_protocol::identifier(worker),
            "invalid service worker"
        );
        let changed = self.execute("UPDATE nx_job_grants SET state='revoked' WHERE deployment=$1 AND tenant=$2 AND worker=$3", &[generation.into(), tenant.into(), worker.into()]).await?;
        ensure!(changed == 1, "service grant unavailable");
        self.execute("UPDATE nx_jobs SET state='paused',reason='grant_revoked',lease_until_ms=0 WHERE deployment=$1 AND tenant=$2 AND worker=$3 AND state IN ('pending','running')", &[generation.into(), tenant.into(), worker.into()]).await?;
        // Schedule names are declaration-owned, so pausing this tenant's scans
        // is conservative and cannot accidentally grant another worker authority.
        self.execute(
            "UPDATE nx_job_recurring SET state='paused' WHERE deployment=$1 AND tenant=$2",
            &[generation.into(), tenant.into()],
        )
        .await?;
        Ok(())
    }

    /// Explicit regrant only within the current approved declaration. Rotate
    /// the version even if the requested worker is unchanged, so old captures
    /// remain paused and cannot acquire new authority by being retried.
    pub(crate) async fn grant_job_service(
        &mut self,
        generation: &str,
        approved_contract: &str,
        approved: &crate::job_deployment::EffectiveJobGrant,
        declarations: &JobContract,
    ) -> Result<()> {
        let (contract, epoch, _) = self.lock_job_operator_runtime(generation).await?;
        ensure!(contract == approved_contract, "operator approval retired");
        let scope = JobScope {
            deployment: generation.into(),
            tenant: approved.tenant.clone(),
        };
        scope.validate()?;
        let rows = self.fetch::<1>("SELECT CAST(version AS TEXT) FROM nx_job_grants WHERE deployment=$1 AND tenant=$2 AND worker=$3", &[generation.into(), scope.tenant.as_str().into(), approved.worker.name.as_str().into()]).await?;
        let version = integer(&rows.first().context("service grant unavailable")?[0])?
            .checked_add(1)
            .context("service grant version exhausted")?;
        let grant = Grant {
            scope,
            worker: approved.worker.clone(),
            version,
            contract,
            epoch,
        };
        grant.validate()?;
        self.execute("UPDATE nx_job_grants SET version=$1,contract=$2,epoch=$3,state='active',declaration=$4 WHERE deployment=$5 AND tenant=$6 AND worker=$7", &[version.into(), grant.contract.as_str().into(), grant.epoch.as_str().into(), serde_json::to_string(&grant)?.into(), generation.into(), grant.scope.tenant.as_str().into(), grant.worker.name.as_str().into()]).await?;
        self.execute("UPDATE nx_jobs SET state='paused',reason='grant_changed',lease_until_ms=0 WHERE deployment=$1 AND tenant=$2 AND worker=$3 AND state IN ('pending','running')", &[generation.into(), grant.scope.tenant.as_str().into(), grant.worker.name.as_str().into()]).await?;
        for schedule in declarations.recurring.iter().filter(|s| {
            s.worker == grant.worker.name
                && grant.worker.actions.iter().any(|a| a.action == s.action)
        }) {
            cpu_checkpoint(self)?;
            self.execute("INSERT INTO nx_job_recurring(deployment,tenant,name,contract,epoch,grant_version,version,state,next_ms,cutoff_ms,cutoff_seq,cursor) VALUES($1,$2,$3,$4,$5,$6,1,'active',0,0,0,'') ON CONFLICT(deployment,tenant,name) DO UPDATE SET contract=$4,epoch=$5,grant_version=$6,version=nx_job_recurring.version+1,state='active',next_ms=0,cutoff_ms=0,cutoff_seq=0,cursor=''", &[generation.into(), grant.scope.tenant.as_str().into(), schedule.name.as_str().into(), grant.contract.as_str().into(), grant.epoch.as_str().into(), version.into()]).await?;
        }
        self.execute(
            "UPDATE nx_job_runtime SET state='active' WHERE singleton=1",
            &[],
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn cancel_job(&mut self, generation: &str, id: &str) -> Result<()> {
        self.lock_job_operator_runtime(generation).await?;
        ensure!(opaque(id), "invalid job identity");
        // Runtime exclusive lock waits for actual execution termination. A lease
        // timestamp alone is never evidence that a previous transaction stopped.
        let changed = self.execute("UPDATE nx_jobs SET state='rejected',reason='operator_cancelled',lease_until_ms=0 WHERE id=$1 AND state IN ('pending','running','paused','dead')", &[id.into()]).await?;
        ensure!(changed == 1, "job cannot be cancelled");
        Ok(())
    }

    /// Explicit restore/fork fence. This is required before starting workers on
    /// copied storage. It preserves every receipt and never resumes old captures.
    pub(crate) async fn fork_job_runtime(&mut self, generation: &str) -> Result<()> {
        self.lock_job_operator_runtime(generation).await?;
        let epoch = crate::security::random_id()?;
        self.execute(
            "UPDATE nx_job_runtime SET epoch=$1,state='paused' WHERE singleton=1",
            &[epoch.into()],
        )
        .await?;
        self.execute(
            "UPDATE nx_job_grants SET state='revoked' WHERE deployment=$1",
            &[generation.into()],
        )
        .await?;
        self.execute("UPDATE nx_jobs SET state='paused',reason='restore_reconciliation',lease_until_ms=0 WHERE deployment=$1 AND state IN ('pending','running')", &[generation.into()]).await?;
        self.execute(
            "UPDATE nx_job_recurring SET state='paused' WHERE deployment=$1",
            &[generation.into()],
        )
        .await?;
        self.pause_effects_for_epoch().await?;
        Ok(())
    }

    /// Bounded metadata only. Input, target seals, rejection text and receipt
    /// bodies intentionally never enter the operator listing.
    pub(crate) async fn inspect_jobs(
        &mut self,
        generation: &str,
        after: &str,
    ) -> Result<Vec<JobSummary>> {
        cpu_checkpoint(self)?;
        ensure!(
            opaque(generation) && (after.is_empty() || opaque(after)),
            "invalid job cursor"
        );
        let rows = self.fetch::<9>("SELECT id,deployment,tenant,worker,CAST(action AS TEXT),state,CAST(attempts AS TEXT),CAST(due_ms AS TEXT),CAST(eligible_ms AS TEXT) FROM nx_jobs WHERE EXISTS(SELECT 1 FROM nx_job_runtime r JOIN nx_deployment d ON d.singleton=r.singleton AND d.generation=r.deployment WHERE r.singleton=1 AND r.deployment=$1) AND id>$2 ORDER BY id LIMIT 100", &[generation.into(), after.into()]).await?;
        rows.into_iter()
            .map(
                |[
                    id,
                    deployment,
                    tenant,
                    worker,
                    action,
                    state,
                    attempts,
                    due,
                    eligible,
                ]| {
                    cpu_checkpoint(self)?;
                    ensure!(
                        opaque(&id) && opaque(&deployment) && noxide_protocol::identifier(&worker),
                        "invalid job metadata"
                    );
                    Ok(JobSummary {
                        id,
                        deployment,
                        tenant,
                        worker,
                        action: integer(&action)?.try_into()?,
                        state,
                        attempts: integer(&attempts)?.try_into()?,
                        due: Timestamp::from_unix_millis(integer(&due)?)?,
                        eligible: Timestamp::from_unix_millis(integer(&eligible)?)?,
                    })
                },
            )
            .collect()
    }
}

impl super::QueueContext<'_> {
    /// The existing adapter has rechecked canonical inputs and current eligible
    /// target reads. Runtime/grant locks are retained through this insertion.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn enqueue_reconciled(
        &mut self,
        previous: &CapturedJob,
        current: &super::VerifiedScheduleGrant,
        action_version: u32,
        now: Timestamp,
        input: noxide_protocol::Fields,
        targets: std::collections::BTreeMap<String, SealedTarget>,
        tenant_limit: u16,
    ) -> Result<String> {
        self.charge()?;
        let parent = previous.id()?;
        let changed = self.tx.execute("UPDATE nx_jobs SET fence=fence WHERE deployment=$1 AND id=$2 AND payload_digest=$3 AND state IN ('paused','dead','rejected')", &[previous.scope.deployment.as_str().into(), parent.as_str().into(), previous.invocation_digest()?.into()]).await?;
        ensure!(changed == 1, "reconciliation source changed");
        let job = CapturedJob::reconcile(
            previous,
            current.grant(),
            action_version,
            now,
            input,
            targets,
        )?;
        let id = job.id()?;
        self.tx.execute("UPDATE nx_jobs SET state='rejected',reason='operator_reconciled',lease_until_ms=0 WHERE id=$1 AND deployment=$2", &[parent.into(), previous.scope.deployment.as_str().into()]).await?;
        self.enqueue(&job, now, tenant_limit).await?;
        Ok(id)
    }
}
