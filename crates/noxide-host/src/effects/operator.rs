//! Trusted operator controls; all changes serialize through the shared runtime.
use super::{
    store::{OutboxContext, checkpoint, integer},
    types::*,
};
use crate::{
    database::Transaction,
    effect_deployment::{EffectiveEffectDeployment, EffectiveEffectGrant},
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::time::{Duration, Timestamp};
use serde::Serialize;

pub enum EffectOperatorCommand {
    Inspect { after: String },
    Cancel { id: String },
    RevokeEndpoint { tenant: String, endpoint: String },
    GrantEndpoint { tenant: String, endpoint: String },
    RevokeSecret { slot: String },
    GrantSecret { slot: String },
    Retry { id: String },
    Resume { id: String },
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOperatorResult {
    Effects(Vec<EffectSummary>),
    Done,
}
#[derive(Debug, Serialize)]
pub struct EffectSummary {
    pub id: String,
    pub deployment: String,
    pub tenant: String,
    pub endpoint: String,
    pub state: String,
    pub attempts: u8,
    pub round: i64,
    pub eligible: Timestamp,
}
impl Transaction {
    /// Invoked only in startup's existing clock-locked maintenance transaction.
    /// Filesystem preparation has already produced the retained directory proof.
    pub(crate) async fn activate_effects(
        &mut self,
        generation: &str,
        contract: &str,
        effective: Option<&EffectiveEffectDeployment>,
        owner_directory: Option<&str>,
    ) -> Result<()> {
        self.maintenance_checkpoint()?;
        ensure!(
            opaque(generation) && opaque(contract),
            "invalid effect activation identity"
        );
        let Some(effective) = effective else {
            return Ok(());
        };
        effective.limits.validate()?;
        let owner_directory = owner_directory.context("effect owner directory was not prepared")?;
        ensure!(
            opaque(owner_directory),
            "invalid effect owner directory proof"
        );
        let runtime=self.fetch::<3>("SELECT contract,epoch,state FROM nx_job_runtime WHERE singleton=1 AND deployment=$1 AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=$1)",&[generation.into()]).await?;
        let [current, epoch, state] = runtime
            .first()
            .context("shared effect runtime unavailable")?;
        ensure!(
            current == contract && opaque(epoch),
            "effect approval differs from shared runtime"
        );
        let rows = self
            .fetch::<2>(
                "SELECT store_id,owner_directory FROM nx_effect_queue WHERE singleton=1",
                &[],
            )
            .await?;
        match rows.first() {
            None => {
                let store_id = crate::security::random_id()?;
                self.execute("INSERT INTO nx_effect_queue(singleton,claim_seq,store_id,owner_directory,pending_limit,tenant_limit,concurrency) VALUES(1,0,$1,$2,$3,$4,$5)",&[store_id.into(),owner_directory.into(),i64::from(effective.limits.pending_per_app).into(),i64::from(effective.limits.pending_per_tenant).into(),i64::from(effective.limits.worker_concurrency).into()]).await?;
            }
            Some([store_id, stored_directory]) => {
                ensure!(
                    opaque(store_id) && stored_directory == owner_directory,
                    "effect database belongs to another owner directory"
                );
                self.execute("UPDATE nx_effect_queue SET pending_limit=$1,tenant_limit=$2,concurrency=$3 WHERE singleton=1",&[i64::from(effective.limits.pending_per_app).into(),i64::from(effective.limits.pending_per_tenant).into(),i64::from(effective.limits.worker_concurrency).into()]).await?;
            }
        }
        // A paused generation (clock recovery or restore) stays paused. Same
        // approval restart also preserves independently revoked row states.
        let initial_state = if state == "active" {
            "active"
        } else {
            "revoked"
        };
        for secret in &effective.secrets {
            self.maintenance_checkpoint()?;
            let rows=self.fetch::<3>("SELECT CAST(version AS TEXT),contract,epoch FROM nx_effect_secrets WHERE deployment=$1 AND slot=$2",&[generation.into(),secret.slot.as_str().into()]).await?;
            if rows
                .first()
                .is_some_and(|[_, c, e]| c == contract && e == epoch)
            {
                continue;
            }
            let version = match rows.first() {
                Some([v, ..]) => integer(v)?
                    .checked_add(1)
                    .context("secret grant version exhausted")?,
                None => 1,
            };
            self.execute("INSERT INTO nx_effect_secrets(deployment,slot,version,contract,epoch,state) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(deployment,slot) DO UPDATE SET version=$3,contract=$4,epoch=$5,state=$6",&[generation.into(),secret.slot.as_str().into(),version.into(),contract.into(),epoch.as_str().into(),initial_state.into()]).await?;
        }
        for binding in &effective.grants {
            self.maintenance_checkpoint()?;
            let rows=self.fetch::<4>("SELECT CAST(version AS TEXT),contract,epoch,declaration FROM nx_effect_grants WHERE deployment=$1 AND tenant=$2 AND endpoint=$3",&[generation.into(),binding.tenant.as_str().into(),binding.endpoint.name.as_str().into()]).await?;
            if let Some([_, c, e, payload]) = rows.first() {
                if c == contract && e == epoch {
                    let stored: EffectiveEffectGrant = serde_json::from_str(payload)?;
                    ensure!(
                        &stored == binding,
                        "same effect approval has different binding"
                    );
                    continue;
                }
            }
            let version = match rows.first() {
                Some([v, ..]) => integer(v)?
                    .checked_add(1)
                    .context("endpoint version exhausted")?,
                None => 1,
            };
            self.execute("INSERT INTO nx_effect_grants(deployment,tenant,endpoint,version,contract,epoch,state,declaration) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(deployment,tenant,endpoint) DO UPDATE SET version=$4,contract=$5,epoch=$6,state=$7,declaration=$8",&[generation.into(),binding.tenant.as_str().into(),binding.endpoint.name.as_str().into(),version.into(),contract.into(),epoch.as_str().into(),initial_state.into(),serde_json::to_string(binding)?.into()]).await?;
        }
        Ok(())
    }
    /// C calls this in the SAME transaction as shared epoch rotation/pause.
    /// This helper neither invents nor rotates an independent replay authority.
    pub(crate) async fn pause_effects_for_epoch(&mut self) -> Result<()> {
        self.execute("UPDATE nx_outbox SET state='paused',reason='runtime_changed',lease_until_ms=0 WHERE state IN ('pending','running')",&[]).await?;
        self.execute(
            "UPDATE nx_effect_grants SET state='revoked' WHERE state='active'",
            &[],
        )
        .await?;
        self.execute(
            "UPDATE nx_effect_secrets SET state='revoked' WHERE state='active'",
            &[],
        )
        .await?;
        Ok(())
    }
    pub(super) async fn lock_effect_operator(
        &mut self,
        generation: &str,
    ) -> Result<(String, String)> {
        checkpoint(self)?;
        ensure!(opaque(generation), "invalid effect generation");
        let n=self.execute("UPDATE nx_job_runtime SET state=state WHERE singleton=1 AND deployment=$1 AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=$1)",&[generation.into()]).await?;
        ensure!(n == 1, "effect runtime retired");
        let rows = self
            .fetch::<2>(
                "SELECT contract,epoch FROM nx_job_runtime WHERE singleton=1",
                &[],
            )
            .await?;
        let [contract, epoch] = rows.first().context("effect runtime missing")?;
        ensure!(opaque(contract) && opaque(epoch), "invalid effect runtime");
        Ok((contract.clone(), epoch.clone()))
    }
    pub(crate) async fn inspect_effects(
        &mut self,
        generation: &str,
        after: &str,
    ) -> Result<Vec<EffectSummary>> {
        self.lock_effect_operator(generation).await?;
        ensure!(
            after.is_empty() || opaque(after),
            "invalid effect inspection cursor"
        );
        let rows=self.fetch::<8>("SELECT id,deployment,tenant,endpoint,state,CAST(attempts AS TEXT),CAST(round AS TEXT),CAST(eligible_ms AS TEXT) FROM nx_outbox WHERE id>$1 ORDER BY id LIMIT 100",&[after.into()]).await?;
        rows.into_iter()
            .map(
                |[
                    id,
                    deployment,
                    tenant,
                    endpoint,
                    state,
                    attempts,
                    round,
                    eligible,
                ]| {
                    Ok(EffectSummary {
                        id,
                        deployment,
                        tenant,
                        endpoint,
                        state,
                        attempts: u8::try_from(integer(&attempts)?)?,
                        round: integer(&round)?,
                        eligible: Timestamp::from_unix_millis(integer(&eligible)?)?,
                    })
                },
            )
            .collect()
    }
    pub(crate) async fn cancel_effect(&mut self, generation: &str, id: &str) -> Result<()> {
        self.lock_effect_operator(generation).await?;
        ensure!(opaque(id), "invalid effect identity");
        let n=self.execute("UPDATE nx_outbox SET state='cancelled',reason='operator_cancelled',lease_until_ms=0 WHERE id=$1 AND state IN ('pending','running','paused','dead')",&[id.into()]).await?;
        ensure!(n == 1, "effect unavailable for cancellation");
        Ok(())
    }
    pub(crate) async fn revoke_effect_endpoint(
        &mut self,
        generation: &str,
        tenant: &str,
        endpoint: &str,
    ) -> Result<()> {
        self.lock_effect_operator(generation).await?;
        let n=self.execute("UPDATE nx_effect_grants SET state='revoked',version=version+1 WHERE deployment=$1 AND tenant=$2 AND endpoint=$3 AND version<9223372036854775807",&[generation.into(),tenant.into(),endpoint.into()]).await?;
        ensure!(n == 1, "endpoint grant missing");
        self.execute("UPDATE nx_outbox SET state='paused',reason='endpoint_revoked',lease_until_ms=0 WHERE tenant=$1 AND endpoint=$2 AND state IN ('pending','running')",&[tenant.into(),endpoint.into()]).await?;
        Ok(())
    }
    pub(crate) async fn revoke_effect_secret(
        &mut self,
        generation: &str,
        slot: &str,
    ) -> Result<()> {
        self.lock_effect_operator(generation).await?;
        let n=self.execute("UPDATE nx_effect_secrets SET state='revoked',version=version+1 WHERE deployment=$1 AND slot=$2 AND version<9223372036854775807",&[generation.into(),slot.into()]).await?;
        ensure!(n == 1, "secret grant missing");
        // Endpoint declarations contain no value/path. JSON extraction is not
        // needed: the bounded current grant list supplies exact endpoint pairs.
        let rows=self.fetch::<3>("SELECT tenant,endpoint,declaration FROM nx_effect_grants WHERE deployment=$1 ORDER BY tenant,endpoint LIMIT 65",&[generation.into()]).await?;
        ensure!(rows.len() <= 64, "effect grant limit");
        for [tenant, endpoint, payload] in rows {
            let binding: EffectiveEffectGrant = serde_json::from_str(&payload)?;
            if binding.endpoint.secret_slot.as_deref() == Some(slot) {
                self.execute("UPDATE nx_outbox SET state='paused',reason='secret_revoked',lease_until_ms=0 WHERE tenant=$1 AND endpoint=$2 AND state IN ('pending','running')",&[tenant.into(),endpoint.into()]).await?;
            }
        }
        Ok(())
    }
    pub(crate) async fn grant_effect_endpoint(
        &mut self,
        generation: &str,
        contract: &str,
        binding: &EffectiveEffectGrant,
    ) -> Result<()> {
        let (current, epoch) = self.lock_effect_operator(generation).await?;
        ensure!(current == contract, "effect approval changed");
        let n=self.execute("UPDATE nx_effect_grants SET state='active',version=version+1,contract=$1,epoch=$2 WHERE deployment=$3 AND tenant=$4 AND endpoint=$5 AND declaration=$6 AND version<9223372036854775807",&[contract.into(),epoch.into(),generation.into(),binding.tenant.as_str().into(),binding.endpoint.name.as_str().into(),serde_json::to_string(binding)?.into()]).await?;
        ensure!(n == 1, "endpoint is not currently approved");
        self.execute(
            "UPDATE nx_job_runtime SET state='active' WHERE singleton=1",
            &[],
        )
        .await?;
        Ok(())
    }
    pub(crate) async fn grant_effect_secret(
        &mut self,
        generation: &str,
        contract: &str,
        slot: &str,
        effective: &EffectiveEffectDeployment,
    ) -> Result<()> {
        let (current, epoch) = self.lock_effect_operator(generation).await?;
        ensure!(
            current == contract && effective.secrets.iter().any(|s| s.slot == slot),
            "secret slot is not currently approved"
        );
        let n=self.execute("UPDATE nx_effect_secrets SET state='active',version=version+1,contract=$1,epoch=$2 WHERE deployment=$3 AND slot=$4 AND version<9223372036854775807",&[contract.into(),epoch.into(),generation.into(),slot.into()]).await?;
        ensure!(n == 1, "secret grant missing");
        Ok(())
    }
    pub(crate) async fn effect_operator_source(
        &mut self,
        generation: &str,
        id: &str,
    ) -> Result<CapturedEffect> {
        self.lock_effect_operator(generation).await?;
        ensure!(opaque(id), "invalid effect identity");
        let payload = self.bounded_text("payload", MAX_CAPTURE_BYTES);
        let rows = self
            .fetch::<2>(
                &format!("SELECT {payload},payload_digest FROM nx_outbox WHERE id=$1"),
                &[id.into()],
            )
            .await?;
        let [payload, digest] = rows.first().context("effect missing")?;
        let capture: CapturedEffect = serde_json::from_str(payload)?;
        capture.validate()?;
        ensure!(
            capture.id()? == id && capture.capture_digest()? == *digest,
            "effect source mismatch"
        );
        Ok(capture)
    }
    /// Explicit current-authority reconciliation changes only the mutable
    /// envelope. Receiver identity, original capture and payload remain intact.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn resume_effect(
        &mut self,
        generation: &str,
        contract: &str,
        effective: &EffectiveEffectDeployment,
        id: &str,
        current_source_version: u32,
        now: Timestamp,
        retry: bool,
    ) -> Result<()> {
        let source = self.effect_operator_source(generation, id).await?;
        ensure!(
            source.source_action_version == current_source_version,
            "effect source action version changed"
        );
        let emission = effective
            .contract
            .emissions
            .iter()
            .find(|e| e.source_action == source.source_action && e.ordinal == source.ordinal)
            .context("effect disclosure no longer declared")?;
        ensure!(
            digest(&("effect-schema-v1", emission))? == source.schema_digest,
            "effect disclosure changed"
        );
        let binding = effective
            .grants
            .iter()
            .find(|b| {
                b.tenant == source.scope.tenant && b.endpoint.name == source.binding.endpoint.name
            })
            .context("effect endpoint no longer approved")?;
        ensure!(binding == &source.binding, "effect destination changed");
        let mut calls = 16;
        let proof = OutboxContext {
            tx: self,
            calls: &mut calls,
        }
        .endpoint_grant(
            &EffectScope {
                deployment: generation.into(),
                tenant: source.scope.tenant.clone(),
            },
            &binding.endpoint.name,
            contract,
        )
        .await?;
        let rows=self.fetch::<4>("SELECT state,CAST(attempts AS TEXT),CAST(first_eligible_ms AS TEXT),CAST(round AS TEXT) FROM nx_outbox WHERE id=$1",&[id.into()]).await?;
        let [state, attempts, first, round] = rows.first().context("effect missing")?;
        ensure!(
            if retry {
                matches!(state.as_str(), "dead" | "paused")
            } else {
                state == "paused"
            },
            "effect not eligible for operator retry/resume"
        );
        if !retry {
            ensure!(
                integer(attempts)? < 5
                    && now
                        < Timestamp::from_unix_millis(integer(first)?)?.checked_add(
                            Duration::from_millis(
                                noxide_protocol::effects::EFFECT_RETRY_WINDOW_MILLIS
                            )?
                        )?,
                "effect automatic retry allowance exhausted; explicit retry required"
            );
        }
        let round = integer(round)?
            .checked_add(i64::from(retry))
            .context("effect retry round exhausted")?;
        OutboxContext {
            tx: self,
            calls: &mut calls,
        }
        .check_operator_quota(&source.scope.tenant, state != "paused")
        .await?;
        self.execute("INSERT INTO nx_effect_tenants(deployment,tenant,claim_seq) VALUES($1,$2,0) ON CONFLICT(deployment,tenant) DO NOTHING",&[generation.into(),source.scope.tenant.as_str().into()]).await?;
        let changed=self.execute("UPDATE nx_outbox SET deployment=$1,contract=$2,epoch=$3,grant_version=$4,secret_version=$5,state='pending',reason='',eligible_ms=$6,first_eligible_ms=$7,attempts=$8,lease_until_ms=0,round=$9,fence=fence+1 WHERE id=$10 AND fence<9223372036854775807",&[generation.into(),contract.into(),proof.grant.epoch.as_str().into(),proof.grant.version.into(),proof.grant.secret_version.into(),now.unix_millis().into(),if retry {now.unix_millis()} else {integer(first)?}.into(),if retry {0} else {integer(attempts)?}.into(),round.into(),id.into()]).await?;
        ensure!(changed == 1, "effect fence exhausted");
        Ok(())
    }
}
