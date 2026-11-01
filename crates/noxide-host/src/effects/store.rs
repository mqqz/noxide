//! Short transactional outbox operations. No network, file reads or commits.
use super::types::*;
use crate::{
    database::{Transaction, lifecycle::RequestScope},
    query_plan::NativeProvider,
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{
    effects::*,
    time::{Duration, Timestamp},
};
use sha2::{Digest, Sha256};

pub(crate) struct OutboxContext<'a> {
    pub(crate) tx: &'a mut Transaction,
    pub(crate) calls: &'a mut u32,
}
#[derive(Clone, Debug)]
pub(crate) struct EffectClaim {
    pub(super) id: String,
    pub(super) scope: EffectScope,
    pub(super) fence: i64,
    pub(super) lease_until: Timestamp,
    pub(super) epoch: String,
    pub(super) exhausted: bool,
}
pub(crate) struct PreparedEffect {
    pub(crate) captured: CapturedEffect,
}
pub(crate) enum Preflight {
    Send(Box<PreparedEffect>),
    Settled(Finalized),
}
impl EffectClaim {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}
pub(crate) enum DeliveryResult {
    Delivered,
    Retry { retry_after_seconds: Option<u32> },
    Terminal,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Finalized {
    Delivered,
    Retrying(Timestamp),
    Dead,
    Paused,
    Superseded,
}
struct Row {
    capture: CapturedEffect,
    state: String,
    attempts: i64,
    first: Timestamp,
    eligible: Timestamp,
    epoch: String,
    contract: String,
    version: i64,
    secret_version: i64,
    lease: Timestamp,
}
impl OutboxContext<'_> {
    pub(super) fn checkpoint(&self) -> Result<()> {
        checkpoint(self.tx)
    }
    pub(super) fn charge(&mut self) -> Result<()> {
        self.checkpoint()?;
        *self.calls = self.calls.checked_sub(1).context("database call budget")?;
        Ok(())
    }
    pub(super) async fn runtime(
        &mut self,
        scope: &EffectScope,
    ) -> Result<(String, String, String)> {
        scope.validate()?;
        self.checkpoint()?;
        let suffix = if matches!(self.tx.query_provider()?, NativeProvider::Postgres) {
            " FOR SHARE"
        } else {
            ""
        };
        let rows=self.tx.fetch::<4>(&format!("SELECT deployment,contract,epoch,state FROM nx_job_runtime WHERE singleton=1 AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=nx_job_runtime.deployment){suffix}"),&[]).await?;
        let [generation, contract, epoch, state] =
            rows.first().context("effect runtime unavailable")?;
        ensure!(
            opaque(contract) && opaque(epoch),
            "invalid effect runtime identity"
        );
        Ok((
            contract.clone(),
            epoch.clone(),
            if generation == &scope.deployment {
                state.clone()
            } else {
                "changed".into()
            },
        ))
    }
    async fn grant(
        &mut self,
        scope: &EffectScope,
        endpoint: &str,
    ) -> Result<Option<(EndpointGrant, String)>> {
        self.checkpoint()?;
        let suffix = if matches!(self.tx.query_provider()?, NativeProvider::Postgres) {
            " FOR SHARE"
        } else {
            ""
        };
        let declaration = self.tx.bounded_text("declaration", 16384);
        let rows=self.tx.fetch::<5>(&format!("SELECT {declaration},state,CAST(version AS TEXT),contract,epoch FROM nx_effect_grants WHERE deployment=$1 AND tenant=$2 AND endpoint=$3{suffix}"),&[scope.deployment.as_str().into(),scope.tenant.as_str().into(),endpoint.into()]).await?;
        let Some([declaration, state, version, contract, epoch]) = rows.first() else {
            return Ok(None);
        };
        let binding: crate::effect_deployment::EffectiveEffectGrant =
            serde_json::from_str(declaration)?;
        ensure!(
            binding.tenant == scope.tenant && binding.endpoint.name == endpoint,
            "effect grant identity mismatch"
        );
        let mut secret_version = 0;
        let mut state = state.clone();
        if let Some(slot) = &binding.endpoint.secret_slot {
            let rows=self.tx.fetch::<4>(&format!("SELECT CAST(version AS TEXT),state,contract,epoch FROM nx_effect_secrets WHERE deployment=$1 AND slot=$2{suffix}"),&[scope.deployment.as_str().into(),slot.as_str().into()]).await?;
            match rows.first() {
                Some([version, secret_state, secret_contract, secret_epoch]) => {
                    secret_version = integer(version)?;
                    if secret_state != "active"
                        || secret_contract != contract
                        || secret_epoch != epoch
                    {
                        state = "revoked".into();
                    }
                }
                None => return Ok(None),
            }
        }
        let grant = EndpointGrant {
            scope: scope.clone(),
            binding,
            contract: contract.clone(),
            epoch: epoch.clone(),
            version: integer(version)?,
            secret_version,
        };
        grant.validate()?;
        Ok(Some((grant, state)))
    }
    pub(crate) async fn endpoint_grant(
        &mut self,
        scope: &EffectScope,
        endpoint: &str,
        contract: &str,
    ) -> Result<VerifiedEndpointGrant> {
        self.charge()?;
        let (current, epoch, state) = self.runtime(scope).await?;
        ensure!(
            state == "active" && current == contract,
            "effect runtime changed"
        );
        let (grant, state) = self
            .grant(scope, endpoint)
            .await?
            .context("endpoint not granted")?;
        ensure!(
            state == "active" && grant.contract == current && grant.epoch == epoch,
            "endpoint or secret grant changed"
        );
        Ok(VerifiedEndpointGrant { grant })
    }
    /// Idempotent admission, atomic with the originating action and receipt.
    pub(crate) async fn enqueue(&mut self, capture: &CapturedEffect, now: Timestamp) -> Result<()> {
        self.charge()?;
        capture.validate()?;
        ensure!(capture.created == now, "effect capture time changed");
        let (contract, epoch, state) = self.runtime(&capture.scope).await?;
        ensure!(
            state == "active" && contract == capture.contract && epoch == capture.epoch,
            "effect runtime changed"
        );
        let changed = self
            .tx
            .execute(
                "UPDATE nx_effect_queue SET claim_seq=claim_seq WHERE singleton=1",
                &[],
            )
            .await?;
        ensure!(changed == 1, "effect queue unavailable");
        let (grant, state) = self
            .grant(&capture.scope, &capture.binding.endpoint.name)
            .await?
            .context("endpoint unavailable")?;
        ensure!(
            state == "active" && grant == capture.grant(),
            "effect grant changed"
        );
        let id = capture.id()?;
        let digest = capture.capture_digest()?;
        let rows = self
            .tx
            .fetch::<1>(
                "SELECT payload_digest FROM nx_outbox WHERE id=$1",
                &[id.as_str().into()],
            )
            .await?;
        if let Some([stored]) = rows.first() {
            ensure!(
                stored == &digest,
                "effect ordinal reused with different capture"
            );
            return Ok(());
        }
        let counts=self.tx.fetch::<4>("SELECT CAST(COUNT(*) AS TEXT),CAST(COALESCE(SUM(CASE WHEN tenant=$1 THEN 1 ELSE 0 END),0) AS TEXT),CAST((SELECT pending_limit FROM nx_effect_queue WHERE singleton=1) AS TEXT),CAST((SELECT tenant_limit FROM nx_effect_queue WHERE singleton=1) AS TEXT) FROM (SELECT tenant FROM nx_outbox WHERE state IN ('pending','running','paused') LIMIT 1001) AS active_effects",&[capture.scope.tenant.as_str().into()]).await?;
        let [app, tenant, app_limit, tenant_limit] =
            counts.first().context("effect quota unavailable")?;
        ensure!(
            integer(app)? < integer(app_limit)?
                && integer(tenant)? < integer(tenant_limit)?
                && integer(app_limit)? <= 1000
                && integer(tenant_limit)? <= integer(app_limit)?,
            "effect queue full"
        );
        self.tx.execute("INSERT INTO nx_effect_tenants(deployment,tenant,claim_seq) VALUES($1,$2,0) ON CONFLICT(deployment,tenant) DO NOTHING",&[capture.scope.deployment.as_str().into(),capture.scope.tenant.as_str().into()]).await?;
        self.tx.execute("INSERT INTO nx_outbox(id,deployment,tenant,origin,ordinal,endpoint,contract,epoch,grant_version,secret_version,payload,payload_digest,eligible_ms,first_eligible_ms,attempts,fence,lease_until_ms,round,state,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,0,0,0,0,'pending','')",&[id.into(),capture.scope.deployment.as_str().into(),capture.scope.tenant.as_str().into(),capture.origin.as_str().into(),i64::from(capture.ordinal).into(),capture.binding.endpoint.name.as_str().into(),capture.contract.as_str().into(),capture.epoch.as_str().into(),capture.grant_version.into(),capture.secret_version.into(),serde_json::to_string(capture)?.into(),digest.into(),now.unix_millis().into()]).await?;
        Ok(())
    }
    /// Called only while the exclusive DB-bound owner and a physical slot live.
    /// In-process active IDs are excluded even after a wall-clock forward jump.
    pub(crate) async fn claim(
        &mut self,
        generation: &str,
        expected_contract: &str,
        owner_directory: &str,
        now: Timestamp,
        active: &[String],
    ) -> Result<Option<EffectClaim>> {
        self.charge()?;
        ensure!(active.len() <= 2, "too many active delivery slots");
        let (contract, epoch, state) = self
            .runtime(&EffectScope {
                deployment: generation.into(),
                tenant: String::new(),
            })
            .await?;
        ensure!(
            state == "active" && contract == expected_contract,
            "effect runtime paused or approval changed"
        );
        // A restore fork re-binds the queue; a host on the old owner stops here.
        ensure!(
            !self
                .tx
                .fetch::<1>(
                    "SELECT CAST(singleton AS TEXT) FROM nx_effect_queue WHERE singleton=1 AND owner_directory=$1",
                    &[owner_directory.into()],
                )
                .await?
                .is_empty(),
            "effect queue unavailable or owned by another directory"
        );
        let suffix = if matches!(self.tx.query_provider()?, NativeProvider::Postgres) {
            " FOR UPDATE OF o SKIP LOCKED"
        } else {
            ""
        };
        let rows=self.tx.fetch::<4>(&format!("SELECT o.id,o.tenant,CAST(o.fence AS TEXT),CAST(o.attempts AS TEXT) FROM nx_outbox o JOIN nx_effect_tenants t ON t.deployment=o.deployment AND t.tenant=o.tenant WHERE o.deployment=$1 AND ((o.state='pending' AND o.eligible_ms<=$2) OR (o.state='running' AND o.lease_until_ms<=$2)) AND o.id<>$3 AND o.id<>$4 AND $5<(SELECT concurrency FROM nx_effect_queue WHERE singleton=1) ORDER BY t.claim_seq,o.eligible_ms,o.id LIMIT 1{suffix}"),&[generation.into(),now.unix_millis().into(),active.first().map(String::as_str).unwrap_or("").into(),active.get(1).map(String::as_str).unwrap_or("").into(),i64::try_from(active.len())?.into()]).await?;
        // An empty poll writes nothing. Bumping the shared sequence on every poll
        // made concurrent workers abort each other's preflight under SERIALIZABLE.
        let Some([id, tenant, fence, attempts]) = rows.first() else {
            return Ok(None);
        };
        let changed=self.tx.execute("UPDATE nx_effect_queue SET claim_seq=claim_seq+1 WHERE singleton=1 AND owner_directory=$1 AND claim_seq<9223372036854775807",&[owner_directory.into()]).await?;
        ensure!(
            changed == 1,
            "effect queue unavailable or owned by another directory"
        );
        let exhausted = integer(attempts)? >= i64::from(MAX_EFFECT_ATTEMPTS);
        let fence = integer(fence)?
            .checked_add(1)
            .context("effect fence exhausted")?;
        let lease = now.checked_add(Duration::from_millis(EFFECT_LEASE_MILLIS)?)?;
        let changed=self.tx.execute("UPDATE nx_outbox SET state='running',fence=$1,lease_until_ms=$2,attempts=CASE WHEN attempts<5 THEN attempts+1 ELSE attempts END WHERE id=$3 AND deployment=$4 AND fence=$5",&[fence.into(),lease.unix_millis().into(),id.as_str().into(),generation.into(),(fence-1).into()]).await?;
        ensure!(changed == 1, "effect claim raced");
        self.tx.execute("UPDATE nx_effect_tenants SET claim_seq=(SELECT claim_seq FROM nx_effect_queue WHERE singleton=1) WHERE deployment=$1 AND tenant=$2",&[generation.into(),tenant.as_str().into()]).await?;
        Ok(Some(EffectClaim {
            id: id.clone(),
            scope: EffectScope {
                deployment: generation.into(),
                tenant: tenant.clone(),
            },
            fence,
            lease_until: lease,
            exhausted,
            epoch,
        }))
    }
    async fn row(&mut self, claim: &EffectClaim, lock: bool) -> Result<Option<Row>> {
        self.checkpoint()?;
        if lock {
            let n=self.tx.execute("UPDATE nx_outbox SET fence=fence WHERE id=$1 AND deployment=$2 AND tenant=$3 AND fence=$4",&[claim.id.as_str().into(),claim.scope.deployment.as_str().into(),claim.scope.tenant.as_str().into(),claim.fence.into()]).await?;
            if n == 0 {
                return Ok(None);
            }
        }
        let payload = self.tx.bounded_text("payload", MAX_CAPTURE_BYTES);
        let rows=self.tx.fetch::<15>(&format!("SELECT {payload},payload_digest,state,CAST(attempts AS TEXT),CAST(first_eligible_ms AS TEXT),CAST(eligible_ms AS TEXT),contract,epoch,CAST(grant_version AS TEXT),CAST(secret_version AS TEXT),CAST(lease_until_ms AS TEXT),origin,CAST(ordinal AS TEXT),endpoint,CAST(fence AS TEXT) FROM nx_outbox WHERE id=$1 AND deployment=$2 AND tenant=$3 AND fence=$4"),&[claim.id.as_str().into(),claim.scope.deployment.as_str().into(),claim.scope.tenant.as_str().into(),claim.fence.into()]).await?;
        let Some(
            [
                payload,
                digest,
                state,
                attempts,
                first,
                eligible,
                contract,
                epoch,
                version,
                secret_version,
                lease,
                origin,
                ordinal,
                endpoint,
                fence,
            ],
        ) = rows.first()
        else {
            return Ok(None);
        };
        let capture: CapturedEffect = serde_json::from_str(payload)?;
        capture.validate()?;
        ensure!(
            capture.id()? == claim.id
                && capture.capture_digest()? == *digest
                && capture.scope.tenant == claim.scope.tenant
                && capture.origin == *origin
                && i64::from(capture.ordinal) == integer(ordinal)?
                && capture.endpoint() == endpoint
                && integer(fence)? == claim.fence,
            "effect capture storage mismatch"
        );
        let row = Row {
            capture,
            state: state.clone(),
            attempts: integer(attempts)?,
            first: Timestamp::from_unix_millis(integer(first)?)?,
            eligible: Timestamp::from_unix_millis(integer(eligible)?)?,
            epoch: epoch.clone(),
            contract: contract.clone(),
            version: integer(version)?,
            secret_version: integer(secret_version)?,
            lease: Timestamp::from_unix_millis(integer(lease)?)?,
        };
        ensure!(
            row.attempts <= 5
                && row.eligible >= row.first
                && row.first >= row.capture.created
                && opaque(&row.contract)
                && opaque(&row.epoch)
                && row.version > 0,
            "invalid effect attempt metadata"
        );
        ensure!(
            match row.state.as_str() {
                "running" => row.attempts > 0 && row.lease == claim.lease_until && claim.fence > 0,
                "pending" => row.attempts < 5 && row.lease == Timestamp::UNIX_EPOCH,
                "delivered" | "dead" | "paused" | "cancelled" => row.lease == Timestamp::UNIX_EPOCH,
                _ => false,
            },
            "invalid effect state shape"
        );
        Ok(Some(row))
    }
    async fn transition(
        &mut self,
        claim: &EffectClaim,
        state: &str,
        reason: &str,
        eligible: Timestamp,
    ) -> Result<()> {
        let changed=self.tx.execute("UPDATE nx_outbox SET state=$1,reason=$2,eligible_ms=$3,lease_until_ms=0 WHERE id=$4 AND deployment=$5 AND tenant=$6 AND state='running' AND fence=$7",&[state.into(),reason.into(),eligible.unix_millis().into(),claim.id.as_str().into(),claim.scope.deployment.as_str().into(),claim.scope.tenant.as_str().into(),claim.fence.into()]).await?;
        ensure!(changed == 1, "effect finalization superseded");
        Ok(())
    }
    async fn authority(
        &mut self,
        claim: &EffectClaim,
        row: &Row,
        runtime: &(String, String, String),
    ) -> Result<bool> {
        let Some((grant, state)) = self.grant(&claim.scope, row.capture.endpoint()).await? else {
            return Ok(false);
        };
        Ok(runtime.2 == "active"
            && runtime.0 == row.contract
            && runtime.1 == row.epoch
            && state == "active"
            && grant.contract == row.contract
            && grant.epoch == row.epoch
            && grant.version == row.version
            && grant.secret_version == row.secret_version
            && grant.binding == row.capture.binding)
    }
    /// Rechecks authority in a fresh short TX immediately before external I/O.
    pub(crate) async fn preflight(
        &mut self,
        claim: &EffectClaim,
        now: Timestamp,
    ) -> Result<Preflight> {
        self.charge()?;
        let runtime = self.runtime(&claim.scope).await?;
        // Preview does not lock; runtime lock prevents operator envelope changes.
        let Some(preview) = self.row(claim, false).await? else {
            return Ok(Preflight::Settled(Finalized::Superseded));
        };
        let allowed = self.authority(claim, &preview, &runtime).await?;
        let Some(row) = self.row(claim, true).await? else {
            return Ok(Preflight::Settled(Finalized::Superseded));
        };
        if row.state != "running" {
            return Ok(Preflight::Settled(match row.state.as_str() {
                "delivered" => Finalized::Delivered,
                "dead" => Finalized::Dead,
                "paused" => Finalized::Paused,
                _ => Finalized::Superseded,
            }));
        }
        if !allowed {
            self.transition(claim, "paused", "authority_changed", now.max(row.eligible))
                .await?;
            return Ok(Preflight::Settled(Finalized::Paused));
        }
        let window = row
            .first
            .checked_add(Duration::from_millis(EFFECT_RETRY_WINDOW_MILLIS)?)?;
        // Claim at attempts==5 is the fifth attempt unless it reclaimed an
        // already exhausted row. The durable eligible time marks its window.
        if now >= window || claim.exhausted {
            self.transition(claim, "dead", "retry_window", now.max(row.eligible))
                .await?;
            return Ok(Preflight::Settled(Finalized::Dead));
        }
        // Nothing was sent under this expired lease; requeue under the
        // already-charged attempt instead of spending the retry window.
        if now >= row.lease {
            let eligible = now.max(row.eligible);
            self.transition(claim, "pending", "lease_expired", eligible)
                .await?;
            return Ok(Preflight::Settled(Finalized::Retrying(eligible)));
        }
        Ok(Preflight::Send(Box::new(PreparedEffect {
            captured: row.capture,
        })))
    }
    /// Returns a claim whose preflight failed before any send. Only a row still
    /// running under this exact fence changes, so a committed preflight
    /// settlement or a newer claim is untouched. The attempt is refunded.
    pub(crate) async fn release_unsent(&mut self, claim: &EffectClaim) -> Result<()> {
        self.charge()?;
        self.tx.execute("UPDATE nx_outbox SET state='pending',reason='preflight_unavailable',lease_until_ms=0,attempts=attempts-$1 WHERE id=$2 AND deployment=$3 AND tenant=$4 AND state='running' AND fence=$5",&[i64::from(!claim.exhausted).into(),claim.id.as_str().into(),claim.scope.deployment.as_str().into(),claim.scope.tenant.as_str().into(),claim.fence.into()]).await?;
        Ok(())
    }
    /// An unknown acknowledgment is resolved by probing this fenced row later;
    /// it must never trigger a second POST in the same attempt.
    pub(crate) async fn finalize(
        &mut self,
        claim: &EffectClaim,
        now: Timestamp,
        result: DeliveryResult,
    ) -> Result<Finalized> {
        self.charge()?;
        let runtime = self.runtime(&claim.scope).await?;
        if matches!(result, DeliveryResult::Delivered) {
            let Some(row) = self.row(claim, true).await? else {
                return Ok(Finalized::Superseded);
            };
            // This is a known receiver observation, not permission to send.
            // Revocation/cancellation and wall-lease expiry cannot retract it.
            if runtime.2 == "changed" || runtime.1 != claim.epoch || row.epoch != claim.epoch {
                return Ok(Finalized::Superseded);
            }
            let changed=self.tx.execute("UPDATE nx_outbox SET state='delivered',reason='',lease_until_ms=0,eligible_ms=$1 WHERE id=$2 AND deployment=$3 AND tenant=$4 AND fence=$5 AND epoch=$6",&[now.max(row.eligible).unix_millis().into(),claim.id.as_str().into(),claim.scope.deployment.as_str().into(),claim.scope.tenant.as_str().into(),claim.fence.into(),claim.epoch.as_str().into()]).await?;
            ensure!(changed == 1, "delivery observation superseded");
            return Ok(Finalized::Delivered);
        }
        let Some(preview) = self.row(claim, false).await? else {
            return Ok(Finalized::Superseded);
        };
        let allowed = self.authority(claim, &preview, &runtime).await?;
        let Some(row) = self.row(claim, true).await? else {
            return Ok(Finalized::Superseded);
        };
        if row.state == "delivered" {
            return Ok(Finalized::Delivered);
        }
        if row.state != "running" {
            return Ok(Finalized::Superseded);
        }
        if !allowed || now >= row.lease {
            self.transition(claim, "paused", "authority_changed", now.max(row.eligible))
                .await?;
            return Ok(Finalized::Paused);
        }
        let (state, reason, eligible, outcome) = match result {
            DeliveryResult::Delivered => {
                ("delivered", "", now.max(row.eligible), Finalized::Delivered)
            }
            DeliveryResult::Terminal => (
                "dead",
                "terminal_response",
                now.max(row.eligible),
                Finalized::Dead,
            ),
            DeliveryResult::Retry {
                retry_after_seconds,
            } => match retry_at(&claim.id, row.attempts, row.first, now, retry_after_seconds)? {
                Some(at) => ("pending", "transient", at, Finalized::Retrying(at)),
                None => (
                    "dead",
                    "retry_window",
                    now.max(row.eligible),
                    Finalized::Dead,
                ),
            },
        };
        self.transition(claim, state, reason, eligible).await?;
        Ok(outcome)
    }
    pub(super) async fn check_operator_quota(
        &mut self,
        tenant: &str,
        increment: bool,
    ) -> Result<()> {
        let n = self
            .tx
            .execute(
                "UPDATE nx_effect_queue SET claim_seq=claim_seq WHERE singleton=1",
                &[],
            )
            .await?;
        ensure!(n == 1, "effect queue unavailable");
        if !increment {
            return Ok(());
        }
        let rows=self.tx.fetch::<4>("SELECT CAST(COUNT(*) AS TEXT),CAST(COALESCE(SUM(CASE WHEN tenant=$1 THEN 1 ELSE 0 END),0) AS TEXT),CAST((SELECT pending_limit FROM nx_effect_queue WHERE singleton=1) AS TEXT),CAST((SELECT tenant_limit FROM nx_effect_queue WHERE singleton=1) AS TEXT) FROM (SELECT tenant FROM nx_outbox WHERE state IN ('pending','running','paused') LIMIT 1001) AS active_effects",&[tenant.into()]).await?;
        let [app, tenant, app_limit, tenant_limit] =
            rows.first().context("effect quota unavailable")?;
        ensure!(
            integer(app)? < integer(app_limit)?
                && integer(tenant)? < integer(tenant_limit)?
                && (1..=1000).contains(&integer(app_limit)?)
                && (1..=integer(app_limit)?).contains(&integer(tenant_limit)?),
            "effect queue full"
        );
        Ok(())
    }
}
fn retry_at(
    id: &str,
    attempts: i64,
    first: Timestamp,
    now: Timestamp,
    retry_after: Option<u32>,
) -> Result<Option<Timestamp>> {
    let window = first.checked_add(Duration::from_millis(EFFECT_RETRY_WINDOW_MILLIS)?)?;
    if attempts >= i64::from(MAX_EFFECT_ATTEMPTS) || now >= window {
        return Ok(None);
    }
    let delay = match attempts {
        1 => 60_000,
        2 => 300_000,
        3 => 1_800_000,
        4 => 7_200_000,
        _ => anyhow::bail!("invalid effect attempt"),
    };
    let hash = Sha256::digest(format!("{id}:{attempts}"));
    let jitter = i64::from(u16::from_be_bytes([hash[0], hash[1]])) % 1_001;
    let delay = (delay + jitter).max(i64::from(retry_after.unwrap_or(0).min(86_400)) * 1_000);
    let next = now.checked_add(Duration::from_millis(delay)?)?;
    Ok((next < window).then_some(next))
}
pub(super) fn integer(value: &str) -> Result<i64> {
    let n: i64 = value.parse()?;
    ensure!(
        n >= 0 && n.to_string() == value,
        "noncanonical effect integer"
    );
    Ok(n)
}
pub(super) fn checkpoint(tx: &Transaction) -> Result<()> {
    if RequestScope::active() {
        RequestScope::checkpoint_current()
    } else {
        tx.operator_checkpoint()?.checkpoint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_limits_apply_at_five_and_exact_twenty_four_hours() {
        let first = Timestamp::from_unix_millis(1_000).unwrap();
        for (attempt, base) in [(1, 60_000), (2, 300_000), (3, 1_800_000), (4, 7_200_000)] {
            let next = retry_at("stable-key", attempt, first, first, None)
                .unwrap()
                .unwrap();
            assert!(
                (first.unix_millis() + base..=first.unix_millis() + base + 1_000)
                    .contains(&next.unix_millis())
            );
        }
        assert_eq!(retry_at("stable-key", 5, first, first, None).unwrap(), None);
        let end = first
            .checked_add(Duration::from_millis(EFFECT_RETRY_WINDOW_MILLIS).unwrap())
            .unwrap();
        assert_eq!(retry_at("stable-key", 1, first, end, None).unwrap(), None);
        assert_eq!(
            retry_at("stable-key", 1, first, first, Some(86_400)).unwrap(),
            None
        );
    }
}
