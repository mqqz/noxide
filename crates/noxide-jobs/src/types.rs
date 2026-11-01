use crate::database::lifecycle::RequestScope;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_protocol::{Fields, jobs::*, time::Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobScope {
    /// Persisted nx_deployment.generation, not the application's display name.
    pub deployment: String,
    pub tenant: String,
}
impl JobScope {
    pub fn validate(&self) -> Result<()> {
        ensure!(opaque(&self.deployment), "invalid job deployment");
        ensure!(
            self.tenant.is_empty() || noxide_protocol::identifier(&self.tenant),
            "invalid job tenant"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedTarget {
    pub resource: u32,
    pub id: u64,
    pub incarnation: String,
    pub revision: i64,
}
impl SealedTarget {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.resource > 0
                && self.id > 0
                && self.id <= i64::MAX as u64
                && self.revision >= 0
                && opaque(&self.incarnation),
            "invalid sealed job target"
        );
        Ok(())
    }
}

/// Operator-installed declaration intersection. The DB row's active state,
/// version, contract and runtime epoch, never this value alone, grant authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub scope: JobScope,
    pub worker: Worker,
    pub version: i64,
    pub contract: String,
    pub epoch: String,
}
impl Grant {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        ensure!(
            self.version > 0 && opaque(&self.contract) && opaque(&self.epoch),
            "invalid service grant version"
        );
        ensure!(
            noxide_protocol::identifier(&self.worker.name) && self.worker.actions.len() <= 32,
            "invalid service worker"
        );
        let mut actions = std::collections::BTreeSet::new();
        for action in &self.worker.actions {
            ensure!(
                action.action > 0 && actions.insert(action.action) && action.targets.len() <= 4,
                "invalid service action grant"
            );
            for (alias, target) in &action.targets {
                ensure!(
                    noxide_protocol::identifier(alias)
                        && target.resource > 0
                        && target.eligible > 0,
                    "invalid service target rule"
                );
            }
        }
        Ok(())
    }
    pub fn permits(&self, job: &CapturedJob) -> Result<()> {
        self.validate()?;
        ensure!(
            self.scope == job.scope
                && self.worker.name == job.worker
                && self.version == job.grant_version
                && self.contract == job.contract
                && self.epoch == job.epoch,
            "job grant changed"
        );
        let action = self
            .worker
            .actions
            .iter()
            .find(|a| a.action == job.action)
            .context("service action not granted")?;
        ensure!(
            action.targets.len() == job.targets.len(),
            "service binding mismatch"
        );
        for (name, target) in &job.targets {
            ensure!(
                action
                    .targets
                    .get(name)
                    .is_some_and(|rule| rule.resource == target.resource),
                "service target not granted"
            );
        }
        Ok(())
    }
}

/// Immutable capture, created only after the common action adapter has evaluated
/// canonical input expressions and resolved authorized target seals once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedJob {
    pub(super) scope: JobScope,
    pub(super) origin: String,
    pub(super) ordinal: u8,
    pub(super) source_action: u32,
    pub(super) worker: String,
    pub(super) action: u32,
    pub(super) action_version: u32,
    pub(super) contract: String,
    pub(super) grant_version: i64,
    pub(super) epoch: String,
    pub(super) due: Timestamp,
    pub(super) input: Fields,
    pub(super) targets: BTreeMap<String, SealedTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reconciled_from: Option<String>,
}
impl CapturedJob {
    #[allow(clippy::too_many_arguments)]
    pub fn capture(
        declaration: &Schedule,
        origin: String,
        grant: &Grant,
        action_version: u32,
        due: Timestamp,
        now: Timestamp,
        input: Fields,
        targets: BTreeMap<String, SealedTarget>,
    ) -> Result<Self> {
        ensure!(
            declaration.ordinal < MAX_SCHEDULES_PER_ACTION as u8
                && declaration.targets.keys().eq(targets.keys())
                && declaration.inputs.keys().eq(input.keys()),
            "schedule capture differs from declaration"
        );
        let job = Self {
            scope: grant.scope.clone(),
            origin,
            ordinal: declaration.ordinal,
            source_action: declaration.source_action,
            worker: declaration.worker.clone(),
            action: declaration.action,
            action_version,
            contract: grant.contract.clone(),
            grant_version: grant.version,
            epoch: grant.epoch.clone(),
            due,
            input,
            targets,
            reconciled_from: None,
        };
        job.validate()?;
        ensure!(
            due <= now.checked_add(noxide_protocol::time::Duration::from_millis(
                MAX_SCHEDULE_HORIZON_MILLIS
            )?)?,
            "job exceeds schedule horizon"
        );
        grant.permits(&job)?;
        Ok(job)
    }
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        ensure!(
            self.reconciled_from.as_ref().is_none_or(|id| opaque(id)),
            "invalid reconciliation parent"
        );
        ensure!(
            opaque(&self.origin)
                && noxide_protocol::identifier(&self.worker)
                && self.source_action > 0
                && self.action > 0
                && self.action_version > 0
                && self.grant_version > 0
                && self.ordinal < 2
                && opaque(&self.contract)
                && opaque(&self.epoch),
            "invalid captured job identity"
        );
        ensure!(
            self.targets.len() <= 4 && self.input.len() <= 32,
            "job capture cardinality"
        );
        for (alias, target) in &self.targets {
            ensure!(
                noxide_protocol::identifier(alias),
                "invalid job target alias"
            );
            target.validate()?;
        }
        for key in self.input.keys() {
            ensure!(noxide_protocol::identifier(key), "invalid job input name");
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_JOB_BYTES,
            "job payload limit"
        );
        Ok(())
    }
    pub fn id(&self) -> Result<String> {
        Ok(format!(
            "j1_{}",
            digest(&(1, "job", &self.scope.deployment, &self.origin, self.ordinal))?
        ))
    }
    pub fn invocation_digest(&self) -> Result<String> {
        // All captured fields, including canonical input, grant version and
        // immutable target seals, participate. Attempts/fences never do.
        digest(&(1, "service-invocation", self.id()?, self))
    }
    pub fn receipt_subject(&self) -> Result<String> {
        Ok(format!(
            "s1_{}",
            digest(&(1, "service", &self.scope, &self.worker))?
        ))
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn input_digest(&self) -> Result<String> {
        digest(&(1, "job-input", &self.input))
    }
    pub fn input(&self) -> &Fields {
        &self.input
    }
    pub fn targets(&self) -> &BTreeMap<String, SealedTarget> {
        &self.targets
    }
    pub fn action(&self) -> (u32, u32) {
        (self.action, self.action_version)
    }
    pub fn scope(&self) -> &JobScope {
        &self.scope
    }
    pub fn worker(&self) -> &str {
        &self.worker
    }
    pub fn contract(&self) -> &str {
        &self.contract
    }
    pub fn reconciled_from(&self) -> Option<&str> {
        self.reconciled_from.as_deref()
    }
    /// Operator-only fresh identity. The caller must have validated canonical
    /// inputs and current eligible target reads using the existing action
    /// adapter in this same transaction; previous seals confer no authority.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn reconcile(
        previous: &Self,
        grant: &Grant,
        action_version: u32,
        now: Timestamp,
        input: Fields,
        targets: BTreeMap<String, SealedTarget>,
    ) -> Result<Self> {
        let parent = previous.id()?;
        let origin = format!(
            "o1_{}",
            digest(&(
                1,
                "operator-reconcile",
                &parent,
                &grant.scope,
                &grant.contract,
                &grant.epoch,
                grant.version
            ))?
        );
        let job = Self {
            scope: grant.scope.clone(),
            origin,
            ordinal: 0,
            source_action: previous.action,
            worker: grant.worker.name.clone(),
            action: previous.action,
            action_version,
            contract: grant.contract.clone(),
            grant_version: grant.version,
            epoch: grant.epoch.clone(),
            due: now,
            input,
            targets,
            reconciled_from: Some(parent),
        };
        grant.permits(&job)?;
        job.validate()?;
        ensure!(
            job.id()? != previous.id()?,
            "reconciliation reused job identity"
        );
        Ok(job)
    }
}

/// A claim is not execution authority. Only locked, current grant/job/receipt
/// admission inside the execution transaction produces VerifiedJob.
#[derive(Clone, Debug)]
pub struct Claim {
    pub(super) id: String,
    pub(super) scope: JobScope,
    pub(super) fence: i64,
    pub(super) lease_until: Timestamp,
    pub(super) exhausted: bool,
}
impl Claim {
    #[cfg(any(test, feature = "test-support"))]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn fence(&self) -> i64 {
        self.fence
    }
}

pub struct VerifiedJob {
    pub(super) claim: Claim,
    pub(super) job: CapturedJob,
    pub(super) grant: Grant,
}
impl VerifiedJob {
    pub fn captured(&self) -> &CapturedJob {
        &self.job
    }
    pub fn grant(&self) -> &Grant {
        &self.grant
    }
    pub fn deployment(&self) -> &str {
        &self.job.scope.deployment
    }
    pub fn tenant(&self) -> &str {
        &self.job.scope.tenant
    }
    pub fn worker(&self) -> &str {
        &self.job.worker
    }
    pub fn action(&self) -> (u32, u32) {
        self.job.action()
    }
    pub fn input(&self) -> &Fields {
        &self.job.input
    }
    pub fn targets(&self) -> &BTreeMap<String, SealedTarget> {
        &self.job.targets
    }
    pub fn receipt_nonce(&self) -> Result<String> {
        self.job.id()
    }
    pub fn receipt_subject(&self) -> Result<String> {
        self.job.receipt_subject()
    }
    pub fn invocation_digest(&self) -> Result<String> {
        self.job.invocation_digest()
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn fence(&self) -> i64 {
        self.claim.fence
    }
}

pub(super) fn digest(value: &impl Serialize) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(value)?)))
}
pub(super) fn opaque(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
pub(super) fn integer(value: &str) -> Result<i64> {
    let parsed: i64 = value.parse()?;
    ensure!(
        parsed >= 0 && parsed.to_string() == value,
        "noncanonical job integer"
    );
    Ok(parsed)
}
pub(super) fn cpu_checkpoint(tx: &crate::database::Transaction) -> Result<()> {
    if RequestScope::active() {
        RequestScope::checkpoint_current()
    } else {
        tx.operator_checkpoint()?.checkpoint()
    }
}
