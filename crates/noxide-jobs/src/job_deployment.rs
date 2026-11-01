//! Pure operator approval for declared services. No paths, keys or database I/O.
use anyhow::{Context, Result, ensure};
use noxide_protocol::jobs::{JobContract, MAX_PENDING_JOBS, MAX_WORKERS_PER_APP, Worker};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobDeployment {
    pub grants: Vec<JobGrant>,
    #[serde(default)]
    pub limits: JobLimits,
}

/// A tenant is always explicit. The empty tenant denotes an unpartitioned app;
/// it never means all tenants. Target rules come unchanged from the declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobGrant {
    pub worker: String,
    pub tenant: String,
    pub actions: BTreeSet<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLimits {
    pub pending_per_app: u16,
    pub pending_per_tenant: u16,
    pub worker_concurrency: u8,
}
impl Default for JobLimits {
    fn default() -> Self {
        Self {
            pending_per_app: MAX_PENDING_JOBS,
            pending_per_tenant: MAX_PENDING_JOBS,
            worker_concurrency: MAX_WORKERS_PER_APP,
        }
    }
}
impl JobLimits {
    pub fn validate(self) -> Result<()> {
        ensure!(
            (1..=MAX_PENDING_JOBS).contains(&self.pending_per_app)
                && (1..=self.pending_per_app).contains(&self.pending_per_tenant)
                && (1..=MAX_WORKERS_PER_APP).contains(&self.worker_concurrency),
            "job limits exceed framework ceilings"
        );
        Ok(())
    }
}

/// Canonical review data, also used by startup installation. This does not by
/// itself authorize execution: every attempt locks the installed database grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EffectiveJobDeployment {
    pub limits: JobLimits,
    pub grants: Vec<EffectiveJobGrant>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EffectiveJobGrant {
    pub tenant: String,
    pub worker: Worker,
}
impl JobDeployment {
    /// Requires the independently admitted manifest contract. Unknown worker or
    /// action requests are rejected rather than silently broadening approval.
    pub fn effective(&self, contract: &JobContract) -> Result<EffectiveJobDeployment> {
        self.limits.validate()?;
        ensure!(self.grants.len() <= 64, "too many operator job grants");
        let mut seen = BTreeSet::new();
        let mut grants = Vec::new();
        for requested in &self.grants {
            ensure!(
                noxide_protocol::identifier(&requested.worker)
                    && (requested.tenant.is_empty()
                        || noxide_protocol::identifier(&requested.tenant))
                    && !requested.actions.is_empty()
                    && requested.actions.len() <= 32
                    && seen.insert((&requested.tenant, &requested.worker)),
                "invalid or duplicate operator job grant"
            );
            let declaration = contract
                .workers
                .iter()
                .find(|worker| worker.name == requested.worker)
                .context("operator granted undeclared worker")?;
            ensure!(
                requested
                    .actions
                    .iter()
                    .all(|id| declaration.actions.iter().any(|a| a.action == *id)),
                "operator granted undeclared action"
            );
            let mut worker = declaration.clone();
            worker
                .actions
                .retain(|action| requested.actions.contains(&action.action));
            worker.actions.sort_by_key(|action| action.action);
            grants.push(EffectiveJobGrant {
                tenant: requested.tenant.clone(),
                worker,
            });
        }
        grants.sort_by(|a, b| (&a.tenant, &a.worker.name).cmp(&(&b.tenant, &b.worker.name)));
        let effective = EffectiveJobDeployment {
            limits: self.limits,
            grants,
        };
        ensure!(
            effective.approval_bytes()?.len() <= noxide_protocol::MAX_MANIFEST_BYTES,
            "operator job approval limit"
        );
        Ok(effective)
    }
}
impl EffectiveJobDeployment {
    /// Stable, secret-free bytes for the central deployment approval digest.
    pub fn approval_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxide_protocol::jobs::WorkerAction;
    fn contract() -> JobContract {
        JobContract {
            workers: vec![Worker {
                name: "repair".into(),
                actions: vec![
                    WorkerAction {
                        action: 2,
                        targets: Default::default(),
                    },
                    WorkerAction {
                        action: 3,
                        targets: Default::default(),
                    },
                ],
            }],
            ..Default::default()
        }
    }
    fn deployment() -> JobDeployment {
        JobDeployment {
            grants: vec![JobGrant {
                worker: "repair".into(),
                tenant: "alpha".into(),
                actions: BTreeSet::from([2]),
            }],
            limits: JobLimits::default(),
        }
    }
    #[test]
    fn approval_is_a_canonical_subset_with_explicit_tenant() {
        let mut configured = deployment();
        let first = configured.effective(&contract()).unwrap();
        assert_eq!(first.grants[0].worker.actions.len(), 1);
        configured.grants[0].tenant = String::new();
        assert_ne!(
            first.approval_bytes().unwrap(),
            configured
                .effective(&contract())
                .unwrap()
                .approval_bytes()
                .unwrap()
        );
        configured.grants[0].actions.insert(9);
        assert!(configured.effective(&contract()).is_err());
        let mut configured = deployment();
        configured.grants.push(configured.grants[0].clone());
        assert!(configured.effective(&contract()).is_err());
    }
    #[test]
    fn ceilings_and_unknown_authority_are_rejected() {
        let mut configured = deployment();
        for limits in [
            JobLimits {
                pending_per_app: 1001,
                ..JobLimits::default()
            },
            JobLimits {
                pending_per_tenant: 0,
                ..JobLimits::default()
            },
            JobLimits {
                worker_concurrency: 3,
                ..JobLimits::default()
            },
        ] {
            configured.limits = limits;
            assert!(configured.effective(&contract()).is_err());
        }
        assert!(
            serde_json::from_str::<JobGrant>(
                r#"{"worker":"repair","tenant":"alpha","actions":[2],"run_as_user":"alice"}"#
            )
            .is_err()
        );
    }
}
