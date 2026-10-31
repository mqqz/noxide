//! Pure, secret-free approval data and host-only delivery resources.
use anyhow::{Context, Result, ensure};
use noxide_protocol::effects::{
    EffectContract, EffectEndpoint, MAX_EFFECT_CONCURRENCY, MAX_PENDING_EFFECTS,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, net::SocketAddr, path::PathBuf};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectDeployment {
    pub grants: Vec<EffectGrant>,
    #[serde(default)]
    pub secrets: Vec<EffectSecret>,
    pub tor_proxy: SocketAddr,
    #[serde(default)]
    pub limits: EffectLimits,
    /// Existing host-key directory, supplied by the host after pure approval.
    #[serde(skip)]
    pub runtime_directory: Option<PathBuf>,
}
impl fmt::Debug for EffectDeployment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EffectDeployment([redacted])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectGrant {
    pub endpoint: String,
    pub tenant: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectSecret {
    pub slot: String,
    pub path: PathBuf,
}
impl fmt::Debug for EffectSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EffectSecret([redacted])")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectLimits {
    pub pending_per_app: u16,
    pub pending_per_tenant: u16,
    pub worker_concurrency: u8,
}
impl Default for EffectLimits {
    fn default() -> Self {
        Self {
            pending_per_app: MAX_PENDING_EFFECTS,
            pending_per_tenant: MAX_PENDING_EFFECTS,
            worker_concurrency: MAX_EFFECT_CONCURRENCY,
        }
    }
}
impl EffectLimits {
    pub fn validate(self) -> Result<()> {
        ensure!(
            (1..=MAX_PENDING_EFFECTS).contains(&self.pending_per_app)
                && (1..=self.pending_per_app).contains(&self.pending_per_tenant)
                && (1..=MAX_EFFECT_CONCURRENCY).contains(&self.worker_concurrency),
            "effect limits exceed framework ceilings"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveEffectGrant {
    pub tenant: String,
    pub endpoint: EffectEndpoint,
    pub host: String,
    pub port: u16,
    pub path: String,
}
#[derive(Clone, Serialize)]
pub struct EffectiveEffectDeployment {
    pub limits: EffectLimits,
    pub tor_proxy: SocketAddr,
    pub grants: Vec<EffectiveEffectGrant>,
    /// Covers the admitted per-emission schemas and disclosure expressions.
    pub contract: EffectContract,
    #[serde(skip)]
    pub(crate) secrets: Vec<EffectSecret>,
    #[serde(skip)]
    pub(crate) runtime_directory: Option<PathBuf>,
}
impl fmt::Debug for EffectiveEffectDeployment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EffectiveEffectDeployment([redacted])")
    }
}
impl EffectDeployment {
    pub fn with_runtime_directory(mut self, directory: PathBuf) -> Self {
        self.runtime_directory = Some(directory);
        self
    }
    pub fn effective(&self, contract: &EffectContract) -> Result<EffectiveEffectDeployment> {
        self.limits.validate()?;
        crate::effects::transport::TorProxy::loopback(self.tor_proxy)
            .map_err(|_| anyhow::anyhow!("invalid effect Tor proxy"))?;
        ensure!(
            self.grants.len() <= 64 && self.secrets.len() <= 32,
            "too many effect grants"
        );
        let mut slots = BTreeSet::new();
        for secret in &self.secrets {
            ensure!(
                noxide_protocol::identifier(&secret.slot)
                    && slots.insert(&secret.slot)
                    && !secret.path.as_os_str().is_empty(),
                "invalid or duplicate effect secret slot"
            );
        }
        let mut seen = BTreeSet::new();
        let mut grants = Vec::new();
        for requested in &self.grants {
            ensure!(
                (requested.tenant.is_empty() || noxide_protocol::identifier(&requested.tenant))
                    && noxide_protocol::identifier(&requested.endpoint)
                    && seen.insert((&requested.tenant, &requested.endpoint)),
                "invalid or duplicate effect grant"
            );
            let endpoint = contract
                .endpoints
                .iter()
                .find(|e| e.name == requested.endpoint)
                .context("operator granted undeclared endpoint")?;
            ensure!(
                endpoint
                    .secret_slot
                    .as_ref()
                    .is_none_or(|slot| slots.contains(slot)),
                "effect secret slot has no host resource"
            );
            crate::effects::transport::Endpoint::checked(
                &requested.host,
                requested.port,
                &requested.path,
            )
            .map_err(|_| anyhow::anyhow!("invalid approved HTTPS endpoint"))?;
            grants.push(EffectiveEffectGrant {
                tenant: requested.tenant.clone(),
                endpoint: endpoint.clone(),
                host: requested.host.clone(),
                port: requested.port,
                path: requested.path.clone(),
            });
        }
        ensure!(
            self.secrets
                .iter()
                .all(|secret| grants
                    .iter()
                    .any(|grant| grant.endpoint.secret_slot.as_ref() == Some(&secret.slot))),
            "unreferenced effect secret resource"
        );
        grants.sort_by(|a, b| (&a.tenant, &a.endpoint.name).cmp(&(&b.tenant, &b.endpoint.name)));
        let mut contract = contract.clone();
        contract.endpoints.sort_by(|a, b| a.name.cmp(&b.name));
        contract
            .emissions
            .sort_by_key(|e| (e.source_action, e.ordinal));
        for emission in &mut contract.emissions {
            emission
                .fields
                .sort_by(|a, b| a.schema.name.cmp(&b.schema.name));
        }
        let effective = EffectiveEffectDeployment {
            limits: self.limits,
            tor_proxy: self.tor_proxy,
            grants,
            contract,
            secrets: self.secrets.clone(),
            runtime_directory: self.runtime_directory.clone(),
        };
        ensure!(
            effective.approval_bytes()?.len() <= noxide_protocol::MAX_MANIFEST_BYTES,
            "effect approval limit"
        );
        Ok(effective)
    }
}
impl EffectiveEffectDeployment {
    pub fn approval_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> EffectDeployment {
        EffectDeployment {
            grants: vec![EffectGrant {
                endpoint: "events".into(),
                tenant: String::new(),
                host: "receiver.org".into(),
                port: 443,
                path: "/events".into(),
            }],
            secrets: vec![],
            tor_proxy: "127.0.0.1:9050".parse().unwrap(),
            limits: EffectLimits::default(),
            runtime_directory: None,
        }
    }
    #[test]
    fn approval_is_pure_canonical_and_binds_destination() {
        let contract = EffectContract {
            endpoints: vec![EffectEndpoint {
                name: "events".into(),
                secret_slot: None,
            }],
            emissions: vec![],
        };
        let config = config();
        let approved = config
            .effective(&contract)
            .unwrap()
            .approval_bytes()
            .unwrap();
        assert_eq!(
            approved,
            config
                .clone()
                .with_runtime_directory("/host/keys".into())
                .effective(&contract)
                .unwrap()
                .approval_bytes()
                .unwrap()
        );
        let mut changed = config.clone();
        changed.grants[0].path = "/other".into();
        assert_ne!(
            approved,
            changed
                .effective(&contract)
                .unwrap()
                .approval_bytes()
                .unwrap()
        );
        changed.grants[0].host = "127.0.0.1".into();
        assert!(changed.effective(&contract).is_err());
        changed = config;
        changed.tor_proxy = "192.0.2.1:9050".parse().unwrap();
        assert!(changed.effective(&contract).is_err());
    }
    #[test]
    fn limits_and_unknown_authority_fail_closed() {
        let mut config = config();
        config.limits.worker_concurrency = 3;
        assert!(config.effective(&EffectContract::default()).is_err());
        assert!(serde_json::from_str::<EffectGrant>(r#"{"endpoint":"e","tenant":"","host":"receiver.org","port":443,"path":"/","method":"GET"}"#).is_err());
    }
}
