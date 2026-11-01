//! Identity values authorization is evaluated against. Holds no credentials.
use anyhow::Result;

#[derive(Clone, Debug)]
pub(crate) enum Principal {
    Anonymous,
    User(User),
    Service(ServiceIdentity),
}

/// Constructed only from the queue's authoritative, transaction-locked grant.
/// A worker has no account ID, user roles, session, or ownership identity.
#[derive(Clone, Debug)]
pub(crate) struct ServiceIdentity {
    deployment: String,
    tenant: String,
    worker: String,
}
impl ServiceIdentity {
    pub(crate) fn tenant(&self) -> &str {
        &self.tenant
    }
    pub(crate) fn worker(&self) -> &str {
        &self.worker
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrincipalKey {
    Anonymous,
    User {
        id: String,
        tenant: String,
    },
    Service {
        deployment: String,
        tenant: String,
        worker: String,
    },
}
impl Principal {
    pub(crate) fn authority_key(&self) -> PrincipalKey {
        match self {
            Self::Anonymous => PrincipalKey::Anonymous,
            Self::User(user) => PrincipalKey::User {
                id: user.id.clone(),
                tenant: user.tenant.clone(),
            },
            Self::Service(service) => PrincipalKey::Service {
                deployment: service.deployment.clone(),
                tenant: service.tenant.clone(),
                worker: service.worker.clone(),
            },
        }
    }
    /// Only job admission, holding a transaction-locked grant, names a service.
    pub(crate) fn service(deployment: String, tenant: String, worker: String) -> Self {
        Self::Service(ServiceIdentity {
            deployment,
            tenant,
            worker,
        })
    }
    pub(crate) fn user(&self) -> Result<&User> {
        match self {
            Self::User(user) => Ok(user),
            Self::Anonymous | Self::Service(_) => anyhow::bail!("policy denied"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct User {
    pub id: String,
    pub tenant: String,
    pub roles: Vec<(String, String)>,
}
