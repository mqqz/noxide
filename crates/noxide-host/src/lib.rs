//! Trusted execution, rendering, and persistence for Noxide applications.
#![forbid(unsafe_code)]
pub use noxide_admission::{Presentation, assets, manifest, schema};
pub(crate) use noxide_admission::{
    action_contract, expiry, ids, membership, policy, principal, query_plan, routing, search, sql,
};
pub(crate) use noxide_effects as effects;
pub use noxide_effects::effect_deployment;
pub use noxide_render as render;
#[cfg(test)]
use noxide_test_support as test_support;
mod blob_inspect;
mod blob_io;
mod blob_upload;
pub mod deployment;
#[cfg(test)]
mod effects_tests;
#[cfg(test)]
mod job_admission_tests;
pub mod job_deployment;
mod limiter;
#[cfg(test)]
mod membership_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod store_tests;
pub use deployment::{BlobDeployment, DeploymentResources};
pub use effect_deployment::{EffectDeployment, EffectGrant, EffectLimits, EffectSecret};
pub use effects::{EffectOperatorCommand, EffectOperatorResult, EffectSummary};
pub use job_deployment::{JobDeployment, JobGrant, JobLimits};
pub use jobs::{JobOperatorCommand, JobOperatorResult, JobSummary};
mod blob_metadata;
mod blob_multipart;
mod blob_state;
mod blob_store;
mod blob_transport;
mod jobs;
pub mod runtime {
    pub use noxide_sandbox::Limits;
    /// A guest with no storage grant, for admission checks outside an application.
    pub type Runtime = noxide_sandbox::Runtime<noxide_sandbox::NoHostCalls>;
}
pub use noxide_store::{Database, StoreResources};
pub(crate) use noxide_store::{database, lifecycle_clock};
mod auth;
mod operator_roles;
pub use auth::{AccountAdmin, Registration, account_id};
pub use operator_roles::{RoleAdmin, RoleAssignment, RoleScope};
mod security;
pub use security::HostKeys;
mod application;
mod repository;
pub use application::{
    ActionRejection, Application, JobRunOutcome, LoginChallenge, RequestError,
    ValidatedActionRejection,
};
pub mod http;

#[cfg(test)]
mod failure_tests;

#[cfg(test)]
mod public_tests;

#[cfg(test)]
mod anonymous_tests;

#[cfg(test)]
mod registration_tests;

mod authority;

#[cfg(test)]
mod parent_tests;

#[cfg(test)]
mod account_tests;

#[cfg(test)]
async fn test_account(db: &Database, login: &str) -> String {
    db.account_id(login)
        .await
        .unwrap_or_else(|_| "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into())
}

#[cfg(test)]
mod parameter_tests;
