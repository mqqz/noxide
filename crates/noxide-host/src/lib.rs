//! Trusted execution, rendering, and persistence for Noxide applications.
#![forbid(unsafe_code)]
pub use noxide_admission::{Presentation, assets, manifest, schema};
pub(crate) use noxide_admission::{
    action_contract, expiry, membership, query_plan, routing, search,
};
#[cfg(test)]
pub(crate) use noxide_admission::{policy, sql};
pub(crate) use noxide_authority::{auth, authority, limiter, operator_roles, security};
pub(crate) use noxide_blobs::{
    inspect as blob_inspect, io as blob_io, metadata as blob_metadata, multipart as blob_multipart,
    state as blob_state, store as blob_store, transport as blob_transport, upload as blob_upload,
};
pub(crate) use noxide_effects as effects;
pub use noxide_effects::effect_deployment;
pub(crate) use noxide_jobs as jobs;
pub use noxide_jobs::job_deployment;
pub use noxide_render as render;
#[cfg(test)]
use noxide_test_support as test_support;
#[cfg(test)]
mod authority_tests;
pub mod deployment;
#[cfg(test)]
mod effects_tests;
#[cfg(test)]
mod job_admission_tests;
#[cfg(test)]
mod membership_tests;
#[cfg(test)]
mod operator_roles_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod store_tests;
pub use deployment::{BlobDeployment, DeploymentResources};
pub use effect_deployment::{EffectDeployment, EffectGrant, EffectLimits, EffectSecret};
pub use effects::{EffectOperatorCommand, EffectOperatorResult, EffectSummary};
pub use job_deployment::{JobDeployment, JobGrant, JobLimits};
pub use jobs::{JobOperatorCommand, JobOperatorResult, JobSummary};
pub mod runtime {
    pub use noxide_guest::Limits;
}
pub use auth::{AccountAdmin, Registration, account_id};
pub use noxide_store::{Database, StoreResources};
pub(crate) use noxide_store::{database, lifecycle_clock};
pub use operator_roles::{RoleAdmin, RoleAssignment, RoleScope};
pub use security::HostKeys;
pub mod application;
pub use application::{
    ActionRejection, Application, JobRunOutcome, LoginChallenge, RequestError,
    ValidatedActionRejection,
};
pub use noxide_repository::repository;

#[cfg(test)]
mod failure_tests;

#[cfg(test)]
mod query_receipt_tests;

#[cfg(test)]
mod parent_tests;

#[cfg(test)]
mod account_tests;

#[cfg(any(test, feature = "test-support"))]
pub async fn test_account(db: &Database, login: &str) -> String {
    db.account_id(login)
        .await
        .unwrap_or_else(|_| "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into())
}
