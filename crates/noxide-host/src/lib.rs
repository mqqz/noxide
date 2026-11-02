//! Trusted execution, rendering, and persistence for Noxide applications.
#![forbid(unsafe_code)]

pub mod application;
pub mod deployment;

pub mod runtime {
    pub use noxide_guest::Limits;
}

pub use application::{
    ActionRejection, Application, JobRunOutcome, LoginChallenge, RequestError,
    ValidatedActionRejection,
};
pub use auth::{AccountAdmin, Registration, account_id};
pub use deployment::{BlobDeployment, DeploymentResources};
pub use effect_deployment::{EffectDeployment, EffectGrant, EffectLimits, EffectSecret};
pub use effects::{EffectOperatorCommand, EffectOperatorResult, EffectSummary};
pub use job_deployment::{JobDeployment, JobGrant, JobLimits};
pub use jobs::{JobOperatorCommand, JobOperatorResult, JobSummary};
pub use noxide_admission::{Presentation, assets, manifest, schema};
pub use noxide_effects::effect_deployment;
pub use noxide_jobs::job_deployment;
pub use noxide_render as render;
pub use noxide_repository::repository;
pub use noxide_store::{Database, StoreResources};
pub use operator_roles::{RoleAdmin, RoleAssignment, RoleScope};
pub use security::HostKeys;
#[cfg(any(test, feature = "test-support"))]
pub use test_account::test_account;

pub(crate) use noxide_admission::{action_contract, expiry, query_plan, routing, search};
#[cfg(test)]
pub(crate) use noxide_admission::{membership, policy, sql};
pub(crate) use noxide_authority::{auth, authority, limiter, operator_roles, security};
pub(crate) use noxide_effects as effects;
pub(crate) use noxide_jobs as jobs;
pub(crate) use noxide_store::{database, lifecycle_clock};

#[cfg(test)]
use noxide_test_support as test_support;

#[cfg(test)]
mod account_tests;
#[cfg(test)]
mod authority_tests;
#[cfg(test)]
mod failure_tests;
#[cfg(test)]
mod operator_roles_tests;
#[cfg(test)]
mod parent_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod query_receipt_tests;
#[cfg(test)]
mod store_tests;
#[cfg(any(test, feature = "test-support"))]
mod test_account;
