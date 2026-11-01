//! Trusted execution, rendering, and persistence for Noxide applications.
mod action_contract;
pub use noxide_assets as assets;
mod blob_inspect;
mod blob_io;
mod blob_upload;
pub mod deployment;
pub mod effect_deployment;
mod ids;
pub mod job_deployment;
mod limiter;
mod principal;
mod sql;
mod temporal;
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
mod database;
mod effects;
mod jobs;
mod lifecycle_clock;
pub mod manifest;
pub mod render;
pub mod runtime {
    pub use noxide_sandbox::Limits;
    /// A guest with no storage grant, for admission checks outside an application.
    pub type Runtime = noxide_sandbox::Runtime<noxide_sandbox::NoHostCalls>;
}
pub mod schema;
pub use database::{Database, StoreResources};
mod auth;
mod operator_roles;
pub use auth::{Registration, account_id};
pub use operator_roles::{RoleAssignment, RoleScope};
mod security;
pub use security::HostKeys;
mod application;
mod repository;
pub use application::{
    ActionRejection, Application, EffectRunOutcome, JobRunOutcome, LoginChallenge, RequestError,
    ValidatedActionRejection,
};
pub mod http;

#[cfg(test)]
mod failure_tests;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

mod presentation;
pub use presentation::Presentation;

#[cfg(test)]
mod public_tests;

#[cfg(test)]
mod anonymous_tests;

#[cfg(test)]
mod registration_tests;

mod authority;
mod expiry;
mod form_layout;
mod membership;
mod policy;
mod routing;

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

mod query_plan;
mod search;

#[cfg(test)]
mod parameter_tests;
