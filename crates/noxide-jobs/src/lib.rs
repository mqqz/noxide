//! Durable queue bookkeeping for the existing action executor.
//!
//! It never runs a component, authorizes a
//! resource operation, commits a caller transaction, or invents a request scope.
#![forbid(unsafe_code)]
pub mod job_deployment;
mod operator;
pub mod recurrence;
pub mod store;
pub mod types;
pub use operator::{JobOperatorCommand, JobOperatorResult, JobSummary};
#[cfg(test)]
mod operator_tests;
pub use crate::manifest::job_contract::validate_recurring_targets;
pub(crate) use noxide_admission::{action_contract, ids, manifest, principal};
pub(crate) use noxide_store::database;
#[cfg(test)]
pub(crate) use noxide_store::{Database, lifecycle_clock};
#[cfg(any(test, feature = "test-support"))]
pub use recurrence::occurrence_key;
pub use store::{Execution, Failure, FailureResult, QueueContext, VerifiedScheduleGrant};
#[cfg(any(test, feature = "test-support"))]
pub use types::Grant;
pub use types::{CapturedJob, Claim, JobScope, SealedTarget, VerifiedJob};
#[cfg(test)]
mod tests;

pub fn locked_grant_principal(proof: &VerifiedScheduleGrant) -> crate::principal::Principal {
    let grant = proof.grant();
    crate::principal::Principal::service(
        grant.scope.deployment.clone(),
        grant.scope.tenant.clone(),
        grant.worker.name.clone(),
    )
}
pub fn verified_job_principal(job: &VerifiedJob) -> crate::principal::Principal {
    crate::principal::Principal::service(
        job.deployment().to_owned(),
        job.tenant().to_owned(),
        job.worker().to_owned(),
    )
}
pub use operator::JobOperatorTransaction;
