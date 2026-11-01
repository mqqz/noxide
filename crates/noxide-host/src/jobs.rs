//! Durable queue bookkeeping for the existing action executor.
//!
//! It never runs a component, authorizes a
//! resource operation, commits a caller transaction, or invents a request scope.
mod operator;
mod recurrence;
mod store;
mod types;
pub use operator::{JobOperatorCommand, JobOperatorResult, JobSummary};
#[cfg(test)]
mod operator_tests;
pub(crate) use crate::manifest::job_contract::validate_recurring_targets;
#[cfg(test)]
pub(crate) use recurrence::occurrence_key;
pub(crate) use store::{Execution, Failure, FailureResult, QueueContext, VerifiedScheduleGrant};
#[cfg(test)]
pub(crate) use types::Grant;
pub(crate) use types::{CapturedJob, Claim, JobScope, SealedTarget, VerifiedJob};
#[cfg(test)]
mod tests;

pub(crate) fn locked_grant_principal(proof: &VerifiedScheduleGrant) -> crate::auth::Principal {
    let grant = proof.grant();
    crate::auth::Principal::service(
        grant.scope.deployment.clone(),
        grant.scope.tenant.clone(),
        grant.worker.name.clone(),
    )
}
pub(crate) fn verified_job_principal(job: &VerifiedJob) -> crate::auth::Principal {
    crate::auth::Principal::service(
        job.deployment().to_owned(),
        job.tenant().to_owned(),
        job.worker().to_owned(),
    )
}
