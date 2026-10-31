//! Durable queue bookkeeping for the existing action executor.
//!
//! It never runs a component, authorizes a
//! resource operation, commits a caller transaction, or invents a request scope.
mod admission;
mod operator;
mod recurrence;
mod store;
mod types;
pub use operator::{JobOperatorCommand, JobOperatorResult, JobSummary};
#[cfg(test)]
mod operator_tests;
pub(crate) use admission::validate_contract;
#[cfg(test)]
pub(crate) use recurrence::occurrence_key;
pub(crate) use store::{Execution, Failure, FailureResult, QueueContext, VerifiedScheduleGrant};
#[cfg(test)]
pub(crate) use types::Grant;
pub(crate) use types::{CapturedJob, Claim, JobScope, SealedTarget, VerifiedJob};
#[cfg(test)]
mod tests;
