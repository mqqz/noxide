//! Durable queue bookkeeping for the existing action executor.
//!
//! This leaf is deliberately unregistered until central admission, schema and
//! the service adapter are integrated. It never runs a component, authorizes a
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
pub(crate) use recurrence::{RecurrenceBatch, RecurrenceCursor, occurrence_key};
pub(crate) use store::{Execution, Failure, FailureResult, QueueContext, VerifiedScheduleGrant};
pub(crate) use types::{CapturedJob, Claim, Grant, JobScope, SealedTarget, VerifiedJob};
#[cfg(test)]
mod tests;
