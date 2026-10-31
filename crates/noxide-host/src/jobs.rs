//! Durable queue bookkeeping for the existing action executor.
//!
//! This leaf is deliberately unregistered until central admission, schema and
//! the service adapter are integrated. It never runs a component, authorizes a
//! resource operation, commits a caller transaction, or invents a request scope.
mod admission;
mod recurrence;
mod store;
mod types;
pub(crate) use admission::validate_contract;
pub(crate) use recurrence::{RecurrenceBatch, RecurrenceCursor, occurrence_key};
pub(crate) use store::{Execution, Failure, FailureResult, QueueContext};
pub(crate) use types::{CapturedJob, Claim, Grant, JobScope, SealedTarget, VerifiedJob};
#[cfg(test)]
mod tests;
