//! Approved action types shared by repository execution, rendering and the
//! application layer. Depends on the protocol alone.
mod rejection;
use anyhow::Result;
use noxide_protocol::{Action, ActionTarget, Input, Step};
#[cfg(any(test, feature = "test-support"))]
pub use rejection::MAX_ACTION_REJECTION_BYTES;
pub use rejection::{ActionRejection, ValidatedActionRejection};

/// A reference named by a request does not exist or is not visible.
#[derive(Debug)]
pub struct ReferenceUnavailable;
impl std::fmt::Display for ReferenceUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("reference unavailable")
    }
}
impl std::error::Error for ReferenceUnavailable {}

/// Execution view of an approved action.
#[derive(Clone, Copy)]
pub struct ActionCore<'a> {
    pub id: u32,
    pub version: u32,
    pub inputs: &'a [Input],
    pub steps: &'a [Step],
    pub targets: &'a [ActionTarget],
}
impl<'a> ActionCore<'a> {
    pub fn of(action: &'a Action) -> Result<Self> {
        Ok(Self {
            id: action.id,
            version: action.version,
            inputs: &action.inputs,
            steps: &action.steps,
            targets: &action.targets,
        })
    }

    pub fn uses_time(self) -> bool {
        self.steps.iter().any(|step| {
            step.guards.iter().any(|guard| guard.condition.uses_time())
                || step
                    .assign
                    .iter()
                    .any(|assignment| match &assignment.change {
                        noxide_protocol::Change::Set(value) => value.uses_time(),
                        noxide_protocol::Change::Increase { by, .. }
                        | noxide_protocol::Change::Decrease { by, .. } => by.uses_time(),
                    })
        })
    }

    pub fn first_operation(self) -> u32 {
        self.steps[0].operation
    }
}
