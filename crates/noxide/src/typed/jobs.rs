//! Explicit background declarations lower to the shared canonical job contract.
pub use noxide_protocol::jobs::{
    JobContract, RecurringSchedule, RecurringSelection, Schedule, ScheduledTarget, Worker,
    WorkerAction, WorkerTarget,
};

impl super::ApplicationDefinition {
    pub fn jobs(&mut self, contract: JobContract) {
        assert!(
            self.jobs.replace(contract).is_none(),
            "duplicate job contract"
        );
    }
}
