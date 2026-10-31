//! Explicit operator CPU work remains tied to its existing transaction lifetime.
use super::*;

#[derive(Clone)]
pub(crate) struct OperatorCheckpoint {
    deadline: tokio::time::Instant,
    cancelled: Arc<AtomicBool>,
    ended: Arc<AtomicBool>,
}
impl OperatorCheckpoint {
    pub(crate) fn checkpoint(&self) -> Result<()> {
        ensure!(!RequestScope::active(), Unavailable::Closed);
        ensure!(
            !self.cancelled.load(Ordering::Acquire) && !self.ended.load(Ordering::Acquire),
            Unavailable::Closed
        );
        ensure!(
            tokio::time::Instant::now() < self.deadline,
            Unavailable::Deadline
        );
        Ok(())
    }
}
impl Transaction {
    pub(crate) fn operator_checkpoint(&self) -> Result<OperatorCheckpoint> {
        ensure!(
            !RequestScope::active()
                && self.active
                && self.ordinary.is_none()
                && self.maintenance.is_none(),
            Unavailable::Closed
        );
        let checkpoint = OperatorCheckpoint {
            deadline: self.deadline,
            cancelled: self.cancelled.clone(),
            ended: self.operator_ended.clone(),
        };
        checkpoint.checkpoint()?;
        Ok(checkpoint)
    }
}
