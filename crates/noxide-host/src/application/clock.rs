use super::*;
use crate::lifecycle_clock::{self, AttemptTime};
use std::time::Duration;

impl Application {
    /// Bind this process to the deployment and durably tick before publishing
    /// readiness. Startup has one deadline, including admission and commit.
    pub async fn activate(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        timeout_at(deadline, async {
            // A real private database connection is opened outside every request,
            // session, worker and Wasm lane. There is no shared connection pool.
            // try_acquire gives one active maintenance transaction and no queue.
            let _maintenance = self.maintenance.try_acquire()?;
            if self
                .manifest
                .operations
                .iter()
                .any(manifest::anonymous_action)
            {
                self.keys.signing_edit_key()?;
            }
            self.presentation.validate(&self.manifest)?;
            let mut tx = self.database.begin_maintenance(deadline.into_std()).await?;
            tx.check_storage().await?;
            tx.bind_schema(&self.manifest).await?;
            let generation = tx
                .deployment(&self.deployment, self.keys.incarnation(), true)
                .await?;
            ensure!(
                self.generation.get().is_none_or(|g| g == &generation),
                "application generation retired"
            );
            let tick = lifecycle_clock::tick(tx, &self.clock).await?;
            // No process readiness on a failed/unknown commit acknowledgement.
            ensure!(
                self.generation.get_or_init(|| generation.clone()) == &generation,
                "concurrent activation differs"
            );
            self.publish_clock(tick)
        })
        .await?
    }

    fn publish_clock(&self, tick: lifecycle_clock::CommittedTick) -> Result<()> {
        let seconds = tick.credential_seconds;
        self.lifecycle_clock.committed(tick)?;
        self.clock.fetch_max(seconds, Ordering::Relaxed);
        self.checkpointed.fetch_max(seconds, Ordering::Relaxed);
        Ok(())
    }

    async fn tick_clock(&self) -> Result<()> {
        let deadline = Instant::now() + security::CLOCK_CHECKPOINT_BEGIN_DEADLINE;
        timeout_at(deadline, async {
            let _maintenance = self.maintenance.try_acquire()?;
            let mut tx = self.database.begin_maintenance(deadline.into_std()).await?;
            self.admission(&mut tx, false).await?;
            let tick = lifecycle_clock::tick(tx, &self.clock).await?;
            self.publish_clock(tick)
        })
        .await?
    }

    /// Future temporal callers retain this value for their complete transaction
    /// attempt. No wall sample or freshness renewal occurs on the request path.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "P07 temporal consumers are not enabled yet")
    )]
    pub(crate) async fn temporal_attempt(
        &self,
        tx: &mut Transaction,
    ) -> std::result::Result<AttemptTime, RequestError> {
        self.admission(tx, false)
            .await
            .map_err(RequestError::database)?;
        self.lifecycle_clock
            .attempt(tx)
            .await
            .map_err(|_| RequestError::Busy)
    }

    pub(crate) fn start_clock_service(self: &Arc<Self>) -> Result<ClockService> {
        ensure!(
            self.generation.get().is_some(),
            "application is not activated"
        );
        self.maintenance_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("clock maintenance is already running"))?;
        // Construct before spawning: cancellation before first poll still drops
        // the guard and releases the single-service ownership bit.
        let owner = ServiceOwner(self.clone());
        let task = tokio::spawn(async move {
            let _owner = owner;
            let mut ticks = tokio::time::interval_at(
                Instant::now() + lifecycle_clock::TICK_INTERVAL,
                lifecycle_clock::TICK_INTERVAL,
            );
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticks.tick().await;
                let _ = _owner.0.tick_clock().await;
            }
        });
        Ok(ClockService { task })
    }
}

struct ServiceOwner(Arc<Application>);
impl Drop for ServiceOwner {
    fn drop(&mut self) {
        self.0.maintenance_running.store(false, Ordering::Release);
    }
}

pub(crate) struct ClockService {
    task: tokio::task::JoinHandle<()>,
}
impl ClockService {
    pub(crate) async fn shutdown(mut self) {
        self.task.abort();
        let _ =
            tokio::time::timeout(security::CLOCK_CHECKPOINT_BEGIN_DEADLINE, &mut self.task).await;
    }
}
impl Drop for ClockService {
    fn drop(&mut self) {
        // Also cancel on listener error or cancellation of serve itself. Dropping
        // its private Transaction cancels SQLite and closes PG unresolved state.
        self.task.abort();
    }
}

#[cfg(test)]
mod tests;
