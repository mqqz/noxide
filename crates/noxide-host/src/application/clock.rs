use super::*;
use crate::{
    database::{MaintenanceLease, MaintenanceUncertain},
    lifecycle_clock::{self, AttemptTime},
};
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
            let permit = self.maintenance.clone().try_acquire_owned()?;
            let mut lease =
                MaintenanceLease::new(permit, deadline.into_std(), self.lifecycle_clock.clone());
            if self
                .manifest
                .operations
                .iter()
                .any(manifest::anonymous_action)
            {
                self.keys.signing_edit_key()?;
            }
            self.presentation.validate(&self.manifest)?;
            self.prepare_effect_delivery(deadline.into_std()).await?;
            lease.begin(&self.database).await?;
            let tx = lease.tx();
            tx.check_storage().await?;
            tx.bind_schema(&self.manifest).await?;
            let generation = tx
                .deployment(&self.deployment, self.keys.incarnation(), true)
                .await?;
            ensure!(
                self.generation.get().is_none_or(|g| g == &generation),
                "application generation retired"
            );
            tx.activate_jobs(
                &generation,
                &self.contract,
                self.jobs.as_ref().map(|jobs| jobs.effective()),
                self.manifest.jobs.as_ref(),
                self.effects.is_some(),
            )
            .await?;
            tx.activate_effects(
                &generation,
                &self.contract,
                self.effects.as_ref().map(|effects| effects.effective()),
                self.effects
                    .as_ref()
                    .map(|effects| effects.owner_directory_digest())
                    .transpose()?,
                self.restore_fork,
            )
            .await?;
            // The queue re-bind above and the job fork commit together, so an
            // interrupted fork never leaves an adopted but unfenced copy.
            if self.restore_fork {
                tx.maintenance_checkpoint()?;
                tx.apply_job_fork(&generation).await?;
            }
            let outcome = lifecycle_clock::tick(tx, &self.clock).await;
            lease.finish().await?;
            let tick = outcome?;
            self.activate_effect_delivery(deadline.into_std()).await?;
            self.activate_blobs(deadline).await?;
            // No process readiness on a failed/unknown commit acknowledgement.
            ensure!(
                self.generation.get_or_init(|| generation.clone()) == &generation,
                "concurrent activation differs"
            );
            self.publish_clock(tick)?;
            self.reconcile_blobs(deadline).await
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
        let permit = self.maintenance.clone().try_acquire_owned()?;
        let mut lease =
            MaintenanceLease::new(permit, deadline.into_std(), self.lifecycle_clock.clone());
        lease.begin(&self.database).await?;
        let outcome = async {
            self.admission(lease.tx(), false).await?;
            lifecycle_clock::tick(lease.tx(), &self.clock).await
        }
        .await;
        lease.finish().await?;
        self.publish_clock(outcome?)
    }

    /// Temporal callers retain this value for their complete transaction
    /// attempt. No wall sample or freshness renewal occurs on the request path.
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

    /// The core calls this only after its existing admission/schema/deployment
    /// checks and committed-receipt recovery. One durable clock read, no renewal.
    pub(super) async fn temporal_after_admission(
        &self,
        tx: &mut Transaction,
    ) -> std::result::Result<AttemptTime, RequestError> {
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
        // Construct before spawning. Only acknowledged, clean shutdown releases
        // service ownership; task panic/abort leaves it quarantined.
        let owner = ServiceOwner {
            app: self.clone(),
            stopped: false,
        };
        let (stop, mut stopping) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut owner = owner;
            let mut ticks = tokio::time::interval_at(
                Instant::now() + lifecycle_clock::TICK_INTERVAL,
                lifecycle_clock::TICK_INTERVAL,
            );
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {biased;
                    _ = &mut stopping => { owner.stopped = true; return Ok(()); },
                    _ = ticks.tick() => {}
                }
                if let Err(error) = owner.app.tick_clock().await
                    && error.is::<MaintenanceUncertain>()
                {
                    return Err(error);
                }
                let _ = owner
                    .app
                    .reconcile_blobs(Instant::now() + owner.app.runtime.limits().wall_time)
                    .await;
            }
        });
        Ok(ClockService {
            stop: Some(stop),
            task: Some(task),
            freshness: self.lifecycle_clock.clone(),
        })
    }
}

struct ServiceOwner {
    app: Arc<Application>,
    stopped: bool,
}
impl Drop for ServiceOwner {
    fn drop(&mut self) {
        if self.stopped {
            self.app.maintenance_running.store(false, Ordering::Release);
        } else {
            self.app.lifecycle_clock.quarantine();
        }
    }
}

pub(crate) struct ClockService {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    freshness: crate::lifecycle_clock::Freshness,
}
impl ClockService {
    pub(crate) async fn shutdown(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let mut task = self.task.take().expect("maintenance task");
        // Timeout does not abort the owner: an uncertain in-flight cleanup keeps
        // both ownership and its reserved permit until acknowledged/quarantined.
        tokio::time::timeout(security::CLOCK_CHECKPOINT_BEGIN_DEADLINE, &mut task)
            .await
            .map_err(|_| {
                self.freshness.quarantine();
                MaintenanceUncertain
            })??
    }
}
impl Drop for ClockService {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        // Detach, never abort provider work. Its single owner finishes cleanup.
    }
}

#[cfg(test)]
mod tests;
