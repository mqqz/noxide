//! The worker only claims and dispatches to the common action executor. It never
//! finalizes a queue attempt from an error or supplies a browser/user identity.
use super::*;
use crate::{
    job_deployment::EffectiveJobDeployment,
    jobs::{Claim, QueueContext},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

tokio::task_local! { static WORKER_SLOT: Arc<OwnedSemaphorePermit>; }

pub(crate) struct JobRuntime {
    effective: EffectiveJobDeployment,
    workers: Arc<Semaphore>,
    database: Arc<Semaphore>,
    running: std::sync::atomic::AtomicBool,
}
impl JobRuntime {
    pub(crate) fn new(effective: EffectiveJobDeployment) -> Self {
        let concurrency = usize::from(effective.limits.worker_concurrency);
        Self {
            effective,
            workers: Arc::new(Semaphore::new(concurrency)),
            database: Arc::new(Semaphore::new(concurrency)),
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }
    pub(crate) fn effective(&self) -> &EffectiveJobDeployment {
        &self.effective
    }
}

impl Application {
    /// Both the worker and service adapter use this dedicated lane. The request
    /// permit is retained by AdmissionOwner through actual provider cleanup;
    /// timing out or dropping a caller cannot prematurely release worker capacity.
    pub(super) async fn admit_job_invocation_work(
        &self,
    ) -> std::result::Result<action::InvocationAdmission, RequestError> {
        let jobs = self.jobs.as_ref().ok_or(RequestError::Rejected)?;
        let request = WORKER_SLOT.try_with(Clone::clone).ok().map_or_else(
            || {
                jobs.workers
                    .clone()
                    .try_acquire_owned()
                    .map(Arc::new)
                    .map_err(|_| RequestError::Busy)
            },
            Ok,
        )?;
        let database = jobs
            .database
            .clone()
            .try_acquire_owned()
            .map_err(|_| RequestError::Busy)?;
        Ok(action::InvocationAdmission {
            owner: self.owned_request(
                request,
                Arc::new(database),
                None,
                self.runtime.limits().wall_time,
            ),
        })
    }

    async fn claim_job(&self) -> std::result::Result<Option<Claim>, RequestError> {
        let admission = self.admit_job_invocation_work().await?;
        admission
            .owner
            .run(async {
                let mut tx = self
                    .database
                    .begin(admission.owner.work_deadline().into_std())
                    .await
                    .map_err(RequestError::database)?;
                // Deployment admission precedes the fresh durable lifecycle sample.
                let now = self.temporal_attempt(&mut tx).await?.timestamp();
                let generation = self.generation.get().ok_or(RequestError::Busy)?;
                let mut calls = 16;
                let claim = QueueContext {
                    tx: &mut tx,
                    calls: &mut calls,
                }
                .claim(generation, now)
                .await
                .map_err(RequestError::database)?;
                Self::finish_commit(&mut tx, claim).await
            })
            .await
    }

    /// One bounded attempt, useful for supervised operation and fixtures. The
    /// core owns recovery and every authoritative outcome. Any Err leaves the
    /// durable Running row available for locked receipt-first recovery.
    pub async fn run_job_once(
        &self,
    ) -> std::result::Result<Option<super::jobs::JobRunOutcome>, RequestError> {
        let jobs = self.jobs.as_ref().ok_or(RequestError::Rejected)?;
        let slot = Arc::new(
            jobs.workers
                .clone()
                .try_acquire_owned()
                .map_err(|_| RequestError::Busy)?,
        );
        let scope = self.request_scope(self.runtime.limits().wall_time);
        WORKER_SLOT
            .scope(
                slot,
                scope.run(async {
                    let Some(claim) = self.claim_job().await? else {
                        return Ok(None);
                    };
                    self.invoke_job(&claim).await.map(Some)
                }),
            )
            .await
    }

    pub(crate) fn start_job_service(self: &Arc<Self>) -> Result<Option<JobService>> {
        let Some(jobs) = &self.jobs else {
            return Ok(None);
        };
        ensure!(
            self.generation.get().is_some(),
            "application is not activated"
        );
        jobs.running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("job workers already running"))?;
        let (stop, stopping) = tokio::sync::watch::channel(false);
        let concurrency = jobs.effective.limits.worker_concurrency;
        let app = self.clone();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..concurrency {
                let app = app.clone();
                let mut stopping = stopping.clone();
                tasks.spawn(async move {
                    let mut polls = tokio::time::interval(std::time::Duration::from_secs(1));
                    polls.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tokio::select! { biased;
                            changed = stopping.changed() => { let _ = changed; return; }
                            _ = polls.tick() => {}
                        }
                        if *stopping.borrow() {
                            return;
                        }
                        // No payload, action error chain or principal enters logs.
                        // An uncertain outcome retains durable Running state.
                        let _ = app.run_job_once().await;
                    }
                });
            }
            let mut failed = false;
            while let Some(result) = tasks.join_next().await {
                failed |= result.is_err();
            }
            if failed {
                anyhow::bail!("job worker task failed; ownership quarantined");
            }
            app.jobs
                .as_ref()
                .expect("worker runtime")
                .running
                .store(false, Ordering::Release);
            Ok(())
        });
        Ok(Some(JobService {
            stop: Some(stop),
            task: Some(task),
        }))
    }
}

pub(crate) struct JobService {
    stop: Option<tokio::sync::watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl JobService {
    /// Waits for in-flight executor/provider cleanup. Shutdown does not cancel a
    /// transaction or infer termination from its lease or a timer.
    pub(crate) async fn shutdown(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        self.task.take().expect("job worker supervisor").await?
    }
}
impl Drop for JobService {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        // Only these <=2 already bounded workers may finish after owner drop.
        // They retain their AdmissionOwner and provider capacity until stopped.
    }
}
