//! The worker only claims and dispatches to the common action executor. It never
//! finalizes a queue attempt from an error or supplies a browser/user identity.
use super::*;
use crate::{
    job_deployment::EffectiveJobDeployment,
    jobs::{Claim, QueueContext},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct WorkerSlot {
    owner: Arc<Semaphore>,
    permit: Arc<OwnedSemaphorePermit>,
}
tokio::task_local! { static WORKER_SLOT: WorkerSlot; }

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
    /// Trusted local operator control. Choices must remain within the current
    /// approved configuration; this entry point is never registered as HTTP.
    pub async fn operate_jobs(
        &self,
        command: crate::jobs::JobOperatorCommand,
    ) -> std::result::Result<crate::jobs::JobOperatorResult, RequestError> {
        use crate::jobs::{JobOperatorCommand as Command, JobOperatorResult as Output};
        let scope = self.request_scope(self.runtime.limits().wall_time);
        scope
            .run(async {
                let admission = self.admit_invocation(false).await?;
                admission
                    .owner
                    .run(async {
                        let mut tx = self
                            .database
                            .begin(admission.owner.work_deadline().into_std())
                            .await
                            .map_err(RequestError::database)?;
                        let time = self.temporal_attempt(&mut tx).await?;
                        let generation = self.generation.get().ok_or(RequestError::Busy)?;
                        let output = match command {
                            Command::Inspect { after } => Output::Jobs(
                                tx.inspect_jobs(generation, &after)
                                    .await
                                    .map_err(RequestError::database)?,
                            ),
                            Command::Cancel { id } => {
                                tx.cancel_job(generation, &id)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::Revoke { tenant, worker } => {
                                tx.revoke_job_grant(generation, &tenant, &worker)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::Grant { tenant, worker } => {
                                let configured = self
                                    .jobs
                                    .as_ref()
                                    .ok_or(RequestError::Rejected)?
                                    .effective
                                    .grants
                                    .iter()
                                    .find(|grant| {
                                        grant.tenant == tenant && grant.worker.name == worker
                                    })
                                    .ok_or(RequestError::Rejected)?;
                                tx.grant_job_service(
                                    generation,
                                    &self.contract,
                                    configured,
                                    self.manifest.jobs.as_ref().ok_or(RequestError::Rejected)?,
                                )
                                .await
                                .map_err(RequestError::database)?;
                                let recurring_resumed = self
                                    .manifest
                                    .jobs
                                    .as_ref()
                                    .ok_or(RequestError::Rejected)?
                                    .recurring
                                    .iter()
                                    .filter(|schedule| {
                                        schedule.worker == configured.worker.name
                                            && configured
                                                .worker
                                                .actions
                                                .iter()
                                                .any(|action| action.action == schedule.action)
                                    })
                                    .count();
                                Output::Granted { recurring_resumed }
                            }
                            Command::Fork => {
                                tx.fork_job_runtime(generation)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::Reconcile { id } => {
                                let jobs = self.jobs.as_ref().ok_or(RequestError::Rejected)?;
                                let previous = tx
                                    .reconciliation_source(generation, &id)
                                    .await
                                    .map_err(RequestError::database)?;
                                let mut calls = 16;
                                let proof = QueueContext {
                                    tx: &mut tx,
                                    calls: &mut calls,
                                }
                                .schedule_grant(
                                    &crate::jobs::JobScope {
                                        deployment: generation.clone(),
                                        tenant: previous.scope().tenant.clone(),
                                    },
                                    previous.worker(),
                                    &self.contract,
                                )
                                .await
                                .map_err(RequestError::database)?;
                                let input = self
                                    .canonical_job_input(previous.action().0, previous.input())
                                    .map_err(RequestError::database)?;
                                let targets = self
                                    .seal_job_targets(
                                        &mut tx,
                                        &proof,
                                        previous.action().0,
                                        previous.targets(),
                                        time,
                                        &mut calls,
                                    )
                                    .await
                                    .map_err(RequestError::database)?;
                                let action = manifest::action(&self.manifest, previous.action().0)
                                    .map_err(RequestError::database)?;
                                let id = QueueContext {
                                    tx: &mut tx,
                                    calls: &mut calls,
                                }
                                .enqueue_reconciled(
                                    &previous,
                                    &proof,
                                    action.version,
                                    time.timestamp(),
                                    input,
                                    targets,
                                    jobs.effective.limits.pending_per_tenant,
                                )
                                .await
                                .map_err(RequestError::database)?;
                                Output::Reconciled { id }
                            }
                        };
                        Self::finish_commit(&mut tx, output).await
                    })
                    .await
            })
            .await
    }
    /// Both the worker and service adapter use this dedicated lane. The request
    /// permit is retained by AdmissionOwner through actual provider cleanup;
    /// timing out or dropping a caller cannot prematurely release worker capacity.
    pub(super) async fn admit_job_invocation_work(
        &self,
    ) -> std::result::Result<action::InvocationAdmission, RequestError> {
        let jobs = self.jobs.as_ref().ok_or(RequestError::Rejected)?;
        let request = WORKER_SLOT
            .try_with(|slot| Arc::ptr_eq(&slot.owner, &jobs.workers).then(|| slot.permit.clone()))
            .ok()
            .flatten()
            .map_or_else(
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

    /// One due schedule and one bounded query frontier. Oldest due time gives
    /// other tenants/schedules a turn after each committed batch.
    pub(crate) async fn run_recurrence_once(&self) -> std::result::Result<(), RequestError> {
        let Some(jobs) = &self.jobs else {
            return Ok(());
        };
        if self
            .manifest
            .jobs
            .as_ref()
            .is_none_or(|contract| contract.recurring.is_empty())
        {
            return Ok(());
        }
        let scope = self.request_scope(self.runtime.limits().wall_time);
        scope.run(async {
            let admission = self.admit_job_invocation_work().await?;
            admission.owner.run(async {
                let mut tx = self.database.begin(admission.owner.work_deadline().into_std()).await.map_err(RequestError::database)?;
                let time = self.temporal_attempt(&mut tx).await?;
                let generation = self.generation.get().ok_or(RequestError::Busy)?;
                let rows = tx.fetch::<2>("SELECT tenant,name FROM nx_job_recurring WHERE deployment=$1 AND state='active' AND next_ms<=$2 ORDER BY next_ms,tenant,name LIMIT 1", &[generation.as_str().into(), time.timestamp().unix_millis().into()]).await.map_err(RequestError::database)?;
                let Some([tenant, name]) = rows.first() else { return Self::finish_commit(&mut tx, ()).await };
                let declaration = self.manifest.jobs.as_ref().and_then(|contract| contract.recurring.iter().find(|schedule| schedule.name == *name)).ok_or(RequestError::Rejected)?;
                let scope = crate::jobs::JobScope { deployment: generation.clone(), tenant: tenant.clone() };
                let mut calls = 15;
                let proof = QueueContext { tx: &mut tx, calls: &mut calls }.schedule_grant(&scope, &declaration.worker, &self.contract).await.map_err(RequestError::database)?;
                let Some(mut batch) = (QueueContext { tx: &mut tx, calls: &mut calls }).begin_recurrence(&scope, declaration, time.timestamp()).await.map_err(RequestError::database)? else { return Self::finish_commit(&mut tx, ()).await };
                let input = declaration.inputs.iter().map(|(name, literal)| {
                    use noxide_protocol::computation::Literal;
                    let value = match literal {
                        Literal::Text(v) | Literal::Choice(v) | Literal::Account(v) => v.clone(),
                        Literal::Integer(v) => v.to_string(), Literal::Boolean(v) => v.to_string(),
                        Literal::Timestamp(v) => v.unix_millis().to_string(), Literal::Duration(v) => v.as_millis().to_string(),
                    };
                    (name.clone(), value)
                }).collect();
                let input = self.canonical_job_input(declaration.action, &input).map_err(RequestError::database)?;
                let version = manifest::action(&self.manifest, declaration.action).map_err(RequestError::database)?.version;
                let next = if let Some(selection) = &declaration.selection {
                    // Query/finalization reserves remain in the existing budget;
                    // fanout 20 never grants twenty additional database calls.
                    let limit = batch.remaining();
                    let page = self.select_recurring(&mut tx, &proof, declaration, time, batch.cutoff(), batch.cutoff_seq().try_into().map_err(|_| RequestError::Rejected)?, batch.cursor(), limit, &mut calls).await.map_err(RequestError::database)?;
                    for item in page.items {
                        // Q returns an independently List-authorized row sealed
                        // through A's current eligible-read helper. Reauthorizing
                        // it here would spend the same budget twice.
                        let targets = BTreeMap::from([(selection.target.clone(), item.target)]);
                        QueueContext { tx: &mut tx, calls: &mut calls }.emit_recurrence(&mut batch, version, input.clone(), targets, item.expiry, jobs.effective.limits.pending_per_tenant).await.map_err(RequestError::database)?;
                    }
                    page.next_cursor
                } else {
                    QueueContext { tx: &mut tx, calls: &mut calls }.emit_recurrence(&mut batch, version, input, BTreeMap::new(), None, jobs.effective.limits.pending_per_tenant).await.map_err(RequestError::database)?;
                    None
                };
                QueueContext { tx: &mut tx, calls: &mut calls }.finish_recurrence(batch, next.as_deref()).await.map_err(RequestError::database)?;
                Self::finish_commit(&mut tx, ()).await
            }).await
        }).await
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
                WorkerSlot {
                    owner: jobs.workers.clone(),
                    permit: slot,
                },
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
                        let _ = app.run_recurrence_once().await;
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

#[cfg(test)]
mod tests;
