//! Test-only fault points that wrap actual provider effects and COMMITs. Compiled
//! only with `test-support`, which no deployed binary enables; an application
//! cannot select them.
#![allow(clippy::new_without_default)]
use crate::database::Transaction;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
pub struct Aborted;
impl std::fmt::Display for Aborted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("injected known-aborted conflict")
    }
}
impl std::error::Error for Aborted {}

#[derive(Clone, Copy, PartialEq)]
pub enum Point {
    Effect,
    Commit,
}
#[derive(Clone, Copy)]
pub enum Mode {
    Abort,
    LoseAck,
    Pause,
    Wait,
}
pub struct Plan {
    pub point: Point,
    pub mode: Mode,
    pub remaining: AtomicUsize,
    pub hits: AtomicUsize,
    pub marker: Option<std::path::PathBuf>,
    pub reached: tokio::sync::Notify,
    pub resume: tokio::sync::Notify,
}
tokio::task_local! {pub static FAULT:Arc<Plan>;}
pub fn plan(point: Point, mode: Mode, remaining: usize) -> Arc<Plan> {
    Arc::new(Plan {
        point,
        mode,
        remaining: AtomicUsize::new(remaining),
        hits: AtomicUsize::new(0),
        marker: None,
        reached: tokio::sync::Notify::new(),
        resume: tokio::sync::Notify::new(),
    })
}
pub fn hit(point: Point) -> Option<Arc<Plan>> {
    FAULT
        .try_with(|plan| {
            if plan.point != point {
                return None;
            }
            plan.hits.fetch_add(1, Ordering::SeqCst);
            plan.remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .ok()
                .map(|_| plan.clone())
        })
        .ok()
        .flatten()
}
pub async fn pause(plan: &Plan) {
    if let Some(path) = &plan.marker {
        std::fs::write(path, b"at fault boundary").unwrap();
    }
    std::future::pending::<()>().await;
}
pub async fn after_effect(tx: &mut Transaction) -> anyhow::Result<()> {
    if let Some(plan) = hit(Point::Effect) {
        match plan.mode {
            Mode::Abort => {
                tx.rollback().await?;
                return Err(Aborted.into());
            }
            Mode::Pause => pause(&plan).await,
            Mode::Wait => {
                plan.reached.notify_one();
                plan.resume.notified().await;
            }
            Mode::LoseAck => unreachable!(),
        }
    }
    Ok(())
}

/// Opaque test fault context explicitly propagated into spawned worker tasks.
/// This module is absent from production artifacts; it conveys no authority.
#[derive(Clone)]
pub struct FaultContext(Option<Arc<Plan>>);
pub fn capture_context() -> FaultContext {
    FaultContext(FAULT.try_with(Clone::clone).ok())
}
pub async fn with_context<T>(
    context: FaultContext,
    future: impl std::future::Future<Output = T>,
) -> T {
    match context.0 {
        Some(plan) => FAULT.scope(plan, future).await,
        None => future.await,
    }
}

/// Acknowledges the existing after-effect boundary while its real transaction
/// remains open, then waits for explicit release by the test.
pub struct EffectWait(Arc<Plan>);
impl EffectWait {
    pub fn new() -> Self {
        Self(plan(Point::Effect, Mode::Wait, 1))
    }
    pub async fn scope<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        FAULT.scope(self.0.clone(), future).await
    }
    pub async fn wait_reached(&self) {
        self.0.reached.notified().await;
    }
    pub fn resume(&self) {
        self.0.resume.notify_one();
    }
}
pub async fn known_conflict_once<T>(future: impl std::future::Future<Output = T>) -> T {
    FAULT
        .scope(plan(Point::Effect, Mode::Abort, 1), future)
        .await
}

pub async fn known_conflicts<T>(count: usize, future: impl std::future::Future<Output = T>) -> T {
    FAULT
        .scope(plan(Point::Effect, Mode::Abort, count), future)
        .await
}
pub async fn lose_commit_ack<T>(future: impl std::future::Future<Output = T>) -> T {
    FAULT
        .scope(plan(Point::Commit, Mode::LoseAck, 1), future)
        .await
}

pub async fn after_commit() -> anyhow::Result<()> {
    if let Some(plan) = hit(Point::Commit) {
        match plan.mode {
            Mode::LoseAck => anyhow::bail!("commit acknowledgement lost"),
            Mode::Pause => pause(&plan).await,
            Mode::Wait => plan.resume.notified().await,
            Mode::Abort => unreachable!(),
        }
    }
    Ok(())
}
