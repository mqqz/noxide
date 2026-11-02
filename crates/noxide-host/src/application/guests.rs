//! Where guest code runs. A deployment uses worker processes, so the server links no
//! guest runtime. Some commands never run guest code at all. Tests may run it in
//! process, which keeps them fast and is otherwise unavailable.
use super::Effects;
use noxide_guest::{Attempt, GuestBusy, Limits, pool::GuestPool};
use noxide_protocol::RequestView;
use std::sync::Arc;
use tokio::time::Instant;

pub(super) struct Guests {
    limits: Limits,
    runner: Runner,
}

enum Runner {
    None,
    Workers(Arc<GuestPool>),
    #[cfg(any(test, feature = "test-support"))]
    InProcess(noxide_sandbox::Runtime<Effects>),
}

impl Guests {
    pub(super) fn none(limits: Limits) -> Self {
        Self {
            limits,
            runner: Runner::None,
        }
    }

    pub(super) fn workers(pool: Arc<GuestPool>) -> Self {
        Self {
            limits: pool.limits().clone(),
            runner: Runner::Workers(pool),
        }
    }

    /// Compilation is also this path's admission check; for workers, the first
    /// worker's compile is.
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn in_process(component: &[u8], limits: Limits) -> anyhow::Result<Self> {
        Ok(Self {
            limits: limits.clone(),
            runner: Runner::InProcess(noxide_sandbox::Runtime::compile(component, limits)?),
        })
    }

    pub(super) fn limits(&self) -> &Limits {
        &self.limits
    }

    pub(super) async fn run(
        &self,
        request: RequestView,
        effects: Option<Effects>,
        fuel: u64,
        calls: u32,
        deadline: Instant,
    ) -> Attempt<Effects> {
        match &self.runner {
            Runner::None => Attempt {
                result: Err(GuestBusy::Capacity.into()),
                effects,
                fuel_left: fuel,
                calls_left: calls,
            },
            Runner::Workers(pool) => pool.run(request, effects, fuel, calls, deadline).await,
            #[cfg(any(test, feature = "test-support"))]
            Runner::InProcess(runtime) => {
                runtime.run(request, effects, fuel, calls, deadline).await
            }
        }
    }
}
