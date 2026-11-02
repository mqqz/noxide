//! Where guest code runs. In process by default; a deployment can move it to worker
//! processes, which changes nothing the application can observe but its failures.
use super::Effects;
use noxide_guest::{Attempt, Limits, pool::GuestPool};
use noxide_protocol::RequestView;
use noxide_sandbox::Runtime;
use std::sync::Arc;
use tokio::time::Instant;

pub(super) enum Guests {
    InProcess(Runtime<Effects>),
    Workers(Arc<GuestPool>),
}

impl Guests {
    pub(super) fn limits(&self) -> &Limits {
        match self {
            Self::InProcess(runtime) => runtime.limits(),
            Self::Workers(pool) => pool.limits(),
        }
    }

    pub(super) async fn run(
        &self,
        request: RequestView,
        effects: Option<Effects>,
        fuel: u64,
        calls: u32,
        deadline: Instant,
    ) -> Attempt<Effects> {
        match self {
            Self::InProcess(runtime) => runtime.run(request, effects, fuel, calls, deadline).await,
            Self::Workers(pool) => pool.run(request, effects, fuel, calls, deadline).await,
        }
    }
}
