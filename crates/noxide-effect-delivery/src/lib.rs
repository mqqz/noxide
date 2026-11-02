//! Effect delivery: outbox worker, Tor SOCKS client and TLS transport. Only the
//! worker process links this crate.
#![cfg_attr(test, allow(clippy::too_many_lines))]
#![forbid(unsafe_code)]
mod delivery;
pub mod owner;
pub mod transport;
pub mod worker;
pub use delivery::{
    DeliveryRuntime, EffectDelivery, EffectRunOutcome, EffectService, POSTGRES_WORKER_GRANTS,
};
