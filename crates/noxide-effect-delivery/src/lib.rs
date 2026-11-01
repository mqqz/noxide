//! Effect delivery: outbox worker, Tor SOCKS client and TLS transport. Only the
//! worker process links this crate.
#![forbid(unsafe_code)]
mod delivery;
pub mod owner;
pub mod transport;
pub mod worker;
pub use delivery::{
    DeliveryRuntime, EffectDelivery, EffectRunOutcome, EffectService, POSTGRES_WORKER_GRANTS,
};
