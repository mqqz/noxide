//! Durable, explicitly approved outbound effects. The transport is never called
//! in an action or database transaction; receiver keys survive every retry.
mod operator;
pub(crate) mod owner;
mod store;
pub(crate) mod transport;
mod types;
pub(crate) mod worker;
pub use operator::{EffectOperatorCommand, EffectOperatorResult, EffectSummary};
pub(crate) use store::{DeliveryResult, EffectClaim, Finalized, OutboxContext, Preflight};
pub(crate) use types::{CapturedEffect, EffectScope};
#[cfg(test)]
mod tests;
