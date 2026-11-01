//! Approved effects as data: deployment approval, the outbox and operator commands.
//! Links no TLS client and opens no outbound socket; delivery is a separate crate
//! that the serving process does not depend on.
#![forbid(unsafe_code)]
pub mod directory;
pub mod effect_deployment;
pub mod operator;
pub mod store;
pub mod transport;
pub mod types;
pub use noxide_admission::{ids, query_plan, sql};
pub use noxide_store::database;
pub use operator::{
    EffectOperatorCommand, EffectOperatorResult, EffectOperatorTransaction, EffectSummary,
};
pub use store::{DeliveryResult, EffectClaim, Finalized, OutboxContext, Preflight};
pub use types::{CapturedEffect, EffectScope};
