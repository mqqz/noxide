//! Durable, explicitly approved outbound effects. The transport is never called
//! in an action or database transaction; receiver keys survive every retry.
pub(crate) mod transport;
mod types;
pub(crate) use types::{CapturedEffect, EffectScope, VerifiedEndpointGrant};
