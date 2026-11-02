//! Pure interpretation of an application contract: manifest admission, policy and
//! query planning, SQL text generation and identity values. Performs no I/O and
//! holds no authority; `noxide-host` enforces what this crate computes.
#![forbid(unsafe_code)]
pub use noxide_assets as assets;
pub mod action_contract;
pub mod expiry;
pub mod form_layout;
pub mod ids;
pub mod manifest;
pub mod membership;
pub mod policy;
pub mod presentation;
pub mod principal;
pub mod query_plan;
pub mod routing;
pub mod scalar;
pub mod schema;
pub mod search;
pub mod sql;
pub mod temporal;
pub use presentation::Presentation;
