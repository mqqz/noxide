//! The store: connections, transactions, schema activation, storage layout, the
//! request lifecycle and durable time. The only crate that links a database driver.
#![cfg_attr(not(feature = "query-metrics"), forbid(unsafe_code))]
pub mod database;
pub mod lifecycle_clock;
pub mod statements;
pub use database::{Database, SidecarHold, StoreResources};
pub(crate) use noxide_admission::{
    ids, manifest, membership, policy, query_plan, schema, search, sql, temporal,
};
#[cfg(test)]
use noxide_test_support as test_support;
