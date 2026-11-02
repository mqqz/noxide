//! The store: connections, transactions, schema activation, storage layout, the
//! request lifecycle and durable time. The only crate that links a database driver.
#![cfg_attr(
    not(feature = "test-support"),
    doc = "```compile_fail
async fn raw(tx: &mut noxide_store::database::Transaction) {
    tx.execute(\"DELETE FROM nx_sessions\", &[]).await.unwrap();
}
```"
)]
//!
//! Outside the store, `Statement` cannot be constructed either:
//!
//! ```compile_fail
//! use noxide_store::statements::Statement;
//! const FORGED: Statement<0, 0> = Statement::new("DELETE FROM nx_sessions");
//! ```
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
