//! Record reads and writes for one request attempt. Every operation is checked
//! against host policy here; guest code reaches it only through the application.
#![cfg_attr(test, allow(clippy::too_many_lines))]
#![forbid(unsafe_code)]
pub(crate) use noxide_admission::{
    action_contract, expiry, manifest, membership, policy, query_plan, routing, search, sql,
};
pub(crate) use noxide_authority::{auth, authority, security};
#[cfg(test)]
pub(crate) use noxide_store::Database;
pub(crate) use noxide_store::{database, lifecycle_clock};
#[cfg(test)]
use noxide_test_support as test_support;
pub mod repository;
