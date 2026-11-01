//! Identity, credentials and request authority: accounts, roles, tokens, admission
//! limits and the per-attempt policy context. Key bytes stay in `noxide-keys`.
#![forbid(unsafe_code)]
pub mod auth;
pub mod authority;
pub mod limiter;
pub mod operator_roles;
pub mod security;
pub(crate) use noxide_admission::{expiry, ids, manifest, membership, policy, principal, sql};
pub(crate) use noxide_store::{Database, database, lifecycle_clock};
