//! The blob directory and blob metadata. The only crate that opens stored objects;
//! every object operation is descriptor-relative and bounded by an I/O pool.
#![forbid(unsafe_code)]
pub mod blob_deployment;
pub mod inspect;
pub mod io;
pub mod metadata;
pub mod multipart;
pub mod runtime;
pub mod state;
pub mod store;
pub mod transport;
pub mod upload;
pub(crate) use noxide_admission::action_contract;
pub(crate) use noxide_store::{database, lifecycle_clock};
