//! Trusted execution, rendering, and persistence for Noxide applications.
mod database;
pub mod manifest;
pub mod render;
pub mod runtime;
pub use database::Database;
mod auth;
mod security;
pub use security::HostKeys;
mod application;
mod repository;
pub use application::{Application, LoginChallenge, RequestError};
pub mod http;

#[cfg(test)]
mod failure_tests;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
