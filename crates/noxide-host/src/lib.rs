//! Trusted execution, rendering, and persistence for Noxide applications.
mod database;
pub mod manifest;
pub mod render;
pub mod runtime;
pub mod schema;
pub use database::Database;
mod auth;
mod operator_roles;
pub use auth::{Registration, account_id};
pub use operator_roles::{RoleAssignment, RoleScope};
mod security;
pub use security::HostKeys;
mod application;
mod repository;
pub use application::{Application, LoginChallenge, RequestError};
pub mod http;

#[cfg(test)]
mod failure_tests;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

mod presentation;
pub use presentation::Presentation;

#[cfg(test)]
mod public_tests;

#[cfg(test)]
mod anonymous_tests;

#[cfg(test)]
mod registration_tests;

mod form_layout;
mod policy;
mod routing;

#[cfg(test)]
mod parent_tests;

#[cfg(test)]
mod account_tests;

#[cfg(test)]
async fn test_account(db: &Database, login: &str) -> String {
    db.account_id(login)
        .await
        .unwrap_or_else(|_| "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into())
}

mod query_plan;

#[cfg(test)]
mod parameter_tests;
