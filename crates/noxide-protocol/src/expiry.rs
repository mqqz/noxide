//! Operator-approved lifecycle visibility and write horizon.
use crate::time::Duration;
use serde::{Deserialize, Serialize};

pub const MAX_EXPIRY_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceExpiry {
    pub field: String,
    pub max_after: Duration,
}
