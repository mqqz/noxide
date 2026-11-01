//! Attempt time and its failure modes, shared by pure lifecycle rules.
use noxide_protocol::time::Timestamp;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporalUnavailable {
    NotStarted,
    Stale,
    Inconsistent,
    Quarantined,
}
impl fmt::Display for TemporalUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotStarted => "lifecycle maintenance has not established freshness",
            Self::Stale => "lifecycle maintenance heartbeat is stale",
            Self::Inconsistent => "lifecycle clock regressed or observation is out of order",
            Self::Quarantined => "lifecycle maintenance cleanup is unconfirmed",
        })
    }
}
impl std::error::Error for TemporalUnavailable {}

/// Transaction-local lifecycle UTC milliseconds. Capture a new value for a new
/// attempt, keep this exact value through every operation within that attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptTime(Timestamp);
impl AttemptTime {
    /// Only the lifecycle clock, after its freshness checks, names attempt times.
    pub const fn from_durable(timestamp: Timestamp) -> Self {
        Self(timestamp)
    }
    pub const fn timestamp(self) -> Timestamp {
        self.0
    }
}
