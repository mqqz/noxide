//! Lifecycle time has millisecond precision. Credential time remains in seconds.
//!
//! These values describe UTC lifecycle state, never execution deadlines. Hosts
//! use a monotonic clock for deadlines and admit feature-specific duration bounds.
use serde::{Deserialize, Serialize};
use std::{fmt, time::SystemTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeError {
    Negative,
    Overflow,
    BeforeEpoch,
    PrecisionLoss,
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Negative => "lifecycle time cannot be negative",
            Self::Overflow => "lifecycle time overflow",
            Self::BeforeEpoch => "wall clock precedes Unix epoch",
            Self::PrecisionLoss => "duration must have whole millisecond precision",
        })
    }
}
impl std::error::Error for TimeError {}

/// UTC milliseconds since the Unix epoch, in the host's signed storage range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct Timestamp(i64);

/// A nonnegative number of whole milliseconds. Feature admission imposes the
/// applicable horizon; this type only enforces representation and arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct Duration(i64);

impl Timestamp {
    pub const UNIX_EPOCH: Self = Self(0);

    pub fn from_unix_millis(value: i64) -> Result<Self, TimeError> {
        Self::try_from(value)
    }

    /// Named boundary for the existing seconds-based credential clock.
    pub fn from_unix_seconds(value: i64) -> Result<Self, TimeError> {
        if value < 0 {
            return Err(TimeError::Negative);
        }
        Self::try_from(value.checked_mul(1_000).ok_or(TimeError::Overflow)?)
    }

    /// Sample trusted wall time, flooring its sub-millisecond fraction exactly
    /// once. No request may substitute this value for the durable watermark.
    pub fn from_system_time(value: SystemTime) -> Result<Self, TimeError> {
        let millis = value
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| TimeError::BeforeEpoch)?
            .as_millis();
        Self::try_from(i64::try_from(millis).map_err(|_| TimeError::Overflow)?)
    }

    pub const fn unix_millis(self) -> i64 {
        self.0
    }

    /// Credentials intentionally retain whole seconds and their old wire format.
    pub const fn unix_seconds_floor(self) -> i64 {
        self.0 / 1_000
    }

    pub fn checked_add(self, duration: Duration) -> Result<Self, TimeError> {
        Self::try_from(self.0.checked_add(duration.0).ok_or(TimeError::Overflow)?)
    }

    pub fn checked_sub(self, duration: Duration) -> Result<Self, TimeError> {
        Self::try_from(self.0.checked_sub(duration.0).ok_or(TimeError::Overflow)?)
    }

    pub fn duration_since(self, earlier: Self) -> Result<Duration, TimeError> {
        Duration::try_from(self.0.checked_sub(earlier.0).ok_or(TimeError::Overflow)?)
    }
}

impl Duration {
    pub const ZERO: Self = Self(0);

    pub fn from_millis(value: i64) -> Result<Self, TimeError> {
        Self::try_from(value)
    }

    pub fn from_secs(value: i64) -> Result<Self, TimeError> {
        if value < 0 {
            return Err(TimeError::Negative);
        }
        Self::try_from(value.checked_mul(1_000).ok_or(TimeError::Overflow)?)
    }

    pub const fn as_millis(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for Timestamp {
    type Error = TimeError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if value < 0 {
            Err(TimeError::Negative)
        } else {
            Ok(Self(value))
        }
    }
}
impl From<Timestamp> for i64 {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}
impl TryFrom<i64> for Duration {
    type Error = TimeError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if value < 0 {
            Err(TimeError::Negative)
        } else {
            Ok(Self(value))
        }
    }
}
impl From<Duration> for i64 {
    fn from(value: Duration) -> Self {
        value.0
    }
}
impl TryFrom<std::time::Duration> for Duration {
    type Error = TimeError;
    fn try_from(value: std::time::Duration) -> Result<Self, Self::Error> {
        if value.subsec_nanos() % 1_000_000 != 0 {
            return Err(TimeError::PrecisionLoss);
        }
        Self::try_from(i64::try_from(value.as_millis()).map_err(|_| TimeError::Overflow)?)
    }
}
impl From<Duration> for std::time::Duration {
    fn from(value: Duration) -> Self {
        Self::from_millis(value.0 as u64)
    }
}
