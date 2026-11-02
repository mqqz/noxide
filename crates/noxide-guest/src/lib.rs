//! Guest execution shared by the sandbox and by a server using worker processes.
//! This crate links no guest runtime, so the server can avoid one.
#![cfg_attr(test, allow(clippy::too_many_lines))]
#![forbid(unsafe_code)]
pub mod broker;
pub mod pool;
pub mod wire;

use anyhow::Result;
use noxide_protocol::ResponseIntent;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Limits {
    pub memory_bytes: usize,
    pub fuel: u64,
    pub host_calls: u32,
    pub wall_time: Duration,
    pub concurrency: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            memory_bytes: 64 * 1024 * 1024,
            fuel: 10_000_000,
            host_calls: 32_768,
            wall_time: Duration::from_secs(2),
            concurrency: 16,
        }
    }
}

/// The guest stopped for lack of time or capacity, not because of what it did. The
/// same request can succeed later, so callers report busy and not a rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestBusy {
    Deadline,
    Capacity,
}
impl std::fmt::Display for GuestBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Deadline => "guest deadline",
            Self::Capacity => "runtime capacity",
        })
    }
}
impl std::error::Error for GuestBusy {}

pub struct Attempt<H> {
    pub result: Result<ResponseIntent>,
    pub effects: Option<H>,
    pub fuel_left: u64,
    pub calls_left: u32,
}
