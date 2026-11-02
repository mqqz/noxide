//! The storage calls a guest may make. Separate from the sandbox so storage code
//! can implement them without linking a guest runtime.
#![forbid(unsafe_code)]
use anyhow::Result;
use std::future::Future;

/// Storage authority a host grants to one guest attempt. The sandbox only routes
/// calls; authorization remains the implementor's, enforced outside the guest.
pub trait HostCalls: Send + 'static {
    /// Whether this attempt is in a phase that may import storage.
    fn storage_allowed(&self) -> bool;
    fn invoke(
        &mut self,
        operation: u32,
        target: u64,
    ) -> impl Future<Output = Result<Vec<u8>>> + Send;
    fn follow_source(&mut self, resource: u32, id: u64) -> Result<()>;
    fn follow(&mut self, operation: u32) -> impl Future<Output = Result<Vec<u8>>> + Send;
}

/// The grant of a guest with no storage authority. It has no values, so such a
/// runtime cannot carry a repository at all.
pub enum NoHostCalls {}
impl HostCalls for NoHostCalls {
    fn storage_allowed(&self) -> bool {
        match *self {}
    }
    async fn invoke(&mut self, _: u32, _: u64) -> Result<Vec<u8>> {
        match *self {}
    }
    fn follow_source(&mut self, _: u32, _: u64) -> Result<()> {
        match *self {}
    }
    async fn follow(&mut self, _: u32) -> Result<Vec<u8>> {
        match *self {}
    }
}
