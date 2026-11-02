//! Application behaviour observed through real HTTP. These live here because the
//! engine cannot depend on the transport it serves.
mod blobs;
mod clock;
mod persistence;
mod targets;

mod prelude {
    pub(super) use crate::{
        Application, Database, HostKeys, RequestError, manifest, runtime::Limits, security,
    };
    pub(super) use noxide_protocol::{blobs::*, *};
    pub(super) use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
}
