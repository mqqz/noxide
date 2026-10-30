//! Typed guest API for isolated Noxide applications.
//!
//! Build application code only through the isolated build workflow.

pub use noxide_protocol::{
    Container, Document, Fields, Instruction, Record, RequestKind, RequestView, ResponseIntent,
    RouteRef,
};

pub trait Handler {
    fn handle(request: RequestView, context: &mut Context) -> ResponseIntent;
}
pub struct Context {
    _private: (),
}

impl Context {
    pub fn list(&mut self, operation: u32) -> Vec<Record> {
        self.invoke(operation, 0)
    }
    pub fn read(&mut self, operation: u32, id: u64) -> Option<Record> {
        self.invoke(operation, id)
    }
    #[cfg(target_arch = "wasm32")]
    fn follow(&mut self, operation: u32, sources: &[(u32, u64)]) -> Vec<Option<Record>> {
        use bindings::noxide::application::host;
        for &(resource, id) in sources {
            host::follow_source(resource, id);
        }
        let len = host::follow(operation);
        let bytes = read_buffer(len, host::result_chunk);
        serde_json::from_slice(&bytes).expect("host follow contract")
    }
    #[cfg(not(target_arch = "wasm32"))]
    fn follow(&mut self, _operation: u32, _sources: &[(u32, u64)]) -> Vec<Option<Record>> {
        panic!("Noxide applications execute as isolated WebAssembly components")
    }
    /// Creates exactly the fields validated for the submitted action. The guest
    /// cannot substitute ownership, a different input, or an unrelated target.
    pub fn create(&mut self, operation: u32) -> Record {
        self.invoke(operation, 0)
    }

    /// Updates the action's bound target with its validated field projection.
    pub fn update(&mut self, operation: u32) -> ResponseIntent {
        self.invoke(operation, 0)
    }

    /// Deletes the action's bound target and returns its semantic outcome.
    pub fn delete(&mut self, operation: u32) -> ResponseIntent {
        self.invoke(operation, 0)
    }

    #[cfg(target_arch = "wasm32")]
    fn invoke<T: serde::de::DeserializeOwned>(&mut self, operation: u32, target: u64) -> T {
        let len = bindings::noxide::application::host::invoke(operation, target);
        let bytes = read_buffer(len, bindings::noxide::application::host::result_chunk);
        serde_json::from_slice(&bytes).expect("host repository contract")
    }
    #[cfg(not(target_arch = "wasm32"))]
    fn invoke<T: serde::de::DeserializeOwned>(&mut self, _operation: u32, _target: u64) -> T {
        panic!("Noxide applications execute as isolated WebAssembly components")
    }
}

#[cfg(target_arch = "wasm32")]
fn read_buffer(length: u32, read: impl Fn(u32) -> u64) -> Vec<u8> {
    assert!(length as usize <= noxide_protocol::MAX_RESULT_BYTES);
    let mut bytes = Vec::with_capacity(length as usize);
    for offset in (0..length).step_by(8) {
        let word = read(offset).to_le_bytes();
        let count = (length - offset).min(8) as usize;
        bytes.extend_from_slice(&word[..count]);
    }
    bytes
}

#[doc(hidden)]
#[cfg(target_arch = "wasm32")]
pub mod bindings {
    wit_bindgen::generate!({path:"wit",world:"application",pub_export_macro:true});
}

#[doc(hidden)]
#[cfg(target_arch = "wasm32")]
pub fn run<H: Handler>() {
    use bindings::noxide::application::host;
    let bytes = read_buffer(host::request_length(), host::request_chunk);
    let request = serde_json::from_slice(&bytes).expect("host request contract");
    let response = H::handle(request, &mut Context { _private: () });
    let output = serde_json::to_vec(&response).expect("document encoding");
    assert!(output.len() <= noxide_protocol::MAX_IR_BYTES);
    for chunk in output.chunks(8) {
        let mut word = [0; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        host::emit(u64::from_le_bytes(word), chunk.len() as u32);
    }
}

/// Export one handler through the fixed Noxide component world.
#[macro_export]
macro_rules! export {
    ($handler:ty) => {
        #[cfg(target_arch = "wasm32")]
        const _: () = {
            struct NoxideGuest;
            impl $crate::bindings::Guest for NoxideGuest {
                fn handle() {
                    $crate::run::<$handler>();
                }
            }
    $crate::bindings::export!(NoxideGuest with_types_in $crate::bindings);
        };
    };
}

mod typed;
pub use noxide_macros::{Choice, Resource, action, app, application, form, html, page, query};
pub use noxide_protocol::{ChoiceVariant, Control, FieldKind, FormInstruction};
pub use typed::*;
#[doc(hidden)]
pub mod __private {
    pub use noxide_protocol::*;
}

/// Common application declarations, capabilities, and rendering types.
pub mod prelude {
    pub use crate::{
        AccountId, ActionError, ActionResult, Choice, Form, FormFields, FormLayout, Fragment, Id,
        NotFound, Page, PageResult, Query, Resource, Submission, action, app, application, form,
        html, page, query,
    };
}
