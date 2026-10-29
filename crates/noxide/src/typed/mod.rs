//! Typed declarations and composition for guest applications.
use noxide_protocol::{Action, FormInstruction, Manifest, Operation, Resource, Route, VERSION};
use std::collections::BTreeMap;
mod resource;
pub use resource::*;
mod query;
pub use query::*;
mod action;
pub use action::*;
mod form;
pub use form::*;
mod page;
pub use page::*;
/// Untrusted build metadata; the trusted host independently admits its output.
#[doc(hidden)]
#[derive(Default)]
pub struct ApplicationDefinition {
    resources: BTreeMap<String, Resource>,
    operations: BTreeMap<u32, Operation>,
    routes: BTreeMap<u32, Route>,
    actions: BTreeMap<u32, Action>,
}
impl ApplicationDefinition {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn resource(&mut self, resource: Resource) {
        if let Some(old) = self
            .resources
            .insert(resource.name.clone(), resource.clone())
        {
            assert_eq!(old, resource, "conflicting resource declarations");
        }
    }
    pub fn operation(&mut self, operation: Operation) {
        if let Some(old) = self.operations.insert(operation.id, operation.clone()) {
            assert_eq!(old, operation, "operation ID collision");
        }
    }
    pub fn page(&mut self, route: Route) {
        assert!(
            self.routes.insert(route.id, route).is_none(),
            "duplicate page"
        );
    }
    pub fn action(&mut self, action: Action) {
        assert!(
            self.actions.insert(action.id, action).is_none(),
            "duplicate action"
        );
    }
    pub fn layout(&mut self, id: u32, layout: Vec<FormInstruction>) {
        self.actions
            .get_mut(&id)
            .expect("layout action must be registered")
            .layout = layout;
    }
    pub fn manifest(self) -> Manifest {
        Manifest {
            version: VERSION,
            resources: self.resources.into_values().collect(),
            operations: self.operations.into_values().collect(),
            routes: self.routes.into_values().collect(),
            actions: self.actions.into_values().collect(),
        }
    }
    pub fn json(self) -> String {
        serde_json::to_string(&self.manifest()).expect("manifest encoding")
    }
}
