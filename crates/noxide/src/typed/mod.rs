//! Typed declarations and composition for guest applications.
use noxide_protocol::{
    Action, FormInstruction, Manifest, Operation, Resource, Route, VERSION, WebBinding,
};
use std::collections::{BTreeMap, BTreeSet};
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
    web_bindings: BTreeMap<u32, WebBinding>,
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
    pub fn web_binding(&mut self, binding: WebBinding) {
        assert!(
            self.web_bindings.insert(binding.id, binding).is_none(),
            "duplicate web binding"
        );
    }
    pub fn layout(&mut self, id: u32, layout: Vec<FormInstruction>) {
        self.web_bindings
            .get_mut(&id)
            .expect("layout binding must be registered")
            .layout = layout;
    }
    pub fn manifest(mut self) -> Manifest {
        // Existing single-action declarations infer eligible reads from their
        // declared page bindings. The emitted execution contract is explicit.
        let infer_reads: BTreeSet<u32> = self
            .actions
            .values()
            .filter(|action| action.target_reads.is_empty())
            .map(|action| action.id)
            .collect();
        for route in self.routes.values() {
            for id in &route.forms {
                let binding = self.web_bindings.get(id).expect("unknown web binding");
                let action = self
                    .actions
                    .get_mut(&binding.action)
                    .expect("unknown action");
                if !infer_reads.contains(&action.id) {
                    continue;
                }
                for id in &route.operations {
                    let operation = &self.operations[id];
                    if operation.kind == noxide_protocol::OperationKind::Read
                        && operation.via.is_none()
                    {
                        action.target_reads.push(*id);
                    }
                }
                action.target_reads.sort_unstable();
                action.target_reads.dedup();
            }
        }
        Manifest {
            version: VERSION,
            resources: self.resources.into_values().collect(),
            operations: self.operations.into_values().collect(),
            routes: self.routes.into_values().collect(),
            actions: self.actions.into_values().collect(),
            web_bindings: self.web_bindings.into_values().collect(),
        }
    }
    pub fn json(self) -> String {
        serde_json::to_string(&self.manifest()).expect("manifest encoding")
    }
}
