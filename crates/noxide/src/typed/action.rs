use super::resource::ResourceType;
use crate::{Fields, RequestView, ResponseIntent};
use noxide_protocol::{Action, Operation, Resource, WebBinding};
use std::{collections::BTreeMap, marker::PhantomData};
pub trait ActionInput: Sized {
    fn from_fields(fields: &Fields) -> Self;
}
impl ActionInput for () {
    fn from_fields(_: &Fields) -> Self {}
}
pub trait ActionType: Sized {
    type Resource: ResourceType;
    type Input: ActionInput;
    type Original: ActionInput;
    fn definition() -> Action;
    fn operations() -> Vec<Operation>;
    fn resources() -> Vec<Resource> {
        vec![Self::Resource::definition()]
    }
    fn inspection() -> Option<Operation> {
        None
    }
}

/// Optional browser controls and navigation for a canonical action.
pub trait WebActionType: ActionType {
    type Controls;
    fn controls() -> Self::Controls;
    fn web_binding() -> WebBinding;
}

pub struct Submission<A: ActionType> {
    input: A::Input,
    original: Option<A::Original>,
    inspections: BTreeMap<String, Fields>,
    marker: PhantomData<A>,
}
impl<A: ActionType> Submission<A> {
    #[doc(hidden)]
    pub fn new(request: &RequestView) -> Self {
        Self {
            input: A::Input::from_fields(&request.input),
            inspections: request.inspection.clone(),
            original: request
                .inspection
                .get("target")
                .map(A::Original::from_fields),
            marker: PhantomData,
        }
    }
    pub fn input(&self) -> &A::Input {
        &self.input
    }
    pub fn inspection(&self, target: &str) -> Option<&Fields> {
        self.inspections.get(target)
    }
    pub fn original(&self) -> Option<&A::Original> {
        self.original.as_ref()
    }
    pub fn execute(self) -> Execute<A> {
        Execute {
            marker: PhantomData,
        }
    }
}
pub struct Execute<A> {
    marker: PhantomData<A>,
}
pub struct ActionError<A> {
    fields: Fields,
    message: String,
    marker: PhantomData<A>,
}
impl<A> ActionError<A> {
    pub fn message(message: impl Into<String>) -> Self {
        Self {
            fields: Fields::new(),
            message: message.into(),
            marker: PhantomData,
        }
    }
    pub fn with<T>(mut self, field: Field<A, T>, message: impl Into<String>) -> Self {
        self.fields.insert(field.key.into(), message.into());
        self
    }
}
impl<A> IntoActionResponse for Execute<A> {
    fn into_response(self) -> ResponseIntent {
        ResponseIntent::Execute
    }
}
pub trait IntoActionResponse {
    fn into_response(self) -> ResponseIntent;
}
impl<A> IntoActionResponse for Result<Execute<A>, ActionError<A>> {
    fn into_response(self) -> ResponseIntent {
        match self {
            Ok(_) => ResponseIntent::Execute,
            Err(error) => ResponseIntent::Rejected {
                field_errors: error.fields,
                message: error.message,
            },
        }
    }
}

pub struct Field<R, T> {
    key: &'static str,
    marker: PhantomData<fn() -> (R, T)>,
}
impl<R, T> Copy for Field<R, T> {}
impl<R, T> Clone for Field<R, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R, T> Field<R, T> {
    pub const fn new(key: &'static str) -> Self {
        Self {
            key,
            marker: PhantomData,
        }
    }
    pub fn error(self, message: impl Into<String>) -> ActionError<R> {
        let message = message.into();
        ActionError {
            fields: BTreeMap::from([(self.key.into(), message)]),
            message: "Review the highlighted fields.".into(),
            marker: PhantomData,
        }
    }
}

/// Lower the ergonomic single-page syntax into the same named-target contract.
#[doc(hidden)]
pub fn page_targets(
    operations: &[Operation],
    steps: &[noxide_protocol::Step],
    revision: noxide_protocol::Revision,
    inspect: Option<noxide_protocol::Inspection>,
) -> Vec<noxide_protocol::ActionTarget> {
    use noxide_protocol::*;
    let mut resource = None;
    let mut include = |id| {
        assert!(
            resource.is_none_or(|old| old == id),
            "inconsistent page target"
        );
        resource = Some(id);
    };
    for step in steps {
        let op = operations
            .iter()
            .find(|operation| operation.id == step.operation)
            .expect("action operation");
        if matches!(&step.target, Target::Named(name) if name == "target") {
            include(op.resource);
        }
        for assignment in &step.assign {
            if matches!(&assignment.change, Change::Set(Value::Target(name)) if name == "target") {
                let eligible = op
                    .bind
                    .get(&assignment.field)
                    .expect("reference eligibility");
                include(
                    operations
                        .iter()
                        .find(|operation| operation.id == *eligible)
                        .expect("eligibility operation")
                        .resource,
                );
            }
        }
    }
    resource
        .map(|resource| ActionTarget {
            name: "target".into(),
            resource,
            source: TargetSource::Page { reads: vec![] },
            revision,
            projection: None,
            inspect,
        })
        .into_iter()
        .collect()
}

/// Explicit named-target declarations; emitted metadata grants no guest authority.
#[derive(Default)]
pub struct TargetDeclarations {
    pub targets: Vec<noxide_protocol::ActionTarget>,
    pub operations: Vec<Operation>,
    pub resources: Vec<Resource>,
}
impl TargetDeclarations {
    pub fn new() -> Self {
        Self::default()
    }
    fn add<Q: super::query::ReadQuery>(
        &mut self,
        name: &str,
        revision: noxide_protocol::Revision,
        source: noxide_protocol::TargetSource,
        fields: &[&str],
    ) {
        let operation = Q::operation();
        self.targets.push(noxide_protocol::ActionTarget {
            name: name.into(),
            resource: operation.resource,
            source,
            revision,
            projection: Some(noxide_protocol::Inspection {
                operation: operation.id,
                fields: fields.iter().map(|field| (*field).into()).collect(),
            }),
            inspect: None,
        });
        self.resources.push(Q::Resource::definition());
        self.operations.push(operation);
    }
    pub fn page<Q: super::query::ReadQuery>(
        mut self,
        name: &str,
        revision: noxide_protocol::Revision,
        fields: &[&str],
    ) -> Self {
        self.add::<Q>(
            name,
            revision,
            noxide_protocol::TargetSource::Page {
                reads: vec![Q::operation().id],
            },
            fields,
        );
        self
    }
    pub fn selected<L, Q>(
        mut self,
        name: &str,
        revision: noxide_protocol::Revision,
        fields: &[&str],
        label: &[&str],
    ) -> Self
    where
        Q: super::query::ReadQuery,
        L: super::query::ListQuery<Resource = Q::Resource>,
    {
        self.add::<Q>(
            name,
            revision,
            noxide_protocol::TargetSource::Selected {
                query: L::operation().id,
                eligible: Q::operation().id,
                label: label.iter().map(|field| (*field).into()).collect(),
            },
            fields,
        );
        self.operations.push(L::operation());
        self
    }
    pub fn reference<Q: super::query::ReadQuery>(
        mut self,
        name: &str,
        source: &str,
        field: &str,
        revision: noxide_protocol::Revision,
        fields: &[&str],
    ) -> Self {
        self.add::<Q>(
            name,
            revision,
            noxide_protocol::TargetSource::Reference {
                target: source.into(),
                field: field.into(),
                eligible: Q::operation().id,
            },
            fields,
        );
        self
    }
    pub fn inspect<Q: super::query::ReadQuery>(mut self, name: &str, fields: &[&str]) -> Self {
        let target = self
            .targets
            .iter_mut()
            .find(|target| target.name == name)
            .expect("declared target");
        target.inspect = Some(noxide_protocol::Inspection {
            operation: Q::operation().id,
            fields: fields.iter().map(|field| (*field).into()).collect(),
        });
        target.revision = noxide_protocol::Revision::Exact;
        self.resources.push(Q::Resource::definition());
        self.operations.push(Q::operation());
        self
    }
}
