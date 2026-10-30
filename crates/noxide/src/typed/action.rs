use super::resource::ResourceType;
use crate::{Context, Fields, RequestView, ResponseIntent, RouteRef};
use noxide_protocol::{Action, Operation, OperationKind};
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
    type Controls;
    fn definition() -> Action;
    fn operation() -> Operation;
    fn inspection() -> Option<Operation> {
        None
    }
    fn controls() -> Self::Controls;
}

pub struct Submission<A: ActionType> {
    input: A::Input,
    original: Option<A::Original>,
    marker: PhantomData<A>,
}
impl<A: ActionType> Submission<A> {
    #[doc(hidden)]
    pub fn new(request: &RequestView) -> Self {
        Self {
            input: A::Input::from_fields(&request.input),
            original: request.inspection.as_ref().map(A::Original::from_fields),
            marker: PhantomData,
        }
    }
    pub fn input(&self) -> &A::Input {
        &self.input
    }
    pub fn original(&self) -> Option<&A::Original> {
        self.original.as_ref()
    }
    /// Stage exactly the host-retained input and target; the host commits later.
    pub fn apply(self) -> ActionResult<A> {
        let mut context = Context { _private: () };
        let op = A::operation();
        let response = match op.kind {
            OperationKind::Create => {
                let record = context.create(op.id);
                ResponseIntent::Created {
                    resource: op.resource,
                    id: record.id,
                    destination: RouteRef {
                        params: Default::default(),
                        route: A::definition().redirect.route(),
                        target: Some(record.id),
                    },
                }
            }
            OperationKind::Update => context.update(op.id),
            OperationKind::Delete => context.delete(op.id),
            _ => panic!("action operation"),
        };
        Ok(ActionOutcome {
            response,
            marker: PhantomData,
        })
    }
}
pub struct ActionOutcome<A> {
    response: ResponseIntent,
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
pub type ActionResult<A> = Result<ActionOutcome<A>, ActionError<A>>;
pub trait IntoActionResponse {
    fn into_response(self) -> ResponseIntent;
}
impl<A> IntoActionResponse for ActionResult<A> {
    fn into_response(self) -> ResponseIntent {
        match self {
            Ok(outcome) => outcome.response,
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
