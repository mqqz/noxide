use super::resource::ResourceType;
use crate::{Fields, RequestView, ResponseIntent};
use noxide_protocol::{Action, Operation, Resource};
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
    fn operations() -> Vec<Operation>;
    fn resources() -> Vec<Resource> {
        vec![Self::Resource::definition()]
    }
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
