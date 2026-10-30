use super::resource::{Id, ResourceType};
use crate::{Context, Record, RequestView};
use noxide_protocol::{Operation, OperationKind};
use std::marker::PhantomData;
pub trait QueryType {
    type Resource: ResourceType;
    type Output;
    fn operation() -> Operation;
    fn from_record(record: Record) -> Self::Output;
}
pub trait ListQuery: QueryType {}
pub trait ReadQuery: QueryType {}
/// Arguments are constructed for one request; host checks remain authoritative.
pub trait FromRequest: Sized {
    fn from_request(request: &RequestView) -> Self;
}
impl<R> FromRequest for Id<R> {
    fn from_request(request: &RequestView) -> Self {
        Self::new(request.target.expect("record route"))
    }
}
pub struct Query<Q> {
    params: std::collections::BTreeMap<String, String>,
    context: Context,
    marker: PhantomData<Q>,
}
impl<Q: QueryType> FromRequest for Query<Q> {
    fn from_request(request: &RequestView) -> Self {
        Self {
            params: request.params.clone(),
            context: Context { _private: () },
            marker: PhantomData,
        }
    }
}
impl<Q: QueryType> Query<Q> {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }
    pub fn fetch(&mut self) -> Vec<Q::Output>
    where
        Q: ListQuery,
    {
        let operation = Q::operation();
        assert!(operation.kind == OperationKind::List, "not a list query");
        self.context
            .list(operation.id)
            .into_iter()
            .map(Q::from_record)
            .collect()
    }
    pub fn get(&mut self, id: Id<Q::Resource>) -> Option<Q::Output>
    where
        Q: ReadQuery,
    {
        let operation = Q::operation();
        assert!(operation.kind == OperationKind::Read, "not a read query");
        self.context
            .read(operation.id, id.get())
            .map(Q::from_record)
    }
}
