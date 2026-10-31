use super::resource::{Id, ResourceType};
use crate::{Context, Record, RequestView};
use noxide_protocol::{Operation, OperationKind};
use std::marker::PhantomData;
pub trait QueryType {
    const PUBLIC: bool = false;
    type Resource: ResourceType;
    type Output;
    fn operation() -> Operation;
    /// Schemas inspected by explicit membership authority; grants no operations.
    fn policy_resources() -> Vec<noxide_protocol::Resource> {
        Vec::new()
    }
    fn from_record(record: Record) -> Self::Output;
    fn record_id(record: &Self::Output) -> u64;
}
pub trait ListQuery: QueryType {}
pub trait ReadQuery: QueryType {}
pub trait FollowQuery: QueryType {
    type Source: QueryType;
}
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
        assert!(
            operation.list.as_ref().is_none_or(|s| s.preview.is_none()),
            "preview query requires fetch_preview"
        );
        self.context
            .list(operation.id)
            .into_iter()
            .map(Q::from_record)
            .collect()
    }
    pub fn fetch_preview(&mut self) -> Preview<Q::Output>
    where
        Q: ListQuery,
    {
        let operation = Q::operation();
        assert!(
            operation.list.as_ref().is_some_and(|s| s.preview.is_some()),
            "not a preview query"
        );
        let result: noxide_protocol::PreviewResult = self.context.invoke(operation.id, 0);
        Preview {
            items: result.items.into_iter().map(Q::from_record).collect(),
            truncated: result.truncated,
        }
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

pub struct Preview<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}

impl<Q: FollowQuery> Query<Q> {
    pub fn follow_many(
        &mut self,
        sources: &[<Q::Source as QueryType>::Output],
    ) -> Result<Vec<Option<Q::Output>>, crate::NotFound> {
        if sources.len() > 20 {
            return Err(crate::NotFound);
        }
        let resource = <Q::Source as QueryType>::Resource::definition().id;
        let identities: Vec<_> = sources
            .iter()
            .map(|source| (resource, Q::Source::record_id(source)))
            .collect();
        let results = self.context.follow(Q::operation().id, &identities);
        Ok(results
            .into_iter()
            .map(|record| record.map(Q::from_record))
            .collect())
    }
}

/// Records retain their supplying query type for typed follow inputs.
pub struct QueryRecord<Q: QueryType> {
    resource: Q::Resource,
    marker: PhantomData<Q>,
}
impl<Q: QueryType> QueryRecord<Q> {
    pub fn into_resource(self) -> Q::Resource {
        self.resource
    }
    #[doc(hidden)]
    pub fn new(resource: Q::Resource) -> Self {
        Self {
            resource,
            marker: PhantomData,
        }
    }
}
impl<Q: QueryType> std::ops::Deref for QueryRecord<Q> {
    type Target = Q::Resource;
    fn deref(&self) -> &Self::Target {
        &self.resource
    }
}

/// Aggregate declarations never implement the row query interface.
pub trait AggregateQuery {
    type Resource: ResourceType;
    type Output;
    fn operation() -> Operation;
    fn support_operations() -> Vec<Operation>;
    fn policy_resources() -> Vec<noxide_protocol::Resource>;
    fn decode(value: noxide_protocol::query::AggregateValue) -> Self::Output;
}
pub trait AggregateScalar: Sized {
    fn decode_aggregate(value: noxide_protocol::query::AggregateValue) -> Option<Self>;
}
impl AggregateScalar for i64 {
    fn decode_aggregate(value: noxide_protocol::query::AggregateValue) -> Option<Self> {
        let noxide_protocol::query::AggregateValue::Integer(value) = value else {
            panic!("host aggregate scalar contract")
        };
        value
    }
}
impl AggregateScalar for super::resource::Timestamp {
    fn decode_aggregate(value: noxide_protocol::query::AggregateValue) -> Option<Self> {
        let noxide_protocol::query::AggregateValue::Timestamp(value) = value else {
            panic!("host aggregate timestamp contract")
        };
        value
    }
}
/// One bounded aggregate host call. A limit/error never contains a partial value.
pub struct Aggregate<Q> {
    params: std::collections::BTreeMap<String, String>,
    context: Context,
    marker: PhantomData<Q>,
}
impl<Q: AggregateQuery> FromRequest for Aggregate<Q> {
    fn from_request(request: &RequestView) -> Self {
        Self {
            params: request.params.clone(),
            context: Context { _private: () },
            marker: PhantomData,
        }
    }
}
impl<Q: AggregateQuery> Aggregate<Q> {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }
    pub fn fetch(&mut self) -> Result<Q::Output, noxide_protocol::query::QueryError> {
        let value: noxide_protocol::query::AggregateResult =
            self.context.invoke(Q::operation().id, 0);
        value.map(Q::decode)
    }
}
/// Bounded raw query spelling. Host canonicalization and admission are mandatory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchText(String);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSearchText;
impl SearchText {
    pub fn new(text: impl Into<String>) -> Result<Self, InvalidSearchText> {
        let text = text.into();
        if text.is_empty() || text.len() > 4096 {
            Err(InvalidSearchText)
        } else {
            Ok(Self(text))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl super::resource::FieldValue for SearchText {
    fn kind() -> noxide_protocol::FieldKind {
        noxide_protocol::FieldKind::Text
    }
    fn encode(&self) -> String {
        self.0.clone()
    }
    fn decode(value: &str) -> Self {
        Self::new(value).expect("host search parameter contract")
    }
}
impl super::resource::ParamValue for SearchText {}

/// Native GET controls derived and validated by the host from a declared route.
/// Include canonical filter/range values; search prefill is optional.
#[derive(Clone, Debug)]
pub struct QueryForm(noxide_protocol::query::QueryForm);
impl QueryForm {
    pub fn new(destination: crate::RouteRef) -> Self {
        Self(noxide_protocol::query::QueryForm {
            destination,
            search_label: "Search".into(),
            submit: "Apply".into(),
        })
    }
    pub fn search_label(mut self, label: impl Into<String>) -> Self {
        self.0.search_label = label.into();
        self
    }
    pub fn submit(mut self, label: impl Into<String>) -> Self {
        self.0.submit = label.into();
        self
    }
}
impl super::page::Render for QueryForm {
    fn render(self, fragment: &mut super::page::Fragment) {
        fragment.nodes.push(crate::Instruction::QueryForm(self.0));
    }
}
impl super::page::Render for &QueryForm {
    fn render(self, fragment: &mut super::page::Fragment) {
        fragment
            .nodes
            .push(crate::Instruction::QueryForm(self.0.clone()));
    }
}
