use super::resource::{Id, ResourceType};
use crate::{Context, Record, RequestView};
use noxide_protocol::{Operation, OperationKind};
use std::marker::PhantomData;
pub trait QueryType {
    type Resource: ResourceType;
    type Output;
    fn operation() -> Operation;
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
