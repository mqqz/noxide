//! Canonical bounded query declarations. Indexes and plans grant no authority.
use crate::Operand;
use serde::{Deserialize, Serialize};

pub const TOKENIZER_ID: &str = "noxide-token-and-v1;nfkc=0.1.25/unicode17.0.0;category=0.1.4/unicode17.0.0;lower=str-default/unicode17.0.0/rust1.98.0";
pub const MAX_INDEXED_FIELDS: usize = 4;
pub const MAX_INDEXED_BYTES: u32 = 16_384;
pub const MAX_SEARCH_CANDIDATES: usize = 256;
pub const MAX_AGGREGATE_CANDIDATES: usize = 1_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SearchIndex {
    pub tokenizer: String,
    pub fields: Vec<String>,
    pub max_bytes: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Search {
    pub fields: Vec<String>,
    pub parameter: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Query {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<Search>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<Range>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<Aggregate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclose: Vec<Disclosure>,
}
impl Query {
    pub fn is_empty(&self) -> bool {
        self.search.is_none()
            && self.range.is_none()
            && self.aggregate.is_none()
            && self.disclose.is_empty()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Disclosure {
    Search { field: String },
    Order { field: String },
    Range { field: String },
    Aggregate { field: Option<String> },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Range {
    pub field: String,
    pub lower: Option<Bound>,
    pub upper: Option<Bound>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub value: Operand,
    pub inclusive: bool,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Ascending,
    Descending,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SortMode {
    Immutable,
    LiveView,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Aggregate {
    /// Complete source List declaration is registered as metadata, not a grant.
    pub source: u32,
    pub function: AggregateFunction,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AggregateFunction {
    Count,
    Sum { field: String },
    Min { field: String },
    Max { field: String },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AggregateValue {
    Count(u64),
    Sum(i64),
    Integer(Option<i64>),
    Timestamp(Option<crate::time::Timestamp>),
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryError {
    LimitExceeded,
    Overflow,
}
/// Only data after full current authorization is represented by a successful value.
pub type AggregateResult = Result<AggregateValue, QueryError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CursorValue {
    Integer(i64),
    Binary(String),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CursorKey {
    Created { sequence: u64, record: u64 },
    Scalar { value: CursorValue, record: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_wire_is_strict_and_outcomes_cannot_label_partial_values() {
        let query = Query {
            search: Some(Search {
                fields: vec!["body".into()],
                parameter: "terms".into(),
            }),
            ..Default::default()
        };
        let encoded = serde_json::to_value(&query).unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({"search":{"fields":["body"],"parameter":"terms"}})
        );
        assert!(serde_json::from_value::<Query>(serde_json::json!({"search":{"fields":["body"],"parameter":"terms","unchecked":true}})).is_err());
        assert_eq!(
            serde_json::to_value(AggregateResult::Err(QueryError::LimitExceeded)).unwrap(),
            serde_json::json!({"Err":"limit_exceeded"})
        );
        assert!(
            serde_json::from_value::<AggregateResult>(
                serde_json::json!({"partial":5,"complete":true})
            )
            .is_err()
        );
    }
}
