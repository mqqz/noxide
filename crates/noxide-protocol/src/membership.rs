//! Specialized membership declarations. These are not enabled until manifest,
//! policy, lifecycle, and provider integration land together.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_MEMBERSHIP_PREDICATES: usize = 2;
pub const MAX_MEMBERSHIP_CONDITIONS: usize = 4;

/// The protected row supplies either its identity or one immutable reference.
/// There is no nested policy, caller-supplied account, or recursive join.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelatedTarget {
    SelfRecord,
    Reference { field: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MembershipLiteral {
    Boolean(bool),
    Choice(String),
}

/// Explicit authority to test these membership fields, without reading or
/// listing membership records. Conditions are canonicalized by field name.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ExistsRelated {
    pub resource: String,
    pub reference: String,
    pub target: RelatedTarget,
    pub account: String,
    pub conditions: BTreeMap<String, MembershipLiteral>,
}

/// Creation uniqueness is independent of role/status and row ownership. A
/// revoked or historical membership still occupies its reference/account tuple.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MembershipUnique {
    pub reference: String,
    pub account: String,
}
