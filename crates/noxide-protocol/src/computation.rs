//! Approved, bounded host computations. Guests return decisions, never expressions.
use crate::time::{Duration, Timestamp};
use serde::{Deserialize, Serialize};

pub const MAX_EXPRESSION_NODES: usize = 64;
pub const MAX_EXPRESSION_DEPTH: usize = 8;
pub const MAX_GUARDS: usize = 8;

/// A literal's scalar type is explicit; resource identities require sealed targets.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Literal {
    Text(String),
    Integer(i64),
    Boolean(bool),
    Choice(String),
    Account(String),
    Timestamp(Timestamp),
    Duration(Duration),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Value {
    Input(String),
    Literal(Literal),
    Target(String),
    Created(u8),
    /// Authenticated actor identity, only for an account field on create.
    Principal,
    TransactionTime,
    SnapshotField {
        target: String,
        field: String,
        reviewed: bool,
    },
    /// Guard-only access to the current row of this step's named target.
    CurrentField {
        target: String,
        field: String,
    },
    Add {
        left: Box<Value>,
        right: Box<Value>,
    },
    Subtract {
        left: Box<Value>,
        right: Box<Value>,
    },
    Multiply {
        left: Box<Value>,
        right: Box<Value>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GuardCondition {
    Compare {
        left: Value,
        comparison: Comparison,
        right: Value,
    },
    All(Vec<GuardCondition>),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Guard {
    pub condition: GuardCondition,
    pub rejection: GuardRejection,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardRejection {
    pub input: Option<String>,
    pub message: String,
}

impl Value {
    /// Structural traversal only; admission validates the complete node/depth budget.
    pub fn uses_time(&self) -> bool {
        match self {
            Self::TransactionTime => true,
            Self::Add { left, right }
            | Self::Subtract { left, right }
            | Self::Multiply { left, right } => left.uses_time() || right.uses_time(),
            _ => false,
        }
    }
}
impl GuardCondition {
    pub fn uses_time(&self) -> bool {
        match self {
            Self::Compare { left, right, .. } => left.uses_time() || right.uses_time(),
            Self::All(conditions) => conditions.iter().any(Self::uses_time),
        }
    }
}
