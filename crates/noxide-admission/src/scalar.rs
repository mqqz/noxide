//! A typed value computed inside an authorized transaction.
use anyhow::Result;
use noxide_protocol::{
    FieldKind,
    time::{Duration, Timestamp},
};
use std::cmp::Ordering;

#[derive(Debug)]
pub struct CalculationUnavailable;
impl std::fmt::Display for CalculationUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("calculation unavailable")
    }
}
impl std::error::Error for CalculationUnavailable {}

#[derive(Clone, Debug)]
pub enum Scalar {
    Text(String),
    Integer(i64),
    Boolean(bool),
    Choice(String),
    Account(String),
    Timestamp(Timestamp),
    Duration(Duration),
    Reference { resource: String, id: u64 },
    Missing(FieldKind),
}
impl Scalar {
    pub fn encode(&self) -> String {
        match self {
            Self::Text(v) | Self::Choice(v) | Self::Account(v) => v.clone(),
            Self::Integer(v) => v.to_string(),
            Self::Boolean(v) => v.to_string(),
            Self::Timestamp(v) => v.unix_millis().to_string(),
            Self::Duration(v) => v.as_millis().to_string(),
            Self::Reference { id, .. } => id.to_string(),
            Self::Missing(_) => String::new(),
        }
    }
    pub fn compare(&self, other: &Self) -> Result<Ordering> {
        Ok(match (self, other) {
            (Self::Text(a), Self::Text(b))
            | (Self::Choice(a), Self::Choice(b))
            | (Self::Account(a), Self::Account(b)) => a.cmp(b),
            (Self::Integer(a), Self::Integer(b)) => a.cmp(b),
            (Self::Boolean(a), Self::Boolean(b)) => a.cmp(b),
            (Self::Timestamp(a), Self::Timestamp(b)) => a.cmp(b),
            (Self::Duration(a), Self::Duration(b)) => a.cmp(b),
            (Self::Reference { resource: a, id: x }, Self::Reference { resource: b, id: y })
                if a == b =>
            {
                x.cmp(y)
            }
            (Self::Missing(a), Self::Missing(b))
                if std::mem::discriminant(a) == std::mem::discriminant(b) =>
            {
                Ordering::Equal
            }
            (Self::Missing(_), _) => Ordering::Less,
            (_, Self::Missing(_)) => Ordering::Greater,
            _ => anyhow::bail!(CalculationUnavailable),
        })
    }
}
