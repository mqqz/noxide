use crate::Record;
use noxide_protocol::{FieldKind, Resource};
use std::marker::PhantomData;
/// Deterministic bundle-local identifier. Host admission rejects collisions.
pub const fn stable_id(key: &str) -> u32 {
    let bytes = key.as_bytes();
    let mut hash = 2166136261u32;
    let mut i = 0;
    while i < bytes.len() {
        hash = (hash ^ bytes[i] as u32).wrapping_mul(16777619);
        i += 1;
    }
    hash
}

/// A record's identity. Possession does not grant access to it.
pub struct Id<R> {
    value: u64,
    marker: PhantomData<fn() -> R>,
}
impl<R> Copy for Id<R> {}
impl<R> Clone for Id<R> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R> std::fmt::Debug for Id<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Id").field(&self.value).finish()
    }
}
impl<R> PartialEq for Id<R> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl<R> Eq for Id<R> {}
impl<R> PartialOrd for Id<R> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<R> Ord for Id<R> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}
impl<R> std::hash::Hash for Id<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}
impl<R> Id<R> {
    pub fn new(value: u64) -> Self {
        assert!(value > 0 && value <= i64::MAX as u64, "record ID range");
        Self {
            value,
            marker: PhantomData,
        }
    }
    pub fn get(self) -> u64 {
        self.value
    }
}

pub trait ResourceType: Sized {
    const KEY: &'static str;
    fn definition() -> Resource;
    fn from_record(record: Record) -> Self;
}
pub trait FieldSpec<const KEY: u32> {
    type Value: FieldValue;
    const KEY: &'static str;
}
pub trait FieldValue: Sized {
    const FILTERABLE: bool = false;
    const IMMUTABLE: bool = false;
    const OPTIONAL: bool = false;
    fn kind() -> FieldKind;
    fn encode(&self) -> String;
    fn decode(value: &str) -> Self;
}
impl<R: ResourceType> FieldValue for Id<R> {
    fn kind() -> FieldKind {
        panic!("parent fields require visible and create_when predicates")
    }
    fn encode(&self) -> String {
        self.value.to_string()
    }
    fn decode(value: &str) -> Self {
        Self::new(value.parse().expect("host parent ID"))
    }
}
impl FieldValue for String {
    fn kind() -> FieldKind {
        FieldKind::Text
    }
    fn encode(&self) -> String {
        self.clone()
    }
    fn decode(value: &str) -> Self {
        value.to_owned()
    }
}
impl FieldValue for bool {
    const FILTERABLE: bool = true;
    fn kind() -> FieldKind {
        FieldKind::Boolean
    }
    fn encode(&self) -> String {
        self.to_string()
    }
    fn decode(value: &str) -> Self {
        match value {
            "true" => true,
            "false" => false,
            _ => panic!("host boolean contract"),
        }
    }
}
impl FieldValue for i64 {
    fn kind() -> FieldKind {
        FieldKind::Integer {
            min: None,
            max: None,
        }
    }
    fn encode(&self) -> String {
        self.to_string()
    }
    fn decode(value: &str) -> Self {
        value.parse().expect("host integer contract")
    }
}
impl<T: FieldValue> FieldValue for Option<T> {
    const FILTERABLE: bool = T::FILTERABLE;
    const OPTIONAL: bool = true;
    fn kind() -> FieldKind {
        T::kind()
    }
    fn encode(&self) -> String {
        self.as_ref().map(FieldValue::encode).unwrap_or_default()
    }
    fn decode(value: &str) -> Self {
        if value.is_empty() {
            None
        } else {
            Some(T::decode(value))
        }
    }
}

/// Stable account identity. Parsing grants no authority and does not check eligibility.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId(String);
impl std::str::FromStr for AccountId {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if noxide_protocol::account_id(value) {
            Ok(Self(value.into()))
        } else {
            Err("invalid account identity")
        }
    }
}
impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl FieldValue for AccountId {
    const IMMUTABLE: bool = true;
    fn kind() -> FieldKind {
        panic!("account fields require explicit scope = same_tenant")
    }
    fn encode(&self) -> String {
        self.0.clone()
    }
    fn decode(value: &str) -> Self {
        value.parse().expect("host account identity")
    }
}

pub trait ParamValue: FieldValue {}
impl ParamValue for bool {}
impl<T: ParamValue> ParamValue for Option<T> {}
