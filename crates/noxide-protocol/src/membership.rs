//! Specialized membership declarations. These are not enabled until manifest,
//! policy, lifecycle, and provider integration land together.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_MEMBERSHIP_PREDICATES: usize = 2;
pub const MAX_MEMBERSHIP_CONDITIONS: usize = 4;
pub const MAX_MEMBERSHIP_UNIQUE_TUPLES: usize = 4;

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
    #[serde(deserialize_with = "conditions")]
    pub conditions: BTreeMap<String, MembershipLiteral>,
}

fn conditions<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, MembershipLiteral>, D::Error> {
    struct Conditions;
    impl<'de> serde::de::Visitor<'de> for Conditions {
        type Value = BTreeMap<String, MembershipLiteral>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most four distinct typed membership conditions")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut fields = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, MembershipLiteral>()? {
                if fields.len() == MAX_MEMBERSHIP_CONDITIONS || fields.insert(key, value).is_some()
                {
                    return Err(serde::de::Error::custom(
                        "duplicate or excess membership condition",
                    ));
                }
            }
            Ok(fields)
        }
    }
    deserializer.deserialize_map(Conditions)
}

/// Creation uniqueness is independent of role/status and row ownership. A
/// revoked or historical membership still occupies its reference/account tuple.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct MembershipUnique {
    pub reference: String,
    pub account: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn membership_condition_map_rejects_duplicates_and_excess() {
        let source = |conditions: &str| {
            format!(
                r#"{{"resource":"memberships","reference":"workspace","target":"self_record","account":"account","conditions":{{{conditions}}}}}"#
            )
        };
        let repeated = r#""active":{"boolean":true},"active":{"boolean":false}"#;
        assert!(serde_json::from_str::<ExistsRelated>(&source(repeated)).is_err());
        let excess = (0..5)
            .map(|i| format!(r#""f{i}":{{"boolean":true}}"#))
            .collect::<Vec<_>>()
            .join(",");
        assert!(serde_json::from_str::<ExistsRelated>(&source(&excess)).is_err());
        let value =
            serde_json::from_str::<ExistsRelated>(&source(r#""active":{"boolean":true}"#)).unwrap();
        assert_eq!(value.conditions["active"], MembershipLiteral::Boolean(true));
    }
}
