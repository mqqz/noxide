//! Fixed JSON disclosures to named, operator-approved webhook endpoints.
//!
//! Declarations contain endpoint/secret-slot identities, never secret bytes or
//! caller-selected URLs. The host owns transport, payload evaluation and outbox.
use crate::{Input, Value};
use serde::{Deserialize, Serialize};

/// Upper bound on one captured effect payload.
pub const MAX_CAPTURE_BYTES: usize = 196_608;
pub const MAX_EFFECTS_PER_ACTION: usize = 2;
pub const MAX_ENDPOINTS: usize = 32;
pub const MAX_PAYLOAD_FIELDS: usize = 32;
pub const MAX_EFFECT_BODY_BYTES: usize = 65_536;
pub const MAX_EFFECT_RESPONSE_BYTES: usize = 16_384;
pub const MAX_PENDING_EFFECTS: u16 = 1_000;
pub const MAX_EFFECT_ATTEMPTS: u8 = 5;
pub const EFFECT_RETRY_WINDOW_MILLIS: i64 = 24 * 60 * 60 * 1_000;
pub const EFFECT_LEASE_MILLIS: i64 = 60_000;
pub const MAX_EFFECT_CONCURRENCY: u8 = 2;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectContract {
    pub endpoints: Vec<EffectEndpoint>,
    pub emissions: Vec<EmitEffect>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectEndpoint {
    pub name: String,
    /// Host secret-slot identity; the value is resolved only at delivery time.
    pub secret_slot: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmitEffect {
    pub source_action: u32,
    /// Stable position within this action's external effects, independent of jobs.
    pub ordinal: u8,
    pub endpoint: String,
    pub fields: Vec<PayloadField>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadField {
    /// Independent scalar schema. `name` is the JSON object key; `label` is
    /// bounded operator-facing text. Blob/upload handles are never admissible.
    pub schema: Input,
    pub value: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caller_selected_urls_and_secret_values_are_not_contract_fields() {
        for json in [
            r#"{"name":"events","secret_slot":null,"url":"https://other.invalid/"}"#,
            r#"{"name":"events","secret_slot":"token","secret":"bytes"}"#,
        ] {
            assert!(serde_json::from_str::<EffectEndpoint>(json).is_err());
        }
        assert!(
            serde_json::from_str::<EmitEffect>(
                r#"{"source_action":1,"ordinal":0,"endpoint":"events","fields":[],"method":"GET"}"#
            )
            .is_err()
        );
    }
}
