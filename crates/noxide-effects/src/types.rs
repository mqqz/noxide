use crate::effect_deployment::EffectiveEffectGrant;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_protocol::{FieldKind, Input, TextField, effects::*, time::Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub(super) use noxide_protocol::effects::MAX_CAPTURE_BYTES;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectScope {
    pub deployment: String,
    pub tenant: String,
}
impl EffectScope {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            opaque(&self.deployment)
                && (self.tenant.is_empty() || noxide_protocol::identifier(&self.tenant)),
            "invalid effect scope"
        );
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EndpointGrant {
    pub(super) scope: EffectScope,
    pub(super) binding: EffectiveEffectGrant,
    pub(super) contract: String,
    pub(super) epoch: String,
    pub(super) version: i64,
    pub(super) secret_version: i64,
}
impl EndpointGrant {
    pub(super) fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        ensure!(
            self.scope.tenant == self.binding.tenant
                && opaque(&self.contract)
                && opaque(&self.epoch)
                && self.version > 0
                && if self.binding.endpoint.secret_slot.is_some() {
                    self.secret_version > 0
                } else {
                    self.secret_version == 0
                },
            "invalid endpoint grant"
        );
        ensure!(
            noxide_protocol::identifier(&self.binding.endpoint.name)
                && self
                    .binding
                    .endpoint
                    .secret_slot
                    .as_ref()
                    .is_none_or(|s| noxide_protocol::identifier(s)),
            "invalid endpoint identity"
        );
        crate::transport::Endpoint::checked(
            &self.binding.host,
            self.binding.port,
            &self.binding.path,
        )
        .map_err(|_| anyhow::anyhow!("invalid granted endpoint"))?;
        Ok(())
    }
}
/// Constructed only from current rows locked in the originating action TX.
pub struct VerifiedEndpointGrant {
    pub(super) grant: EndpointGrant,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedEffect {
    pub(super) scope: EffectScope,
    pub(super) origin: String,
    pub(super) ordinal: u8,
    pub(super) source_action: u32,
    pub(super) source_action_version: u32,
    pub(super) contract: String,
    pub(super) epoch: String,
    pub(super) grant_version: i64,
    pub(super) secret_version: i64,
    pub(super) binding: EffectiveEffectGrant,
    pub(super) schema_digest: String,
    pub(super) fields: Vec<Input>,
    pub(super) body: String,
    pub(super) created: Timestamp,
}
impl fmt::Debug for CapturedEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapturedEffect([redacted])")
    }
}
impl CapturedEffect {
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn capture(
        declaration: &EmitEffect,
        origin: String,
        source_action_version: u32,
        proof: &VerifiedEndpointGrant,
        canonical_json: Vec<u8>,
        now: Timestamp,
    ) -> Result<Self> {
        proof.grant.validate()?;
        ensure!(
            declaration.endpoint == proof.grant.binding.endpoint.name,
            "effect destination differs from grant"
        );
        validate_body(declaration, &canonical_json)?;
        let captured = Self {
            scope: proof.grant.scope.clone(),
            origin,
            ordinal: declaration.ordinal,
            source_action: declaration.source_action,
            source_action_version,
            contract: proof.grant.contract.clone(),
            epoch: proof.grant.epoch.clone(),
            grant_version: proof.grant.version,
            secret_version: proof.grant.secret_version,
            binding: proof.grant.binding.clone(),
            schema_digest: digest(&("effect-schema-v1", declaration))?,
            fields: declaration
                .fields
                .iter()
                .map(|f| f.schema.clone())
                .collect(),
            body: String::from_utf8(canonical_json)?,
            created: now,
        };
        captured.validate()?;
        Ok(captured)
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        ensure!(
            !self.origin.is_empty()
                && self.origin.len() <= 128
                && !self.origin.contains('\0')
                && self.ordinal < MAX_EFFECTS_PER_ACTION as u8
                && self.source_action > 0
                && self.source_action_version > 0
                && opaque(&self.schema_digest),
            "invalid effect capture identity"
        );
        self.grant().validate()?;
        ensure!(
            self.body.len() <= MAX_EFFECT_BODY_BYTES && !self.body.contains('\0'),
            "effect body limit"
        );
        let value: serde_json::Value = serde_json::from_str(&self.body)?;
        ensure!(
            value.is_object() && serde_json::to_string(&value)? == self.body,
            "noncanonical captured JSON object"
        );
        validate_fields(&self.fields, self.body.as_bytes())?;
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_CAPTURE_BYTES,
            "effect capture limit"
        );
        Ok(())
    }
    pub(super) fn grant(&self) -> EndpointGrant {
        EndpointGrant {
            scope: self.scope.clone(),
            binding: self.binding.clone(),
            contract: self.contract.clone(),
            epoch: self.epoch.clone(),
            version: self.grant_version,
            secret_version: self.secret_version,
        }
    }
    /// Immutable identity, independent of grant changes, rounds, epoch or fence.
    pub fn id(&self) -> Result<String> {
        Ok(format!(
            "e1_{}",
            digest(&(
                "effect-v1",
                &self.scope.deployment,
                &self.scope.tenant,
                &self.origin,
                self.ordinal
            ))?
        ))
    }
    pub fn receiver_key(&self) -> Result<String> {
        self.id()
    }
    pub fn capture_digest(&self) -> Result<String> {
        digest(&("effect-capture-v1", self))
    }
    pub fn endpoint(&self) -> &str {
        &self.binding.endpoint.name
    }
    pub fn binding(&self) -> &EffectiveEffectGrant {
        &self.binding
    }
    pub fn body(&self) -> &[u8] {
        self.body.as_bytes()
    }
    pub fn source_action(&self) -> (u32, u32) {
        (self.source_action, self.source_action_version)
    }
}
fn validate_body(declaration: &EmitEffect, bytes: &[u8]) -> Result<()> {
    ensure!(
        declaration.source_action > 0
            && declaration.ordinal < MAX_EFFECTS_PER_ACTION as u8
            && declaration.fields.len() <= MAX_PAYLOAD_FIELDS
            && bytes.len() <= MAX_EFFECT_BODY_BYTES,
        "effect capture limits"
    );
    validate_fields(
        &declaration
            .fields
            .iter()
            .map(|f| f.schema.clone())
            .collect::<Vec<_>>(),
        bytes,
    )
}
fn validate_fields(schemas: &[Input], bytes: &[u8]) -> Result<()> {
    ensure!(
        schemas.len() <= MAX_PAYLOAD_FIELDS && bytes.len() <= MAX_EFFECT_BODY_BYTES,
        "effect capture limits"
    );
    let fields: BTreeMap<String, serde_json::Value> = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&fields)? == bytes && fields.len() == schemas.len(),
        "noncanonical effect object"
    );
    let mut seen = BTreeSet::new();
    for schema in schemas {
        ensure!(
            noxide_protocol::identifier(&schema.name) && seen.insert(&schema.name),
            "invalid effect field name"
        );
        let value = fields.get(&schema.name).context("effect field missing")?;
        ensure!(
            !matches!(
                schema.kind,
                FieldKind::Blob { .. } | FieldKind::UploadHandle { .. }
            ),
            "effect handle disclosure refused"
        );
        if value.is_null() {
            ensure!(schema.optional, "required effect field is null");
            continue;
        }
        let width = match value {
            serde_json::Value::String(s) => s.len(),
            _ => value.to_string().len(),
        };
        ensure!(
            width <= schema.max_bytes as usize,
            "effect field byte limit"
        );
        let valid = match &schema.kind {
            FieldKind::Text => value.is_string(),
            FieldKind::Account { .. } => value
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 64 && !s.contains('\0')),
            FieldKind::Boolean => value.is_boolean(),
            FieldKind::Integer { min, max } => value
                .as_i64()
                .is_some_and(|v| min.is_none_or(|m| v >= m) && max.is_none_or(|m| v <= m)),
            FieldKind::Timestamp => value
                .as_i64()
                .is_some_and(|v| Timestamp::from_unix_millis(v).is_ok()),
            FieldKind::Duration { max_millis } => {
                value.as_i64().is_some_and(|v| v >= 0 && v <= *max_millis)
            }
            FieldKind::Reference { .. } => value.as_i64().is_some_and(|v| v > 0),
            FieldKind::Choice { variants } => value
                .as_str()
                .is_some_and(|s| variants.iter().any(|v| v.key == s)),
            FieldKind::Blob { .. } | FieldKind::UploadHandle { .. } => false,
        };
        ensure!(valid, "effect scalar differs from declared schema");
        let scalar = match value {
            serde_json::Value::String(s) => s.clone(),
            _ => value.to_string(),
        };
        let validator = TextField {
            immutable: false,
            kind: schema.kind.clone(),
            optional: false,
            initial: None,
            name: schema.name.clone(),
            label: schema.label.clone(),
            max_bytes: schema.max_bytes,
        };
        let canonical = validator
            .canonical(&scalar)
            .map_err(|_| anyhow::anyhow!("invalid effect scalar"))?;
        ensure!(canonical == scalar, "noncanonical effect scalar");
    }
    Ok(())
}
pub fn digest(value: &impl Serialize) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(value)?)))
}
pub fn opaque(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && !value.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxide_protocol::{Input, Literal, Value};
    fn declaration() -> EmitEffect {
        EmitEffect {
            source_action: 1,
            ordinal: 0,
            endpoint: "events".into(),
            fields: vec![PayloadField {
                schema: Input {
                    name: "count".into(),
                    label: "Count".into(),
                    kind: FieldKind::Integer {
                        min: Some(0),
                        max: Some(10),
                    },
                    optional: false,
                    max_bytes: 2,
                },
                value: Value::Literal(Literal::Integer(1)),
            }],
        }
    }
    #[test]
    fn canonical_types_and_disclosure_shape_are_checked_independently() {
        let d = declaration();
        assert!(validate_body(&d, br#"{"count":1}"#).is_ok());
        for bytes in [
            br#"{"count":"1"}"#.as_slice(),
            br#"{"count":11}"#,
            br#"{"count":null}"#,
            br#"{"count":1,"other":2}"#,
            br#"{ "count":1}"#,
            br#"{"count":1,"count":1}"#,
        ] {
            assert!(validate_body(&d, bytes).is_err());
        }
    }
    #[test]
    fn independent_capture_reuses_scalar_grammar_without_normalizing() {
        let mut d = declaration();
        d.fields[0].schema.kind = FieldKind::Text;
        d.fields[0].schema.max_bytes = 64;
        for bytes in [
            br#"{"count":""}"#.as_slice(),
            br#"{"count":"a\rb"}"#,
            br#"{"count":"a\u0001b"}"#,
        ] {
            assert!(validate_body(&d, bytes).is_err());
        }
        assert!(validate_body(&d, br#"{"count":"a\nb"}"#).is_ok());
        d.fields[0].schema.kind = FieldKind::Account {
            scope: noxide_protocol::AccountScope::SameTenant,
        };
        assert!(validate_body(&d, br#"{"count":"x"}"#).is_err());
    }
}
