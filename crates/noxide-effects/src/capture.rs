//! Turning an action's declared emissions into outbox rows, inside its transaction.
//! The host supplies values it computed under authorization; nothing here reads records.
use crate::{CapturedEffect, EffectScope, OutboxContext};
use anyhow::{Result, ensure};
use noxide_admission::scalar::Scalar;
use noxide_protocol::{
    FieldKind, Input, TextField, Value,
    effects::{
        EffectContract, EmitEffect, MAX_EFFECT_BODY_BYTES, MAX_EFFECTS_PER_ACTION,
        MAX_PAYLOAD_FIELDS,
    },
    time::Timestamp,
};
use std::{collections::BTreeMap, io::Write};

struct Body(Vec<u8>);
impl Write for Body {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|size| size > MAX_EFFECT_BODY_BYTES)
        {
            return Err(std::io::Error::other("effect body limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn same_kind(source: &FieldKind, destination: &FieldKind) -> bool {
    match (source, destination) {
        (FieldKind::Integer { .. }, FieldKind::Integer { .. })
        | (FieldKind::Choice { .. }, FieldKind::Choice { .. })
        | (FieldKind::Duration { .. }, FieldKind::Duration { .. }) => true,
        _ => source == destination,
    }
}
fn scalar_json(scalar: Scalar, schema: &Input) -> Result<serde_json::Value> {
    ensure!(
        !matches!(
            schema.kind,
            FieldKind::Blob { .. } | FieldKind::UploadHandle { .. }
        ),
        "opaque effect scalar"
    );
    if let Scalar::Missing(kind) = &scalar {
        ensure!(
            schema.optional && same_kind(kind, &schema.kind),
            "invalid optional effect scalar"
        );
        return Ok(serde_json::Value::Null);
    }
    let value = match (&scalar, &schema.kind) {
        (Scalar::Text(value), FieldKind::Text)
        | (Scalar::Choice(value), FieldKind::Choice { .. })
        | (Scalar::Account(value), FieldKind::Account { .. }) => {
            serde_json::Value::String(value.clone())
        }
        (Scalar::Integer(value), FieldKind::Integer { .. }) => serde_json::Value::from(*value),
        (Scalar::Boolean(value), FieldKind::Boolean) => serde_json::Value::from(*value),
        (Scalar::Timestamp(value), FieldKind::Timestamp) => {
            serde_json::Value::from(value.unix_millis())
        }
        (Scalar::Duration(value), FieldKind::Duration { .. }) => {
            serde_json::Value::from(value.as_millis())
        }
        (Scalar::Reference { resource, id }, FieldKind::Reference { resource: expected })
            if resource == expected =>
        {
            serde_json::Value::from(*id)
        }
        _ => anyhow::bail!("effect scalar type differs"),
    };
    let encoded = scalar.encode();
    let field = TextField {
        immutable: false,
        kind: schema.kind.clone(),
        optional: false,
        initial: None,
        name: schema.name.clone(),
        label: schema.label.clone(),
        max_bytes: schema.max_bytes,
    };
    ensure!(
        field
            .canonical(&encoded)
            .is_ok_and(|canonical| canonical == encoded),
        "noncanonical effect scalar"
    );
    Ok(value)
}
/// A JSON object of the emission's fields, with each value checked against its schema.
pub fn payload(
    emission: &EmitEffect,
    mut value: impl FnMut(&Value) -> Result<Scalar>,
) -> Result<Vec<u8>> {
    ensure!(
        emission.fields.len() <= MAX_PAYLOAD_FIELDS,
        "effect payload field limit"
    );
    let mut fields = BTreeMap::new();
    for field in &emission.fields {
        ensure!(
            noxide_protocol::identifier(&field.schema.name),
            "invalid effect field name"
        );
        let scalar = value(&field.value)?;
        ensure!(
            fields
                .insert(
                    field.schema.name.clone(),
                    scalar_json(scalar, &field.schema)?
                )
                .is_none(),
            "duplicate effect payload field"
        );
    }
    let mut body = Body(Vec::new());
    serde_json::to_writer(&mut body, &fields).map_err(|_| anyhow::anyhow!("effect body limit"))?;
    Ok(body.0)
}

/// The emissions an action declares, within the per-action limit.
pub fn emissions_for(contract: &EffectContract, action: u32) -> Result<Vec<&EmitEffect>> {
    let emissions: Vec<_> = contract
        .emissions
        .iter()
        .filter(|emission| emission.source_action == action)
        .collect();
    ensure!(
        emissions.len() <= MAX_EFFECTS_PER_ACTION,
        "effect emission limit"
    );
    Ok(emissions)
}

/// One action's capture. Each emission's endpoint grant is verified once per action.
pub struct ActionCapture<'a> {
    pub scope: &'a EffectScope,
    pub contract: &'a str,
    pub origin: &'a str,
    pub source_action_version: u32,
    pub now: Timestamp,
}
impl ActionCapture<'_> {
    pub async fn enqueue(
        &self,
        outbox: OutboxContext<'_>,
        emissions: &[&EmitEffect],
        mut value: impl FnMut(&Value) -> Result<Scalar> + Send,
    ) -> Result<()> {
        let mut grants = BTreeMap::new();
        for emission in emissions {
            let bytes = payload(emission, &mut value)?;
            if let std::collections::btree_map::Entry::Vacant(entry) =
                grants.entry(emission.endpoint.as_str())
            {
                entry.insert(
                    OutboxContext {
                        tx: &mut *outbox.tx,
                        calls: &mut *outbox.calls,
                    }
                    .endpoint_grant(self.scope, &emission.endpoint, self.contract)
                    .await?,
                );
            }
            let proof = &grants[emission.endpoint.as_str()];
            let capture = CapturedEffect::capture(
                emission,
                self.origin.to_owned(),
                self.source_action_version,
                proof,
                bytes,
                self.now,
            )?;
            OutboxContext {
                tx: &mut *outbox.tx,
                calls: &mut *outbox.calls,
            }
            .enqueue(&capture, self.now)
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
