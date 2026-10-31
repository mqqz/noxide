//! Transactional captures only. Delivery and all networking belong to the outbox worker.
use super::*;
use crate::effects::{CapturedEffect, EffectScope, OutboxContext};
use noxide_protocol::effects::{
    EmitEffect, MAX_EFFECT_BODY_BYTES, MAX_EFFECTS_PER_ACTION, MAX_PAYLOAD_FIELDS,
};
use std::io::Write;

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
fn scalar_json(scalar: repository::ScheduleScalar, schema: &Input) -> Result<serde_json::Value> {
    use repository::ScheduleScalar as Scalar;
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
fn payload(
    values: &repository::ScheduleValues<'_>,
    action: ActionCore<'_>,
    emission: &EmitEffect,
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
        let scalar = values.value(&field.value, action)?;
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
impl Application {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn enqueue_action_effects(
        &self,
        effects: &mut Effects,
        action: ActionCore<'_>,
        snapshots: &BTreeMap<(u32, u64), StoredRecord>,
        outcomes: &[MutationOutcome],
        time: Option<crate::lifecycle_clock::AttemptTime>,
        origin: &str,
    ) -> Result<()> {
        let Some(contract) = &self.manifest.effects else {
            return Ok(());
        };
        let emissions: Vec<_> = contract
            .emissions
            .iter()
            .filter(|emission| emission.source_action == action.id)
            .collect();
        if emissions.is_empty() {
            return Ok(());
        }
        ensure!(
            emissions.len() <= MAX_EFFECTS_PER_ACTION,
            "effect emission limit"
        );
        let now = time.ok_or(repository::CalculationUnavailable)?.timestamp();
        let scope = EffectScope {
            deployment: self
                .generation
                .get()
                .ok_or_else(|| anyhow::anyhow!("application is not activated"))?
                .clone(),
            tenant: match &effects.principal {
                auth::Principal::Anonymous => String::new(),
                auth::Principal::User(user) => user.tenant.clone(),
                auth::Principal::Service(service) => service.tenant().to_owned(),
            },
        };
        let mut grants = BTreeMap::new();
        for emission in emissions {
            let bytes = payload(
                &repository::ScheduleValues {
                    manifest: &self.manifest,
                    input: &effects.request.input,
                    principal: &effects.principal,
                    grants: &effects.grants,
                    snapshots,
                    outcomes,
                    time,
                    current: None,
                },
                action,
                emission,
            )?;
            if let std::collections::btree_map::Entry::Vacant(entry) =
                grants.entry(emission.endpoint.as_str())
            {
                entry.insert(
                    OutboxContext {
                        tx: &mut effects.tx,
                        calls: &mut effects.calls,
                    }
                    .endpoint_grant(&scope, &emission.endpoint, &self.contract)
                    .await?,
                );
            }
            let proof = &grants[emission.endpoint.as_str()];
            let capture = CapturedEffect::capture(
                emission,
                origin.to_owned(),
                action.version,
                proof,
                bytes,
                now,
            )?;
            OutboxContext {
                tx: &mut effects.tx,
                calls: &mut effects.calls,
            }
            .enqueue(&capture, now)
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
