//! Endpoint disclosures share the existing action expression/type/budget checker.
use super::*;
use noxide_protocol::effects::*;

pub(super) fn validate_payload_schema(manifest: &Manifest, schema: &Input) -> Result<()> {
    ensure!(identifier(&schema.name), "invalid effect payload field");
    ensure!(
        !matches!(
            schema.kind,
            FieldKind::Blob { .. } | FieldKind::UploadHandle { .. }
        ),
        "opaque blob identity cannot be disclosed"
    );
    if let FieldKind::Reference { resource } = &schema.kind {
        let mut scalar = schema.clone();
        scalar.kind = FieldKind::Text;
        validate_input_schema(&scalar)?;
        ensure!(
            schema.max_bytes >= 19
                && manifest
                    .resources
                    .iter()
                    .any(|declared| declared.name == *resource),
            "invalid effect resource identity schema"
        );
    } else {
        validate_input_schema(schema)?;
    }
    Ok(())
}
fn fits(domain: &computation::Domain, schema: &Input) -> bool {
    match (&domain.kind, &schema.kind) {
        (
            FieldKind::Reference { resource: source },
            FieldKind::Reference {
                resource: destination,
            },
        ) => {
            source == destination && (!domain.optional || schema.optional) && schema.max_bytes >= 19
        }
        _ => computation::fits_input(domain, schema),
    }
}
pub(super) fn validate(manifest: &Manifest) -> Result<()> {
    let Some(contract) = &manifest.effects else {
        return Ok(());
    };
    ensure!(
        contract.endpoints.len() <= MAX_ENDPOINTS
            && contract.emissions.len() <= manifest.actions.len() * MAX_EFFECTS_PER_ACTION,
        "effect declaration limit"
    );
    let mut endpoints = BTreeSet::new();
    for endpoint in &contract.endpoints {
        ensure!(
            identifier(&endpoint.name)
                && endpoints.insert(&endpoint.name)
                && endpoint
                    .secret_slot
                    .as_ref()
                    .is_none_or(|slot| identifier(slot)),
            "invalid or duplicate effect endpoint"
        );
    }
    let mut positions = BTreeSet::new();
    for emission in &contract.emissions {
        action(manifest, emission.source_action)?;
        ensure!(
            usize::from(emission.ordinal) < MAX_EFFECTS_PER_ACTION
                && positions.insert((emission.source_action, emission.ordinal))
                && endpoints.contains(&emission.endpoint),
            "invalid or duplicate effect position/endpoint"
        );
        ensure!(
            emission.fields.len() <= MAX_PAYLOAD_FIELDS,
            "effect field limit"
        );
        let mut names = BTreeSet::new();
        for field in &emission.fields {
            ensure!(
                names.insert(&field.schema.name),
                "duplicate effect payload field"
            );
            validate_payload_schema(manifest, &field.schema)?;
        }
    }
    Ok(())
}
pub(super) fn action_values<'a>(
    manifest: &Manifest,
    action: &'a Action,
    admission: &mut computation::Admission,
    used: &mut BTreeSet<&'a str>,
) -> Result<()> {
    let Some(contract) = &manifest.effects else {
        return Ok(());
    };
    for emission in contract
        .emissions
        .iter()
        .filter(|emission| emission.source_action == action.id)
    {
        for field in &emission.fields {
            validate_payload_schema(manifest, &field.schema)?;
            let domain = admission.effect_value(manifest, action, &field.value, used)?;
            ensure!(
                fits(&domain, &field.schema),
                "effect source domain does not fit payload schema"
            );
        }
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectSource {
    Input {
        name: String,
    },
    Constant {
        kind: FieldKind,
    },
    Principal,
    TransactionTime,
    Target {
        name: String,
    },
    Created {
        step: u8,
    },
    Snapshot {
        target: String,
        field: String,
        read: u32,
        reviewed: bool,
    },
}
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct EffectDisclosure {
    pub ordinal: u8,
    pub endpoint: String,
    pub field: Input,
    pub sources: Vec<EffectSource>,
}
fn collect(value: &Value, action: &Action, out: &mut Vec<EffectSource>) -> Result<()> {
    out.push(match value {
        Value::Input(name) => EffectSource::Input { name: name.clone() },
        Value::Literal(literal) => EffectSource::Constant {
            kind: computation::literal_domain(literal)?.kind,
        },
        Value::Principal => EffectSource::Principal,
        Value::TransactionTime => EffectSource::TransactionTime,
        Value::Target(name) => EffectSource::Target { name: name.clone() },
        Value::Created(step) => EffectSource::Created { step: *step },
        Value::SnapshotField {
            target,
            field,
            reviewed,
        } => EffectSource::Snapshot {
            target: target.clone(),
            field: field.clone(),
            reviewed: *reviewed,
            read: action_target(&action.targets, target)?
                .projection
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing effect projection"))?
                .operation,
        },
        Value::CurrentField { .. } => anyhow::bail!("effect cannot read step-current values"),
        Value::Add { left, right }
        | Value::Subtract { left, right }
        | Value::Multiply { left, right } => {
            collect(left, action, out)?;
            collect(right, action, out)?;
            return Ok(());
        }
    });
    Ok(())
}
pub fn effect_disclosures(manifest: &Manifest, id: u32) -> Result<Vec<EffectDisclosure>> {
    super::validate(manifest)?;
    disclosures(manifest, id)
}
fn disclosures(manifest: &Manifest, id: u32) -> Result<Vec<EffectDisclosure>> {
    let action = action(manifest, id)?;
    let mut out = Vec::new();
    if let Some(contract) = &manifest.effects {
        let mut emissions: Vec<_> = contract
            .emissions
            .iter()
            .filter(|emission| emission.source_action == id)
            .collect();
        emissions.sort_by_key(|emission| emission.ordinal);
        for emission in emissions {
            let mut fields: Vec<_> = emission.fields.iter().collect();
            fields.sort_by(|a, b| a.schema.name.cmp(&b.schema.name));
            for field in fields {
                let mut sources = Vec::new();
                collect(&field.value, action, &mut sources)?;
                out.push(EffectDisclosure {
                    ordinal: emission.ordinal,
                    endpoint: emission.endpoint.clone(),
                    field: field.schema.clone(),
                    sources,
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
