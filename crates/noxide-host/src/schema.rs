//! Host-interpreted application schema changes. Migration files contain data only.
use anyhow::{Context, Result, ensure};
use noxide_protocol::{FieldKind, Resource, TextField};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// A versioned, operator-approved transition between two normalized schemas.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migration {
    pub version: u32,
    pub from: String,
    pub to: String,
    pub operations: Vec<MigrationOp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum MigrationOp {
    AddResource {
        resource: String,
    },
    DropResource {
        resource: String,
    },
    RenameResource {
        from: String,
        to: String,
    },
    AddField {
        resource: String,
        field: String,
        value: String,
    },
    DropField {
        resource: String,
        field: String,
    },
    RenameField {
        resource: String,
        from: String,
        to: String,
    },
    ConvertField {
        resource: String,
        field: String,
        conversion: Conversion,
    },
    MapChoices {
        resource: String,
        field: String,
        mapping: BTreeMap<String, String>,
    },
    /// Adopt the destination constraints, rejecting any incompatible stored value.
    ChangeField {
        resource: String,
        field: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conversion {
    TextToInteger,
    IntegerToText,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppliedMigration {
    pub from: String,
    pub to: String,
    pub digest: String,
}

/// Ignore declaration ordering, bundle identifiers and presentation metadata.
pub fn normalized(resources: &[Resource]) -> Vec<Resource> {
    let mut resources = resources.to_vec();
    for resource in &mut resources {
        resource.id = 0;
        for field in &mut resource.fields {
            field.label = field.name.clone();
            if let FieldKind::Choice { variants } = &mut field.kind {
                for variant in variants.iter_mut() {
                    variant.label = variant.key.clone();
                }
                variants.sort_by(|a, b| a.key.cmp(&b.key));
            }
        }
        resource.fields.sort_by(|a, b| a.name.cmp(&b.name));
    }
    resources.sort_by(|a, b| a.name.cmp(&b.name));
    resources
}

pub fn digest(resources: &[Resource]) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&normalized(resources))?))
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Migration {
    pub(crate) fn validate(&self) -> Result<String> {
        ensure!(
            self.version == 1,
            "unsupported application migration version"
        );
        let fingerprint = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        };
        ensure!(
            fingerprint(&self.from) && fingerprint(&self.to),
            "invalid schema fingerprint"
        );
        ensure!(self.from != self.to, "migration must change the schema");
        ensure!(
            !self.operations.is_empty() && self.operations.len() <= 128,
            "migration operation limit"
        );
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= 65_536, "migration byte limit");
        Ok(hash(&bytes))
    }
}

pub(crate) fn resource<'a>(resources: &'a [Resource], key: &str) -> Result<&'a Resource> {
    resources
        .iter()
        .find(|r| r.name == key)
        .context("unknown migration resource")
}
pub(crate) fn field<'a>(resource: &'a Resource, key: &str) -> Result<&'a TextField> {
    resource
        .fields
        .iter()
        .find(|f| f.name == key)
        .context("unknown migration field")
}

/// Resolve every structural change before touching data. No removal is inferred.
pub(crate) fn transition(
    source: &[Resource],
    target: &[Resource],
    operations: &[MigrationOp],
) -> Result<()> {
    let mut current = normalized(source);
    let target = normalized(target);
    for op in operations {
        match op {
            MigrationOp::AddResource { resource: key } => {
                ensure!(
                    !current.iter().any(|r| &r.name == key),
                    "resource already exists"
                );
                current.push(resource(&target, key)?.clone());
            }
            MigrationOp::DropResource { resource: key } => {
                resource(&current, key)?;
                current.retain(|r| &r.name != key);
            }
            MigrationOp::RenameResource { from, to } => {
                ensure!(
                    !current.iter().any(|r| &r.name == to),
                    "resource destination already exists"
                );
                resource(&target, to)?;
                current
                    .iter_mut()
                    .find(|r| &r.name == from)
                    .context("unknown migration resource")?
                    .name = to.clone();
            }
            MigrationOp::AddField {
                resource: key,
                field: name,
                value,
            } => {
                let destination = field(resource(&target, key)?, name)?.clone();
                destination.canonical(value).map_err(anyhow::Error::msg)?;
                let r = current
                    .iter_mut()
                    .find(|r| &r.name == key)
                    .context("unknown migration resource")?;
                ensure!(
                    !r.fields.iter().any(|f| &f.name == name),
                    "field already exists"
                );
                r.fields.push(destination);
            }
            MigrationOp::DropField {
                resource: key,
                field: name,
            } => {
                let r = current
                    .iter_mut()
                    .find(|r| &r.name == key)
                    .context("unknown migration resource")?;
                field(r, name)?;
                r.fields.retain(|f| &f.name != name);
            }
            MigrationOp::RenameField {
                resource: key,
                from,
                to,
            } => {
                let r = current
                    .iter_mut()
                    .find(|r| &r.name == key)
                    .context("unknown migration resource")?;
                ensure!(
                    !r.fields.iter().any(|f| &f.name == to),
                    "field destination already exists"
                );
                field(resource(&target, key)?, to)?;
                let f = r
                    .fields
                    .iter_mut()
                    .find(|f| &f.name == from)
                    .context("unknown migration field")?;
                f.name = to.clone();
                f.label = to.clone();
                // Keep the source schema here. A following explicit operation
                // may convert or constrain the renamed field; the final equality
                // check rejects undeclared schema changes.
            }
            MigrationOp::ConvertField {
                resource: key,
                field: name,
                conversion,
            } => {
                let r = current
                    .iter_mut()
                    .find(|r| &r.name == key)
                    .context("unknown migration resource")?;
                let source = field(r, name)?;
                let destination = field(resource(&target, key)?, name)?;
                ensure!(
                    matches!(
                        (conversion, &source.kind, &destination.kind),
                        (
                            Conversion::TextToInteger,
                            FieldKind::Text,
                            FieldKind::Integer { .. }
                        ) | (
                            Conversion::IntegerToText,
                            FieldKind::Integer { .. },
                            FieldKind::Text
                        )
                    ),
                    "incompatible conversion"
                );
                *r.fields.iter_mut().find(|f| &f.name == name).unwrap() = destination.clone();
            }
            MigrationOp::MapChoices {
                resource: key,
                field: name,
                mapping,
            } => {
                let r = current
                    .iter_mut()
                    .find(|r| &r.name == key)
                    .context("unknown migration resource")?;
                let source = field(r, name)?;
                let destination = field(resource(&target, key)?, name)?;
                let (FieldKind::Choice { variants: before }, FieldKind::Choice { variants: after }) =
                    (&source.kind, &destination.kind)
                else {
                    anyhow::bail!("choice mapping requires enum fields")
                };
                ensure!(mapping.len() <= 32, "choice mapping limit");
                for (from, to) in mapping {
                    ensure!(
                        before.iter().any(|v| &v.key == from) && after.iter().any(|v| &v.key == to),
                        "invalid choice mapping"
                    );
                }
                *r.fields.iter_mut().find(|f| &f.name == name).unwrap() = destination.clone();
            }
            MigrationOp::ChangeField {
                resource: key,
                field: name,
            } => {
                let r = current
                    .iter_mut()
                    .find(|r| &r.name == key)
                    .context("unknown migration resource")?;
                let destination = field(resource(&target, key)?, name)?;
                let f = r
                    .fields
                    .iter_mut()
                    .find(|f| &f.name == name)
                    .context("unknown migration field")?;
                ensure!(
                    same_kind(&f.kind, &destination.kind),
                    "type changes require a conversion"
                );
                *f = destination.clone();
            }
        }
    }
    ensure!(
        normalized(&current) == target,
        "migration operations do not produce the target schema"
    );
    let keys: BTreeSet<_> = current.iter().map(|r| &r.name).collect();
    ensure!(keys.len() == current.len(), "duplicate migration resource");
    Ok(())
}

fn same_kind(a: &FieldKind, b: &FieldKind) -> bool {
    matches!(
        (a, b),
        (FieldKind::Text, FieldKind::Text)
            | (FieldKind::Boolean, FieldKind::Boolean)
            | (FieldKind::Integer { .. }, FieldKind::Integer { .. })
            | (FieldKind::Choice { .. }, FieldKind::Choice { .. })
            | (FieldKind::Parent { .. }, FieldKind::Parent { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> Vec<Resource> {
        crate::test_support::manifest().resources
    }

    #[test]
    fn renamed_field_can_be_converted_in_the_same_migration() {
        let source = source();
        let mut target = source.clone();
        let field = &mut target[0].fields[0];
        field.name = "count".into();
        field.kind = FieldKind::Integer {
            min: Some(0),
            max: Some(100),
        };
        field.max_bytes = 20;
        let rename = MigrationOp::RenameField {
            resource: "notes".into(),
            from: "body".into(),
            to: "count".into(),
        };
        assert!(transition(&source, &target, std::slice::from_ref(&rename)).is_err());
        transition(
            &source,
            &target,
            &[
                rename,
                MigrationOp::ConvertField {
                    resource: "notes".into(),
                    field: "count".into(),
                    conversion: Conversion::TextToInteger,
                },
            ],
        )
        .unwrap();
    }

    #[test]
    fn renamed_field_can_change_constraints_explicitly() {
        let source = source();
        let mut target = source.clone();
        target[0].fields[0].name = "content".into();
        target[0].fields[0].max_bytes = 2048;
        let rename = MigrationOp::RenameField {
            resource: "notes".into(),
            from: "body".into(),
            to: "content".into(),
        };
        assert!(transition(&source, &target, std::slice::from_ref(&rename)).is_err());
        transition(
            &source,
            &target,
            &[
                rename,
                MigrationOp::ChangeField {
                    resource: "notes".into(),
                    field: "content".into(),
                },
            ],
        )
        .unwrap();
    }

    #[test]
    fn constraint_change_cannot_replace_an_explicit_type_conversion() {
        let source = source();
        let mut target = source.clone();
        target[0].fields[0].kind = FieldKind::Boolean;
        target[0].fields[0].max_bytes = 5;
        assert!(
            transition(
                &source,
                &target,
                &[MigrationOp::ChangeField {
                    resource: "notes".into(),
                    field: "body".into()
                },]
            )
            .is_err()
        );
    }
}
