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
    /// Activate the approved index only after an explicit canonical rebuild.
    AddSearchIndex {
        resource: String,
    },
    RebuildSearchIndex {
        resource: String,
    },
    RemoveSearchIndex {
        resource: String,
    },
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
    /// Explicitly adopt only the approved target's gate, expiry and unique tuples.
    ChangeResourceAuthority {
        resource: String,
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
pub struct AppliedMigration {
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
            field.initial = None;
            if let FieldKind::Choice { variants } = &mut field.kind {
                for variant in variants.iter_mut() {
                    variant.label = variant.key.clone();
                }
                variants.sort_by(|a, b| a.key.cmp(&b.key));
            }
        }
        resource.fields.sort_by(|a, b| a.name.cmp(&b.name));
        resource
            .unique
            .sort_by(|a, b| (&a.reference, &a.account).cmp(&(&b.reference, &b.account)));
    }
    resources.sort_by(|a, b| a.name.cmp(&b.name));
    resources
}

pub fn digest(resources: &[Resource]) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&normalized(resources))?))
}

pub fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Migration {
    pub fn validate(&self) -> Result<String> {
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

pub fn resource<'a>(resources: &'a [Resource], key: &str) -> Result<&'a Resource> {
    resources
        .iter()
        .find(|r| r.name == key)
        .context("unknown migration resource")
}
pub fn field<'a>(resource: &'a Resource, key: &str) -> Result<&'a TextField> {
    resource
        .fields
        .iter()
        .find(|f| f.name == key)
        .context("unknown migration field")
}

/// Resolve every structural change before touching data. No removal is inferred.
#[allow(clippy::too_many_lines)]
pub fn transition(
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
                ensure!(
                    resource(&current, key)?.search.is_none(),
                    "search resource removal requires explicit RemoveSearchIndex"
                );
                ensure!(
                    !resource(&current, key)?
                        .fields
                        .iter()
                        .any(|f| matches!(f.kind, FieldKind::Blob { .. })),
                    "blob resource removal requires atomic attachment maintenance"
                );
                current.retain(|r| &r.name != key);
            }
            MigrationOp::RenameResource { from, to } => {
                ensure!(
                    !resource(&current, from)?
                        .fields
                        .iter()
                        .any(|f| matches!(f.kind, FieldKind::Blob { .. })),
                    "blob resource renaming requires attachment migration proof"
                );
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
                ensure!(
                    !matches!(
                        destination.kind,
                        FieldKind::Account { .. }
                            | FieldKind::Reference { .. }
                            | FieldKind::Blob { .. }
                            | FieldKind::UploadHandle { .. }
                    ),
                    "identity and attachment bindings require creation of a new record"
                );
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
                ensure!(
                    !matches!(field(r, name)?.kind, FieldKind::Blob { .. }),
                    "blob field removal requires atomic attachment maintenance"
                );
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
                ensure!(
                    !matches!(f.kind, FieldKind::Blob { .. }),
                    "blob field renaming requires atomic attachment maintenance"
                );
                f.name = to.clone();
                f.label = to.clone();
                if let Some(gate) = &mut r.gate
                    && gate.field == *from
                {
                    gate.field = to.clone();
                }
                if let Some(expiry) = &mut r.expiry
                    && expiry.field == *from
                {
                    expiry.field = to.clone();
                }
                for unique in &mut r.unique {
                    if unique.reference == *from {
                        unique.reference = to.clone();
                    }
                    if unique.account == *from {
                        unique.account = to.clone();
                    }
                }
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
            MigrationOp::AddSearchIndex { resource: key } => {
                let destination = resource(&target, key)?
                    .search
                    .clone()
                    .context("AddSearchIndex requires an approved target index")?;
                let r = current
                    .iter_mut()
                    .find(|r| &r.name == key)
                    .context("unknown migration resource")?;
                ensure!(r.search.is_none(), "search index already exists");
                r.search = Some(destination);
            }
            MigrationOp::RebuildSearchIndex { resource: key } => {
                let destination = resource(&target, key)?
                    .search
                    .clone()
                    .context("RebuildSearchIndex requires an approved target index")?;
                let r = current
                    .iter_mut()
                    .find(|r| &r.name == key)
                    .context("unknown migration resource")?;
                ensure!(r.search.is_some(), "search index does not exist");
                r.search = Some(destination);
            }
            MigrationOp::RemoveSearchIndex { resource: key } => {
                ensure!(
                    target
                        .iter()
                        .find(|r| &r.name == key)
                        .is_none_or(|r| r.search.is_none()),
                    "RemoveSearchIndex requires no target index"
                );
                let r = current
                    .iter_mut()
                    .find(|r| &r.name == key)
                    .context("unknown migration resource")?;
                ensure!(r.search.take().is_some(), "search index does not exist");
            }
            MigrationOp::ChangeResourceAuthority { resource: key } => {
                let destination = resource(&target, key)?;
                let r = current
                    .iter_mut()
                    .find(|r| &r.name == key)
                    .context("unknown migration resource")?;
                r.gate = destination.gate.clone();
                r.expiry = destination.expiry.clone();
                r.unique = destination.unique.clone();
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
    if let (FieldKind::Account { scope: a }, FieldKind::Account { scope: b }) = (a, b) {
        return a == b;
    }
    if let (FieldKind::Reference { resource: a }, FieldKind::Reference { resource: b }) = (a, b) {
        return a == b;
    }
    matches!(
        (a, b),
        (FieldKind::Text, FieldKind::Text)
            | (FieldKind::Boolean, FieldKind::Boolean)
            | (FieldKind::Timestamp, FieldKind::Timestamp)
            | (FieldKind::Duration { .. }, FieldKind::Duration { .. })
            | (FieldKind::Integer { .. }, FieldKind::Integer { .. })
            | (FieldKind::Choice { .. }, FieldKind::Choice { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> Vec<Resource> {
        noxide_test_support::manifest().resources
    }

    #[test]
    fn blob_associations_cannot_be_reinterpreted_by_schema_migrations() {
        let mut before = source();
        let key = before[0].name.clone();
        let name = before[0].fields[0].name.clone();
        before[0].fields[0].kind = FieldKind::Blob { max_bytes: 1024 };
        before[0].fields[0].max_bytes = 67;
        let mut target = before.clone();
        target.remove(0);
        assert!(
            transition(
                &before,
                &target,
                &[MigrationOp::DropResource {
                    resource: key.clone()
                }]
            )
            .is_err()
        );
        let mut target = before.clone();
        target[0].name = "renamed".into();
        assert!(
            transition(
                &before,
                &target,
                &[MigrationOp::RenameResource {
                    from: key.clone(),
                    to: "renamed".into()
                }]
            )
            .is_err()
        );
        let mut target = before.clone();
        target[0].fields.remove(0);
        assert!(
            transition(
                &before,
                &target,
                &[MigrationOp::DropField {
                    resource: key.clone(),
                    field: name.clone()
                }]
            )
            .is_err()
        );
        let mut target = before.clone();
        target[0].fields[0].name = "attachment".into();
        target[0].fields[0].label = "attachment".into();
        assert!(
            transition(
                &before,
                &target,
                &[MigrationOp::RenameField {
                    resource: key.clone(),
                    from: name.clone(),
                    to: "attachment".into()
                }]
            )
            .is_err()
        );
        let mut target = before.clone();
        target[0].fields[0].kind = FieldKind::Text;
        assert!(
            transition(
                &before,
                &target,
                &[MigrationOp::ChangeField {
                    resource: key.clone(),
                    field: name.clone()
                }]
            )
            .is_err()
        );
        assert!(
            transition(
                &before,
                &target,
                &[MigrationOp::ConvertField {
                    resource: key.clone(),
                    field: name.clone(),
                    conversion: Conversion::IntegerToText
                }]
            )
            .is_err()
        );
        let mut empty = before.clone();
        empty[0].fields.remove(0);
        assert!(
            transition(
                &empty,
                &before,
                &[MigrationOp::AddField {
                    resource: key,
                    field: name,
                    value: format!("b1_{}", "a".repeat(64))
                }]
            )
            .is_err()
        );
        assert!(
            transition(
                &[],
                &before,
                &[MigrationOp::AddResource {
                    resource: before[0].name.clone()
                }]
            )
            .is_ok()
        );
    }

    fn authority_source() -> Vec<Resource> {
        let mut resources = source();
        let mut parent = resources[0].clone();
        parent.id = 2;
        parent.name = "parents".into();
        parent.fields[0].kind = FieldKind::Boolean;
        for (name, kind) in [
            (
                "workspace",
                FieldKind::Reference {
                    resource: "parents".into(),
                },
            ),
            (
                "project",
                FieldKind::Reference {
                    resource: "parents".into(),
                },
            ),
            (
                "account",
                FieldKind::Account {
                    scope: noxide_protocol::AccountScope::SameTenant,
                },
            ),
            ("expires", FieldKind::Timestamp),
        ] {
            resources[0].fields.push(TextField {
                immutable: false,
                name: name.into(),
                label: name.into(),
                kind,
                optional: false,
                initial: None,
                max_bytes: 64,
            });
        }
        resources.push(parent);
        resources
    }

    #[test]
    fn authority_is_hashed_canonically_and_requires_explicit_adoption() {
        use noxide_protocol::{
            expiry::ResourceExpiry, membership::MembershipUnique, time::Duration,
        };
        let source = authority_source();
        let mut target = source.clone();
        target[0].expiry = Some(ResourceExpiry {
            field: "expires".into(),
            max_after: Duration::from_secs(60).unwrap(),
        });
        target[0].unique = vec![
            MembershipUnique {
                reference: "workspace".into(),
                account: "account".into(),
            },
            MembershipUnique {
                reference: "project".into(),
                account: "account".into(),
            },
        ];
        target[0].gate = Some(noxide_protocol::Gate {
            field: "workspace".into(),
            visible: noxide_protocol::Visibility {
                field: "body".into(),
                equals: "true".into(),
            },
            create_when: noxide_protocol::Visibility {
                field: "body".into(),
                equals: "true".into(),
            },
        });
        assert_ne!(digest(&source).unwrap(), digest(&target).unwrap());
        let mut reversed = target.clone();
        reversed[0].unique.reverse();
        assert_eq!(digest(&target).unwrap(), digest(&reversed).unwrap());
        assert!(transition(&source, &target, &[]).is_err());
        let adopt = MigrationOp::ChangeResourceAuthority {
            resource: "notes".into(),
        };
        transition(&source, &target, std::slice::from_ref(&adopt)).unwrap();
        reversed[0].expiry.as_mut().unwrap().max_after = Duration::from_secs(61).unwrap();
        assert_ne!(digest(&target).unwrap(), digest(&reversed).unwrap());
        // An authority operation cannot silently alter field storage or names.
        target[0].fields[0].max_bytes += 1;
        assert!(transition(&source, &target, &[adopt]).is_err());
    }

    #[test]
    fn field_rename_preserves_local_authority_bindings() {
        use noxide_protocol::{
            expiry::ResourceExpiry, membership::MembershipUnique, time::Duration,
        };
        let mut source = authority_source();
        source[0].expiry = Some(ResourceExpiry {
            field: "expires".into(),
            max_after: Duration::ZERO,
        });
        source[0].unique = vec![MembershipUnique {
            reference: "workspace".into(),
            account: "account".into(),
        }];
        source[0].gate = Some(noxide_protocol::Gate {
            field: "workspace".into(),
            visible: noxide_protocol::Visibility {
                field: "body".into(),
                equals: "true".into(),
            },
            create_when: noxide_protocol::Visibility {
                field: "body".into(),
                equals: "true".into(),
            },
        });
        let mut target = source.clone();
        let renames = [
            ("workspace", "group"),
            ("account", "member"),
            ("expires", "until"),
        ];
        for (from, to) in renames {
            target[0]
                .fields
                .iter_mut()
                .find(|f| f.name == from)
                .unwrap()
                .name = to.into();
        }
        target[0].expiry.as_mut().unwrap().field = "until".into();
        target[0].gate.as_mut().unwrap().field = "group".into();
        target[0].unique[0].reference = "group".into();
        target[0].unique[0].account = "member".into();
        let operations: Vec<_> = renames
            .into_iter()
            .map(|(from, to)| MigrationOp::RenameField {
                resource: "notes".into(),
                from: from.into(),
                to: to.into(),
            })
            .collect();
        transition(&source, &target, &operations).unwrap();
    }

    #[test]
    fn account_constraints_can_change_without_converting_identity() {
        let mut source = source();
        source[0].fields[0].kind = FieldKind::Account {
            scope: noxide_protocol::AccountScope::SameTenant,
        };
        source[0].fields[0].max_bytes = 1024;
        let mut target = source.clone();
        target[0].fields[0].max_bytes = 43;
        let change = MigrationOp::ChangeField {
            resource: "notes".into(),
            field: "body".into(),
        };
        transition(&source, &target, std::slice::from_ref(&change)).unwrap();
        let mut text = source.clone();
        text[0].fields[0].kind = FieldKind::Text;
        assert!(transition(&text, &target, std::slice::from_ref(&change)).is_err());
        assert!(transition(&source, &text, &[change]).is_err());
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

#[cfg(test)]
mod search_transition_tests {
    use super::*;
    fn source() -> Vec<Resource> {
        noxide_test_support::manifest().resources
    }
    fn index(max_bytes: u32) -> noxide_protocol::query::SearchIndex {
        noxide_protocol::query::SearchIndex {
            tokenizer: noxide_protocol::query::TOKENIZER_ID.into(),
            fields: vec!["body".into()],
            max_bytes,
        }
    }
    #[test]
    fn search_activation_changes_require_exact_explicit_operations() {
        let before = source();
        let key = before[0].name.clone();
        let mut indexed = before.clone();
        indexed[0].search = Some(index(4096));
        let add = MigrationOp::AddSearchIndex {
            resource: key.clone(),
        };
        let rebuild = MigrationOp::RebuildSearchIndex {
            resource: key.clone(),
        };
        let remove = MigrationOp::RemoveSearchIndex {
            resource: key.clone(),
        };
        let authority = MigrationOp::ChangeResourceAuthority {
            resource: key.clone(),
        };
        assert!(transition(&before, &indexed, &[]).is_err());
        assert!(transition(&before, &indexed, std::slice::from_ref(&authority)).is_err());
        assert!(transition(&before, &indexed, std::slice::from_ref(&rebuild)).is_err());
        transition(&before, &indexed, std::slice::from_ref(&add)).unwrap();
        assert!(transition(&indexed, &indexed, &[add]).is_err());
        let mut changed = indexed.clone();
        changed[0].search = Some(index(2048));
        assert!(transition(&indexed, &changed, &[authority]).is_err());
        transition(&indexed, &changed, &[rebuild]).unwrap();
        assert!(transition(&indexed, &changed, std::slice::from_ref(&remove)).is_err());
        transition(&indexed, &before, std::slice::from_ref(&remove)).unwrap();
        assert!(transition(&before, &before, &[remove]).is_err());
    }
    #[test]
    fn search_removal_precedes_drop_and_rename_preserves_storage_semantics() {
        let mut indexed = source();
        let key = indexed[0].name.clone();
        indexed[0].search = Some(index(4096));
        let drop = MigrationOp::DropResource {
            resource: key.clone(),
        };
        let remove = MigrationOp::RemoveSearchIndex {
            resource: key.clone(),
        };
        assert!(transition(&indexed, &[], std::slice::from_ref(&drop)).is_err());
        assert!(transition(&indexed, &[], &[drop.clone(), remove.clone()]).is_err());
        transition(&indexed, &[], &[remove, drop]).unwrap();
        let mut renamed = indexed.clone();
        renamed[0].name = "renamed_notes".into();
        transition(
            &indexed,
            &renamed,
            &[MigrationOp::RenameResource {
                from: key,
                to: "renamed_notes".into(),
            }],
        )
        .unwrap();
        transition(
            &[],
            &indexed,
            &[MigrationOp::AddResource {
                resource: indexed[0].name.clone(),
            }],
        )
        .unwrap();
    }
    #[test]
    fn indexed_field_rename_requires_explicit_metadata_rebuild_and_same_schema_stays_denied() {
        let mut before = source();
        let key = before[0].name.clone();
        before[0].search = Some(index(4096));
        let mut after = before.clone();
        after[0].fields[0].name = "text".into();
        after[0].search.as_mut().unwrap().fields = vec!["text".into()];
        let rename = MigrationOp::RenameField {
            resource: key.clone(),
            from: "body".into(),
            to: "text".into(),
        };
        assert!(transition(&before, &after, std::slice::from_ref(&rename)).is_err());
        transition(
            &before,
            &after,
            &[rename, MigrationOp::RebuildSearchIndex { resource: key }],
        )
        .unwrap();
        let digest = digest(&before).unwrap();
        assert!(
            Migration {
                version: 1,
                from: digest.clone(),
                to: digest,
                operations: vec![MigrationOp::RebuildSearchIndex {
                    resource: before[0].name.clone()
                }]
            }
            .validate()
            .is_err()
        );
        assert!(
            serde_json::from_str::<MigrationOp>(
                r#"{"op":"add_search_index","resource":"notes","unchecked":true}"#
            )
            .is_err()
        );
    }
}
