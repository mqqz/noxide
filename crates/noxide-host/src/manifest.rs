use anyhow::{Result, ensure};
use noxide_protocol::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub fn parse(bytes: &[u8]) -> Result<Manifest> {
    ensure!(bytes.len() <= MAX_MANIFEST_BYTES, "manifest limit");
    let manifest: Manifest = serde_json::from_slice(bytes)?;
    validate(&manifest)?;
    Ok(manifest)
}

pub fn digest(manifest: &Manifest) -> Result<[u8; 32]> {
    validate(manifest)?;
    Ok(Sha256::digest(serde_json::to_vec(manifest)?).into())
}

fn unique(ids: impl Iterator<Item = u32>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for id in ids {
        ensure!(id != 0 && seen.insert(id), "duplicate or zero identifier");
    }
    Ok(())
}

pub fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub fn validate(m: &Manifest) -> Result<()> {
    ensure!(m.version == VERSION, "unsupported manifest version");
    ensure!(
        !m.resources.is_empty() && m.resources.len() <= 16,
        "resource limit"
    );
    ensure!(!m.routes.is_empty() && m.routes.len() <= 32, "route limit");
    ensure!(
        m.operations.len() <= 64 && m.actions.len() <= 32,
        "contract limit"
    );
    unique(m.resources.iter().map(|x| x.id))?;
    unique(m.operations.iter().map(|x| x.id))?;
    unique(m.routes.iter().map(|x| x.id))?;
    unique(m.actions.iter().map(|x| x.id))?;
    let mut resource_keys = BTreeSet::new();
    for r in &m.resources {
        ensure!(
            identifier(&r.name)
                && resource_keys.insert(&r.name)
                && !r.fields.is_empty()
                && r.fields.len() <= 8,
            "invalid resource"
        );
        let mut fields = BTreeSet::new();
        for f in &r.fields {
            ensure!(
                identifier(&f.name) && fields.insert(&f.name),
                "invalid field"
            );
            ensure!(f.max_bytes > 0 && f.max_bytes <= 4096, "field limit");
            match &f.kind {
                FieldKind::Text => {}
                FieldKind::Boolean => ensure!(f.max_bytes >= 5, "boolean field budget"),
                FieldKind::Integer { min, max } => {
                    ensure!(
                        f.max_bytes >= 20 && min.zip(*max).is_none_or(|(min, max)| min <= max),
                        "integer schema"
                    );
                }
                FieldKind::Choice { variants } => {
                    ensure!(!variants.is_empty() && variants.len() <= 32, "choice limit");
                    let mut keys = BTreeSet::new();
                    for v in variants {
                        ensure!(
                            identifier(&v.key)
                                && keys.insert(&v.key)
                                && v.key.len() <= f.max_bytes as usize,
                            "choice key"
                        );
                        ensure!(
                            !v.label.is_empty()
                                && v.label.len() <= 128
                                && !v.label.chars().any(char::is_control),
                            "choice label"
                        );
                    }
                }
            }
            ensure!(
                !f.label.is_empty()
                    && f.label.len() <= 128
                    && !f.label.chars().any(char::is_control),
                "invalid label"
            );
        }
        ensure!(
            r.fields.iter().map(|f| f.max_bytes as usize).sum::<usize>() <= 8192,
            "record limit"
        );
    }
    for op in &m.operations {
        ensure!(
            m.resources.iter().any(|r| r.id == op.resource),
            "unknown resource"
        );
        ensure!(
            !op.policy.any.is_empty() && op.policy.any.len() <= 8,
            "invalid policy"
        );
        for rule in &op.policy.any {
            ensure!(!rule.is_empty() && rule.len() <= 4, "invalid policy rule");
            for p in rule {
                if let Predicate::Role { name, .. } = p {
                    ensure!(identifier(name), "invalid role");
                }
            }
        }
    }
    let mut paths = BTreeSet::new();
    for r in &m.routes {
        crate::render::validate_path(r)?;
        ensure!(paths.insert(&r.path), "duplicate route path");
        for other in &m.routes {
            if other.id != r.id {
                ensure!(
                    !crate::render::paths_overlap(r, other),
                    "ambiguous route patterns"
                );
            }
        }
        unique(r.operations.iter().copied())?;
        unique(r.forms.iter().copied())?;
        ensure!(
            r.resource.is_some() || r.operations.len() <= 1,
            "a list route has one cursor scope"
        );
        for id in &r.operations {
            let op = operation(m, *id)?;
            ensure!(
                matches!(
                    (&op.kind, r.resource.is_some()),
                    (OperationKind::List, false) | (OperationKind::Read, true)
                ),
                "route operation mismatch"
            );
            ensure!(
                r.resource.is_none_or(|resource| resource == op.resource),
                "route resource mismatch"
            );
        }
        if let Some(id) = r.resource {
            resource(m, id)?;
            ensure!(
                !r.operations.is_empty(),
                "record route requires a read operation"
            );
        }
        for id in &r.forms {
            let a = action(m, *id)?;
            let op = operation(m, a.operation)?;
            if op.kind != OperationKind::Create {
                ensure!(
                    r.resource == Some(op.resource),
                    "mutation form requires its record route"
                );
            }
        }
    }
    ensure!(
        m.routes
            .iter()
            .any(|r| r.path == "/" && r.resource.is_none()),
        "missing index route"
    );
    for a in &m.actions {
        ensure!(
            a.version > 0
                && !a.name.is_empty()
                && a.name.len() <= 64
                && !a.name.chars().any(char::is_control),
            "invalid action"
        );
        let op = operation(m, a.operation)?;
        let fields = action_fields(m, a)?;
        match op.kind {
            OperationKind::Create => ensure!(
                fields.len() == resource(m, op.resource)?.fields.len(),
                "creation requires every field"
            ),
            OperationKind::Update => ensure!(!fields.is_empty(), "update requires writable fields"),
            OperationKind::Delete => ensure!(fields.is_empty(), "delete has no writable fields"),
            _ => anyhow::bail!("action must declare a mutation"),
        }
        if let Some(inspect) = &a.inspect {
            let read = operation(m, inspect.operation)?;
            ensure!(
                op.kind != OperationKind::Create
                    && read.kind == OperationKind::Read
                    && read.resource == op.resource,
                "invalid inspection operation"
            );
            ensure!(!inspect.fields.is_empty(), "empty inspection");
            projected_fields(resource(m, op.resource)?, &inspect.fields)?;
        }
        validate_layout(m, a)?;
        let r = route(m, a.redirect)?;
        ensure!(
            if op.kind == OperationKind::Delete {
                r.resource.is_none()
            } else {
                r.resource == Some(op.resource)
            },
            "invalid outcome route"
        );
    }
    Ok(())
}

pub fn operation(m: &Manifest, id: u32) -> Result<&Operation> {
    m.operations
        .iter()
        .find(|o| o.id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown operation"))
}
pub fn resource(m: &Manifest, id: u32) -> Result<&Resource> {
    m.resources
        .iter()
        .find(|o| o.id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown resource"))
}
pub fn route(m: &Manifest, id: u32) -> Result<&Route> {
    m.routes
        .iter()
        .find(|o| o.id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown route"))
}
pub fn action(m: &Manifest, id: u32) -> Result<&Action> {
    m.actions
        .iter()
        .find(|o| o.id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown action"))
}
pub fn validate_fields(resource: &Resource, fields: &Fields) -> Result<()> {
    ensure!(fields.len() == resource.fields.len(), "unexpected fields");
    for f in &resource.fields {
        validate_field(f, fields)?;
    }
    Ok(())
}

fn projected_fields<'a>(resource: &'a Resource, names: &[String]) -> Result<Vec<&'a TextField>> {
    ensure!(
        names.len() <= resource.fields.len(),
        "field projection limit"
    );
    let mut seen = BTreeSet::new();
    names
        .iter()
        .map(|name| {
            ensure!(seen.insert(name), "duplicate projected field");
            resource
                .fields
                .iter()
                .find(|field| &field.name == name)
                .ok_or_else(|| anyhow::anyhow!("unknown projected field"))
        })
        .collect()
}

pub(crate) fn action_fields<'a>(m: &'a Manifest, action: &Action) -> Result<Vec<&'a TextField>> {
    projected_fields(
        resource(m, operation(m, action.operation)?.resource)?,
        &action.fields,
    )
}

pub(crate) fn validate_input(m: &Manifest, action: &Action, fields: &Fields) -> Result<()> {
    let declared = action_fields(m, action)?;
    ensure!(fields.len() == declared.len(), "unexpected action fields");
    for field in declared {
        validate_field(field, fields)?;
    }
    Ok(())
}

pub fn validate_value(field: &TextField, value: &str) -> Result<()> {
    let canonical = field.canonical(value).map_err(anyhow::Error::msg)?;
    ensure!(canonical == value, "noncanonical stored value");
    Ok(())
}

fn validate_field(f: &TextField, fields: &Fields) -> Result<()> {
    let value = fields
        .get(&f.name)
        .ok_or_else(|| anyhow::anyhow!("missing field"))?;
    validate_value(f, value)
}

/// Normalize browser input once, before receipt binding and guest execution.
pub fn canonical_input(m: &Manifest, action: &Action, input: &Fields) -> Result<Fields> {
    ensure!(
        input.keys().all(|key| action.fields.contains(key)),
        "unexpected action field"
    );
    action_fields(m, action)?
        .into_iter()
        .map(|field| {
            let raw = match input.get(&field.name) {
                Some(value) => value.as_str(),
                None if field.optional => "",
                None if field.kind == FieldKind::Boolean => "false",
                None => return Err(anyhow::anyhow!("missing required field")),
            };
            let value = field.canonical(raw).map_err(anyhow::Error::msg)?;
            Ok((field.name.clone(), value))
        })
        .collect()
}

fn validate_layout(m: &Manifest, action: &Action) -> Result<()> {
    if action.layout.is_empty() {
        return Ok(());
    }
    ensure!(
        action.layout.len() <= MAX_NODES
            && serde_json::to_vec(&action.layout)?.len() <= MAX_IR_BYTES,
        "form layout limit"
    );
    let fields = action_fields(m, action)?;
    let mut seen = BTreeSet::new();
    let mut stack = Vec::new();
    let mut submit = false;
    for node in &action.layout {
        match node {
            FormInstruction::Begin(c) => {
                ensure!(
                    matches!(
                        c,
                        Container::Section
                            | Container::Div
                            | Container::Article
                            | Container::Header
                            | Container::Footer
                            | Container::Paragraph
                            | Container::Strong
                            | Container::Emphasis
                            | Container::Heading1
                            | Container::Heading2
                    ),
                    "form container"
                );
                ensure!(stack.len() < MAX_DEPTH, "form depth");
                let phrasing = |c: &Container| {
                    matches!(
                        c,
                        Container::Paragraph
                            | Container::Strong
                            | Container::Emphasis
                            | Container::Heading1
                            | Container::Heading2
                    )
                };
                ensure!(
                    !stack.last().is_some_and(phrasing)
                        || matches!(c, Container::Strong | Container::Emphasis),
                    "form content model"
                );
                stack.push(c.clone());
            }
            FormInstruction::End => {
                ensure!(stack.pop().is_some(), "unmatched form end");
            }
            FormInstruction::Text(text) => ensure!(
                text.len() <= 4096
                    && !text
                        .chars()
                        .any(|c| c.is_control() && !matches!(c, '\n' | '\t')),
                "form text"
            ),
            FormInstruction::Field { name, control } => {
                ensure!(
                    !stack.last().is_some_and(|c| matches!(
                        c,
                        Container::Paragraph
                            | Container::Strong
                            | Container::Emphasis
                            | Container::Heading1
                            | Container::Heading2
                    )),
                    "form field context"
                );
                let f = fields
                    .iter()
                    .find(|f| f.name == *name)
                    .ok_or_else(|| anyhow::anyhow!("unknown form field"))?;
                ensure!(seen.insert(name), "duplicate form field");
                ensure!(
                    match control {
                        Control::Auto => true,
                        Control::TextInput =>
                            matches!(f.kind, FieldKind::Text | FieldKind::Integer { .. }),
                        Control::Textarea { rows } =>
                            matches!(f.kind, FieldKind::Text) && (1..=40).contains(rows),
                        Control::Checkbox => f.kind == FieldKind::Boolean && !f.optional,
                        Control::Select =>
                            matches!(f.kind, FieldKind::Choice { .. })
                                || f.kind == FieldKind::Boolean && f.optional,
                    },
                    "incompatible form control"
                );
            }
            FormInstruction::Submit { label } => {
                ensure!(
                    !submit
                        && !label.is_empty()
                        && label.len() <= 128
                        && !label.chars().any(char::is_control),
                    "form submit"
                );
                ensure!(
                    !stack.last().is_some_and(|c| matches!(
                        c,
                        Container::Paragraph
                            | Container::Strong
                            | Container::Emphasis
                            | Container::Heading1
                            | Container::Heading2
                    )),
                    "submit context"
                );
                submit = true;
            }
        }
    }
    ensure!(
        stack.is_empty() && submit && seen.len() == fields.len(),
        "incomplete form layout"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, kind: FieldKind, optional: bool) -> TextField {
        TextField {
            name: name.into(),
            label: name.into(),
            max_bytes: 200,
            kind,
            optional,
        }
    }

    fn schema(fields: Vec<TextField>) -> Manifest {
        let mut manifest = crate::test_support::manifest();
        manifest.actions[0].fields = fields.iter().map(|field| field.name.clone()).collect();
        manifest.resources[0].fields = fields;
        validate(&manifest).unwrap();
        manifest
    }

    #[test]
    fn canonical_input_fills_only_schema_defined_absence() {
        let manifest = schema(vec![
            field("done", FieldKind::Boolean, false),
            field("flag", FieldKind::Boolean, true),
            field("details", FieldKind::Text, true),
            field(
                "estimate",
                FieldKind::Integer {
                    min: None,
                    max: None,
                },
                true,
            ),
        ]);
        let action = &manifest.actions[0];
        let input = canonical_input(&manifest, action, &Fields::new()).unwrap();
        assert_eq!(
            input,
            Fields::from([
                ("done".into(), "false".into()),
                ("flag".into(), "".into()),
                ("details".into(), "".into()),
                ("estimate".into(), "".into()),
            ])
        );
        validate_input(&manifest, action, &input).unwrap();
        assert!(
            canonical_input(
                &manifest,
                action,
                &Fields::from([("foreign".into(), "x".into())])
            )
            .is_err()
        );
        let required = schema(vec![field("body", FieldKind::Text, false)]);
        assert!(canonical_input(&required, &required.actions[0], &Fields::new()).is_err());
    }

    #[test]
    fn integer_forms_have_one_canonical_value_and_checked_bounds() {
        let manifest = schema(vec![field(
            "estimate",
            FieldKind::Integer {
                min: Some(-5),
                max: Some(10),
            },
            false,
        )]);
        let action = &manifest.actions[0];
        let canonical = |raw: &str| {
            canonical_input(
                &manifest,
                action,
                &Fields::from([("estimate".into(), raw.into())]),
            )
        };
        assert_eq!(canonical("+01").unwrap(), canonical("1").unwrap());
        assert_eq!(canonical("-0").unwrap()["estimate"], "0");
        for valid in ["-5", "10"] {
            assert!(canonical(valid).is_ok());
        }
        for invalid in [
            "-6",
            "11",
            "9223372036854775808",
            "-9223372036854775809",
            "1.0",
            "1e0",
            " 1",
            "",
        ] {
            assert!(canonical(invalid).is_err(), "{invalid}");
        }
        // Stored values are stricter than transport input: canonicalize once,
        // then reject any noncanonical value crossing back from persistence.
        assert!(validate_value(&manifest.resources[0].fields[0], "+01").is_err());
    }

    #[test]
    fn text_canonicalization_preserves_whitespace_and_normalizes_newlines() {
        let manifest = schema(vec![field("body", FieldKind::Text, false)]);
        let action = &manifest.actions[0];
        let input = canonical_input(
            &manifest,
            action,
            &Fields::from([("body".into(), " \r\nline\r\t ".into())]),
        )
        .unwrap();
        assert_eq!(input["body"], " \nline\n\t ");
        let whitespace = canonical_input(
            &manifest,
            action,
            &Fields::from([("body".into(), "   ".into())]),
        )
        .unwrap();
        assert_eq!(whitespace["body"], "   ");
        assert!(
            canonical_input(
                &manifest,
                action,
                &Fields::from([("body".into(), "\0".into())])
            )
            .is_err()
        );
        assert!(
            canonical_input(
                &manifest,
                action,
                &Fields::from([("body".into(), "é".repeat(101))])
            )
            .is_err()
        );
    }

    #[test]
    fn enum_keys_and_boolean_encoding_are_host_validated() {
        let manifest = schema(vec![
            field(
                "priority",
                FieldKind::Choice {
                    variants: vec![ChoiceVariant {
                        key: "high".into(),
                        label: "High priority".into(),
                    }],
                },
                false,
            ),
            field("done", FieldKind::Boolean, false),
        ]);
        let action = &manifest.actions[0];
        let canonical = canonical_input(
            &manifest,
            action,
            &Fields::from([
                ("priority".into(), "high".into()),
                ("done".into(), "on".into()),
            ]),
        )
        .unwrap();
        assert_eq!(canonical["done"], "true");
        for invalid in ["High priority", "unknown", ""] {
            assert!(
                canonical_input(
                    &manifest,
                    action,
                    &Fields::from([("priority".into(), invalid.into())])
                )
                .is_err()
            );
        }
        assert!(
            canonical_input(
                &manifest,
                action,
                &Fields::from([
                    ("priority".into(), "high".into()),
                    ("done".into(), "yes".into()),
                ])
            )
            .is_err()
        );
    }

    fn layout_field(name: &str, control: Control) -> FormInstruction {
        FormInstruction::Field {
            name: name.into(),
            control,
        }
    }

    fn submit() -> FormInstruction {
        FormInstruction::Submit {
            label: "Save changes".into(),
        }
    }

    #[test]
    fn optional_boolean_requires_a_control_that_represents_unset() {
        let mut manifest = schema(vec![field("flag", FieldKind::Boolean, true)]);
        manifest.actions[0].layout = vec![layout_field("flag", Control::Select), submit()];
        validate(&manifest).unwrap();
        manifest.actions[0].layout[0] = layout_field("flag", Control::Checkbox);
        assert!(validate(&manifest).is_err());
        manifest.resources[0].fields[0].optional = false;
        validate(&manifest).unwrap();
        manifest.actions[0].layout[0] = layout_field("flag", Control::Select);
        assert!(validate(&manifest).is_err());
    }

    #[test]
    fn blueprint_requires_exactly_the_declared_fields_and_one_submit() {
        let mut manifest = schema(vec![field("body", FieldKind::Text, false)]);
        manifest.actions[0].layout = vec![
            FormInstruction::Begin(Container::Section),
            FormInstruction::Text("Review changes".into()),
            layout_field("body", Control::Textarea { rows: 12 }),
            submit(),
            FormInstruction::End,
        ];
        validate(&manifest).unwrap();
        for invalid in [
            vec![submit()],
            vec![
                layout_field("body", Control::Auto),
                layout_field("body", Control::Auto),
                submit(),
            ],
            vec![layout_field("foreign", Control::Auto), submit()],
            vec![layout_field("body", Control::Auto)],
            vec![layout_field("body", Control::Auto), submit(), submit()],
            vec![
                FormInstruction::Begin(Container::Paragraph),
                layout_field("body", Control::Auto),
                FormInstruction::End,
                submit(),
            ],
            vec![
                layout_field("body", Control::Textarea { rows: 0 }),
                submit(),
            ],
            vec![
                FormInstruction::Begin(Container::Section),
                layout_field("body", Control::Auto),
                submit(),
            ],
        ] {
            manifest.actions[0].layout = invalid;
            assert!(validate(&manifest).is_err());
        }
    }

    #[test]
    fn admission_checks_explicit_paths_and_overlaps() {
        let mut manifest = crate::test_support::manifest();
        manifest.routes[1].path = "/notes/{note}".into();
        validate(&manifest).unwrap();
        let mut duplicate = manifest.routes[1].clone();
        duplicate.id = 3;
        duplicate.path = "/notes/{other}".into();
        manifest.routes.push(duplicate);
        assert!(validate(&manifest).is_err());
        manifest.routes[2].path = "/notes".into();
        assert!(validate(&manifest).is_err());
        manifest.routes.pop();
        manifest.routes[1].path = "/notes/{one}/{two}".into();
        assert!(validate(&manifest).is_err());
        manifest.routes[1].path = "/notes/{note}".into();
        let mut reserved = manifest.routes[0].clone();
        reserved.id = 3;
        reserved.path = "/login".into();
        manifest.routes.push(reserved);
        validate(&manifest).unwrap();
        assert!(crate::Presentation::default().validate(&manifest).is_err());
    }
}
