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

pub use noxide_protocol::identifier;

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
        for field in &r.fields {
            if let Some(value) = &field.initial {
                ensure!(
                    !field.optional
                        && matches!(field.kind, FieldKind::Boolean | FieldKind::Choice { .. }),
                    "initial requires a non-optional boolean or choice"
                );
                ensure!(
                    field.canonical(value).as_ref().ok() == Some(value),
                    "invalid initial value"
                );
            }
        }
        ensure!(
            identifier(&r.name)
                && resource_keys.insert(&r.name)
                && !r.fields.is_empty()
                && r.fields.len() <= 8,
            "invalid resource"
        );
        ensure!(
            r.fields
                .iter()
                .filter(|f| matches!(f.kind, FieldKind::Parent { .. }))
                .count()
                <= 1,
            "one parent per resource"
        );
        ensure!(
            r.fields
                .iter()
                .filter(|f| matches!(f.kind, FieldKind::Account { .. }))
                .count()
                <= 4,
            "account field limit"
        );
        let mut fields = BTreeSet::new();
        for f in &r.fields {
            ensure!(
                identifier(&f.name) && fields.insert(&f.name),
                "invalid field"
            );
            ensure!(f.max_bytes > 0 && f.max_bytes <= 4096, "field limit");
            match &f.kind {
                FieldKind::Parent {
                    resource: key,
                    visible,
                    create_when,
                } => {
                    ensure!(
                        !f.optional && f.max_bytes >= 19,
                        "parent must be required and hold an ID"
                    );
                    let parent = m
                        .resources
                        .iter()
                        .find(|p| &p.name == key)
                        .ok_or_else(|| anyhow::anyhow!("unknown parent resource"))?;
                    ensure!(
                        parent.id != r.id && parent_field(parent).is_none(),
                        "parent relationships have one level"
                    );
                    for predicate in [visible, create_when] {
                        let field = parent
                            .fields
                            .iter()
                            .find(|f| f.name == predicate.field)
                            .ok_or_else(|| anyhow::anyhow!("unknown parent predicate field"))?;
                        ensure!(
                            matches!(field.kind, FieldKind::Boolean | FieldKind::Choice { .. })
                                && field
                                    .canonical(&predicate.equals)
                                    .is_ok_and(|v| v == predicate.equals),
                            "invalid parent predicate"
                        );
                    }
                }
                FieldKind::Account { .. } => ensure!(
                    !f.optional && f.initial.is_none() && f.max_bytes >= 43,
                    "account fields must be required without defaults"
                ),
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
        if op.kind == OperationKind::List {
            crate::query_plan::compile(m, op)?;
        }
        ensure!(
            op.list
                .as_ref()
                .is_none_or(|s| op.kind == OperationKind::List && (1..=20).contains(&s.page_size)),
            "invalid list settings"
        );
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
                if let Predicate::PrincipalIs { field } = p {
                    ensure!(
                        matches!(op.kind, OperationKind::Read | OperationKind::List),
                        "principal_is requires read or list"
                    );
                    ensure!(
                        resource(m, op.resource)?.fields.iter().any(
                            |f| f.name == *field && matches!(f.kind, FieldKind::Account { .. })
                        ),
                        "principal_is requires an account field"
                    );
                }
                if let Predicate::Role { name, .. } = p {
                    ensure!(identifier(name), "invalid role");
                }
            }
        }
    }
    for op in &m.operations {
        if is_public(op) {
            ensure!(
                op.policy.any == [vec![Predicate::Public]],
                "public policy must stand alone"
            );
            if op.kind == OperationKind::Create {
                ensure!(
                    op.visibility.is_none() && op.fields.is_none(),
                    "public create cannot project or filter"
                );
                continue;
            }
            ensure!(
                matches!(op.kind, OperationKind::List | OperationKind::Read),
                "public operations must read"
            );
            let visibility = op
                .visibility
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("public visibility required"))?;
            let resource = resource(m, op.resource)?;
            let field = resource
                .fields
                .iter()
                .find(|field| field.name == visibility.field)
                .ok_or_else(|| anyhow::anyhow!("unknown visibility field"))?;
            ensure!(
                matches!(field.kind, FieldKind::Boolean | FieldKind::Choice { .. }),
                "visibility must be boolean or choice"
            );
            ensure!(
                field
                    .canonical(&visibility.equals)
                    .is_ok_and(|v| v == visibility.equals),
                "visibility must be canonical"
            );
            let fields = op
                .fields
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("public fields required"))?;
            ensure!(!fields.is_empty(), "empty public fields");
            projected_fields(resource, fields)?;
        } else {
            ensure!(
                op.visibility.is_none() && op.fields.is_none(),
                "private operations cannot declare public visibility or fields"
            );
        }
    }
    for op in &m.operations {
        if is_capability(op) {
            ensure!(
                op.policy.any == [vec![Predicate::Capability]]
                    && matches!(op.kind, OperationKind::Update | OperationKind::Delete),
                "capability policy requires standalone update or delete"
            );
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
        if r.access == Access::Public {
            ensure!(r.forms.is_empty(), "public routes cannot have forms");
            for id in &r.operations {
                ensure!(
                    is_public(operation(m, *id)?),
                    "public routes require public operations"
                );
            }
        }
        ensure!(
            r.operations
                .iter()
                .filter(|id| operation(m, **id).is_ok_and(|op| op.kind == OperationKind::List))
                .count()
                <= 1,
            "a list route has one cursor scope"
        );
        for id in &r.operations {
            let op = operation(m, *id)?;
            let parent = parent_resource(m, op.resource)?;
            if op.kind == OperationKind::List {
                ensure!(
                    r.resource == parent.map(|p| p.id),
                    "list requires its parent route or a collection route"
                );
            } else {
                ensure!(
                    op.kind == OperationKind::Read && r.resource == Some(op.resource),
                    "route operation mismatch"
                );
            }
        }
        if let Some(id) = r.resource {
            resource(m, id)?;
            ensure!(
                r.operations
                    .iter()
                    .any(|id| operation(m, *id)
                        .is_ok_and(|op| op.kind == OperationKind::Read
                            && op.resource == r.resource.unwrap())),
                "record route requires a read operation"
            );
        }
        for id in &r.forms {
            let a = action(m, *id)?;
            let op = operation(m, a.operation)?;
            if op.kind == OperationKind::Create {
                if let Some(parent) = parent_resource(m, op.resource)? {
                    ensure!(
                        r.resource == Some(parent.id),
                        "child create requires parent route"
                    );
                }
            } else {
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
        if op.kind == OperationKind::Update {
            ensure!(
                fields
                    .iter()
                    .all(|f| !matches!(f.kind, FieldKind::Account { .. })),
                "account fields are immutable"
            );
        }

        ensure!(
            fields
                .iter()
                .all(|f| !matches!(f.kind, FieldKind::Parent { .. })),
            "parent is host-bound and immutable"
        );
        match op.kind {
            OperationKind::Create => {
                ensure!(!fields.is_empty(), "create requires writable fields");
                ensure!(
                    fields.iter().all(|f| f.initial.is_none()),
                    "initial value is host-applied"
                );
                ensure!(
                    fields.len()
                        + resource(m, op.resource)?
                            .fields
                            .iter()
                            .filter(|f| f.initial.is_some())
                            .count()
                        + usize::from(parent_resource(m, op.resource)?.is_some())
                        == resource(m, op.resource)?.fields.len(),
                    "creation requires every writable field"
                );
            }
            OperationKind::Update => {
                ensure!(!fields.is_empty(), "update requires writable fields")
            }
            OperationKind::Delete => ensure!(fields.is_empty(), "delete has no writable fields"),
            _ => anyhow::bail!("action must declare a mutation"),
        }
        if let Some(inspect) = &a.inspect {
            let read = operation(m, inspect.operation)?;
            ensure!(!is_public(read), "inspection cannot use a public operation");
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
        let r = route(m, a.redirect.route())?;
        if matches!(a.redirect, Redirect::Parent { .. }) {
            ensure!(
                r.operations
                    .iter()
                    .filter(|id| operation(m, **id)
                        .is_ok_and(|read| read.kind == OperationKind::Read
                            && Some(read.resource) == r.resource))
                    .count()
                    == 1,
                "parent destination requires one unambiguous resource read"
            );
        }
        ensure!(
            if matches!(a.redirect, Redirect::Parent { .. }) {
                r.resource == parent_resource(m, op.resource)?.map(|p| p.id) && r.resource.is_some()
            } else if op.kind == OperationKind::Delete {
                r.resource.is_none()
            } else {
                r.resource == Some(op.resource)
            },
            "invalid outcome route"
        );
    }
    Ok(())
}

pub(crate) fn parent_field(resource: &Resource) -> Option<&TextField> {
    resource
        .fields
        .iter()
        .find(|f| matches!(f.kind, FieldKind::Parent { .. }))
}
pub(crate) fn parent_resource(m: &Manifest, child: u32) -> Result<Option<&Resource>> {
    match parent_field(resource(m, child)?) {
        Some(TextField {
            kind: FieldKind::Parent { resource: key, .. },
            ..
        }) => Ok(Some(
            m.resources
                .iter()
                .find(|r| &r.name == key)
                .ok_or_else(|| anyhow::anyhow!("unknown parent"))?,
        )),
        _ => Ok(None),
    }
}
pub(crate) fn parent_permits(field: &TextField, parent: &Fields, write: bool) -> bool {
    let FieldKind::Parent {
        visible,
        create_when,
        ..
    } = &field.kind
    else {
        return false;
    };
    parent.get(&visible.field) == Some(&visible.equals)
        && (!write || parent.get(&create_when.field) == Some(&create_when.equals))
}

pub(crate) fn is_public(op: &Operation) -> bool {
    op.policy
        .any
        .iter()
        .flatten()
        .any(|p| *p == Predicate::Public)
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
    crate::form_layout::validate(m, action, &action.layout)
}

pub(crate) fn is_capability(op: &Operation) -> bool {
    op.policy
        .any
        .iter()
        .flatten()
        .any(|p| matches!(p, Predicate::Capability))
}
pub(crate) fn anonymous_action(op: &Operation) -> bool {
    (is_public(op) && op.kind == OperationKind::Create) || is_capability(op)
}

#[cfg(test)]
mod tests {
    #[test]
    fn query_contract_bytes_and_digests_are_unchanged() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/fixtures/queries");
        for line in include_str!("../../../tools/fixtures/queries/digests.txt").lines() {
            let (name, expected) = line.split_once(' ').unwrap();
            let bytes = std::fs::read(root.join(name)).unwrap();
            let manifest = parse(&bytes).unwrap();
            assert_eq!(serde_json::to_vec(&manifest).unwrap(), bytes, "{name}");
            assert_eq!(
                URL_SAFE_NO_PAD.encode(digest(&manifest).unwrap()),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn private_notes_approval_digest_is_unchanged() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let m = parse(include_bytes!(
            "../../../examples/private-notes/manifest.json"
        ))
        .unwrap();
        // Explicit initial declarations and list settings require renewed
        // approval. Pin the generated contract to catch unintended drift.
        assert_eq!(
            URL_SAFE_NO_PAD.encode(digest(&m).unwrap()),
            "1W3N2rgaNuZIFY6OzFQgfOLkmnxdBHJCej52XIJ8N1o"
        );
    }

    use super::*;

    fn field(name: &str, kind: FieldKind, optional: bool) -> TextField {
        TextField {
            name: name.into(),
            label: name.into(),
            max_bytes: 200,
            kind,
            optional,
            initial: None,
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

#[cfg(test)]
mod pagination_tests {
    use super::*;
    #[test]
    fn host_rejects_forged_list_settings_and_contract_binds_page_size() {
        let mut m = crate::test_support::manifest();
        m.operations[0].list = Some(ListSettings {
            order: ListOrder::CreatedAsc,
            page_size: 20,
        });
        validate(&m).unwrap();
        let original = digest(&m).unwrap();
        m.operations[0].list.as_mut().unwrap().page_size = 3;
        assert_ne!(digest(&m).unwrap(), original);
        for size in [0, 21, 255] {
            m.operations[0].list.as_mut().unwrap().page_size = size;
            assert!(validate(&m).is_err());
        }
        m.operations[0].list = None;
        m.operations[1].list = Some(ListSettings {
            order: ListOrder::CreatedAsc,
            page_size: 3,
        });
        assert!(validate(&m).is_err());
    }
}

#[cfg(test)]
mod initial_tests {
    use super::*;
    fn declarations() -> Manifest {
        let mut m = crate::test_support::manifest();
        m.resources[0].fields.push(TextField {
            name: "published".into(),
            label: "Published".into(),
            kind: FieldKind::Boolean,
            optional: false,
            initial: Some("true".into()),
            max_bytes: 5,
        });
        m
    }
    #[test]
    fn initial_admission_and_digest_boundaries() {
        let m = declarations();
        validate(&m).unwrap();
        for value in ["on", "TRUE", "", "false "] {
            let mut bad = m.clone();
            bad.resources[0].fields[1].initial = Some(value.into());
            assert!(validate(&bad).is_err(), "{value}");
        }
        for kind in [
            FieldKind::Text,
            FieldKind::Integer {
                min: Some(0),
                max: Some(10),
            },
            FieldKind::Choice { variants: vec![] },
        ] {
            let mut bad = m.clone();
            bad.resources[0].fields[1].kind = kind;
            assert!(validate(&bad).is_err());
        }
        let mut choice = m.clone();
        choice.resources[0].fields[1].kind = FieldKind::Choice {
            variants: vec![
                ChoiceVariant {
                    key: "draft".into(),
                    label: "Draft".into(),
                },
                ChoiceVariant {
                    key: "live".into(),
                    label: "Live".into(),
                },
            ],
        };
        assert!(validate(&choice).is_err());
        choice.resources[0].fields[1].initial = Some("draft".into());
        validate(&choice).unwrap();
        let mut parent = m.clone();
        parent.resources[0].fields[1].kind = FieldKind::Parent {
            resource: "notes".into(),
            visible: Visibility {
                field: "published".into(),
                equals: "true".into(),
            },
            create_when: Visibility {
                field: "published".into(),
                equals: "true".into(),
            },
        };
        assert!(
            validate(&parent)
                .unwrap_err()
                .to_string()
                .contains("initial requires")
        );
        let mut bad = m.clone();
        bad.resources[0].fields[1].optional = true;
        assert!(validate(&bad).is_err());
        bad = m.clone();
        bad.resources[0].fields[1].max_bytes = 3;
        assert!(validate(&bad).is_err());
        bad = m.clone();
        bad.actions[0].fields.push("published".into());
        assert!(
            validate(&bad)
                .unwrap_err()
                .to_string()
                .contains("initial value is host-applied")
        );
        bad = m.clone();
        bad.actions[0].fields.clear();
        bad.resources[0].fields.remove(0);
        assert!(
            validate(&bad)
                .unwrap_err()
                .to_string()
                .contains("create requires writable fields")
        );
        for value in ["on", "false"] {
            assert!(
                canonical_input(
                    &m,
                    &m.actions[0],
                    &Fields::from([
                        ("body".into(), "hello".into()),
                        ("published".into(), value.into())
                    ])
                )
                .is_err()
            );
        }
        let mut changed = m.clone();
        changed.resources[0].fields[1].initial = Some("false".into());
        assert_ne!(digest(&m).unwrap(), digest(&changed).unwrap());
        assert_eq!(
            crate::schema::digest(&m.resources).unwrap(),
            crate::schema::digest(&changed.resources).unwrap()
        );
    }
}
