use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn form(
    out: &mut Buffer,
    m: &Manifest,
    action: &crate::manifest::WebAction<'_>,
    credentials: &FormCredentials,
    input: &Fields,
    readonly: bool,
    errors: &Fields,
    button: Option<&str>,
    instance: usize,
    presentation: &crate::Presentation,
) -> Result<()> {
    let fields = crate::manifest::action_fields(m, action)?;
    ensure!(
        input
            .keys()
            .chain(errors.keys())
            .all(|name| action.inputs.iter().any(|input| &input.name == name)),
        "unexpected form field"
    );
    out.push(&format!(
        "<form method=\"post\" action=\"{}/{}\" accept-charset=\"utf-8\"{}>",
        presentation.action_path,
        action.id,
        if credentials.upload_ticket.is_some() {
            " enctype=\"multipart/form-data\""
        } else {
            ""
        }
    ))?;
    for (name, value) in [
        (presentation.csrf_field.as_str(), &credentials.csrf),
        (
            presentation.submission_field.as_str(),
            &credentials.submission,
        ),
    ] {
        hidden(out, name, value)?;
    }
    if let Some(ticket) = &credentials.upload_ticket {
        hidden(out, "_upload", ticket)?;
    }
    for target in action
        .targets
        .iter()
        .filter(|target| matches!(target.source, TargetSource::Selected { .. }))
    {
        let name = format!("_target_{}", target.name);
        if let Some(value) = credentials.selected.get(&target.name) {
            hidden(out, &name, value)?;
            continue;
        }
        out.push("<label>")?;
        out.text(&target.name.replace('_', " "))?;
        out.push("<select name=\"")?;
        out.text(&name)?;
        out.push("\" required><option value=\"\">Choose a record</option>")?;
        if let Some(options) = credentials.selections.get(&target.name) {
            for (handle, label) in options {
                out.push("<option value=\"")?;
                out.text(handle)?;
                out.push("\">")?;
                out.text(label)?;
                out.push("</option>")?;
            }
        }
        out.push("</select></label>")?;
    }
    if crate::manifest::is_capability(crate::manifest::operation(m, action.steps[0].operation)?) {
        out.push(&format!("<label>Edit secret<input type=\"password\" name=\"{}\" autocomplete=\"off\" maxlength=\"128\" required></label>", presentation.capability_field))?;
    }
    let default_button = if crate::manifest::operation(m, action.steps[0].operation)?.kind
        == OperationKind::Delete
    {
        "Delete record"
    } else {
        &action.name
    };
    let default_layout;
    let layout = if action.layout.is_empty() {
        default_layout = fields
            .iter()
            .map(|field| FormInstruction::Field {
                name: field.name.clone(),
                control: Control::Auto,
            })
            .chain(std::iter::once(FormInstruction::Submit {
                label: default_button.into(),
            }))
            .collect::<Vec<_>>();
        &default_layout
    } else {
        action.layout
    };
    crate::form_layout::validate(m, action, layout)?;
    let mut stack = Vec::new();
    for node in layout {
        match node {
            FormInstruction::Begin(container) => {
                out.push("<")?;
                out.push(tag(container))?;
                out.push(">")?;
                stack.push(container);
            }
            FormInstruction::End => {
                let container = stack.pop().expect("validated layout");
                out.push("</")?;
                out.push(tag(container))?;
                out.push(">")?;
            }
            FormInstruction::Text(text) => out.text(text)?,
            FormInstruction::Field { name, control } => {
                let field = fields
                    .iter()
                    .find(|field| &field.name == name)
                    .expect("validated field");
                if matches!(field.kind, FieldKind::UploadHandle { .. }) {
                    continue;
                }
                render_field(
                    out,
                    action,
                    field,
                    control,
                    input,
                    readonly,
                    errors,
                    button.is_some() || !input.is_empty(),
                    instance,
                )?;
            }
            FormInstruction::Submit { label } => {
                out.push("<button type=\"submit\">")?;
                out.text(button.unwrap_or(label))?;
                out.push("</button>")?;
            }
        }
    }
    for field in fields
        .iter()
        .filter(|f| matches!(f.kind, FieldKind::UploadHandle { .. }))
    {
        let staged = input
            .get(&field.name)
            .is_some_and(|value| !value.is_empty());
        if staged {
            out.push("<p>File already uploaded. This submission reuses that file.</p>")?;
        }
        out.push("<label>")?;
        out.text(&field.label)?;
        out.push("<input type=\"file\" name=\"")?;
        out.text(&field.name)?;
        out.push("\"")?;
        if !field.optional && !staged {
            out.push(" required")?;
        }
        out.push("></label>")?;
    }
    out.push("</form>")
}

pub(super) fn hidden(out: &mut Buffer, name: &str, value: &str) -> Result<()> {
    out.push("<input type=\"hidden\" name=\"")?;
    out.text(name)?;
    out.push("\" value=\"")?;
    out.text(value)?;
    out.push("\">")
}

#[allow(clippy::too_many_arguments)]
fn render_field(
    out: &mut Buffer,
    action: &crate::manifest::WebAction<'_>,
    field: &Input,
    requested: &Control,
    input: &Fields,
    readonly: bool,
    errors: &Fields,
    validate: bool,
    instance: usize,
) -> Result<()> {
    let mut control = match requested {
        Control::Auto => match &field.kind {
            FieldKind::Blob { .. } | FieldKind::UploadHandle { .. } => {
                anyhow::bail!("blob controls are not available")
            }
            FieldKind::Text => Control::Textarea { rows: 4 },
            FieldKind::Account { .. } => Control::TextInput,
            FieldKind::Boolean if !field.optional => Control::Checkbox,
            FieldKind::Boolean | FieldKind::Choice { .. } => Control::Select,
            FieldKind::Integer { .. } | FieldKind::Timestamp | FieldKind::Duration { .. } => {
                Control::TextInput
            }
            FieldKind::Reference { .. } => anyhow::bail!("parent fields cannot be form controls"),
        },
        control => control.clone(),
    };
    ensure!(
        matches!(
            (&control, &field.kind, field.optional),
            (
                Control::Textarea { .. } | Control::TextInput,
                FieldKind::Text,
                _
            ) | (
                Control::TextInput,
                FieldKind::Integer { .. }
                    | FieldKind::Account { .. }
                    | FieldKind::Timestamp
                    | FieldKind::Duration { .. },
                _
            ) | (Control::Checkbox, FieldKind::Boolean, false)
                | (Control::Select, FieldKind::Choice { .. }, _)
                | (Control::Select, FieldKind::Boolean, true)
        ),
        "control type mismatch"
    );
    let missing = if field.kind == FieldKind::Boolean && !field.optional {
        "false"
    } else {
        ""
    };
    let value = input
        .get(&field.name)
        .map(String::as_str)
        .unwrap_or(missing);
    if matches!(control, Control::TextInput) && value.contains(['\r', '\n']) {
        // Browsers strip line breaks from text inputs. A recovery view must
        // preserve submitted bytes, including invalid numeric input.
        control = Control::Textarea { rows: 4 };
    }
    let invalid = validate && field.canonical(value).is_err();
    let error = errors.get(&field.name);
    let id = format!("field-{}-{}-{}", action.id, instance, field.name);
    let error_id = format!("error-{}-{}-{}", action.id, instance, field.name);
    out.push("<label for=\"")?;
    out.text(&id)?;
    out.push("\">")?;
    out.text(&field.label)?;
    match &control {
        Control::File => anyhow::bail!("blob controls are not available"),
        Control::Textarea { rows } => {
            ensure!(*rows > 0 && *rows <= 64, "textarea rows");
            out.push(&format!(
                "<textarea rows=\"{rows}\" maxlength=\"{}\"",
                field.max_bytes
            ))?;
        }
        Control::TextInput => {
            out.push("<input type=\"text\"")?;
            if matches!(
                field.kind,
                FieldKind::Integer { .. } | FieldKind::Timestamp | FieldKind::Duration { .. }
            ) {
                out.push(" inputmode=\"numeric\"")?;
            }
            out.push(&format!(" maxlength=\"{}\" value=\"", field.max_bytes))?;
            out.text(value)?;
            out.push("\"")?;
        }
        Control::Checkbox => {
            out.push("<input type=\"checkbox\" value=\"true\"")?;
            if field.canonical(value).is_ok_and(|value| value == "true") {
                out.push(" checked")?;
            }
        }
        Control::Select => out.push("<select")?,
        Control::Auto => unreachable!("resolved automatic control"),
    }
    out.push(" id=\"")?;
    out.text(&id)?;
    out.push("\" name=\"")?;
    out.text(&field.name)?;
    out.push("\"")?;
    if !field.optional && !matches!(control, Control::Checkbox) {
        out.push(" required")?;
    }
    if readonly {
        out.push(if matches!(control, Control::Checkbox | Control::Select) {
            " disabled"
        } else {
            " readonly"
        })?;
    }
    if invalid || error.is_some() {
        out.push(" aria-invalid=\"true\" aria-describedby=\"")?;
        out.text(&error_id)?;
        out.push("\"")?;
    }
    match &control {
        Control::Textarea { .. } => {
            // Supply the parser-consumed LF so stored initial newlines survive.
            out.push(">\n")?;
            out.text(value)?;
            out.push("</textarea>")?;
        }
        Control::Select => {
            out.push(">")?;
            let boolean_variants = vec![
                ChoiceVariant {
                    key: "true".into(),
                    label: "Yes".into(),
                },
                ChoiceVariant {
                    key: "false".into(),
                    label: "No".into(),
                },
            ];
            let variants = match &field.kind {
                FieldKind::Boolean => &boolean_variants,
                FieldKind::Choice { variants } => variants,
                _ => unreachable!("validated select control"),
            };
            option(
                out,
                "",
                if field.optional {
                    "Not set"
                } else {
                    "Choose an option"
                },
                value.is_empty(),
            )?;
            if !value.is_empty() && !variants.iter().any(|variant| variant.key == value) {
                // Keep an invalid submitted enum value intact for recovery.
                option(out, value, value, true)?;
            }
            for variant in variants {
                option(out, &variant.key, &variant.label, variant.key == value)?;
            }
            out.push("</select>")?;
        }
        _ => out.push(">")?,
    }
    out.push("</label>")?;
    if readonly && matches!(control, Control::Checkbox | Control::Select) {
        // Disabled controls do not submit. Preserve the exact original input
        // while the host determines whether its receipt already committed.
        hidden(out, &field.name, value)?;
    }
    if invalid || error.is_some() {
        out.push("<p id=\"")?;
        out.text(&error_id)?;
        out.push("\">")?;
        if let Some(error) = error {
            out.text(error)?;
        } else {
            out.text(&match &field.kind {
                FieldKind::Blob { .. } | FieldKind::UploadHandle { .. } => {
                    anyhow::bail!("blob controls are not available")
                }
                FieldKind::Text | FieldKind::Account { .. } => format!(
                    "Enter {}at most {} UTF-8 bytes.",
                    if field.optional {
                        ""
                    } else {
                        "nonempty text of "
                    },
                    field.max_bytes
                ),
                FieldKind::Boolean => "Choose a boolean value.".into(),
                FieldKind::Integer { .. } => "Enter an integer within the declared bounds.".into(),
                FieldKind::Timestamp => "Enter UTC milliseconds since the Unix epoch.".into(),
                FieldKind::Duration { .. } => {
                    "Enter duration milliseconds within the declared bound.".into()
                }
                FieldKind::Choice { .. } => "Choose a declared option.".into(),
                FieldKind::Reference { .. } => {
                    anyhow::bail!("parent fields cannot be form controls")
                }
            })?;
        }
        out.push("</p>")?;
    }
    Ok(())
}

fn option(out: &mut Buffer, value: &str, label: &str, selected: bool) -> Result<()> {
    out.push("<option value=\"")?;
    out.text(value)?;
    out.push(if selected { "\" selected>" } else { "\">" })?;
    out.text(label)?;
    out.push("</option>")
}

/// Query controls convey input only. Their next GET passes normal route and
/// current read authorization; the form itself contains no grant or cursor.
pub(super) fn query_form(
    out: &mut Buffer,
    m: &Manifest,
    form: &noxide_protocol::query::QueryForm,
    mut checkpoint: fn() -> Result<()>,
) -> Result<()> {
    use crate::manifest::ParameterField;
    ensure!(
        !form.search_label.is_empty()
            && form.search_label.len() <= 128
            && !form.submit.is_empty()
            && form.submit.len() <= 128,
        "query form label limit"
    );
    let route = crate::manifest::route(m, form.destination.route)?;
    ensure!(
        !route.params.is_empty()
            && route
                .operations
                .iter()
                .any(
                    |id| crate::manifest::operation(m, *id).is_ok_and(|op| matches!(
                        op.kind,
                        OperationKind::List | OperationKind::Aggregate
                    ))
                ),
        "query form requires declared query"
    );
    let fields = crate::manifest::parameter_fields(m, route)?;
    ensure!(
        form.destination
            .params
            .keys()
            .all(|name| fields.contains_key(name)),
        "unknown query form parameter"
    );
    let path = crate::routing::resolve_path(m, &form.destination)?;
    // Validate every control before emitting any form markup. Search can be blank
    // only in a form prefill; a submitted query still requires meaningful terms.
    let mut values = Fields::new();
    for (name, field) in &fields {
        let value = form.destination.params.get(name);
        match field {
            ParameterField::Search => {
                if let Some(value) = value {
                    field.validate(value)?;
                    let canonical = crate::search::canonical_query(value, &mut checkpoint)?;
                    values.insert(name.clone(), canonical.tokens().join(" "));
                }
            }
            ParameterField::Field(_) => {
                let value = value.ok_or_else(|| anyhow::anyhow!("missing query form parameter"))?;
                field.validate(value)?;
                values.insert(name.clone(), value.clone());
            }
        }
    }
    out.push("<form method=\"get\" action=\"")?;
    out.text(&path)?;
    out.push("\" accept-charset=\"utf-8\">")?;
    for (name, field) in &fields {
        let value = values.get(name).map(String::as_str).unwrap_or("");
        out.push("<label>")?;
        match field {
            ParameterField::Search => out.text(&form.search_label)?,
            ParameterField::Field(field) => {
                out.text(&field.label)?;
                out.push(" (")?;
                out.text(name)?;
                out.push(")")?;
            }
        }
        let choices = match field {
            ParameterField::Field(TextField {
                kind: FieldKind::Boolean,
                optional,
                ..
            }) => Some((
                vec![
                    ChoiceVariant {
                        key: "false".into(),
                        label: "False".into(),
                    },
                    ChoiceVariant {
                        key: "true".into(),
                        label: "True".into(),
                    },
                ],
                *optional,
            )),
            ParameterField::Field(TextField {
                kind: FieldKind::Choice { variants },
                optional,
                ..
            }) => Some((variants.clone(), *optional)),
            _ => None,
        };
        if let Some((choices, optional)) = choices {
            out.push("<select name=\"")?;
            out.text(name)?;
            out.push("\">")?;
            if optional {
                option(out, "", "Not set", value.is_empty())?;
            }
            for choice in choices {
                option(out, &choice.key, &choice.label, choice.key == value)?;
            }
            out.push("</select>")?;
        } else {
            out.push("<input type=\"")?;
            out.push(if matches!(field, ParameterField::Search) {
                "search"
            } else {
                "text"
            })?;
            out.push("\" name=\"")?;
            out.text(name)?;
            out.push("\" value=\"")?;
            out.text(value)?;
            out.push("\" maxlength=\"")?;
            let max = match field {
                ParameterField::Search => 1024,
                ParameterField::Field(field) => field.max_bytes.min(1024),
            };
            out.text(&max.to_string())?;
            out.push("\" required>")?;
        }
        out.push("</label>")?;
    }
    out.push("<button type=\"submit\">")?;
    out.text(&form.submit)?;
    out.push("</button></form>")
}

#[cfg(test)]
mod query_form_tests {
    use super::*;
    fn fixture() -> (Manifest, noxide_protocol::query::QueryForm) {
        let mut m = noxide_test_support::manifest();
        m.resources[0].fields.push(TextField {
            immutable: false,
            name: "visible".into(),
            label: "Public <visibility>".into(),
            kind: FieldKind::Boolean,
            optional: false,
            max_bytes: 5,
            initial: None,
        });
        m.operations[0].filter.push(Condition {
            field: "visible".into(),
            equals: Operand::Param("public".into()),
        });
        m.operations[0].query = Some(noxide_protocol::query::Query {
            search: Some(noxide_protocol::query::Search {
                fields: vec!["body".into()],
                parameter: "terms".into(),
            }),
            ..Default::default()
        });
        m.routes[0].path = "/search".into();
        m.routes[0].params = vec!["terms".into(), "public".into()];
        let form = noxide_protocol::query::QueryForm {
            destination: RouteRef {
                route: 1,
                target: None,
                params: Fields::from([("public".into(), "true".into())]),
            },
            search_label: "Find <terms>".into(),
            submit: "Apply <filters>".into(),
        };
        (m, form)
    }
    #[test]
    fn query_form_uses_escaped_native_get_controls_without_cursor() {
        let (m, form) = fixture();
        let mut out = Buffer(String::new());
        query_form(&mut out, &m, &form, super::no_budget).unwrap();
        assert!(out.0.starts_with("<form method=\"get\" action=\"/search\""));
        assert!(
            out.0
                .contains("Find &lt;terms&gt;<input type=\"search\" name=\"terms\" value=\"\"")
        );
        assert!(out.0.contains("Public &lt;visibility&gt;"));
        assert!(
            out.0
                .contains("<option value=\"true\" selected>True</option>")
        );
        assert!(out.0.contains("Apply &lt;filters&gt;"));
        assert!(!out.0.contains("cursor"));
        assert!(!out.0.contains("<script"));
    }
    #[test]
    fn query_form_rejects_forged_controls_paths_and_labels() {
        let (m, form) = fixture();
        let mut bad = form.clone();
        bad.destination
            .params
            .insert("cursor".into(), "forged".into());
        assert!(query_form(&mut Buffer(String::new()), &m, &bad, super::no_budget).is_err());
        bad = form.clone();
        bad.destination.params.clear();
        assert!(query_form(&mut Buffer(String::new()), &m, &bad, super::no_budget).is_err());
        bad = form.clone();
        bad.destination.target = Some(1);
        assert!(query_form(&mut Buffer(String::new()), &m, &bad, super::no_budget).is_err());
        bad = form.clone();
        bad.search_label = "x".repeat(129);
        assert!(query_form(&mut Buffer(String::new()), &m, &bad, super::no_budget).is_err());
        bad = form.clone();
        bad.destination
            .params
            .insert("public".into(), "TRUE".into());
        assert!(query_form(&mut Buffer(String::new()), &m, &bad, super::no_budget).is_err());
        let mut bad_manifest = m.clone();
        bad_manifest.routes[0].path = "//foreign.example".into();
        assert!(
            query_form(
                &mut Buffer(String::new()),
                &bad_manifest,
                &form,
                super::no_budget
            )
            .is_err()
        );
    }
}
