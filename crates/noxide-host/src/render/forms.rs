use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn form(
    out: &mut Buffer,
    m: &Manifest,
    action: &Action,
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
            .all(|name| action.fields.contains(name)),
        "unexpected form field"
    );
    out.push(&format!(
        "<form method=\"post\" action=\"{}/{}\" accept-charset=\"utf-8\">",
        presentation.action_path, action.id
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
    if crate::manifest::is_capability(crate::manifest::operation(m, action.operation)?) {
        out.push(&format!("<label>Edit secret<input type=\"password\" name=\"{}\" autocomplete=\"off\" maxlength=\"128\" required></label>", presentation.capability_field))?;
    }
    let default_button =
        if crate::manifest::operation(m, action.operation)?.kind == OperationKind::Delete {
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
        &action.layout
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
    action: &Action,
    field: &TextField,
    requested: &Control,
    input: &Fields,
    readonly: bool,
    errors: &Fields,
    validate: bool,
    instance: usize,
) -> Result<()> {
    let mut control = match requested {
        Control::Auto => match &field.kind {
            FieldKind::Text => Control::Textarea { rows: 4 },
            FieldKind::Boolean if !field.optional => Control::Checkbox,
            FieldKind::Boolean | FieldKind::Choice { .. } => Control::Select,
            FieldKind::Integer { .. } => Control::TextInput,
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
            ) | (Control::TextInput, FieldKind::Integer { .. }, _)
                | (Control::Checkbox, FieldKind::Boolean, false)
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
    let invalid = validate && crate::manifest::validate_value(field, value).is_err();
    let error = errors.get(&field.name);
    let id = format!("field-{}-{}-{}", action.id, instance, field.name);
    let error_id = format!("error-{}-{}-{}", action.id, instance, field.name);
    out.push("<label for=\"")?;
    out.text(&id)?;
    out.push("\">")?;
    out.text(&field.label)?;
    match &control {
        Control::Textarea { rows } => {
            ensure!(*rows > 0 && *rows <= 64, "textarea rows");
            out.push(&format!(
                "<textarea rows=\"{rows}\" maxlength=\"{}\"",
                field.max_bytes
            ))?;
        }
        Control::TextInput => {
            out.push("<input type=\"text\"")?;
            if matches!(field.kind, FieldKind::Integer { .. }) {
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
                FieldKind::Text => format!(
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
                FieldKind::Choice { .. } => "Choose a declared option.".into(),
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
