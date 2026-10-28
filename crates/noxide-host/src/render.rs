use anyhow::{Result, ensure};
use noxide_protocol::*;
use std::collections::BTreeMap;

pub const CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

pub struct FormCredentials {
    pub csrf: String,
    pub submission: String,
    pub values: Fields,
}

pub struct RenderContext<'a> {
    pub presentation: &'a crate::Presentation,
    pub manifest: Option<&'a Manifest>,
    /// Missing entries are undeclared; None is declared but denied by policy.
    pub forms: BTreeMap<u32, Option<FormCredentials>>,
    pub logout_csrf: Option<String>,
    pub next_page: Option<String>,
}

impl RenderContext<'_> {
    pub fn empty() -> Self {
        Self {
            presentation: &crate::presentation::DEFAULT,
            manifest: None,
            forms: BTreeMap::new(),
            logout_csrf: None,
            next_page: None,
        }
    }
}

#[derive(Debug)]
pub struct Rendered {
    pub status: u16,
    pub body: Vec<u8>,
    pub location: Option<String>,
}

fn stylesheet(out: &mut Buffer, presentation: &crate::Presentation) -> Result<()> {
    if presentation.stylesheet.is_some() {
        out.push("<link rel=\"stylesheet\" href=\"")?;
        out.text(&presentation.stylesheet_path)?;
        out.push("\">")?;
    }
    Ok(())
}

struct Buffer(String);
impl Buffer {
    fn push(&mut self, text: &str) -> Result<()> {
        ensure!(
            self.0.len().saturating_add(text.len()) <= MAX_OUTPUT_BYTES,
            "response limit"
        );
        self.0.push_str(text);
        Ok(())
    }
    fn text(&mut self, text: &str) -> Result<()> {
        ensure!(
            !text
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
            "invalid text"
        );
        for c in text.chars() {
            self.push(match c {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                '"' => "&quot;",
                '\'' => "&#39;",
                _ => {
                    let mut b = [0; 4];
                    self.push(c.encode_utf8(&mut b))?;
                    continue;
                }
            })?;
        }
        Ok(())
    }
}

fn tag(c: &Container) -> &'static str {
    match c {
        Container::Article => "article",
        Container::Section => "section",
        Container::Heading1 => "h1",
        Container::Heading2 => "h2",
        Container::Paragraph => "p",
        Container::List => "ul",
        Container::Item => "li",
        Container::Strong => "strong",
        Container::Emphasis => "em",
        Container::Code => "code",
        Container::Pre => "pre",
        Container::Main => "main",
        Container::Nav => "nav",
        Container::Header => "header",
        Container::Footer => "footer",
        Container::Div => "div",
    }
}
fn inline(c: &Container) -> bool {
    matches!(c, Container::Strong | Container::Emphasis | Container::Code)
}
fn phrasing(c: &Container) -> bool {
    inline(c)
        || matches!(
            c,
            Container::Paragraph | Container::Heading1 | Container::Heading2 | Container::Pre
        )
}
fn flow(stack: &[Container]) -> bool {
    stack
        .last()
        .is_none_or(|p| !phrasing(p) && *p != Container::List)
}

#[derive(Clone, Copy)]
enum PathSegment<'a> {
    Static(&'a str),
    Target,
}

fn canonical_id(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|id| *id <= i64::MAX as u64)
}

fn path_segments(route: &Route) -> Result<Vec<PathSegment<'_>>> {
    ensure!(
        route.path.starts_with('/') && route.path.len() <= 128,
        "invalid route path"
    );
    let mut segments = Vec::new();
    let mut targets = 0;
    if route.path != "/" {
        for part in route.path[1..].split('/') {
            if let Some(name) = part
                .strip_prefix('{')
                .and_then(|name| name.strip_suffix('}'))
            {
                ensure!(crate::manifest::identifier(name), "invalid route parameter");
                targets += 1;
                segments.push(PathSegment::Target);
            } else {
                ensure!(crate::manifest::identifier(part), "invalid route segment");
                segments.push(PathSegment::Static(part));
            }
        }
    }
    ensure!(
        targets == usize::from(route.resource.is_some()),
        "route parameter mismatch"
    );
    ensure!(segments.len() <= 8, "route segment limit");
    Ok(segments)
}

/// Check the finite route grammar independently of guest-generated handles.
pub fn validate_path(route: &Route) -> Result<()> {
    path_segments(route)?;
    Ok(())
}

/// Whether two admitted patterns can name the same concrete request path.
pub fn paths_overlap(left: &Route, right: &Route) -> bool {
    let (Ok(left), Ok(right)) = (path_segments(left), path_segments(right)) else {
        return true;
    };
    left.len() == right.len()
        && left
            .iter()
            .zip(&right)
            .all(|(left, right)| match (left, right) {
                (PathSegment::Static(left), PathSegment::Static(right)) => left == right,
                (PathSegment::Target, PathSegment::Target) => true,
                (PathSegment::Static(value), PathSegment::Target)
                | (PathSegment::Target, PathSegment::Static(value)) => {
                    canonical_id(value).is_some()
                }
            })
}

/// Match only canonical decimal record IDs, with no alternate path encodings.
pub fn match_path(route: &Route, path: &str) -> Option<Option<u64>> {
    let segments = path_segments(route).ok()?;
    if !path.starts_with('/') {
        return None;
    }
    let parts: Vec<_> = if path == "/" {
        vec![]
    } else {
        path[1..].split('/').collect()
    };
    if segments.len() != parts.len() {
        return None;
    }
    let mut target = None;
    for (segment, part) in segments.iter().zip(parts) {
        match segment {
            PathSegment::Static(expected) if *expected == part => {}
            PathSegment::Target => target = Some(canonical_id(part)?),
            _ => return None,
        }
    }
    Some(target)
}

pub fn resolve(m: &Manifest, reference: &RouteRef) -> Result<String> {
    let route = crate::manifest::route(m, reference.route)?;
    let segments = path_segments(route)?;
    ensure!(
        route.resource.is_some() == reference.target.is_some(),
        "invalid route target"
    );
    if let Some(id) = reference.target {
        ensure!(id > 0 && id <= i64::MAX as u64, "invalid route target");
    }
    let mut path = String::new();
    for segment in segments {
        path.push('/');
        match segment {
            PathSegment::Static(value) => path.push_str(value),
            PathSegment::Target => path.push_str(
                &reference
                    .target
                    .ok_or_else(|| anyhow::anyhow!("missing route target"))?
                    .to_string(),
            ),
        }
    }
    if path.is_empty() {
        path.push('/');
    }
    Ok(path)
}

pub fn render(intent: &ResponseIntent, context: &RenderContext<'_>) -> Result<Rendered> {
    let (doc, status) = match intent {
        ResponseIntent::Page(d) => (d, 200),
        ResponseIntent::NotFound(d) => (d, 404),
        ResponseIntent::Redirect(dest)
        | ResponseIntent::Created {
            destination: dest, ..
        }
        | ResponseIntent::Updated {
            destination: dest, ..
        }
        | ResponseIntent::Deleted {
            destination: dest, ..
        } => {
            let m = context
                .manifest
                .ok_or_else(|| anyhow::anyhow!("no routes"))?;
            return Ok(Rendered {
                status: 303,
                body: Vec::new(),
                location: Some(resolve(m, dest)?),
            });
        }
        ResponseIntent::Rejected { .. } => anyhow::bail!("rejection requires action context"),
    };
    ensure!(
        doc.title.len() <= 128 && doc.nodes.len() <= MAX_NODES,
        "document limit"
    );
    let mut out = Buffer(String::new());
    out.push("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>")?;
    out.text(&doc.title)?;
    out.push("</title>")?;
    stylesheet(&mut out, context.presentation)?;
    out.push("</head><body>")?;
    if let Some(csrf) = &context.logout_csrf {
        out.push(
            "<nav aria-label=\"Account\"><a href=\"/\">Home</a><form method=\"post\" action=\"",
        )?;
        out.text(&context.presentation.logout_path)?;
        out.push("\"><input type=\"hidden\" name=\"_csrf\" value=\"")?;
        out.text(csrf)?;
        out.push("\"><button>Sign out</button></form></nav>")?;
    }
    let explicit_main = doc
        .nodes
        .iter()
        .any(|node| matches!(node, Instruction::Begin(Container::Main)));
    if !explicit_main {
        out.push("<main>")?;
    }
    let mut main_seen = false;
    let mut stack = Vec::new();
    let mut forms = 0;
    let mut link_depth = None;
    for node in &doc.nodes {
        match node {
            Instruction::Begin(c) => {
                ensure!(link_depth.is_none() || inline(c), "link content");
                ensure!(stack.len() < MAX_DEPTH, "document depth");
                if *c == Container::Main {
                    ensure!(!main_seen && stack.is_empty(), "main structure");
                    main_seen = true;
                }
                if *c == Container::Item {
                    ensure!(stack.last() == Some(&Container::List), "orphan list item");
                } else if stack.last() == Some(&Container::List) {
                    anyhow::bail!("list content");
                } else if stack.last().is_some_and(phrasing) {
                    ensure!(inline(c), "phrasing content");
                }
                out.push("<")?;
                out.push(tag(c))?;
                out.push(">")?;
                if *c == Container::Pre {
                    // HTML consumes one LF immediately after <pre>. Supply
                    // that LF ourselves so every guest text node is preserved.
                    out.push("\n")?;
                }
                stack.push(c.clone());
            }
            Instruction::End => {
                ensure!(
                    link_depth.is_none_or(|depth| stack.len() > depth),
                    "link boundary"
                );
                let c = stack
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("unmatched end"))?;
                out.push("</")?;
                out.push(tag(&c))?;
                out.push(">")?;
            }
            Instruction::Text(s) => {
                ensure!(stack.last() != Some(&Container::List), "list text");
                out.text(s)?;
            }
            Instruction::BeginLink { destination } => {
                ensure!(
                    link_depth.is_none() && stack.last() != Some(&Container::List),
                    "nested or misplaced link"
                );
                let path = resolve(
                    context
                        .manifest
                        .ok_or_else(|| anyhow::anyhow!("no routes"))?,
                    destination,
                )?;
                out.push("<a href=\"")?;
                out.text(&path)?;
                out.push("\">")?;
                link_depth = Some(stack.len());
            }
            Instruction::EndLink => {
                ensure!(link_depth == Some(stack.len()), "unbalanced link");
                link_depth = None;
                out.push("</a>")?;
            }
            Instruction::Link { destination, text } => {
                ensure!(link_depth.is_none(), "nested link");
                ensure!(stack.last() != Some(&Container::List), "list link");
                let path = resolve(
                    context
                        .manifest
                        .ok_or_else(|| anyhow::anyhow!("no routes"))?,
                    destination,
                )?;
                out.push("<a href=\"")?;
                out.text(&path)?;
                out.push("\">")?;
                out.text(text)?;
                out.push("</a>")?;
            }
            Instruction::Form { action } => {
                ensure!(
                    link_depth.is_none() && flow(&stack) && forms < 8,
                    "form structure or limit"
                );
                forms += 1;
                let credentials = context
                    .forms
                    .get(action)
                    .ok_or_else(|| anyhow::anyhow!("form not granted"))?;
                let m = context
                    .manifest
                    .ok_or_else(|| anyhow::anyhow!("no actions"))?;
                let a = crate::manifest::action(m, *action)?;
                let Some(credentials) = credentials else {
                    continue;
                };
                form(
                    &mut out,
                    m,
                    a,
                    credentials,
                    &credentials.values,
                    false,
                    &Fields::new(),
                    None,
                    forms,
                    context.presentation,
                )?;
            }
        }
    }
    ensure!(
        stack.is_empty() && link_depth.is_none(),
        "unclosed document"
    );
    if let Some(next) = &context.next_page {
        out.push("<nav aria-label=\"Pages\"><a href=\"")?;
        out.text(next)?;
        out.push("\">Next page</a></nav>")?;
    }
    if !explicit_main {
        out.push("</main>")?;
    }
    out.push("</body></html>")?;
    Ok(Rendered {
        status,
        body: out.0.into_bytes(),
        location: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn form(
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
        ("_csrf", &credentials.csrf),
        ("_submission", &credentials.submission),
    ] {
        hidden(out, name, value)?;
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
    ensure!(layout.len() <= MAX_NODES, "form layout limit");
    let mut stack = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut submitted = false;
    for node in layout {
        match node {
            FormInstruction::Begin(container) => {
                ensure!(container != &Container::Main, "form main element");
                ensure!(stack.len() < MAX_DEPTH, "form depth");
                if *container == Container::Item {
                    ensure!(stack.last() == Some(&Container::List), "orphan list item");
                } else if stack.last() == Some(&Container::List) {
                    anyhow::bail!("list content");
                } else if stack.last().is_some_and(phrasing) {
                    ensure!(inline(container), "phrasing content");
                }
                out.push("<")?;
                out.push(tag(container))?;
                out.push(">")?;
                if *container == Container::Pre {
                    out.push("\n")?;
                }
                stack.push(container.clone());
            }
            FormInstruction::End => {
                let container = stack
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("unmatched form end"))?;
                out.push("</")?;
                out.push(tag(&container))?;
                out.push(">")?;
            }
            FormInstruction::Text(text) => {
                ensure!(stack.last() != Some(&Container::List), "list text");
                out.text(text)?;
            }
            FormInstruction::Field { name, control } => {
                ensure!(flow(&stack) && seen.insert(name), "form field structure");
                let field = fields
                    .iter()
                    .find(|field| &field.name == name)
                    .ok_or_else(|| anyhow::anyhow!("unknown form field"))?;
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
                ensure!(flow(&stack) && !submitted, "submit structure");
                submitted = true;
                out.push("<button type=\"submit\">")?;
                out.text(button.unwrap_or(label))?;
                out.push("</button>")?;
            }
        }
    }
    ensure!(
        stack.is_empty() && submitted && seen.len() == fields.len(),
        "incomplete form layout"
    );
    out.push("</form>")
}

fn hidden(out: &mut Buffer, name: &str, value: &str) -> Result<()> {
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

pub(crate) enum Recovery<'a> {
    Retry {
        unknown: bool,
    },
    Conflict {
        current: &'a Fields,
    },
    Rejected {
        errors: &'a Fields,
        message: &'a str,
    },
}

/// Only host-authenticated scope and freshly authorized values reach this page.
pub(crate) fn recovery(
    presentation: &crate::Presentation,
    m: &Manifest,
    action: u32,
    credentials: &FormCredentials,
    input: &Fields,
    reason: Recovery<'_>,
) -> Result<Rendered> {
    let a = crate::manifest::action(m, action)?;
    let empty = Fields::new();
    let (title, explanation, status, readonly, button, errors) = match &reason {
        Recovery::Retry { unknown: true } => (
            "Submission result",
            "The result is not yet confirmed. Check this submission before starting another one.",
            503,
            true,
            "Check this submission",
            &empty,
        ),
        Recovery::Retry { unknown: false } => (
            "Submission result",
            "No change is confirmed. Check the fields and retry this form.",
            422,
            false,
            "Retry this submission",
            &empty,
        ),
        Recovery::Conflict { .. } => (
            "This record changed",
            "Your changes were not saved. Review the current values before submitting again.",
            409,
            false,
            if crate::manifest::operation(m, a.operation)?.kind == OperationKind::Delete {
                "Delete current version"
            } else {
                "Save these changes"
            },
            &empty,
        ),
        Recovery::Rejected { errors, .. } => (
            "No changes saved",
            "The application declined this change. Review its explanation and try again.",
            422,
            false,
            "Retry this submission",
            *errors,
        ),
    };
    let mut out = Buffer(String::new());
    out.push("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>")?;
    out.text(title)?;
    out.push("</title>")?;
    stylesheet(&mut out, presentation)?;
    out.push("</head><body><main><h1>")?;
    out.text(title)?;
    out.push("</h1><p role=\"status\">")?;
    out.text(explanation)?;
    out.push("</p>")?;
    if let Recovery::Conflict { current } = &reason {
        out.push("<section aria-label=\"Current values\"><h2>Current values</h2>")?;
        let resource =
            crate::manifest::resource(m, crate::manifest::operation(m, a.operation)?.resource)?;
        for (name, value) in *current {
            let field = resource
                .fields
                .iter()
                .find(|f| &f.name == name)
                .ok_or_else(|| anyhow::anyhow!("unknown current field"))?;
            out.push("<p>")?;
            out.text(&field.label)?;
            out.push("</p><pre>\n")?;
            out.text(value)?;
            out.push("</pre>")?;
        }
        out.push("</section>")?;
        if !a.fields.is_empty() {
            out.push("<h2>Your changes</h2>")?;
        }
    }
    if let Recovery::Rejected { errors, message } = &reason {
        ensure!(
            message.len() <= 1024
                && errors.len() <= 8
                && errors.values().all(|e| !e.is_empty() && e.len() <= 256),
            "rejection limit"
        );
        out.push("<p class=\"application-error\">")?;
        out.text(message)?;
        out.push("</p>")?;
    }
    form(
        &mut out,
        m,
        a,
        credentials,
        input,
        readonly,
        errors,
        Some(button),
        0,
        presentation,
    )?;
    out.push("<a href=\"/\">Return home</a></main></body></html>")?;
    Ok(Rendered {
        status,
        body: out.0.into_bytes(),
        location: None,
    })
}

pub(crate) fn unavailable(presentation: &crate::Presentation, m: &Manifest) -> Result<Rendered> {
    render(
        &ResponseIntent::NotFound(Document::new(
            "Record unavailable",
            vec![
                Instruction::Text("This record is no longer available for this action.".into()),
                Instruction::Link {
                    destination: RouteRef {
                        route: m
                            .routes
                            .iter()
                            .find(|r| r.path == "/")
                            .expect("index route")
                            .id,
                        target: None,
                    },
                    text: "Return home".into(),
                },
            ],
        )),
        &RenderContext {
            presentation,
            manifest: Some(m),
            ..RenderContext::empty()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, kind: FieldKind, optional: bool) -> TextField {
        TextField {
            name: name.into(),
            label: format!("Label {name}"),
            max_bytes: 200,
            kind,
            optional,
        }
    }

    fn custom_form(
        fields: Vec<TextField>,
        layout: Vec<FormInstruction>,
        input: Fields,
        readonly: bool,
    ) -> String {
        let mut manifest = crate::test_support::manifest();
        manifest.resources[0].fields = fields;
        manifest.actions[0].fields = manifest.resources[0]
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect();
        manifest.actions[0].layout = layout;
        let mut out = Buffer(String::new());
        form(
            &mut out,
            &manifest,
            &manifest.actions[0],
            &FormCredentials {
                csrf: "csrf".into(),
                submission: "token".into(),
                values: Fields::new(),
            },
            &input,
            readonly,
            &Fields::new(),
            Some("Retry"),
            0,
            &crate::presentation::DEFAULT,
        )
        .unwrap();
        out.0
    }

    #[test]
    fn readonly_discrete_controls_preserve_exact_submission() {
        let html = custom_form(
            vec![
                field("done", FieldKind::Boolean, false),
                field("flag", FieldKind::Boolean, true),
                field(
                    "priority",
                    FieldKind::Choice {
                        variants: vec![ChoiceVariant {
                            key: "high".into(),
                            label: "High & urgent".into(),
                        }],
                    },
                    false,
                ),
            ],
            vec![],
            Fields::from([
                ("done".into(), "false".into()),
                ("flag".into(), "".into()),
                ("priority".into(), "<unknown>".into()),
            ]),
            true,
        );
        assert!(html.contains("type=\"checkbox\" value=\"true\""));
        assert!(!html.contains(" checked"));
        assert!(html.contains("<input type=\"hidden\" name=\"done\" value=\"false\">"));
        assert!(html.contains("<input type=\"hidden\" name=\"flag\" value=\"\">"));
        assert!(
            html.contains("<option value=\"&lt;unknown&gt;\" selected>&lt;unknown&gt;</option>")
        );
        assert!(html.contains("High &amp; urgent"));
        assert_eq!(html.matches(" disabled").count(), 3);
        assert!(html.contains("aria-invalid=\"true\""));
    }

    #[test]
    fn blueprint_preserves_invalid_integer_and_multiline_text() {
        let html = custom_form(
            vec![
                field(
                    "estimate",
                    FieldKind::Integer {
                        min: Some(0),
                        max: Some(10),
                    },
                    false,
                ),
                field("title", FieldKind::Text, false),
            ],
            vec![
                FormInstruction::Begin(Container::Section),
                FormInstruction::Text("Custom editor".into()),
                FormInstruction::Field {
                    name: "title".into(),
                    control: Control::TextInput,
                },
                FormInstruction::Field {
                    name: "estimate".into(),
                    control: Control::Auto,
                },
                FormInstruction::Submit {
                    label: "Save".into(),
                },
                FormInstruction::End,
            ],
            Fields::from([
                ("estimate".into(), "1e9".into()),
                ("title".into(), "\nline one\nline two".into()),
            ]),
            false,
        );
        assert!(html.starts_with("<form"));
        assert!(html.contains("<section>Custom editor"));
        assert!(html.contains("value=\"1e9\""));
        assert!(html.contains("inputmode=\"numeric\""));
        assert!(html.contains(">\n\nline one\nline two</textarea>"));
        assert!(html.contains("aria-describedby=\"error-1-0-estimate\""));
        assert!(html.contains("<button type=\"submit\">Retry</button></section>"));
    }

    #[test]
    fn explicit_main_has_no_implicit_nested_main() {
        let response = ResponseIntent::Page(Document::new(
            "Main",
            vec![
                Instruction::Begin(Container::Main),
                Instruction::Text("Content".into()),
                Instruction::End,
            ],
        ));
        let html =
            String::from_utf8(render(&response, &RenderContext::empty()).unwrap().body).unwrap();
        assert_eq!(html.matches("<main>").count(), 1);
        let duplicate = ResponseIntent::Page(Document::new(
            "Main",
            vec![
                Instruction::Begin(Container::Main),
                Instruction::End,
                Instruction::Begin(Container::Main),
                Instruction::End,
            ],
        ));
        assert!(render(&duplicate, &RenderContext::empty()).is_err());
    }

    fn record_route(path: &str) -> Route {
        Route {
            id: 1,
            path: path.into(),
            resource: Some(1),
            operations: vec![],
            forms: vec![],
        }
    }

    #[test]
    fn typed_paths_match_and_resolve_in_both_directions() {
        let route = record_route("/tasks/{task}/details");
        validate_path(&route).unwrap();
        assert_eq!(match_path(&route, "/tasks/81/details"), Some(Some(81)));
        for path in [
            "/tasks/0/details",
            "/tasks/01/details",
            "/tasks/+1/details",
            "/tasks/9223372036854775808/details",
            "/tasks/1/details/",
            "/tasks/%31/details",
            "/tasks/1/details/extra",
        ] {
            assert_eq!(match_path(&route, path), None, "{path}");
        }
        let mut manifest = crate::test_support::manifest();
        manifest.routes[0] = route;
        assert_eq!(
            resolve(
                &manifest,
                &RouteRef {
                    route: 1,
                    target: Some(81)
                }
            )
            .unwrap(),
            "/tasks/81/details"
        );
        assert!(
            resolve(
                &manifest,
                &RouteRef {
                    route: 1,
                    target: None
                }
            )
            .is_err()
        );
        assert!(!paths_overlap(
            &record_route("/tasks/{task}"),
            &record_route("/notes/{note}")
        ));
    }

    #[test]
    fn route_grammar_rejects_ambiguous_patterns() {
        for path in [
            "/tasks",
            "/tasks/{one}/{two}",
            "/tasks/{Bad}",
            "/tasks//details",
            "/tasks/",
            "/tasks/{task}suffix",
        ] {
            assert!(validate_path(&record_route(path)).is_err(), "{path}");
        }
        for path in ["/login", "/logout"] {
            let mut route = record_route(path);
            route.resource = None;
            assert!(validate_path(&route).is_ok());
        }
        let mut collection = record_route("/tasks/{task}");
        collection.resource = None;
        assert!(validate_path(&collection).is_err());
        assert!(paths_overlap(
            &record_route("/tasks/{task}"),
            &record_route("/tasks/{other}")
        ));
    }

    #[test]
    fn disabled_declared_forms_are_omitted_and_undeclared_forms_rejected() {
        let manifest = crate::test_support::manifest();
        let context = RenderContext {
            manifest: Some(&manifest),
            forms: BTreeMap::from([(1, None)]),
            ..RenderContext::empty()
        };
        let page = |action| {
            ResponseIntent::Page(Document::new(
                "Read only",
                vec![
                    Instruction::Text("Authorized content".into()),
                    Instruction::Form { action },
                ],
            ))
        };
        let rendered = render(&page(1), &context).unwrap();
        let html = String::from_utf8(rendered.body).unwrap();
        assert!(html.contains("Authorized content") && !html.contains("<form"));
        assert!(render(&page(2), &context).is_err());
        let no_grants = RenderContext {
            manifest: Some(&manifest),
            ..RenderContext::empty()
        };
        assert!(render(&page(1), &no_grants).is_err());
    }
}

#[cfg(test)]
mod link_tests {
    use super::*;
    #[test]
    fn inline_link_fragments_are_escaped_and_structurally_bounded() {
        let manifest = crate::test_support::manifest();
        let context = RenderContext {
            manifest: Some(&manifest),
            ..RenderContext::empty()
        };
        let begin = Instruction::BeginLink {
            destination: RouteRef {
                route: 1,
                target: None,
            },
        };
        let valid = vec![
            begin.clone(),
            Instruction::Begin(Container::Strong),
            Instruction::Text("<title>".into()),
            Instruction::End,
            Instruction::EndLink,
        ];
        let html = String::from_utf8(
            render(
                &ResponseIntent::Page(Document::new("Links", valid)),
                &context,
            )
            .unwrap()
            .body,
        )
        .unwrap();
        assert!(html.contains("<a href=\"/\"><strong>&lt;title&gt;</strong></a>"));
        for invalid in [
            vec![
                begin.clone(),
                begin.clone(),
                Instruction::EndLink,
                Instruction::EndLink,
            ],
            vec![
                begin.clone(),
                Instruction::Begin(Container::Paragraph),
                Instruction::End,
                Instruction::EndLink,
            ],
            vec![begin.clone()],
            vec![Instruction::EndLink],
            vec![
                Instruction::Begin(Container::Strong),
                begin,
                Instruction::End,
                Instruction::EndLink,
            ],
        ] {
            assert!(
                render(
                    &ResponseIntent::Page(Document::new("Invalid", invalid)),
                    &context
                )
                .is_err()
            );
        }
    }
}
