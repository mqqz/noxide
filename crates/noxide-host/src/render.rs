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
    pub manifest: Option<&'a Manifest>,
    /// Missing entries are undeclared; None is declared but denied by policy.
    pub forms: BTreeMap<u32, Option<FormCredentials>>,
    pub logout_csrf: Option<String>,
    pub next_page: Option<String>,
}

impl RenderContext<'_> {
    pub fn empty() -> Self {
        Self {
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

pub fn resolve(m: &Manifest, reference: &RouteRef) -> Result<String> {
    let r = crate::manifest::route(m, reference.route)?;
    match (r.resource.is_some(), reference.target) {
        (false, None) => Ok(r.path.clone()),
        (true, Some(id)) if id > 0 && id <= i64::MAX as u64 => {
            Ok(format!("{}/{id}", r.path.trim_end_matches('/')))
        }
        _ => Err(anyhow::anyhow!("invalid route target")),
    }
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
    out.push("</title><link rel=\"stylesheet\" href=\"/_noxide/style.css\"></head><body>")?;
    if let Some(csrf) = &context.logout_csrf {
        out.push("<nav aria-label=\"Account\"><a href=\"/\">Home</a><form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"_csrf\" value=\"")?;
        out.text(csrf)?;
        out.push("\"><button>Sign out</button></form></nav>")?;
    }
    out.push("<main>")?;
    let mut stack = Vec::new();
    let mut forms = 0;
    for node in &doc.nodes {
        match node {
            Instruction::Begin(c) => {
                ensure!(stack.len() < MAX_DEPTH, "document depth");
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
            Instruction::Link { destination, text } => {
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
                ensure!(flow(&stack) && forms < 8, "form structure or limit");
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
                )?;
            }
        }
    }
    ensure!(stack.is_empty(), "unclosed document");
    if let Some(next) = &context.next_page {
        out.push("<nav aria-label=\"Pages\"><a href=\"")?;
        out.text(next)?;
        out.push("\">Next page</a></nav>")?;
    }
    out.push("</main></body></html>")?;
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
        "<form method=\"post\" action=\"/_noxide/action/{}\" accept-charset=\"utf-8\">",
        action.id
    ))?;
    for (name, value) in [
        ("_csrf", &credentials.csrf),
        ("_submission", &credentials.submission),
    ] {
        out.push(&format!("<input type=\"hidden\" name=\"{name}\" value=\""))?;
        out.text(value)?;
        out.push("\">")?;
    }
    for field in fields {
        let value = input.get(&field.name).map(String::as_str).unwrap_or("");
        let invalid = !input.is_empty()
            && (value.trim().is_empty() || value.len() > field.max_bytes as usize);
        let error = errors.get(&field.name);
        out.push("<label>")?;
        out.text(&field.label)?;
        out.push(&format!(
            "<textarea name=\"{}\" maxlength=\"{}\" required",
            field.name, field.max_bytes
        ))?;
        if readonly {
            out.push(" readonly")?;
        }
        if invalid || error.is_some() {
            out.push(&format!(
                " aria-invalid=\"true\" aria-describedby=\"error-{}-{}\"",
                action.id, field.name
            ))?;
        }
        // HTML normalizes CR/CRLF and consumes one initial textarea LF.
        // Supply that LF so prefilled values keep every leading newline.
        out.push(">\n")?;
        out.text(value)?;
        out.push("</textarea></label>")?;
        if invalid || error.is_some() {
            out.push(&format!("<p id=\"error-{}-{}\">", action.id, field.name))?;
            if let Some(error) = error {
                out.text(error)?;
            } else {
                out.push(&format!(
                    "Enter between 1 and {} UTF-8 bytes.",
                    field.max_bytes
                ))?;
            }
            out.push("</p>")?;
        }
    }
    let default_button =
        if crate::manifest::operation(m, action.operation)?.kind == OperationKind::Delete {
            "Delete record"
        } else {
            &action.name
        };
    out.push("<button type=\"submit\">")?;
    out.text(button.unwrap_or(default_button))?;
    out.push("</button></form>")
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
    out.push(
        "</title><link rel=\"stylesheet\" href=\"/_noxide/style.css\"></head><body><main><h1>",
    )?;
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
    )?;
    out.push("<a href=\"/\">Return home</a></main></body></html>")?;
    Ok(Rendered {
        status,
        body: out.0.into_bytes(),
        location: None,
    })
}

pub(crate) fn unavailable(m: &Manifest) -> Result<Rendered> {
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
            manifest: Some(m),
            ..RenderContext::empty()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
