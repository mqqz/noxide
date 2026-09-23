use anyhow::{Result, ensure};
use noxide_protocol::*;
use std::collections::BTreeMap;

pub const CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

pub struct FormCredentials {
    pub csrf: String,
    pub submission: String,
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
    match (r.record, reference.target) {
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
                let op = crate::manifest::operation(m, a.operation)?;
                let resource = crate::manifest::resource(m, op.resource)?;
                out.push(&format!("<form method=\"post\" action=\"/_noxide/action/{action}\" accept-charset=\"utf-8\">"))?;
                for (name, value) in [
                    ("_csrf", &credentials.csrf),
                    ("_submission", &credentials.submission),
                ] {
                    out.push(&format!("<input type=\"hidden\" name=\"{name}\" value=\""))?;
                    out.text(value)?;
                    out.push("\">")?;
                }
                for field in &resource.fields {
                    out.push("<label>")?;
                    out.text(&field.label)?;
                    out.push("<textarea name=\"")?;
                    out.text(&field.name)?;
                    out.push(&format!(
                        "\" maxlength=\"{}\" required></textarea></label>",
                        field.max_bytes
                    ))?;
                }
                out.push("<button type=\"submit\">")?;
                out.text(&a.name)?;
                out.push("</button></form>")?;
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

/// Trusted form recovery never passes the saved submission or entered values
/// through a guest. Every retry retains the original action identity.
pub(crate) fn recovery(
    m: &Manifest,
    action: u32,
    credentials: &FormCredentials,
    input: &Fields,
    unknown: bool,
) -> Result<Rendered> {
    let a = crate::manifest::action(m, action)?;
    let op = crate::manifest::operation(m, a.operation)?;
    let resource = crate::manifest::resource(m, op.resource)?;
    ensure!(
        input
            .keys()
            .all(|name| resource.fields.iter().any(|f| &f.name == name)),
        "unexpected field"
    );
    let mut out = Buffer(String::new());
    out.push("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Save result</title><link rel=\"stylesheet\" href=\"/_noxide/style.css\"></head><body><main><h1>Save result</h1><p role=\"status\">")?;
    out.push(if unknown {
        "The result is not yet confirmed. Check this save before starting another one."
    } else {
        "The save has no confirmed result. Check the fields and retry this form."
    })?;
    out.push(&format!(
        "</p><form method=\"post\" action=\"/_noxide/action/{action}\" accept-charset=\"utf-8\">"
    ))?;
    for (name, value) in [
        ("_csrf", &credentials.csrf),
        ("_submission", &credentials.submission),
    ] {
        out.push(&format!("<input type=\"hidden\" name=\"{name}\" value=\""))?;
        out.text(value)?;
        out.push("\">")?;
    }
    for field in &resource.fields {
        let value = input.get(&field.name).map(String::as_str).unwrap_or("");
        let invalid = value.trim().is_empty() || value.len() > field.max_bytes as usize;
        out.push("<label>")?;
        out.text(&field.label)?;
        out.push(&format!(
            "<textarea name=\"{}\" maxlength=\"{}\" required",
            field.name, field.max_bytes
        ))?;
        if unknown {
            out.push(" readonly")?;
        }
        if invalid {
            out.push(&format!(
                " aria-invalid=\"true\" aria-describedby=\"error-{}\"",
                field.name
            ))?;
        }
        out.push(">")?;
        // HTML discards one initial LF in textarea content. Preserve the
        // canonical entered value, including during an uncertain-outcome retry.
        if value.starts_with('\n') {
            out.push("\n")?;
        }
        out.text(value)?;
        out.push("</textarea></label>")?;
        if invalid {
            out.push(&format!(
                "<p id=\"error-{}\">Enter between 1 and {} UTF-8 bytes.</p>",
                field.name, field.max_bytes
            ))?;
        }
    }
    out.push(if unknown {
        "<button>Check this submission</button>"
    } else {
        "<button>Retry this submission</button>"
    })?;
    out.push("</form><a href=\"/\">Return to notes</a></main></body></html>")?;
    Ok(Rendered {
        status: if unknown { 503 } else { 422 },
        body: out.0.into_bytes(),
        location: None,
    })
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
