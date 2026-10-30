use anyhow::{Result, ensure};
use noxide_protocol::*;
use std::collections::BTreeSet;

pub(crate) fn validate(m: &Manifest, action: &Action, layout: &[FormInstruction]) -> Result<()> {
    ensure!(
        layout.len() <= MAX_NODES && serde_json::to_vec(&layout)?.len() <= MAX_IR_BYTES,
        "form layout limit"
    );
    let fields = crate::manifest::action_fields(m, action)?;
    let mut seen = BTreeSet::new();
    let mut stack = Vec::new();
    let mut submit = false;
    for node in layout {
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
                        Control::TextInput => matches!(
                            f.kind,
                            FieldKind::Text | FieldKind::Account { .. } | FieldKind::Integer { .. }
                        ),
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
