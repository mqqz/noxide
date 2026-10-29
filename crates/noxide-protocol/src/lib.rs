//! Versioned semantic protocol shared by the guest SDK and trusted host.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VERSION: u32 = 4;
pub const MAX_IR_BYTES: usize = 65_536;
pub const MAX_NODES: usize = 1_024;
pub const MAX_DEPTH: usize = 32;
pub const MAX_OUTPUT_BYTES: usize = 262_144;
pub const MAX_INPUT_BYTES: usize = 32_768;
pub const MAX_REQUEST_BYTES: usize = 65_536;
pub const MAX_RESULT_BYTES: usize = 65_536;
pub const MAX_MANIFEST_BYTES: usize = 32_768;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Container {
    Main,
    Nav,
    Header,
    Footer,
    Div,
    Article,
    Section,
    Heading1,
    Heading2,
    Paragraph,
    List,
    Item,
    Strong,
    Emphasis,
    Code,
    Pre,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteRef {
    pub route: u32,
    pub target: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Instruction {
    Begin(Container),
    End,
    Text(String),
    Link { destination: RouteRef, text: String },
    BeginLink { destination: RouteRef },
    EndLink,
    Form { action: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub title: String,
    pub nodes: Vec<Instruction>,
}

impl Document {
    pub fn new(title: impl Into<String>, nodes: Vec<Instruction>) -> Self {
        Self {
            title: title.into(),
            nodes,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseIntent {
    Page(Document),
    NotFound(Document),
    Redirect(RouteRef),
    Created {
        resource: u32,
        id: u64,
        destination: RouteRef,
    },
    Updated {
        resource: u32,
        id: u64,
        destination: RouteRef,
    },
    Deleted {
        resource: u32,
        id: u64,
        destination: RouteRef,
    },
    Rejected {
        field_errors: Fields,
        message: String,
    },
}

pub fn decode_response(bytes: &[u8]) -> Result<ResponseIntent, String> {
    if bytes.len() > MAX_IR_BYTES {
        return Err("document byte limit".into());
    }
    // serde_json has its own recursion bound. The byte cap also bounds all
    // deserialization allocations, including strings, before structural checks.
    let response: ResponseIntent =
        serde_json::from_slice(bytes).map_err(|_| "invalid document encoding")?;
    if let ResponseIntent::Page(doc) | ResponseIntent::NotFound(doc) = &response
        && doc.nodes.len() > MAX_NODES
    {
        return Err("document node limit".into());
    }
    Ok(response)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Predicate {
    Public,
    Capability,
    Owner,
    SameTenant,
    Role { name: String, tenant_scoped: bool },
}

/// Grants access if every predicate in at least one nonempty rule matches.
/// An empty policy denies access. Rules are flat lists of predicates.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub any: Vec<Vec<Predicate>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TextField {
    pub kind: FieldKind,
    pub optional: bool,
    #[serde(deserialize_with = "required_initial")]
    pub initial: Option<String>,
    pub name: String,
    pub label: String,
    pub max_bytes: u32,
}

fn required_initial<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

/// Portable scalar schemas. Values cross the boundary in canonical text form.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldKind {
    #[default]
    Text,
    Boolean,
    Parent {
        resource: String,
        visible: Visibility,
        create_when: Visibility,
    },
    Integer {
        min: Option<i64>,
        max: Option<i64>,
    },
    Choice {
        variants: Vec<ChoiceVariant>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChoiceVariant {
    pub key: String,
    pub label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Control {
    Auto,
    TextInput,
    Textarea { rows: u8 },
    Checkbox,
    Select,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FormInstruction {
    Begin(Container),
    End,
    Text(String),
    Field { name: String, control: Control },
    Submit { label: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub id: u32,
    pub name: String,
    pub fields: Vec<TextField>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationKind {
    List,
    Read,
    Create,
    Update,
    Delete,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: u32,
    pub resource: u32,
    pub kind: OperationKind,
    pub policy: Policy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Visibility {
    pub field: String,
    pub equals: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Access {
    #[default]
    Authenticated,
    Public,
    PublicOptional,
}
impl Access {
    fn is_authenticated(&self) -> bool {
        *self == Self::Authenticated
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub id: u32,
    pub path: String,
    /// A record route addresses exactly one declared resource.
    pub resource: Option<u32>,
    pub operations: Vec<u32>,
    pub forms: Vec<u32>,
    #[serde(default, skip_serializing_if = "Access::is_authenticated")]
    pub access: Access,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub layout: Vec<FormInstruction>,
    pub id: u32,
    pub version: u32,
    pub name: String,
    pub operation: u32,
    pub redirect: u32,
    /// Every listed field is required; all other application fields are rejected.
    pub fields: Vec<String>,
    pub inspect: Option<Inspection>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub operation: u32,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub resources: Vec<Resource>,
    pub operations: Vec<Operation>,
    pub routes: Vec<Route>,
    pub actions: Vec<Action>,
}

pub type Fields = BTreeMap<String, String>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub resource: u32,
    pub id: u64,
    pub fields: Fields,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestKind {
    Route(u32),
    Action(u32),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestView {
    pub version: u32,
    pub kind: RequestKind,
    pub target: Option<u64>,
    pub input: Fields,
    /// Original target values permitted by the action's explicit read projection.
    pub inspection: Option<Fields>,
    pub available_forms: Vec<u32>,
}

impl TextField {
    /// Host-defined canonical scalar encoding; optional absence is the empty string.
    pub fn canonical(&self, input: &str) -> Result<String, String> {
        if self.optional && input.is_empty() {
            return Ok(String::new());
        }
        let value = match &self.kind {
            FieldKind::Text => {
                let value = input.replace("\r\n", "\n").replace('\r', "\n");
                if value.is_empty()
                    || value
                        .chars()
                        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
                {
                    return Err("Enter text.".into());
                }
                value
            }
            FieldKind::Boolean => match input {
                "true" | "on" => "true".into(),
                "false" => "false".into(),
                _ => return Err("Choose true or false.".into()),
            },
            FieldKind::Parent { .. } => {
                let id = input.parse::<u64>().map_err(|_| "invalid parent ID")?;
                if id == 0 || id > i64::MAX as u64 || id.to_string() != input {
                    return Err("invalid parent ID".into());
                }
                id.to_string()
            }
            FieldKind::Integer { min, max } => {
                let value: i64 = input.parse().map_err(|_| "Enter a whole number.")?;
                if min.is_some_and(|min| value < min) || max.is_some_and(|max| value > max) {
                    return Err("Number is outside the permitted range.".into());
                }
                value.to_string()
            }
            FieldKind::Choice { variants } => {
                if !variants.iter().any(|variant| variant.key == input) {
                    return Err("Choose a listed value.".into());
                }
                input.into()
            }
        };
        if value.len() > self.max_bytes as usize {
            return Err(format!("Use at most {} UTF-8 bytes.", self.max_bytes));
        }
        Ok(value)
    }
}

/// Stable contract identifier grammar, shared by producers and the host.
pub fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_protocol_requires_explicit_declarations_and_form_availability() {
        fn required<T: serde::de::DeserializeOwned>(value: serde_json::Value, fields: &[&str]) {
            assert!(serde_json::from_value::<T>(value.clone()).is_ok());
            for field in fields {
                let mut missing = value.clone();
                missing.as_object_mut().unwrap().remove(*field);
                assert!(
                    serde_json::from_value::<T>(missing).is_err(),
                    "missing {field}"
                );
            }
        }
        required::<TextField>(
            serde_json::json!({
                "kind": "text", "optional": false, "initial": null, "name": "body", "label": "Body", "max_bytes": 4096
            }),
            &["kind", "optional", "initial"],
        );
        required::<Action>(
            serde_json::json!({
                "layout": [], "id": 1, "version": 1, "name": "Create", "operation": 1,
                "redirect": 1, "fields": ["body"], "inspect": null
            }),
            &["layout"],
        );
        required::<RequestView>(
            serde_json::json!({
                "version": VERSION, "kind": {"route": 1}, "target": null, "input": {},
                "inspection": null, "available_forms": []
            }),
            &["available_forms"],
        );
    }
}
