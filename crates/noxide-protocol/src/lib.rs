//! Versioned semantic protocol shared by the guest SDK and trusted host.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VERSION: u32 = 1;
pub const MAX_IR_BYTES: usize = 65_536;
pub const MAX_NODES: usize = 1_024;
pub const MAX_DEPTH: usize = 32;
pub const MAX_OUTPUT_BYTES: usize = 262_144;
pub const MAX_INPUT_BYTES: usize = 32_768;
pub const MAX_RESULT_BYTES: usize = 65_536;
pub const MAX_MANIFEST_BYTES: usize = 32_768;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Container {
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
    pub name: String,
    pub label: String,
    pub max_bytes: u32,
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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: u32,
    pub resource: u32,
    pub kind: OperationKind,
    pub policy: Policy,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub id: u32,
    pub path: String,
    pub record: bool,
    pub operations: Vec<u32>,
    pub forms: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub id: u32,
    pub version: u32,
    pub name: String,
    pub operation: u32,
    pub redirect: u32,
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
}
