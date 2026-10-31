//! Versioned semantic protocol shared by the guest SDK and trusted host.

pub mod assets;
pub mod blobs;
pub mod computation;
pub mod document;
pub mod expiry;
pub mod membership;
pub mod query;
pub mod time;
pub use computation::{Comparison, Guard, GuardCondition, GuardRejection, Literal, Value};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VERSION: u32 = 11;
pub const MAX_IR_BYTES: usize = 65_536;
pub const MAX_NODES: usize = 1_024;
pub const MAX_DEPTH: usize = 32;
pub const MAX_OUTPUT_BYTES: usize = 262_144;
pub const MAX_INPUT_BYTES: usize = 32_768;
pub const MAX_REQUEST_BYTES: usize = 65_536;
pub const MAX_RESULT_BYTES: usize = 65_536;
pub const MAX_LIST_RESULT_BYTES: usize = 131_072;
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
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
    Stylesheet { asset: String },
    Download(blobs::DocumentDownload),
    Rich(document::PresentationNode),
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
    Execute,
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
    PrincipalIs { field: String },
    Role { name: String, tenant_scoped: bool },
    ExistsRelated(membership::ExistsRelated),
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
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub immutable: bool,
    pub kind: FieldKind,
    pub optional: bool,
    #[serde(deserialize_with = "required_initial")]
    pub initial: Option<String>,
    pub name: String,
    pub label: String,
    pub max_bytes: u32,
}

impl TextField {
    pub fn is_immutable(&self) -> bool {
        self.immutable
            || matches!(
                self.kind,
                FieldKind::Reference { .. } | FieldKind::Account { .. } | FieldKind::Blob { .. }
            )
    }
}

fn required_initial<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountScope {
    SameTenant,
}

pub fn account_id(value: &str) -> bool {
    // 32 bytes in unpadded base64url: 42 full digits and two residual bits.
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && matches!(
            value.as_bytes()[42],
            b'A' | b'E'
                | b'I'
                | b'M'
                | b'Q'
                | b'U'
                | b'Y'
                | b'c'
                | b'g'
                | b'k'
                | b'o'
                | b's'
                | b'w'
                | b'0'
                | b'4'
                | b'8'
        )
}

/// Portable scalar schemas. Values cross the boundary in canonical text form.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldKind {
    #[default]
    Text,
    Account {
        scope: AccountScope,
    },
    Boolean,
    Blob {
        max_bytes: u64,
    },
    UploadHandle {
        max_bytes: u64,
    },
    Timestamp,
    Duration {
        max_millis: i64,
    },
    Reference {
        resource: String,
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
    File,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<query::SearchIndex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<expiry::ResourceExpiry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unique: Vec<membership::MembershipUnique>,
    pub gate: Option<Gate>,
    pub id: u32,
    pub name: String,
    pub fields: Vec<TextField>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationKind {
    Aggregate,
    List,
    Read,
    Create,
    Update,
    Delete,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<query::Query>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "reference_bindings"
    )]
    pub bind: BTreeMap<String, u32>,
    pub scope: Option<String>,
    pub via: Option<Via>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filter: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclose: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list: Option<ListSettings>,
    pub id: u32,
    pub resource: u32,
    pub kind: OperationKind,
    pub policy: Policy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
}

fn reference_bindings<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, u32>, D::Error> {
    struct Bindings;
    impl<'de> serde::de::Visitor<'de> for Bindings {
        type Value = BTreeMap<String, u32>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most four distinct reference eligibility fields")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut fields = BTreeMap::new();
            while let Some((field, operation)) = access.next_entry::<String, u32>()? {
                if fields.len() == 4 || fields.insert(field, operation).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive reference eligibility field",
                    ));
                }
            }
            Ok(fields)
        }
    }
    deserializer.deserialize_map(Bindings)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<Preview>,
    pub order: ListOrder,
    pub page_size: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub see_all: Option<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreviewResult {
    pub items: Vec<Record>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: String,
    pub equals: Operand,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Operand {
    Literal(String),
    Param(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListOrder {
    Field {
        field: String,
        direction: query::Direction,
        mode: query::SortMode,
    },
    CreatedAsc,
    CreatedDesc,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
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
pub struct Redirect {
    pub route: u32,
    pub source: RedirectSource,
}
impl Redirect {
    pub fn route(&self) -> u32 {
        self.route
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RedirectSource {
    Target(String),
    Step(u8),
    Reference { step: u8, field: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub id: u32,
    pub version: u32,
    pub name: String,
    pub targets: Vec<ActionTarget>,
    pub inputs: Vec<Input>,
    pub steps: Vec<Step>,
}

/// Existing targets have explicit provenance, review and independent read grants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionTarget {
    pub name: String,
    pub resource: u32,
    pub source: TargetSource,
    pub revision: Revision,
    pub projection: Option<Inspection>,
    pub inspect: Option<Inspection>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetSource {
    Page {
        reads: Vec<u32>,
    },
    Selected {
        query: u32,
        eligible: u32,
        label: Vec<String>,
    },
    Reference {
        target: String,
        field: String,
        eligible: u32,
    },
}

/// Browser presentation refers to a canonical action; it grants no authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebBinding {
    pub id: u32,
    pub version: u32,
    pub action: u32,
    pub layout: Vec<FormInstruction>,
    pub redirect: Redirect,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MutationKind {
    Created,
    Updated,
    Deleted,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutationOutcome {
    pub kind: MutationKind,
    pub resource: u32,
    pub id: u64,
    pub incarnation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub name: String,
    pub label: String,
    pub kind: FieldKind,
    pub optional: bool,
    pub max_bytes: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub guards: Vec<Guard>,
    pub operation: u32,
    pub target: Target,
    pub assign: Vec<Assignment>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    None,
    Named(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub field: String,
    pub change: Change,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Set(Value),
    Decrease {
        by: Value,
        rejection: GuardRejection,
    },
    Increase {
        by: Value,
        rejection: GuardRejection,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Revision {
    Exact,
    Identity,
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
    pub assets: Vec<assets::AssetDeclaration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blobs: Option<blobs::BlobPolicy>,
    pub version: u32,
    pub resources: Vec<Resource>,
    pub operations: Vec<Operation>,
    pub routes: Vec<Route>,
    pub actions: Vec<Action>,
    pub web_bindings: Vec<WebBinding>,
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    pub version: u32,
    pub kind: RequestKind,
    pub target: Option<u64>,
    pub input: Fields,
    /// Original target values permitted by the action's explicit read projection.
    pub inspection: BTreeMap<String, Fields>,
    pub available_forms: Vec<u32>,
}

impl TextField {
    /// Host-defined canonical scalar encoding; optional absence is the empty string.
    pub fn canonical(&self, input: &str) -> Result<String, String> {
        if matches!(self.kind, FieldKind::UploadHandle { .. }) {
            return Err("upload handles are action inputs only".into());
        }
        canonical_scalar(&self.kind, self.optional, self.max_bytes, input)
    }
}

impl Input {
    pub fn canonical(&self, input: &str) -> Result<String, String> {
        if matches!(
            self.kind,
            FieldKind::Reference { .. } | FieldKind::Blob { .. }
        ) {
            return Err("invalid input kind".into());
        }
        canonical_scalar(&self.kind, self.optional, self.max_bytes, input)
    }
}

fn canonical_scalar(
    kind: &FieldKind,
    optional: bool,
    max_bytes: u32,
    input: &str,
) -> Result<String, String> {
    if optional && input.is_empty() {
        return Ok(String::new());
    }
    let value = match kind {
        FieldKind::Blob { .. } => blobs::BlobRef::parse(input.to_owned())?.as_str().to_owned(),
        FieldKind::UploadHandle { .. } => blobs::UploadHandle::parse(input.to_owned())?
            .as_str()
            .to_owned(),
        FieldKind::Account { .. } => {
            if !account_id(input) {
                return Err("invalid account reference".into());
            }
            input.to_owned()
        }
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
        FieldKind::Reference { .. } => {
            let id = input.parse::<u64>().map_err(|_| "invalid reference ID")?;
            if id == 0 || id > i64::MAX as u64 || id.to_string() != input {
                return Err("invalid reference ID".into());
            }
            id.to_string()
        }
        FieldKind::Timestamp => {
            let value = input
                .parse::<i64>()
                .map_err(|_| "Enter UTC milliseconds.")?;
            time::Timestamp::from_unix_millis(value)
                .map_err(|_| "Timestamp is outside its permitted range.")?;
            value.to_string()
        }
        FieldKind::Duration { max_millis } => {
            let value = input
                .parse::<i64>()
                .map_err(|_| "Enter whole duration milliseconds.")?;
            if value < 0 || value > *max_millis {
                return Err("Duration is outside its permitted range.".into());
            }
            value.to_string()
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
    if value.len() > max_bytes as usize {
        return Err(format!("Use at most {} UTF-8 bytes.", max_bytes));
    }
    Ok(value)
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
    fn blob_tokens_are_distinct_input_and_storage_domains() {
        let blob = format!("b1_{}", "a".repeat(64));
        let upload = format!("u1_{}", "b".repeat(64));
        let field = TextField {
            immutable: false,
            kind: FieldKind::Blob { max_bytes: 1024 },
            optional: false,
            initial: None,
            name: "attachment".into(),
            label: "Attachment".into(),
            max_bytes: 67,
        };
        let input = Input {
            kind: FieldKind::UploadHandle { max_bytes: 1024 },
            optional: false,
            name: "file".into(),
            label: "File".into(),
            max_bytes: 67,
        };
        assert_eq!(field.canonical(&blob).unwrap(), blob);
        assert!(field.canonical(&upload).is_err());
        assert_eq!(input.canonical(&upload).unwrap(), upload);
        assert!(input.canonical(&blob).is_err());
        assert!(
            TextField {
                kind: input.kind.clone(),
                ..field.clone()
            }
            .canonical(&upload)
            .is_err()
        );
        assert!(
            Input {
                kind: field.kind.clone(),
                ..input.clone()
            }
            .canonical(&blob)
            .is_err()
        );
        assert!(
            Input {
                max_bytes: 66,
                ..input.clone()
            }
            .canonical(&upload)
            .is_err()
        );
        assert_eq!(
            Input {
                optional: true,
                ..input
            }
            .canonical("")
            .unwrap(),
            ""
        );
    }

    #[test]
    fn transaction_input_canonicalization_enforces_quantity_and_byte_bounds() {
        let quantity = Input {
            name: "quantity".into(),
            label: "Quantity".into(),
            kind: FieldKind::Integer {
                min: Some(1),
                max: Some(10),
            },
            optional: false,
            max_bytes: 20,
        };
        for invalid in ["0", "-1", "11", "9223372036854775808", ""] {
            assert!(quantity.canonical(invalid).is_err(), "{invalid}");
        }
        assert_eq!(quantity.canonical("+01").unwrap(), "1");
        let body = Input {
            name: "body".into(),
            label: "Body".into(),
            kind: FieldKind::Text,
            optional: false,
            max_bytes: 4,
        };
        assert_eq!(body.canonical("a\r\nb").unwrap(), "a\nb");
        assert!(body.canonical("ééé").is_err());
        let reference = Input {
            kind: FieldKind::Reference {
                resource: "product".into(),
            },
            optional: true,
            ..body.clone()
        };
        assert!(reference.canonical("").is_err());
        let account = Input {
            kind: FieldKind::Account {
                scope: AccountScope::SameTenant,
            },
            max_bytes: 43,
            ..body
        };
        assert!(account.canonical("not-an-account").is_err());
        assert_eq!(account.canonical(&"A".repeat(43)).unwrap(), "A".repeat(43));
    }

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
                "targets": [], "id": 1, "version": 1, "name": "Create", "inputs": [],
                "steps": [{"guards": [], "operation": 1, "target": "none", "assign": []}]
            }),
            &["targets", "inputs", "steps"],
        );
        required::<WebBinding>(
            serde_json::json!({ "id": 11, "version": 1, "action": 1, "layout": [], "redirect": {"route": 1, "source": {"step": 0}} }),
            &["id", "version", "action", "layout", "redirect"],
        );
        required::<RequestView>(
            serde_json::json!({
                "version": VERSION, "kind": {"route": 1}, "target": null, "input": {},
                "inspection": {}, "available_forms": []
            }),
            &["available_forms"],
        );
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub field: String,
    pub visible: Visibility,
    pub create_when: Visibility,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Via {
    pub source: u32,
    pub field: String,
}

#[cfg(test)]
mod reference_binding_tests {
    use super::*;
    #[test]
    fn time_scalars_are_distinct_bounded_canonical_milliseconds() {
        let timestamp = Input {
            name: "at".into(),
            label: "At".into(),
            kind: FieldKind::Timestamp,
            optional: false,
            max_bytes: 20,
        };
        assert_eq!(timestamp.canonical("+001").unwrap(), "1");
        for invalid in ["-1", "9223372036854775808", "1.5", ""] {
            assert!(timestamp.canonical(invalid).is_err());
        }
        let duration = Input {
            kind: FieldKind::Duration {
                max_millis: 900_000,
            },
            ..timestamp.clone()
        };
        assert_eq!(duration.canonical("900000").unwrap(), "900000");
        assert_eq!(duration.canonical("0").unwrap(), "0");
        for invalid in ["-1", "900001", "1.5", ""] {
            assert!(duration.canonical(invalid).is_err());
        }
        assert_ne!(
            serde_json::to_value(&timestamp.kind).unwrap(),
            serde_json::to_value(&duration.kind).unwrap()
        );
        assert!(
            serde_json::from_str::<Value>(
                r#"{"snapshot_field":{"target":"product","field":"price"}}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<Literal>(r#"{"timestamp":-1}"#).is_err());
    }

    #[test]
    fn eligibility_fields_are_canonical_maps_and_duplicate_wire_keys_are_rejected() {
        let operation = r#"{"bind":{"right":2,"left":1},"scope":null,"via":null,"id":3,"resource":4,"kind":"create","policy":{"any":[["owner"]]}}"#;
        let parsed: Operation = serde_json::from_str(operation).unwrap();
        let reordered: Operation = serde_json::from_str(
            &operation.replace("\"right\":2,\"left\":1", "\"left\":1,\"right\":2"),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&parsed).unwrap(),
            serde_json::to_vec(&reordered).unwrap()
        );
        assert!(
            serde_json::from_str::<Operation>(
                &operation.replace("\"right\":2,\"left\":1", "\"left\":2,\"left\":1")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Operation>(&operation.replace(
                "\"right\":2,\"left\":1",
                "\"a\":1,\"b\":1,\"c\":1,\"d\":1,\"e\":1"
            ))
            .is_err()
        );
    }
}
