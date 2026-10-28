//! Typed declarations and composition for guest applications.
use crate::{
    Context, Document, Fields, Instruction, Record, RequestView, ResponseIntent, RouteRef,
};
use noxide_protocol::*;
use std::{collections::BTreeMap, marker::PhantomData, ops::Deref};

/// Deterministic bundle-local identifier. Host admission rejects collisions.
pub const fn stable_id(key: &str) -> u32 {
    let bytes = key.as_bytes();
    let mut hash = 2166136261u32;
    let mut i = 0;
    while i < bytes.len() {
        hash = (hash ^ bytes[i] as u32).wrapping_mul(16777619);
        i += 1;
    }
    hash
}

/// A record's identity. Possession does not grant access to it.
pub struct Id<R> {
    value: u64,
    marker: PhantomData<fn() -> R>,
}
impl<R> Copy for Id<R> {}
impl<R> Clone for Id<R> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R> std::fmt::Debug for Id<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Id").field(&self.value).finish()
    }
}
impl<R> PartialEq for Id<R> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl<R> Eq for Id<R> {}
impl<R> PartialOrd for Id<R> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<R> Ord for Id<R> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}
impl<R> std::hash::Hash for Id<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}
impl<R> Id<R> {
    pub fn new(value: u64) -> Self {
        assert!(value > 0 && value <= i64::MAX as u64, "record ID range");
        Self {
            value,
            marker: PhantomData,
        }
    }
    pub fn get(self) -> u64 {
        self.value
    }
}

pub trait ResourceType: Sized {
    const KEY: &'static str;
    fn definition() -> Resource;
    fn from_record(record: Record) -> Self;
}
pub trait FieldSpec<const KEY: u32> {
    type Value: FieldValue;
    const KEY: &'static str;
}
pub trait FieldValue: Sized {
    const OPTIONAL: bool = false;
    fn kind() -> FieldKind;
    fn encode(&self) -> String;
    fn decode(value: &str) -> Self;
}
impl FieldValue for String {
    fn kind() -> FieldKind {
        FieldKind::Text
    }
    fn encode(&self) -> String {
        self.clone()
    }
    fn decode(value: &str) -> Self {
        value.to_owned()
    }
}
impl FieldValue for bool {
    fn kind() -> FieldKind {
        FieldKind::Boolean
    }
    fn encode(&self) -> String {
        self.to_string()
    }
    fn decode(value: &str) -> Self {
        match value {
            "true" => true,
            "false" => false,
            _ => panic!("host boolean contract"),
        }
    }
}
impl FieldValue for i64 {
    fn kind() -> FieldKind {
        FieldKind::Integer {
            min: None,
            max: None,
        }
    }
    fn encode(&self) -> String {
        self.to_string()
    }
    fn decode(value: &str) -> Self {
        value.parse().expect("host integer contract")
    }
}
impl<T: FieldValue> FieldValue for Option<T> {
    const OPTIONAL: bool = true;
    fn kind() -> FieldKind {
        T::kind()
    }
    fn encode(&self) -> String {
        self.as_ref().map(FieldValue::encode).unwrap_or_default()
    }
    fn decode(value: &str) -> Self {
        if value.is_empty() {
            None
        } else {
            Some(T::decode(value))
        }
    }
}

pub trait QueryType {
    type Resource: ResourceType;
    type Output;
    fn operation() -> Operation;
    fn from_record(record: Record) -> Self::Output;
}
pub trait ListQuery: QueryType {}
pub trait ReadQuery: QueryType {}
pub trait ActionInput: Sized {
    fn from_fields(fields: &Fields) -> Self;
}
impl ActionInput for () {
    fn from_fields(_: &Fields) -> Self {}
}
pub trait ActionType: Sized {
    type Resource: ResourceType;
    type Input: ActionInput;
    type Original: ActionInput;
    type Controls;
    fn definition() -> Action;
    fn operation() -> Operation;
    fn inspection() -> Option<Operation> {
        None
    }
    fn controls() -> Self::Controls;
}

/// Arguments are constructed for one request; host checks remain authoritative.
pub trait FromRequest: Sized {
    fn from_request(request: &RequestView) -> Self;
}
impl<R> FromRequest for Id<R> {
    fn from_request(request: &RequestView) -> Self {
        Self::new(request.target.expect("record route"))
    }
}
pub struct Query<Q> {
    context: Context,
    marker: PhantomData<Q>,
}
impl<Q: QueryType> FromRequest for Query<Q> {
    fn from_request(_: &RequestView) -> Self {
        Self {
            context: Context { _private: () },
            marker: PhantomData,
        }
    }
}
impl<Q: QueryType> Query<Q> {
    pub fn fetch(&mut self) -> Vec<Q::Output>
    where
        Q: ListQuery,
    {
        let operation = Q::operation();
        assert!(operation.kind == OperationKind::List, "not a list query");
        self.context
            .list(operation.id)
            .into_iter()
            .map(Q::from_record)
            .collect()
    }
    pub fn get(&mut self, id: Id<Q::Resource>) -> Option<Q::Output>
    where
        Q: ReadQuery,
    {
        let operation = Q::operation();
        assert!(operation.kind == OperationKind::Read, "not a read query");
        self.context
            .read(operation.id, id.get())
            .map(Q::from_record)
    }
}

pub struct Form<A> {
    available: bool,
    marker: PhantomData<A>,
}
impl<A: ActionType> FromRequest for Form<A> {
    fn from_request(request: &RequestView) -> Self {
        Self {
            available: request.available_forms.contains(&A::definition().id),
            marker: PhantomData,
        }
    }
}
impl<A> Form<A> {
    pub fn is_available(&self) -> bool {
        self.available
    }
}

pub struct Submission<A: ActionType> {
    input: A::Input,
    original: Option<A::Original>,
    marker: PhantomData<A>,
}
impl<A: ActionType> Submission<A> {
    #[doc(hidden)]
    pub fn new(request: &RequestView) -> Self {
        Self {
            input: A::Input::from_fields(&request.input),
            original: request.inspection.as_ref().map(A::Original::from_fields),
            marker: PhantomData,
        }
    }
    pub fn input(&self) -> &A::Input {
        &self.input
    }
    pub fn original(&self) -> Option<&A::Original> {
        self.original.as_ref()
    }
    /// Stage exactly the host-retained input and target; the host commits later.
    pub fn apply(self) -> ActionResult<A> {
        let mut context = Context { _private: () };
        let op = A::operation();
        let response = match op.kind {
            OperationKind::Create => {
                let record = context.create(op.id);
                ResponseIntent::Created {
                    resource: op.resource,
                    id: record.id,
                    destination: RouteRef {
                        route: A::definition().redirect,
                        target: Some(record.id),
                    },
                }
            }
            OperationKind::Update => context.update(op.id),
            OperationKind::Delete => context.delete(op.id),
            _ => panic!("action operation"),
        };
        Ok(ActionOutcome {
            response,
            marker: PhantomData,
        })
    }
}
pub struct ActionOutcome<A> {
    response: ResponseIntent,
    marker: PhantomData<A>,
}
pub struct ActionError<A> {
    fields: Fields,
    message: String,
    marker: PhantomData<A>,
}
impl<A> ActionError<A> {
    pub fn message(message: impl Into<String>) -> Self {
        Self {
            fields: Fields::new(),
            message: message.into(),
            marker: PhantomData,
        }
    }
    pub fn with<T>(mut self, field: Field<A, T>, message: impl Into<String>) -> Self {
        self.fields.insert(field.key.into(), message.into());
        self
    }
}
pub type ActionResult<A> = Result<ActionOutcome<A>, ActionError<A>>;
pub trait IntoActionResponse {
    fn into_response(self) -> ResponseIntent;
}
impl<A> IntoActionResponse for ActionResult<A> {
    fn into_response(self) -> ResponseIntent {
        match self {
            Ok(outcome) => outcome.response,
            Err(error) => ResponseIntent::Rejected {
                field_errors: error.fields,
                message: error.message,
            },
        }
    }
}

pub struct Field<R, T> {
    key: &'static str,
    marker: PhantomData<fn() -> (R, T)>,
}
impl<R, T> Copy for Field<R, T> {}
impl<R, T> Clone for Field<R, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R, T> Field<R, T> {
    pub const fn new(key: &'static str) -> Self {
        Self {
            key,
            marker: PhantomData,
        }
    }
    pub fn error(self, message: impl Into<String>) -> ActionError<R> {
        let message = message.into();
        ActionError {
            fields: BTreeMap::from([(self.key.into(), message)]),
            message: "Review the highlighted fields.".into(),
            marker: PhantomData,
        }
    }
}

/// An escaped, composable document instruction sequence.
#[derive(Clone, Default)]
pub struct Fragment {
    nodes: Vec<Instruction>,
}
impl Fragment {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn begin(&mut self, container: Container) {
        self.nodes.push(Instruction::Begin(container));
    }
    pub fn end(&mut self) {
        self.nodes.push(Instruction::End);
    }
    pub fn text(&mut self, text: impl ToString) {
        self.nodes.push(Instruction::Text(text.to_string()));
    }
    pub fn append(&mut self, value: impl Render) {
        value.render(self);
    }
    pub fn link(&mut self, destination: RouteRef, body: Fragment) {
        self.nodes.push(Instruction::BeginLink { destination });
        self.nodes.extend(body.nodes);
        self.nodes.push(Instruction::EndLink);
    }
}
pub trait Render {
    fn render(self, fragment: &mut Fragment);
}
impl Render for Fragment {
    fn render(self, fragment: &mut Fragment) {
        fragment.nodes.extend(self.nodes);
    }
}
impl Render for &Fragment {
    fn render(self, fragment: &mut Fragment) {
        fragment.nodes.extend(self.nodes.clone());
    }
}
macro_rules! text_render {
    ($($t:ty),*) => { $(impl Render for $t { fn render(self, fragment: &mut Fragment) { fragment.text(self); } })* };
}
text_render!(&str, String, &String, char, bool, i64, u64, usize, i32, u32);
impl<A: ActionType> Render for Form<A> {
    fn render(self, fragment: &mut Fragment) {
        fragment.nodes.push(Instruction::Form {
            action: A::definition().id,
        });
    }
}
impl<A: ActionType> Render for &Form<A> {
    fn render(self, fragment: &mut Fragment) {
        fragment.nodes.push(Instruction::Form {
            action: A::definition().id,
        });
    }
}
impl<'a, T> Render for &'a Option<T>
where
    &'a T: Render,
{
    fn render(self, fragment: &mut Fragment) {
        if let Some(value) = self {
            value.render(fragment);
        }
    }
}
impl<T: Render> Render for Option<T> {
    fn render(self, fragment: &mut Fragment) {
        if let Some(value) = self {
            value.render(fragment);
        }
    }
}

pub struct Page {
    document: Document,
}
impl Page {
    pub fn new(title: impl Into<String>, content: Fragment) -> Self {
        Self {
            document: Document::new(title, content.nodes),
        }
    }
}
#[derive(Debug)]
pub struct NotFound;
pub type PageResult = Result<Page, NotFound>;
pub trait IntoPageResponse {
    fn into_response(self) -> ResponseIntent;
}
impl IntoPageResponse for Page {
    fn into_response(self) -> ResponseIntent {
        ResponseIntent::Page(self.document)
    }
}
impl IntoPageResponse for PageResult {
    fn into_response(self) -> ResponseIntent {
        match self {
            Ok(page) => page.into_response(),
            Err(NotFound) => ResponseIntent::NotFound(Document::new(
                "Not found",
                vec![Instruction::Text("This page is not available.".into())],
            )),
        }
    }
}

pub struct FormFields<A: ActionType> {
    controls: A::Controls,
}
impl<A: ActionType> Default for FormFields<A> {
    fn default() -> Self {
        Self::new()
    }
}
impl<A: ActionType> FormFields<A> {
    pub fn new() -> Self {
        Self {
            controls: A::controls(),
        }
    }
    pub fn submit(&self, label: impl Into<String>) -> FormLayout {
        FormLayout {
            instructions: vec![FormInstruction::Submit {
                label: label.into(),
            }],
        }
    }
}
impl<A: ActionType> Deref for FormFields<A> {
    type Target = A::Controls;
    fn deref(&self) -> &Self::Target {
        &self.controls
    }
}
#[derive(Clone, Default)]
pub struct FormLayout {
    #[doc(hidden)]
    pub instructions: Vec<FormInstruction>,
}
impl FormLayout {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn begin(&mut self, c: Container) {
        self.instructions.push(FormInstruction::Begin(c));
    }
    pub fn end(&mut self) {
        self.instructions.push(FormInstruction::End);
    }
    pub fn text(&mut self, text: impl ToString) {
        self.instructions
            .push(FormInstruction::Text(text.to_string()));
    }
    pub fn append(&mut self, other: Self) {
        self.instructions.extend(other.instructions);
    }
    pub fn rows(mut self, rows: u8) -> Self {
        if let [
            FormInstruction::Field {
                control: Control::Textarea { rows: old },
                ..
            },
        ] = self.instructions.as_mut_slice()
        {
            *old = rows;
        } else {
            panic!("rows applies to textarea controls");
        }
        self
    }
}
pub struct ControlField<T> {
    key: &'static str,
    marker: PhantomData<fn() -> T>,
}
impl<T> Copy for ControlField<T> {}
impl<T> Clone for ControlField<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> ControlField<T> {
    pub const fn new(key: &'static str) -> Self {
        Self {
            key,
            marker: PhantomData,
        }
    }
    fn control(self, control: Control) -> FormLayout {
        FormLayout {
            instructions: vec![FormInstruction::Field {
                name: self.key.into(),
                control,
            }],
        }
    }
}
pub trait TextControl {}
impl TextControl for String {}
impl TextControl for i64 {}
impl<T: TextControl> TextControl for Option<T> {}
pub trait TextareaValue {}
impl TextareaValue for String {}
impl TextareaValue for Option<String> {}
pub trait SelectValue {}
impl SelectValue for Option<bool> {}
impl<T: SelectValue> SelectValue for Option<T> {}
impl<T: TextControl> ControlField<T> {
    pub fn text_input(self) -> FormLayout {
        self.control(Control::TextInput)
    }
}
impl<T: TextareaValue> ControlField<T> {
    pub fn textarea(self) -> FormLayout {
        self.control(Control::Textarea { rows: 4 })
    }
}
impl ControlField<bool> {
    pub fn checkbox(self) -> FormLayout {
        self.control(Control::Checkbox)
    }
}
impl<T: SelectValue> ControlField<T> {
    pub fn select(self) -> FormLayout {
        self.control(Control::Select)
    }
}

/// Untrusted build metadata; the trusted host independently admits its output.
#[doc(hidden)]
#[derive(Default)]
pub struct ApplicationDefinition {
    resources: BTreeMap<String, Resource>,
    operations: BTreeMap<u32, Operation>,
    routes: BTreeMap<u32, Route>,
    actions: BTreeMap<u32, Action>,
}
impl ApplicationDefinition {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn resource(&mut self, resource: Resource) {
        if let Some(old) = self
            .resources
            .insert(resource.name.clone(), resource.clone())
        {
            assert_eq!(old, resource, "conflicting resource declarations");
        }
    }
    pub fn operation(&mut self, operation: Operation) {
        if let Some(old) = self.operations.insert(operation.id, operation.clone()) {
            assert_eq!(old, operation, "operation ID collision");
        }
    }
    pub fn page(&mut self, route: Route) {
        assert!(
            self.routes.insert(route.id, route).is_none(),
            "duplicate page"
        );
    }
    pub fn action(&mut self, action: Action) {
        assert!(
            self.actions.insert(action.id, action).is_none(),
            "duplicate action"
        );
    }
    pub fn layout(&mut self, id: u32, layout: Vec<FormInstruction>) {
        self.actions
            .get_mut(&id)
            .expect("layout action must be registered")
            .layout = layout;
    }
    pub fn manifest(self) -> Manifest {
        Manifest {
            version: VERSION,
            resources: self.resources.into_values().collect(),
            operations: self.operations.into_values().collect(),
            routes: self.routes.into_values().collect(),
            actions: self.actions.into_values().collect(),
        }
    }
    pub fn json(self) -> String {
        serde_json::to_string(&self.manifest()).expect("manifest encoding")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifiers_do_not_require_resource_traits() {
        struct ResourceWithoutTraits;
        let id = Id::<ResourceWithoutTraits>::new(9);
        assert_eq!(id, id);
        assert_eq!(format!("{id:?}"), "Id(9)");
    }
    #[test]
    fn interpolation_stays_text_and_links_keep_fragments() {
        let mut content = Fragment::new();
        content.append("<script>bad</script>");
        let mut link = Fragment::new();
        link.begin(Container::Strong);
        link.append("Open");
        link.end();
        content.link(
            RouteRef {
                route: 1,
                target: None,
            },
            link,
        );
        assert!(
            matches!(&content.nodes[0],Instruction::Text(value) if value=="<script>bad</script>")
        );
        assert!(matches!(content.nodes[1], Instruction::BeginLink { .. }));
        assert_eq!(content.nodes.last(), Some(&Instruction::EndLink));
    }
}
