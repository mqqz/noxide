use noxide::__private::{Change, RedirectSource, Revision, Target, Value};
use noxide::prelude::*;
use noxide::{
    ActionType, IntoActionResponse, RequestKind, RequestView, ResponseIntent, WebActionType,
};

#[derive(Resource)]
#[resource(key = "products")]
pub struct Product {
    #[id]
    pub id: Id<Self>,
    #[field(min = 0, max = 100)]
    pub stock: i64,
}
#[derive(Resource)]
#[resource(key = "orders")]
pub struct Order {
    #[id]
    pub id: Id<Self>,
    #[field()]
    pub product: Id<Product>,
    #[field(min = 1, max = 10)]
    pub quantity: i64,
}
#[derive(Resource)]
#[resource(key = "notes")]
pub struct Note {
    #[id]
    pub id: Id<Self>,
    #[field()]
    pub order: Id<Order>,
    #[field(max_bytes = 2000)]
    pub body: String,
}
#[query(read(Product), allow = owner)]
struct ReadProduct;
#[query(read(Order), allow = owner)]
struct ReadOrder;

mod show_order {
    pub fn id() -> u32 {
        99
    }
}
#[action(
    inputs(quantity: i64 = 1..=10, body: String = 2000),
    revision = identity,
    transaction(
        update(Product, target, decrease(stock, by = quantity, reject(quantity, "Not enough stock"))),
        order = create(Order, set(product = target, quantity = quantity), eligible = ReadProduct),
        create(Note, set(order = order, body = body), eligible = ReadOrder),
    ),
    allow = owner,
    redirect = show_order(order),
)]
struct PlaceOrder;

#[action(update(Product), fields(stock), allow = owner, redirect = show_order)]
struct SetStock;

#[test]
fn transaction_lowering_keeps_shared_input_and_created_step_identity() {
    let action = PlaceOrder::definition();
    assert_eq!(action.inputs.len(), 2);
    assert_eq!(action.inputs[0].name, "quantity");
    assert_eq!(action.inputs[1].max_bytes, 2000);
    assert_eq!(action.revision, Revision::Identity);
    assert_eq!(action.steps.len(), 3);
    assert_eq!(action.steps[0].target, Target::Signed);
    assert_eq!(action.steps[1].target, Target::None);
    assert!(
        matches!(&action.steps[0].assign[0].change, Change::Decrease { by, rejection } if by == "quantity" && rejection.input == "quantity" && rejection.message == "Not enough stock")
    );
    assert_eq!(
        action.steps[1].assign[1].change,
        Change::Set(Value::Input("quantity".into()))
    );
    assert_eq!(
        action.steps[2].assign[0].change,
        Change::Set(Value::Created(1))
    );
    assert_eq!(
        PlaceOrder::web_binding().redirect.source,
        RedirectSource::Step(1)
    );
    assert_eq!(PlaceOrder::resources().len(), 3);
    assert_eq!(PlaceOrder::operations().len(), 5);
}

#[test]
fn single_action_uses_the_transaction_protocol_and_defaults_to_exact() {
    let action = SetStock::definition();
    assert_eq!(action.revision, Revision::Exact);
    assert_eq!(action.steps.len(), 1);
    assert_eq!(action.steps[0].target, Target::Signed);
    assert_eq!(
        action.steps[0].assign[0].change,
        Change::Set(Value::Input("stock".into()))
    );
    assert_eq!(action.inputs[0].name, "stock");
}

#[test]
fn action_decisions_require_no_storage_callback() {
    let request = RequestView {
        params: Default::default(),
        version: noxide::__private::VERSION,
        kind: RequestKind::Action(PlaceOrder::definition().id),
        target: Some(1),
        input: [
            ("quantity".into(), "2".into()),
            ("body".into(), "First note".into()),
        ]
        .into(),
        inspection: None,
        available_forms: vec![],
    };
    let submission = Submission::<PlaceOrder>::new(&request);
    assert_eq!(submission.input().quantity, 2);
    assert_eq!(
        submission.execute().into_response(),
        ResponseIntent::Execute
    );
    let error: Result<Execute<PlaceOrder>, ActionError<PlaceOrder>> =
        Err(PlaceOrder::quantity.error("Choose fewer"));
    assert!(
        matches!(error.into_response(), ResponseIntent::Rejected { field_errors, .. } if field_errors["quantity"] == "Choose fewer")
    );
}

// Explicit execution-only declarations compile without controls, routes or redirects.
struct Headless;
impl ActionType for Headless {
    type Resource = Product;
    type Input = ();
    type Original = ();
    fn definition() -> noxide::__private::Action {
        use noxide::__private::*;
        Action {
            id: 7,
            version: 1,
            name: "Initialize stock".into(),
            target_reads: vec![],
            inspect: None,
            inputs: vec![],
            revision: Revision::Exact,
            steps: vec![Step {
                operation: 8,
                target: Target::None,
                assign: vec![Assignment {
                    field: "stock".into(),
                    change: Change::Set(Value::Constant("1".into())),
                }],
            }],
        }
    }
    fn operations() -> Vec<noxide::__private::Operation> {
        use noxide::__private::*;
        vec![Operation {
            id: 8,
            resource: <Product as noxide::ResourceType>::definition().id,
            kind: OperationKind::Create,
            policy: Policy {
                any: vec![vec![Predicate::Owner]],
            },
            bind: None,
            scope: None,
            via: None,
            filter: vec![],
            disclose: vec![],
            list: None,
            visibility: None,
            fields: None,
        }]
    }
}

#[test]
fn explicit_headless_sdk_needs_no_web_trait_or_redirect() {
    let mut builder = noxide::ApplicationDefinition::new();
    for resource in Headless::resources() {
        builder.resource(resource);
    }
    for operation in Headless::operations() {
        builder.operation(operation);
    }
    builder.action(Headless::definition());
    let manifest = builder.manifest();
    assert!(manifest.routes.is_empty());
    assert!(manifest.web_bindings.is_empty());
    assert_eq!(manifest.actions, vec![Headless::definition()]);
    let request = RequestView {
        version: noxide::__private::VERSION,
        kind: RequestKind::Action(7),
        target: None,
        input: Default::default(),
        inspection: None,
        params: Default::default(),
        available_forms: vec![],
    };
    assert_eq!(
        Submission::<Headless>::new(&request)
            .execute()
            .into_response(),
        ResponseIntent::Execute
    );
}

#[test]
fn explicit_sdk_keeps_two_bindings_on_one_canonical_action() {
    let mut action = SetStock::definition();
    let read = <ReadProduct as noxide::QueryType>::operation();
    action.target_reads = vec![read.id];
    let mut other_read = read.clone();
    other_read.id = u32::MAX;
    let mut first = SetStock::web_binding();
    first.id = 41;
    let mut second = first.clone();
    second.id = 42;
    second.version = 2;
    let mut builder = noxide::ApplicationDefinition::new();
    for resource in SetStock::resources() {
        builder.resource(resource);
    }
    for operation in SetStock::operations() {
        builder.operation(operation);
    }
    builder.operation(read.clone());
    builder.operation(other_read.clone());
    builder.page(noxide::__private::Route {
        id: 1,
        path: "/".into(),
        resource: None,
        operations: vec![],
        forms: vec![],
        params: vec![],
        access: noxide::__private::Access::Authenticated,
    });
    builder.page(noxide::__private::Route {
        id: 99,
        path: "/products/{product}".into(),
        resource: Some(read.resource),
        operations: vec![read.id, other_read.id],
        forms: vec![41, 42],
        params: vec![],
        access: noxide::__private::Access::Authenticated,
    });
    builder.action(action.clone());
    builder.web_binding(first.clone());
    builder.web_binding(second.clone());
    let manifest = builder.manifest();
    assert_eq!(manifest.actions, vec![action]);
    assert_eq!(manifest.web_bindings, vec![first, second]);
    assert_eq!(manifest.web_bindings[0].action, manifest.actions[0].id);
    assert_eq!(manifest.web_bindings[1].action, manifest.actions[0].id);
}
