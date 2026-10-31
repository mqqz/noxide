use noxide::__private::{Change, RedirectSource, Revision, Target, Value};
use noxide::prelude::*;
use noxide::{
    ActionType, IntoActionResponse, RequestKind, RequestView, ResponseIntent, WebActionType,
};
use noxide::{QueryType, ResourceType};

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
    assert_eq!(action.targets[0].revision, Revision::Identity);
    assert_eq!(action.steps.len(), 3);
    assert_eq!(action.steps[0].target, Target::Named("target".into()));
    assert_eq!(action.steps[1].target, Target::None);
    assert!(
        matches!(&action.steps[0].assign[0].change, Change::Decrease { by, rejection } if by == &Value::Input("quantity".into()) && rejection.input.as_deref() == Some("quantity") && rejection.message == "Not enough stock")
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
    assert_eq!(action.targets[0].revision, Revision::Exact);
    assert_eq!(action.steps.len(), 1);
    assert_eq!(action.steps[0].target, Target::Named("target".into()));
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
        inspection: Default::default(),
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
            targets: vec![],
            inputs: vec![],
            steps: vec![Step {
                guards: vec![],
                operation: 8,
                target: Target::None,
                assign: vec![Assignment {
                    field: "stock".into(),
                    change: Change::Set(Value::Literal(noxide_protocol::Literal::Integer(1))),
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
            bind: Default::default(),
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
        inspection: Default::default(),
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
    action.targets[0].source = noxide::__private::TargetSource::Page {
        reads: vec![read.id],
    };
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

#[derive(Resource)]
#[resource(key = "paired_orders")]
pub struct PairedOrder {
    #[id]
    pub id: Id<Self>,
    #[field()]
    pub left: Id<Product>,
    #[field()]
    pub right: Id<Product>,
}
#[query(list(Product), allow = owner, page_size = 20)]
struct ProductChoices;
fn pair_targets() -> noxide::TargetDeclarations {
    noxide::TargetDeclarations::new()
        .selected::<ProductChoices, ReadProduct>("left", Revision::Identity, &["stock"], &["stock"])
        .selected::<ProductChoices, ReadProduct>("right", Revision::Exact, &["stock"], &["stock"])
}
#[action(
    inputs(), targets = pair_targets,
    transaction(order = create(PairedOrder, set(left = left, right = right), eligible(left = ReadProduct, right = ReadProduct))),
    allow = owner, redirect = show_order(order),
)]
struct PairOrder;
#[test]
fn named_target_helpers_lower_to_explicit_field_keyed_contract() {
    let action = PairOrder::definition();
    let expected: Vec<_> = [("left", Revision::Identity), ("right", Revision::Exact)]
        .into_iter()
        .map(|(name, revision)| noxide::__private::ActionTarget {
            name: name.into(),
            resource: Product::definition().id,
            source: noxide::__private::TargetSource::Selected {
                query: ProductChoices::operation().id,
                eligible: ReadProduct::operation().id,
                label: vec!["stock".into()],
            },
            revision,
            projection: Some(noxide::__private::Inspection {
                operation: ReadProduct::operation().id,
                fields: vec!["stock".into()],
            }),
            inspect: None,
        })
        .collect();
    assert_eq!(action.targets, expected);
    let create = &PairOrder::operations()[0];
    assert_eq!(
        create.bind,
        std::collections::BTreeMap::from([
            ("left".into(), ReadProduct::operation().id),
            ("right".into(), ReadProduct::operation().id)
        ])
    );
    assert_eq!(
        action.steps[0].assign[0].change,
        Change::Set(Value::Target("left".into()))
    );
    assert_eq!(
        action.steps[0].assign[1].change,
        Change::Set(Value::Target("right".into()))
    );
}

#[derive(Resource)]
#[resource(key = "timed_values")]
struct TimedValue {
    #[id]
    id: Id<Self>,
    #[field()]
    at: noxide::Timestamp,
    #[field(max_duration_seconds = 3600)]
    duration: noxide::Duration,
}
#[test]
fn typed_time_fields_keep_timestamp_and_duration_distinct() {
    let schema = TimedValue::definition();
    assert_eq!(schema.fields[0].kind, noxide::FieldKind::Timestamp);
    assert_eq!(
        schema.fields[1].kind,
        noxide::FieldKind::Duration {
            max_millis: 3_600_000
        }
    );
    let row = TimedValue::from_record(noxide::Record {
        resource: schema.id,
        id: 1,
        fields: noxide::Fields::from([
            ("at".into(), "1".into()),
            ("duration".into(), "1000".into()),
        ]),
    });
    assert_eq!(row.at.unix_millis(), 1);
    assert_eq!(row.duration.as_millis(), 1000);
    assert_eq!(schema.fields[0].canonical("+001").unwrap(), "1");
    assert!(schema.fields[0].canonical("-1").is_err());
    assert!(schema.fields[1].canonical("3600001").is_err());
}
#[test]
fn calculated_and_transition_helpers_equal_the_explicit_step() {
    use noxide::__private::{
        Assignment, Comparison, Guard, GuardCondition, GuardRejection, Literal, Step,
    };
    use noxide::{guards, values};
    let rejection = GuardRejection {
        input: None,
        message: "Already cancelled".into(),
    };
    let expected = Step {
        operation: 7,
        target: Target::Named("order".into()),
        guards: vec![Guard {
            condition: GuardCondition::Compare {
                left: Value::CurrentField {
                    target: "order".into(),
                    field: "status".into(),
                },
                comparison: Comparison::Equal,
                right: Value::Literal(Literal::Choice("pending".into())),
            },
            rejection: rejection.clone(),
        }],
        assign: vec![Assignment {
            field: "status".into(),
            change: Change::Set(Value::Literal(Literal::Choice("cancelled".into()))),
        }],
    };
    assert_eq!(
        noxide::transition(
            7,
            "order",
            "status",
            Literal::Choice("pending".into()),
            Literal::Choice("cancelled".into()),
            rejection.clone()
        ),
        expected
    );
    assert_eq!(
        noxide::CalculatedStep::new(7, Target::Named("order".into()))
            .guard(guards::require(
                guards::equal(
                    values::current("order", "status"),
                    values::choice("pending")
                ),
                None,
                "Already cancelled"
            ))
            .set("status", values::choice("cancelled"))
            .finish(),
        expected
    );
    assert_eq!(
        values::reviewed("product", "price"),
        Value::SnapshotField {
            target: "product".into(),
            field: "price".into(),
            reviewed: true
        }
    );
}
fn quantity_guard() -> noxide::__private::Guard {
    noxide::guards::require(
        noxide::guards::greater(
            noxide::values::input("quantity"),
            noxide::values::integer(0),
        ),
        Some("quantity"),
        "Choose a positive quantity",
    )
}
fn calculated_targets() -> noxide::TargetDeclarations {
    noxide::TargetDeclarations::new().page::<ReadProduct>("product", Revision::Identity, &["stock"])
}
#[action(inputs(quantity:i64=1..=10),targets=calculated_targets,transaction(update(Product,product,guards(quantity_guard()),decrease(stock,by=quantity*2,reject("Stock unavailable")))),allow=owner,redirect=show_order(product))]
struct CalculatedAdjustment;
#[test]
fn calculation_macro_uses_the_same_bounded_values_and_action_rejection() {
    let definition = CalculatedAdjustment::definition();
    assert_eq!(definition.steps[0].guards, vec![quantity_guard()]);
    assert!(
        matches!(&definition.steps[0].assign[0].change,Change::Decrease{by:Value::Multiply{left,right},rejection}if **left==Value::Input("quantity".into())&&**right==Value::Literal(noxide::__private::Literal::Integer(2))&&rejection.input.is_none())
    );
}

#[action(inputs(quantity:i64=1..=10),targets=calculated_targets,transaction(
    update(Product,product,allow=owner,decrease(stock,by=quantity,reject(quantity,"Stock unavailable"))),
    update(Product,product,allow=same_tenant,increase(stock,by=quantity,reject("Stock limit"))),
),allow=all(owner,same_tenant),redirect=show_order(product))]
struct IndividuallyAuthorized;
#[test]
fn per_step_policies_equal_explicit_ordinary_operations() {
    use noxide::__private::{Policy, Predicate};
    let operations = IndividuallyAuthorized::operations();
    assert_eq!(
        operations[0].policy,
        Policy {
            any: vec![vec![Predicate::Owner]]
        }
    );
    assert_eq!(
        operations[1].policy,
        Policy {
            any: vec![vec![Predicate::SameTenant]]
        }
    );
    let action = IndividuallyAuthorized::definition();
    assert_eq!(
        action.steps[0],
        noxide::CalculatedStep::new(operations[0].id, Target::Named("product".into()))
            .decrease(
                "stock",
                noxide::values::input("quantity"),
                noxide::__private::GuardRejection {
                    input: Some("quantity".into()),
                    message: "Stock unavailable".into()
                }
            )
            .finish()
    );
}
