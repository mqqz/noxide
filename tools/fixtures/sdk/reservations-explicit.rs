//! Authoritative minor-unit pricing, cancellation and service expiry; no payments.
pub mod reservations {
    use noxide::prelude::*;
    use noxide::{__private::Revision, Timestamp, guards, values};

    #[derive(Choice)]
    pub enum Currency {
        #[choice(key = "sar", label = "SAR")]
        Sar,
        #[choice(key = "usd", label = "USD")]
        Usd,
    }
    #[derive(Choice)]
    pub enum Status {
        #[choice(key = "pending", label = "Pending")]
        Pending,
        #[choice(key = "cancelled", label = "Cancelled")]
        Cancelled,
        #[choice(key = "expired", label = "Expired")]
        Expired,
    }
    #[derive(Resource)]
    #[resource(key = "products")]
    pub struct Product {
        #[id]
        id: Id<Self>,
        #[field(max_bytes = 160)]
        name: String,
        #[field(min = 0, max = 1000)]
        stock: i64,
        #[field(min = 0, max = 1_000_000_000)]
        price_minor: i64,
        #[field(max_bytes = 3)]
        currency: Currency,
        #[field()]
        active: bool,
    }
    #[derive(Resource)]
    #[resource(key = "orders", expiry(expires_at, max_after_seconds = 900))]
    pub struct Order {
        #[id]
        id: Id<Self>,
        #[field()]
        product: Id<Product>,
        #[field(immutable, min = 1, max = 10)]
        quantity: i64,
        #[field(immutable, min = 0, max = 1_000_000_000)]
        unit_price_minor: i64,
        #[field(immutable, max_bytes = 3)]
        currency: Currency,
        #[field(immutable, min = 0, max = 10_000_000_000)]
        total_minor: i64,
        #[field()]
        status: Status,
        #[field(immutable)]
        reserved_at: Timestamp,
        #[field(immutable)]
        expires_at: Timestamp,
    }
    #[query(list(Product),allow=same_tenant,order=created_desc,page_size=20)]
    struct Products;
    #[query(read(Product),allow=same_tenant)]
    struct ReadProduct;
    #[query(read(Order),allow=all(owner,same_tenant))]
    struct OwnOrder;

    fn reserve_guard() -> noxide::__private::Guard {
        guards::require(
            guards::all([
                guards::equal(values::snapshot("product", "active"), values::boolean(true)),
                guards::greater(values::input("quantity"), values::integer(0)),
            ]),
            Some("quantity"),
            "Choose an active product and a positive quantity.",
        )
    }
    fn pending_guard() -> noxide::__private::Guard {
        guards::require(
            guards::equal(
                values::current("order", "status"),
                values::choice("pending"),
            ),
            None,
            "This reservation is no longer pending.",
        )
    }
    #[action(create(Product),fields(name,stock,price_minor,currency,active),allow=all(owner,same_tenant),redirect=product)]
    struct CreateProduct;
    #[action(update(Product),fields(price_minor,currency,active),allow=all(owner,same_tenant),redirect=product)]
    struct EditProduct;
    struct Reserve;
    struct ReserveInput {
        quantity: i64,
    }
    impl noxide::ActionInput for ReserveInput {
        fn from_fields(fields: &noxide::Fields) -> Self {
            Self {
                quantity: fields["quantity"].parse().unwrap(),
            }
        }
    }
    struct ReserveControls {
        pub quantity: noxide::ControlField<i64>,
    }
    fn op(
        id: u32,
        resource: u32,
        kind: noxide::__private::OperationKind,
        policy: noxide::__private::Policy,
    ) -> noxide::__private::Operation {
        noxide::__private::Operation {
            maintenance: false,
            query: None,
            id,
            resource,
            kind,
            policy,
            bind: Default::default(),
            scope: None,
            via: None,
            filter: vec![],
            disclose: vec![],
            list: None,
            visibility: None,
            fields: None,
        }
    }
    impl noxide::ActionType for Reserve {
        type Resource = Product;
        type Input = ReserveInput;
        type Original = ();
        fn resources() -> Vec<noxide::__private::Resource> {
            vec![
                <Product as noxide::ResourceType>::definition(),
                <Order as noxide::ResourceType>::definition(),
            ]
        }
        fn operations() -> Vec<noxide::__private::Operation> {
            use noxide::__private::{OperationKind, Policy, Predicate};
            use noxide::{QueryType, ResourceType};
            let stock = op(
                noxide::stable_id(concat!("mutation:", module_path!(), "::Reserve:0u8")),
                Product::definition().id,
                OperationKind::Update,
                Policy {
                    any: vec![vec![Predicate::SameTenant]],
                },
            );
            let mut create = op(
                noxide::stable_id(concat!("mutation:", module_path!(), "::Reserve:1u8")),
                Order::definition().id,
                OperationKind::Create,
                Policy {
                    any: vec![vec![Predicate::Owner, Predicate::SameTenant]],
                },
            );
            create
                .bind
                .insert("product".into(), ReadProduct::operation().id);
            vec![stock, create, ReadProduct::operation()]
        }
        fn definition() -> noxide::__private::Action {
            use noxide::__private::*;
            use noxide::{QueryType, ResourceType};
            let operations = Self::operations();
            let source = |field: &str| Value::SnapshotField {
                target: "product".into(),
                field: field.into(),
                reviewed: true,
            };
            let set = |field: &str, value| Assignment {
                field: field.into(),
                change: Change::Set(value),
            };
            Action {
                id: noxide::stable_id(concat!("action:", module_path!(), "::Reserve")),
                version: 1,
                name: "Reserve".into(),
                inputs: vec![Input {
                    name: "quantity".into(),
                    label: "Quantity".into(),
                    kind: FieldKind::Integer {
                        min: Some(1),
                        max: Some(10),
                    },
                    optional: false,
                    max_bytes: 20,
                }],
                targets: vec![ActionTarget {
                    name: "product".into(),
                    resource: Product::definition().id,
                    source: TargetSource::Page {
                        reads: vec![ReadProduct::operation().id],
                    },
                    revision: Revision::Exact,
                    projection: Some(Inspection {
                        operation: ReadProduct::operation().id,
                        fields: vec!["price_minor".into(), "currency".into(), "active".into()],
                    }),
                    inspect: None,
                }],
                steps: vec![
                    Step {
                        operation: operations[0].id,
                        target: Target::Named("product".into()),
                        guards: vec![reserve_guard()],
                        assign: vec![Assignment {
                            field: "stock".into(),
                            change: Change::Decrease {
                                by: Value::Input("quantity".into()),
                                rejection: GuardRejection {
                                    input: Some("quantity".into()),
                                    message: "Not enough stock.".into(),
                                },
                            },
                        }],
                    },
                    Step {
                        operation: operations[1].id,
                        target: Target::None,
                        guards: vec![],
                        assign: vec![
                            set("product", Value::Target("product".into())),
                            set("quantity", Value::Input("quantity".into())),
                            set("unit_price_minor", source("price_minor")),
                            set("currency", source("currency")),
                            set(
                                "total_minor",
                                Value::Multiply {
                                    left: Box::new(source("price_minor")),
                                    right: Box::new(Value::Input("quantity".into())),
                                },
                            ),
                            set("status", Value::Literal(Literal::Choice("pending".into()))),
                            set("reserved_at", Value::TransactionTime),
                            set("expires_at", expiry_due()),
                        ],
                    },
                ],
            }
        }
    }
    impl noxide::WebActionType for Reserve {
        type Controls = ReserveControls;
        fn controls() -> Self::Controls {
            ReserveControls {
                quantity: noxide::ControlField::new("quantity"),
            }
        }
        fn web_binding() -> noxide::__private::WebBinding {
            use noxide::ActionType;
            let action = Self::definition();
            noxide::__private::WebBinding {
                id: action.id,
                version: action.version,
                action: action.id,
                layout: vec![],
                redirect: noxide::__private::Redirect {
                    route: order::id(),
                    source: noxide::__private::RedirectSource::Step(1),
                },
            }
        }
    }

    struct Cancel;
    impl noxide::ActionType for Cancel {
        type Resource = Order;
        type Input = ();
        type Original = ();
        fn resources() -> Vec<noxide::__private::Resource> {
            vec![
                <Order as noxide::ResourceType>::definition(),
                <Product as noxide::ResourceType>::definition(),
            ]
        }
        fn operations() -> Vec<noxide::__private::Operation> {
            use noxide::__private::{OperationKind, Policy, Predicate};
            use noxide::{QueryType, ResourceType};
            vec![
                op(
                    noxide::stable_id(concat!("mutation:", module_path!(), "::Cancel:0u8")),
                    Order::definition().id,
                    OperationKind::Update,
                    Policy {
                        any: vec![vec![Predicate::Owner, Predicate::SameTenant]],
                    },
                ),
                op(
                    noxide::stable_id(concat!("mutation:", module_path!(), "::Cancel:1u8")),
                    Product::definition().id,
                    OperationKind::Update,
                    Policy {
                        any: vec![vec![Predicate::SameTenant]],
                    },
                ),
                OwnOrder::operation(),
                ReadProduct::operation(),
            ]
        }
        fn definition() -> noxide::__private::Action {
            use noxide::__private::*;
            use noxide::{QueryType, ResourceType};
            let operations = Self::operations();
            Action {
                id: noxide::stable_id(concat!("action:", module_path!(), "::Cancel")),
                version: 1,
                name: "Cancel".into(),
                inputs: vec![],
                targets: vec![
                    ActionTarget {
                        name: "order".into(),
                        resource: Order::definition().id,
                        source: TargetSource::Page {
                            reads: vec![OwnOrder::operation().id],
                        },
                        revision: Revision::Exact,
                        projection: Some(Inspection {
                            operation: OwnOrder::operation().id,
                            fields: vec![
                                "product".into(),
                                "quantity".into(),
                                "status".into(),
                                "expires_at".into(),
                            ],
                        }),
                        inspect: None,
                    },
                    ActionTarget {
                        name: "product".into(),
                        resource: Product::definition().id,
                        source: TargetSource::Reference {
                            target: "order".into(),
                            field: "product".into(),
                            eligible: ReadProduct::operation().id,
                        },
                        revision: Revision::Identity,
                        projection: Some(Inspection {
                            operation: ReadProduct::operation().id,
                            fields: vec![],
                        }),
                        inspect: None,
                    },
                ],
                steps: vec![
                    Step {
                        operation: operations[0].id,
                        target: Target::Named("order".into()),
                        guards: vec![pending_guard()],
                        assign: vec![Assignment {
                            field: "status".into(),
                            change: Change::Set(Value::Literal(Literal::Choice(
                                "cancelled".into(),
                            ))),
                        }],
                    },
                    Step {
                        operation: operations[1].id,
                        target: Target::Named("product".into()),
                        guards: vec![],
                        assign: vec![Assignment {
                            field: "stock".into(),
                            change: Change::Increase {
                                by: Value::SnapshotField {
                                    target: "order".into(),
                                    field: "quantity".into(),
                                    reviewed: false,
                                },
                                rejection: GuardRejection {
                                    input: None,
                                    message: "Stock limit reached.".into(),
                                },
                            },
                        }],
                    },
                ],
            }
        }
    }
    impl noxide::WebActionType for Cancel {
        type Controls = ();
        fn controls() -> Self::Controls {}
        fn web_binding() -> noxide::__private::WebBinding {
            use noxide::ActionType;
            let action = Self::definition();
            noxide::__private::WebBinding {
                id: action.id,
                version: action.version,
                action: action.id,
                layout: vec![],
                redirect: noxide::__private::Redirect {
                    route: order::id(),
                    source: noxide::__private::RedirectSource::Target("order".into()),
                },
            }
        }
    }

    #[page(path = "/")]
    fn index(mut products: Query<Products>, create: Form<CreateProduct>) -> Page {
        let products = products.fetch();
        Page::new(
            "Reservations",
            html! {main{
                h1{"Reservations"} p{"Prices and totals use integer minor units. This example takes no payments."}
                @for item in products { article {a href=(routes::product(item.id)){(&item.name)}} }
                h2{"Add product"}(create)
            }},
        )
    }
    #[page(path = "/products/{product}")]
    fn product(
        product: Id<Product>,
        mut read: Query<ReadProduct>,
        reserve: Form<Reserve>,
        edit: Form<EditProduct>,
    ) -> PageResult {
        let product = read.get(product).ok_or(NotFound)?;
        Ok(Page::new(
            &product.name,
            html! {main{
                h1{(&product.name)} p{"Available stock: "(product.stock)}
                p{"Price in minor units: "(product.price_minor)" "(&product.currency)}
                p{"A reservation holds this reviewed price for fifteen minutes, then disappears from ordinary reads. Inventory stays reserved until cancellation or the approved expiry worker commits. Delayed jobs delay stock release."}
                @if product.active { (reserve) } @else {p{"This product is inactive."}}
                @if edit.is_available(){h2{"Edit price and availability"}(edit)}
                a href=(routes::index()){"Products"}
            }},
        ))
    }
    #[page(path = "/orders/{order}")]
    fn order(order: Id<Order>, mut read: Query<OwnOrder>, cancel: Form<Cancel>) -> PageResult {
        let order = read.get(order).ok_or(NotFound)?;
        Ok(Page::new(
            "Reservation",
            html! {main{
                h1{"Reservation"} p{"Quantity: "(order.quantity)}
                p{"Unit price in minor units: "(order.unit_price_minor)" "(&order.currency)}
                p{"Total in minor units: "(order.total_minor)" "(&order.currency)}
                p{"Status: "(&order.status)}
                p{"This page becomes unavailable after fifteen minutes. Stock release requires a committed cancellation or expiry job."}
                @if matches!(order.status,Status::Pending){(cancel)}
                a href=(routes::product(order.product)){"Product"}
            }},
        ))
    }

    const EXPIRY_WORKER: &str = "reservation_expiry";

    // This same pure expression is used by Reserve's expiry assignment and
    // transactional scheduling. No guest-provided time or owner impersonation.
    fn expiry_due() -> noxide::__private::Value {
        values::add(
            values::transaction_time(),
            values::duration(noxide::Duration::from_secs(900).unwrap()),
        )
    }

    fn service_policy() -> noxide::__private::Policy {
        use noxide::__private::{Policy, Predicate};
        Policy {
            any: vec![vec![
                Predicate::Service {
                    worker: EXPIRY_WORKER.into(),
                },
                Predicate::SameTenant,
            ]],
        }
    }

    fn expiry_operation(
        key: &str,
        resource: u32,
        kind: noxide::__private::OperationKind,
        maintenance: bool,
    ) -> noxide::__private::Operation {
        noxide::__private::Operation {
            id: noxide::stable_id(key),
            resource,
            kind,
            policy: service_policy(),
            maintenance,
            query: None,
            bind: Default::default(),
            scope: None,
            via: None,
            filter: vec![],
            disclose: vec![],
            list: None,
            visibility: None,
            fields: None,
        }
    }

    fn expiry_order_read() -> noxide::__private::Operation {
        use noxide::ResourceType;
        expiry_operation(
            "reservations:expiry:order-read",
            Order::definition().id,
            noxide::__private::OperationKind::Read,
            true,
        )
    }
    fn expiry_product_read() -> noxide::__private::Operation {
        use noxide::ResourceType;
        expiry_operation(
            "reservations:expiry:product-read",
            Product::definition().id,
            noxide::__private::OperationKind::Read,
            false,
        )
    }
    fn expiry_candidates() -> noxide::__private::Operation {
        use noxide::{__private::*, ResourceType};
        let mut operation = expiry_operation(
            "reservations:expiry:candidates",
            Order::definition().id,
            OperationKind::List,
            true,
        );
        operation.list = Some(ListSettings {
            order: ListOrder::CreatedAsc,
            page_size: 20,
            preview: None,
        });
        operation.filter = vec![Condition {
            field: "status".into(),
            equals: Operand::Literal("pending".into()),
        }];
        operation
    }

    // A distinct service-only action: no WebActionType, browser binding, inputs,
    // user owner, or ability to reschedule itself.
    struct Expire;
    impl noxide::ActionType for Expire {
        type Resource = Order;
        type Input = ();
        type Original = ();
        fn resources() -> Vec<noxide::__private::Resource> {
            use noxide::ResourceType;
            vec![Order::definition(), Product::definition()]
        }
        fn operations() -> Vec<noxide::__private::Operation> {
            use noxide::{__private::OperationKind, ResourceType};
            vec![
                expiry_operation(
                    "reservations:expiry:order-update",
                    Order::definition().id,
                    OperationKind::Update,
                    true,
                ),
                expiry_operation(
                    "reservations:expiry:product-update",
                    Product::definition().id,
                    OperationKind::Update,
                    true,
                ),
                expiry_order_read(),
                expiry_product_read(),
            ]
        }
        fn definition() -> noxide::__private::Action {
            use noxide::{__private::*, CalculatedStep, ResourceType};
            let operations = Self::operations();
            Action {
                id: noxide::stable_id("action:reservations:Expire"),
                version: 1,
                name: "Expire reservation".into(),
                inputs: vec![],
                targets: vec![
                    ActionTarget {
                        name: "order".into(),
                        resource: Order::definition().id,
                        source: TargetSource::Service {
                            eligible: expiry_order_read().id,
                        },
                        revision: Revision::Identity,
                        projection: Some(Inspection {
                            operation: expiry_order_read().id,
                            fields: vec![
                                "product".into(),
                                "quantity".into(),
                                "status".into(),
                                "expires_at".into(),
                            ],
                        }),
                        inspect: None,
                    },
                    ActionTarget {
                        name: "product".into(),
                        resource: Product::definition().id,
                        source: TargetSource::Reference {
                            target: "order".into(),
                            field: "product".into(),
                            eligible: expiry_product_read().id,
                        },
                        revision: Revision::Identity,
                        projection: Some(Inspection {
                            operation: expiry_product_read().id,
                            fields: vec![],
                        }),
                        inspect: None,
                    },
                ],
                steps: vec![
                    CalculatedStep::new(operations[0].id, Target::Named("order".into()))
                        .guard(pending_guard())
                        .guard(guards::require(
                            guards::less_or_equal(
                                values::current("order", "expires_at"),
                                values::transaction_time(),
                            ),
                            None,
                            "The reservation has not expired.",
                        ))
                        .set("status", values::choice("expired"))
                        .finish(),
                    CalculatedStep::new(operations[1].id, Target::Named("product".into()))
                        .increase(
                            "stock",
                            values::snapshot("order", "quantity"),
                            GuardRejection {
                                input: None,
                                message: "Stock limit reached.".into(),
                            },
                        )
                        .finish(),
                ],
            }
        }
    }

    fn jobs() -> noxide::JobContract {
        use noxide::{
            ActionType, JobContract, RecurringSchedule, RecurringSelection, ResourceType, Schedule,
            ScheduledTarget, Worker, WorkerAction, WorkerTarget,
        };
        use std::collections::BTreeMap;
        JobContract {
            workers: vec![Worker {
                name: EXPIRY_WORKER.into(),
                actions: vec![WorkerAction {
                    action: Expire::definition().id,
                    targets: BTreeMap::from([
                        (
                            "order".into(),
                            WorkerTarget {
                                resource: Order::definition().id,
                                eligible: expiry_order_read().id,
                            },
                        ),
                        (
                            "product".into(),
                            WorkerTarget {
                                resource: Product::definition().id,
                                eligible: expiry_product_read().id,
                            },
                        ),
                    ]),
                }],
            }],
            schedules: vec![Schedule {
                source_action: Reserve::definition().id,
                ordinal: 0,
                worker: EXPIRY_WORKER.into(),
                action: Expire::definition().id,
                targets: BTreeMap::from([
                    ("order".into(), ScheduledTarget::Created(1)),
                    ("product".into(), ScheduledTarget::Target("product".into())),
                ]),
                inputs: BTreeMap::new(),
                due_at: expiry_due(),
            }],
            recurring: vec![RecurringSchedule {
                name: "repair_expired_reservations".into(),
                worker: EXPIRY_WORKER.into(),
                action: Expire::definition().id,
                interval: noxide::Duration::from_secs(60).unwrap(),
                inputs: BTreeMap::new(),
                selection: Some(RecurringSelection {
                    operation: expiry_candidates().id,
                    target: "order".into(),
                    expiry_repair: true,
                }),
            }],
        }
    }

    pub mod routes {
        pub use super::index::link as index;
        pub use super::order::link as order;
        pub use super::product::link as product;
    }
    fn register_web<A: noxide::WebActionType>(builder: &mut noxide::ApplicationDefinition) {
        for resource in A::resources() {
            builder.resource(resource);
        }
        for operation in A::operations() {
            builder.operation(operation);
        }
        if let Some(operation) = A::inspection() {
            builder.operation(operation);
        }
        builder.action(A::definition());
        builder.web_binding(A::web_binding());
    }
    pub fn noxide_manifest() -> String {
        use noxide::ActionType;
        let mut builder = noxide::ApplicationDefinition::new();
        index::register(&mut builder);
        product::register(&mut builder);
        order::register(&mut builder);
        register_web::<CreateProduct>(&mut builder);
        register_web::<EditProduct>(&mut builder);
        register_web::<Reserve>(&mut builder);
        register_web::<Cancel>(&mut builder);
        for resource in Expire::resources() {
            builder.resource(resource);
        }
        for operation in Expire::operations() {
            builder.operation(operation);
        }
        builder.operation(expiry_candidates());
        builder.action(Expire::definition());
        builder.jobs(jobs());
        builder.json()
    }
    struct Reservations;
    impl noxide::Handler for Reservations {
        fn handle(request: noxide::RequestView, _: &mut noxide::Context) -> noxide::ResponseIntent {
            use noxide::{ActionType, IntoActionResponse, RequestKind, ResponseIntent, Submission};
            match request.kind {
                RequestKind::Route(id) if id == index::id() => index::dispatch(&request),
                RequestKind::Route(id) if id == product::id() => product::dispatch(&request),
                RequestKind::Route(id) if id == order::id() => order::dispatch(&request),
                RequestKind::Action(id) if id == CreateProduct::definition().id => {
                    Submission::<CreateProduct>::new(&request)
                        .execute()
                        .into_response()
                }
                RequestKind::Action(id) if id == EditProduct::definition().id => {
                    Submission::<EditProduct>::new(&request)
                        .execute()
                        .into_response()
                }
                RequestKind::Action(id) if id == Reserve::definition().id => {
                    Submission::<Reserve>::new(&request)
                        .execute()
                        .into_response()
                }
                RequestKind::Action(id) if id == Cancel::definition().id => {
                    Submission::<Cancel>::new(&request)
                        .execute()
                        .into_response()
                }
                RequestKind::Action(id) if id == Expire::definition().id => {
                    Submission::<Expire>::new(&request)
                        .execute()
                        .into_response()
                }
                _ => ResponseIntent::NotFound(noxide::Document::new("Not found", vec![])),
            }
        }
    }
    noxide::export!(Reservations);
}

pub use reservations::noxide_manifest;
