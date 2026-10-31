//! Authoritative minor-unit pricing and guarded cancellation; no payments.
#[noxide::app]
pub mod reservations {
    use noxide::prelude::*;
    use noxide::{__private::Revision, TargetDeclarations, Timestamp, guards, values};

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
    #[resource(key = "products", owner)]
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
    #[resource(key = "orders", owner)]
    pub struct Order {
        #[id]
        id: Id<Self>,
        #[field()]
        product: Id<Product>,
        #[field(min = 1, max = 10)]
        quantity: i64,
        #[field(min = 0, max = 1_000_000_000)]
        unit_price_minor: i64,
        #[field(max_bytes = 3)]
        currency: Currency,
        #[field(min = 0, max = 10_000_000_000)]
        total_minor: i64,
        #[field()]
        status: Status,
        #[field()]
        reserved_at: Timestamp,
        #[field()]
        expires_at: Timestamp,
    }
    #[query(list(Product),allow=same_tenant,order=created_desc,page_size=20)]
    struct Products;
    #[query(read(Product),allow=same_tenant)]
    struct ReadProduct;
    #[query(read(Order),allow=all(owner,same_tenant))]
    struct OwnOrder;
    #[query(list(Order),allow=all(owner,same_tenant),order=created_desc,page_size=20)]
    struct OwnOrders;

    fn reserve_targets() -> TargetDeclarations {
        TargetDeclarations::new().page::<ReadProduct>(
            "product",
            Revision::Exact,
            &["price_minor", "currency", "active"],
        )
    }
    fn cancel_targets() -> TargetDeclarations {
        TargetDeclarations::new()
            .page::<OwnOrder>(
                "order",
                Revision::Exact,
                &["product", "quantity", "status", "expires_at"],
            )
            .reference::<ReadProduct>("product", "order", "product", Revision::Identity, &[])
    }
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
    #[action(
        inputs(quantity:i64=1..=10),targets=reserve_targets,
        transaction(
            update(Product,product,allow=same_tenant,guards(reserve_guard()),decrease(stock,by=quantity,reject(quantity,"Not enough stock."))),
            order=create(Order,allow=all(owner,same_tenant),set(
                product=product,quantity=quantity,
                unit_price_minor=reviewed(product,price_minor),currency=reviewed(product,currency),
                total_minor=reviewed(product,price_minor)*quantity,status="pending",
                reserved_at=transaction_time(),expires_at=transaction_time()+seconds(900),
            ),eligible(product=ReadProduct)),
        ),allow=same_tenant,redirect=order(order),
    )]
    struct Reserve;
    #[action(
        inputs(),targets=cancel_targets,
        transaction(
            update(Order,order,allow=all(owner,same_tenant),guards(pending_guard()),set(status="cancelled")),
            update(Product,product,allow=same_tenant,increase(stock,by=snapshot(order,quantity),reject("Stock limit reached."))),
        ),allow=same_tenant,redirect=order(order),
    )]
    struct Cancel;

    #[page("/")]
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
    #[page("/products/{product}")]
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
                p{"A reservation holds this reviewed price for fifteen minutes. Inventory is released only by a committed cancellation; automatic expiry execution is not enabled."}
                @if product.active { (reserve) } @else {p{"This product is inactive."}}
                @if edit.is_available(){h2{"Edit price and availability"}(edit)}
                a href=(routes::index()){"Products"}
            }},
        ))
    }
    #[page("/orders/{order}")]
    fn order(order: Id<Order>, mut read: Query<OwnOrder>, cancel: Form<Cancel>) -> PageResult {
        let order = read.get(order).ok_or(NotFound)?;
        Ok(Page::new(
            "Reservation",
            html! {main{
                h1{"Reservation"} p{"Quantity: "(order.quantity)}
                p{"Unit price in minor units: "(order.unit_price_minor)" "(&order.currency)}
                p{"Total in minor units: "(order.total_minor)" "(&order.currency)}
                p{"Status: "(&order.status)}
                @if matches!(order.status,Status::Pending){(cancel)}
                a href=(routes::product(order.product)){"Product"}
            }},
        ))
    }

    /// A separate headless declaration for future verified service admission.
    /// It is not registered in the web app and no service adapter is enabled.
    pub fn expiry_manifest() -> String {
        use noxide::{ActionType, ApplicationDefinition, QueryType};
        let mut action = Cancel::definition();
        action.id = noxide::stable_id("action:reservations:Expire");
        action.name = "Expire reservation".into();
        action
            .targets
            .iter_mut()
            .find(|target| target.name == "order")
            .unwrap()
            .source = noxide::__private::TargetSource::Selected {
            query: OwnOrders::operation().id,
            eligible: OwnOrder::operation().id,
            label: vec!["status".into()],
        };
        action.steps[0].guards.push(guards::require(
            guards::less_or_equal(
                values::current("order", "expires_at"),
                values::transaction_time(),
            ),
            None,
            "The reservation has not expired.",
        ));
        action.steps[0].assign[0].change =
            noxide::__private::Change::Set(values::choice("expired"));
        let mut definition = ApplicationDefinition::new();
        for resource in Cancel::resources() {
            definition.resource(resource);
        }
        for operation in Cancel::operations() {
            definition.operation(operation);
        }
        definition.operation(OwnOrders::operation());
        definition.action(action);
        definition.json()
    }
}
