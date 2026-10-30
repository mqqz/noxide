use noxide::prelude::*;

#[derive(Resource)]
#[resource(key = "products")]
pub struct Product {
    #[id]
    id: Id<Self>,
    #[field(max_bytes = 200)]
    name: String,
    #[field(min = 0, max = 100_000)]
    stock: i64,
}
#[derive(Resource)]
#[resource(key = "orders")]
pub struct Order {
    #[id]
    id: Id<Self>,
    #[field()]
    product: Id<Product>,
    #[field(min = 1, max = 10)]
    quantity: i64,
}
#[derive(Resource)]
#[resource(key = "order_notes")]
pub struct OrderNote {
    #[id]
    id: Id<Self>,
    #[field()]
    order: Id<Order>,
    #[field(max_bytes = 2000)]
    body: String,
}

#[query(list(Product), allow = owner)]
struct ListProducts;
#[query(read(Product), allow = owner)]
struct ReadProduct;
#[query(read(Order), allow = owner)]
struct ReadOrder;
#[query(list(OrderNote), allow = owner, scope(order))]
struct ListOrderNotes;

#[action(create(Product), fields(name, stock), allow = owner, redirect = show_product)]
struct CreateProduct;
#[action(
    inputs(quantity: i64 = 1..=10, body: String = 2000),
    revision = identity,
    transaction(
        update(Product, target, decrease(stock, by = quantity,
            reject(quantity, "Not enough stock"))),
        order = create(Order, set(quantity = quantity, product = target), eligible = ReadProduct),
        create(OrderNote, set(body = body, order = order), eligible = ReadOrder),
    ),
    allow = owner,
    redirect = show_order(order),
)]
struct PlaceOrder;

#[page(path = "/")]
fn index(mut products: Query<ListProducts>, create: Form<CreateProduct>) -> Page {
    let products = products.fetch();
    Page::new(
        "Shop",
        html! { main {
            h1 { "Shop" }
            p { "Create a product, then place an order with its first note. Orders reserve stock atomically." }
            @if products.is_empty() { p { "No products yet." } }
            @for product in &products {
                article { a href=(routes::show_product(product.id)) { (&product.name) } }
            }
            h2 { "Create product" }
            (create)
        } },
    )
}
#[page(path = "/products/{product}")]
fn show_product(
    product: Id<Product>,
    mut read: Query<ReadProduct>,
    order: Form<PlaceOrder>,
) -> PageResult {
    let product = read.get(product).ok_or(NotFound)?;
    Ok(Page::new(
        &product.name,
        html! { main {
            h1 { (&product.name) }
            p { "Available stock: " (product.stock.to_string()) }
            p { "Choose a quantity from 1 to 10 and add the first order note." }
            (order)
            a href=(routes::index()) { "All products" }
        } },
    ))
}
#[page(path = "/orders/{order}")]
fn show_order(
    order: Id<Order>,
    mut read: Query<ReadOrder>,
    mut notes: Query<ListOrderNotes>,
) -> PageResult {
    let order = read.get(order).ok_or(NotFound)?;
    let notes = notes.fetch();
    Ok(Page::new(
        "Order saved",
        html! { main {
            h1 { "Order saved" }
            p { "Quantity: " (order.quantity.to_string()) }
            @for note in &notes { article { pre { (&note.body) } } }
            a href=(routes::index()) { "All products" }
        } },
    ))
}
noxide::application! { pages: [index, show_product, show_order], actions: [CreateProduct, PlaceOrder] }
