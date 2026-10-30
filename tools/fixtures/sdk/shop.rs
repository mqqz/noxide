#[noxide::app]
mod shop {
    use noxide::prelude::*;
    #[derive(Resource)]
    #[resource(key = "products")]
    pub struct Product {
        #[id] id: Id<Self>,
        #[field(max_bytes = 120)] name: String,
        #[field(min = 0)] price: i64,
        #[field()] available: bool,
    }
    #[derive(Resource)]
    #[resource(key = "orders", owner)]
    pub struct Order {
        #[id] id: Id<Self>,
        product: Id<Product>,
        #[field(min = 1, max = 100)] quantity: i64,
    }
    #[query(list(Product), allow = public, visible(available = true), fields(name, price))]
    struct Products;
    #[query(read(Product), allow = public, visible(available = true), fields(name, price))]
    struct AvailableProduct;
    #[query(list(Order), allow = owner, page_size = 20)]
    struct MyOrders;
    #[query(read(Order), allow = owner)]
    struct MyOrder;
    #[query(read(Product), allow = public, visible(available = true), fields(name, price), via(MyOrders.product))]
    struct OrderProduct;
    #[action(create(Order), fields(quantity), bind(product = target, eligible = AvailableProduct), allow = owner, redirect = order)]
    struct PlaceOrder;
    #[page(path = "/", access = public)]
    fn index(mut products: Query<Products>) -> Page {
        Page::new("Products", html! { main { @for product in products.fetch() {
            a href=(routes::product(product.id())) { (&product.name) }
        } } })
    }
    #[page(path = "/products/{product}", access = public_optional)]
    fn product(product: Id<Product>, mut read: Query<AvailableProduct>, place: Form<PlaceOrder>) -> PageResult {
        let product = read.get(product).ok_or(NotFound)?;
        Ok(Page::new("Product", html! { main { h1 { (&product.name) } (place) } }))
    }
    #[page(path = "/orders")]
    fn orders(mut orders: Query<MyOrders>, mut products: Query<OrderProduct>) -> Page {
        let orders = orders.fetch();
        let products = products.follow_many(&orders).expect("bounded follow");
        Page::new("Orders", html! { main {
            @for (order, product) in orders.iter().zip(products.iter()) {
                article {
                    @if let Some(product) = product { p { (&product.name) } }
                    @else { p { "Product unavailable" } }
                    p { (order.quantity.to_string()) }
                }
            }
        } })
    }
    #[page(path = "/orders/{order}")]
    fn order(order: Id<Order>, mut read: Query<MyOrder>) -> PageResult {
        let order = read.get(order).ok_or(NotFound)?;
        Ok(Page::new("Order", html! { main { p { (order.quantity.to_string()) } } }))
    }
}
