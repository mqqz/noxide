use noxide::{
    AccountId, Form, Id, NotFound, Page, PageResult, Query, Resource, action, html, page, query,
};

#[derive(Resource)]
#[resource(key = "messages")]
pub struct Message {
    #[id]
    id: Id<Self>,
    #[field(scope = same_tenant)]
    recipient: AccountId,
    #[field(max_bytes = 4096)]
    body: String,
}
#[query(list(Message), allow = any(owner, principal_is(recipient)), page_size = 20)]
struct ListMessages;
#[query(read(Message), allow = any(owner, principal_is(recipient)))]
struct ReadMessage;
#[action(create(Message), fields(recipient, body), allow = owner, redirect = show_message)]
struct SendMessage;
#[action(delete(Message), allow = owner, redirect = index)]
struct DeleteMessage;

#[page(path = "/")]
fn index(mut messages: Query<ListMessages>, send: Form<SendMessage>) -> Page {
    let messages = messages.fetch();
    Page::new(
        "Private inbox",
        html! { main {
            h1 { "Private inbox" }
            p { "Send a message using an account ID shared with you. Use Account ID in the navigation to find your own ID." }
            @if messages.is_empty() { p { "No messages yet." } }
            @for message in &messages {
                article { pre { (&message.body) } a href=(routes::show_message(message.id)) { "Open message" } }
            }
            (send)
        } },
    )
}
#[page(path = "/messages/{message}")]
fn show_message(
    message: Id<Message>,
    mut read: Query<ReadMessage>,
    delete: Form<DeleteMessage>,
) -> PageResult {
    let message = read.get(message).ok_or(NotFound)?;
    Ok(Page::new(
        "Private message",
        html! { main {
            h1 { "Private message" }
            p { "Recipient: " (message.recipient.to_string()) }
            pre { (&message.body) }
            (delete)
            a href=(routes::index()) { "All messages" }
        } },
    ))
}
noxide::application! { pages: [index, show_message], actions: [SendMessage, DeleteMessage] }
