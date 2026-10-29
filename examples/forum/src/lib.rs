#[noxide::app]
pub mod forum {
    use noxide::prelude::*;

    #[derive(Resource)]
    #[resource(key = "threads", owner)]
    pub struct Thread {
        #[id]
        id: Id<Self>,
        #[field(max_bytes = 200)]
        title: String,
        #[field(max_bytes = 4096)]
        body: String,
        #[field(initial = false)]
        published: bool,
        #[field(initial = false)]
        locked: bool,
    }

    #[derive(Resource)]
    #[resource(key = "replies", owner)]
    pub struct Reply {
        #[id]
        id: Id<Self>,
        #[field(visible(published = true), create_when(locked = false))]
        thread: Id<Thread>,
        #[field(max_bytes = 4096)]
        body: String,
        #[field(initial = false)]
        published: bool,
    }
    #[query(list(Reply), order = created_asc, page_size = 20, allow = public, visible(published = true), fields(body))]
    struct PublicReplies;
    #[query(read(Reply), allow = public, visible(published = true), fields(thread, body))]
    struct PublicReply;
    #[query(list(Reply), order = created_asc, page_size = 20, allow = role("moderator"))]
    struct ReviewReplies;
    #[query(read(Reply), allow = role("moderator"))]
    struct ReviewReply;

    #[query(list(Thread), allow = public, visible(published = true), fields(title, body, locked))]
    struct PublicThreads;
    #[query(read(Thread), allow = public, visible(published = true), fields(title, body, locked))]
    struct PublicThread;
    #[query(list(Thread), allow = role("moderator"))]
    struct ModerationQueue;
    #[query(read(Thread), allow = role("moderator"))]
    struct ReviewThread;

    #[page(path = "/", access = public_optional)]
    fn index(
        mut threads: Query<PublicThreads>,
        create: Form<CreateThread>,
        anonymous: Form<CreateAnonymousThread>,
    ) -> Page {
        let threads = threads.fetch();
        Page::new(
            "Forum",
            html! { main {
                h1 { "Forum" }
                p { "New threads and replies await moderator approval." }
                @if threads.is_empty() { p { "No public threads yet. Start a discussion below." } }
                @for thread in threads { article {
                    h2 { a href=(routes::thread(thread.id())) { (&thread.title) } }
                } }
                section { h2 { "Start a thread" } (create) }
                section { h2 { "Post with an edit secret" }
                    p { "Save the secret shown after posting. You will need it to edit your post." }
                    (anonymous)
                }
            } },
        )
    }

    #[page(path = "/threads/{thread}", access = public_optional)]
    fn thread(
        thread: Id<Thread>,
        mut read: Query<PublicThread>,
        edit: Form<EditThread>,
        secret_edit: Form<EditWithSecret>,
        mut replies: Query<PublicReplies>,
        reply: Form<CreateReply>,
        anonymous_reply: Form<CreateAnonymousReply>,
    ) -> PageResult {
        let thread = read.get(thread).ok_or(NotFound)?;
        Ok(Page::new(
            &thread.title,
            html! { main {
                nav { a href=(routes::index()) { "All threads" } }
                h1 { (&thread.title) } pre { (&thread.body) }
                h2 { "Replies" }
                @for reply in replies.fetch() { article {
                    pre { (&reply.body) }
                    a href=(routes::show_reply(reply.id())) { "View or edit reply" }
                } }
                @if thread.locked { p { "This thread is closed to new replies." } }
                @if reply.is_available() { section { h2 { "Reply with your account" } (reply) } }
                @if anonymous_reply.is_available() { section { h2 { "Reply with an edit secret" } (anonymous_reply) } }
                @if edit.is_available() { section { h2 { "Edit your thread" } (edit) } }
                section { h2 { "Edit with your secret" } (secret_edit) }
            } },
        ))
    }

    #[page("/moderation")]
    fn moderation(mut threads: Query<ModerationQueue>) -> Page {
        Page::new(
            "Moderation",
            html! { main {
                h1 { "Moderation" }
                @for thread in threads.fetch() {
                    p { a href=(routes::review(thread.id)) { (&thread.title) } }
                }
            } },
        )
    }

    #[page("/moderation/{thread}")]
    fn review(
        thread: Id<Thread>,
        mut read: Query<ReviewThread>,
        visibility: Form<ModerateThread>,
        mut replies: Query<ReviewReplies>,
    ) -> PageResult {
        let thread = read.get(thread).ok_or(NotFound)?;
        Ok(Page::new(
            "Review thread",
            html! { main {
                nav { a href=(routes::moderation()) { "Moderation queue" } }
                h1 { (&thread.title) } pre { (&thread.body) }
                p { "Clear Published to hide this thread. Only the declared moderator actions can change visibility." }
                (visibility)
                @for reply in replies.fetch() { p { a href=(routes::review_reply(reply.id)) { "Review reply" } } }
            } },
        ))
    }

    #[page(path = "/replies/{reply}", access = public_optional)]
    fn show_reply(
        reply: Id<Reply>,
        mut read: Query<PublicReply>,
        edit: Form<EditReply>,
        secret: Form<EditReplyWithSecret>,
    ) -> PageResult {
        let reply = read.get(reply).ok_or(NotFound)?;
        Ok(Page::new(
            "Reply",
            html! { main {
                a href=(routes::thread(reply.thread)) { "Back to thread" }
                h1 { "Reply" } pre { (&reply.body) }
                (edit) (secret)
            } },
        ))
    }
    #[page("/reply_review/{reply}")]
    fn review_reply(
        reply: Id<Reply>,
        mut read: Query<ReviewReply>,
        moderate: Form<ModerateReply>,
    ) -> PageResult {
        let reply = read.get(reply).ok_or(NotFound)?;
        Ok(Page::new(
            "Review reply",
            html! { main {
                a href=(routes::review(reply.thread)) { "Back to thread moderation" }
                h1 { "Review reply" } pre { (&reply.body) } (moderate)
            } },
        ))
    }
    #[action(create(Reply), fields(body), allow = owner, redirect = show_reply)]
    struct CreateReply;
    #[action(create(Reply), fields(body), allow = public, redirect = show_reply)]
    struct CreateAnonymousReply;
    #[action(update(Reply), fields(body), allow = owner, redirect = show_reply)]
    struct EditReply;
    #[action(update(Reply), fields(body), allow = capability, redirect = show_reply)]
    struct EditReplyWithSecret;
    #[action(update(Reply), fields(published), allow = role("moderator"), redirect = review_reply)]
    struct ModerateReply;

    #[action(create(Thread), fields(title, body), allow = owner, redirect = thread)]
    struct CreateThread;
    #[action(create(Thread), fields(title, body), allow = public, redirect = thread)]
    struct CreateAnonymousThread;
    #[action(update(Thread), fields(title, body), allow = owner, redirect = thread)]
    struct EditThread;
    #[action(update(Thread), fields(title, body), allow = capability, redirect = thread)]
    struct EditWithSecret;
    #[action(update(Thread), fields(published, locked), allow = role("moderator"), redirect = review)]
    struct ModerateThread;
}
