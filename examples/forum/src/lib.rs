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
    #[query(list(Reply), order = created_asc, page_size = 6, allow = public, visible(published = true), fields(body))]
    struct PublicReplies;
    #[query(read(Reply), allow = public, visible(published = true), fields(thread, body))]
    struct PublicReply;
    #[query(read(Reply), allow = owner)]
    struct OwnReply;
    #[query(list(Reply), order = created_asc, page_size = 20, allow = role("moderator"))]
    struct ReviewReplies;
    #[query(read(Reply), allow = role("moderator"))]
    struct ReviewReply;

    #[query(list(Thread), allow = public, visible(published = true), fields(title, body, locked))]
    struct PublicThreads;
    #[query(read(Thread), allow = public, visible(published = true), fields(title, body, locked))]
    struct PublicThread;
    #[query(read(Thread), allow = owner)]
    struct OwnThread;
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
                @if create.is_available() { section { h2 { "Start a thread" } (create) } }
                @if anonymous.is_available() { section { h2 { "Post with an edit secret" }
                    p { "Save the secret shown after posting. You will need it to edit your post after approval." }
                    (anonymous)
                } }
            } },
        )
    }

    #[page(path = "/threads/{thread}", access = public_optional)]
    fn thread(
        thread: Id<Thread>,
        mut read: Query<PublicThread>,
        mut own: Query<OwnThread>,
        edit: Form<EditThread>,
        secret_edit: Form<EditWithSecret>,
        mut replies: Query<PublicReplies>,
        reply: Form<CreateReply>,
        anonymous_reply: Form<CreateAnonymousReply>,
    ) -> PageResult {
        let (title, body, locked) = own
            .get(thread)
            .map(|t| (t.title.clone(), t.body.clone(), t.locked))
            .or_else(|| {
                read.get(thread)
                    .map(|t| (t.title.clone(), t.body.clone(), t.locked))
            })
            .ok_or(NotFound)?;
        let replies = replies.fetch();
        Ok(Page::new(
            "Thread",
            html! { main {
                nav { a href=(routes::index()) { "All threads" } }
                h1 { (&title) } pre { (&body) }
                h2 { "Replies" }
                @if replies.is_empty() { p { "No public replies yet." } }
                @for reply in replies { article {
                    pre { (&reply.body) }
                    a href=(routes::show_reply(reply.id())) { "View or edit reply" }
                } }
                @if locked { p { "This thread is closed to new replies." } }
                @if reply.is_available() { section { h2 { "Reply with your account" } (reply) } }
                @if anonymous_reply.is_available() { section { h2 { "Reply with an edit secret" } (anonymous_reply) } }
                @if edit.is_available() { section { h2 { "Edit your thread" } (edit) } }
                @if secret_edit.is_available() { section { h2 { "Edit with your secret" } (secret_edit) } }
            } },
        ))
    }

    #[page("/moderation")]
    fn moderation(mut threads: Query<ModerationQueue>) -> Page {
        let threads = threads.fetch();
        Page::new(
            "Moderation",
            html! { main {
                h1 { "Moderation" }
                @if threads.is_empty() { p { "No threads to review." } }
                @for thread in threads {
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
                @if visibility.is_available() { section {
                    h2 { "Moderate thread" }
                    p { "Clear Published to hide this thread. Locking prevents new replies." }
                    (visibility)
                } }
                @for reply in replies.fetch() { p { a href=(routes::review_reply(reply.id)) { "Review reply" } } }
            } },
        ))
    }

    #[page(path = "/replies/{reply}", access = public_optional)]
    fn show_reply(
        reply: Id<Reply>,
        mut read: Query<PublicReply>,
        mut own: Query<OwnReply>,
        edit: Form<EditReply>,
        secret: Form<EditReplyWithSecret>,
    ) -> PageResult {
        let (thread, body) = own
            .get(reply)
            .map(|r| (r.thread, r.body.clone()))
            .or_else(|| read.get(reply).map(|r| (r.thread, r.body.clone())))
            .ok_or(NotFound)?;
        Ok(Page::new(
            "Reply",
            html! { main {
                a href=(routes::thread(thread)) { "Back to thread" }
                h1 { "Reply" } pre { (&body) }
                @if edit.is_available() { section { h2 { "Edit your reply" } (edit) } }
                @if secret.is_available() { section { h2 { "Edit with your secret" } (secret) } }
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
                h1 { "Review reply" } pre { (&reply.body) }
                @if moderate.is_available() { section { h2 { "Moderate reply" } (moderate) } }
            } },
        ))
    }
    fn reply_create_layout(fields: FormFields<CreateReply>) -> FormLayout {
        form! {
            (fields.body.textarea().rows(8))
            (fields.submit("Submit reply"))
        }
    }
    fn reply_create(
        submission: Submission<CreateReply>,
    ) -> Result<Execute<CreateReply>, ActionError<CreateReply>> {
        if submission.input().body.trim().is_empty() {
            return Err(CreateReply::body.error("Enter a message."));
        }
        Ok(submission.execute())
    }
    fn reply_anonymous_layout(fields: FormFields<CreateAnonymousReply>) -> FormLayout {
        form! {
            (fields.body.textarea().rows(8))
            (fields.submit("Submit reply"))
        }
    }
    fn reply_anonymous(
        submission: Submission<CreateAnonymousReply>,
    ) -> Result<Execute<CreateAnonymousReply>, ActionError<CreateAnonymousReply>> {
        if submission.input().body.trim().is_empty() {
            return Err(CreateAnonymousReply::body.error("Enter a message."));
        }
        Ok(submission.execute())
    }
    fn reply_edit_layout(fields: FormFields<EditReply>) -> FormLayout {
        form! {
            (fields.body.textarea().rows(8))
            (fields.submit("Save changes"))
        }
    }
    fn reply_edit(
        submission: Submission<EditReply>,
    ) -> Result<Execute<EditReply>, ActionError<EditReply>> {
        if submission.input().body.trim().is_empty() {
            return Err(EditReply::body.error("Enter a message."));
        }
        Ok(submission.execute())
    }
    fn reply_secret_layout(fields: FormFields<EditReplyWithSecret>) -> FormLayout {
        form! {
            (fields.body.textarea().rows(8))
            (fields.submit("Save changes"))
        }
    }
    fn reply_secret(
        submission: Submission<EditReplyWithSecret>,
    ) -> Result<Execute<EditReplyWithSecret>, ActionError<EditReplyWithSecret>> {
        if submission.input().body.trim().is_empty() {
            return Err(EditReplyWithSecret::body.error("Enter a message."));
        }
        Ok(submission.execute())
    }
    fn reply_moderate_layout(fields: FormFields<ModerateReply>) -> FormLayout {
        form! {
            (fields.published.checkbox())
            (fields.submit("Save moderation"))
        }
    }
    fn thread_create_layout(fields: FormFields<CreateThread>) -> FormLayout {
        form! {
            (fields.title.text_input())
            (fields.body.textarea().rows(8))
            (fields.submit("Submit thread"))
        }
    }
    fn thread_create(
        submission: Submission<CreateThread>,
    ) -> Result<Execute<CreateThread>, ActionError<CreateThread>> {
        if submission.input().title.trim().is_empty() {
            return Err(CreateThread::title.error("Enter a title."));
        }
        if submission.input().body.trim().is_empty() {
            return Err(CreateThread::body.error("Enter a message."));
        }
        Ok(submission.execute())
    }
    fn thread_anonymous_layout(fields: FormFields<CreateAnonymousThread>) -> FormLayout {
        form! {
            (fields.title.text_input())
            (fields.body.textarea().rows(8))
            (fields.submit("Submit thread"))
        }
    }
    fn thread_anonymous(
        submission: Submission<CreateAnonymousThread>,
    ) -> Result<Execute<CreateAnonymousThread>, ActionError<CreateAnonymousThread>> {
        if submission.input().title.trim().is_empty() {
            return Err(CreateAnonymousThread::title.error("Enter a title."));
        }
        if submission.input().body.trim().is_empty() {
            return Err(CreateAnonymousThread::body.error("Enter a message."));
        }
        Ok(submission.execute())
    }
    fn thread_edit_layout(fields: FormFields<EditThread>) -> FormLayout {
        form! {
            (fields.title.text_input())
            (fields.body.textarea().rows(8))
            (fields.submit("Save changes"))
        }
    }
    fn thread_edit(
        submission: Submission<EditThread>,
    ) -> Result<Execute<EditThread>, ActionError<EditThread>> {
        if submission.input().title.trim().is_empty() {
            return Err(EditThread::title.error("Enter a title."));
        }
        if submission.input().body.trim().is_empty() {
            return Err(EditThread::body.error("Enter a message."));
        }
        Ok(submission.execute())
    }
    fn thread_secret_layout(fields: FormFields<EditWithSecret>) -> FormLayout {
        form! {
            (fields.title.text_input())
            (fields.body.textarea().rows(8))
            (fields.submit("Save changes"))
        }
    }
    fn thread_secret(
        submission: Submission<EditWithSecret>,
    ) -> Result<Execute<EditWithSecret>, ActionError<EditWithSecret>> {
        if submission.input().title.trim().is_empty() {
            return Err(EditWithSecret::title.error("Enter a title."));
        }
        if submission.input().body.trim().is_empty() {
            return Err(EditWithSecret::body.error("Enter a message."));
        }
        Ok(submission.execute())
    }
    fn thread_moderate_layout(fields: FormFields<ModerateThread>) -> FormLayout {
        form! {
            (fields.published.checkbox())
            (fields.locked.checkbox())
            (fields.submit("Save moderation"))
        }
    }

    crud! { Reply {
        create CreateReply { fields(body), bind(thread = target, eligible = PublicThread), allow = owner, redirect(show_reply), layout(reply_create_layout), handler(reply_create) }
        create CreateAnonymousReply { fields(body), bind(thread = target, eligible = PublicThread), allow = public, redirect(show_reply), layout(reply_anonymous_layout), handler(reply_anonymous) }
        update EditReply { fields(body), allow = owner, redirect(show_reply), layout(reply_edit_layout), handler(reply_edit) }
        update EditReplyWithSecret { fields(body), allow = capability, redirect(show_reply), layout(reply_secret_layout), handler(reply_secret) }
        update ModerateReply { fields(published), allow = role("moderator"), redirect(review_reply), layout(reply_moderate_layout) }
    } }
    crud! { Thread {
        create CreateThread { fields(title, body), allow = owner, redirect(thread), layout(thread_create_layout), handler(thread_create) }
        create CreateAnonymousThread { fields(title, body), allow = public, redirect(thread), layout(thread_anonymous_layout), handler(thread_anonymous) }
        update EditThread { fields(title, body), allow = owner, redirect(thread), layout(thread_edit_layout), handler(thread_edit) }
        update EditWithSecret { fields(title, body), allow = capability, redirect(thread), layout(thread_secret_layout), handler(thread_secret) }
        update ModerateThread { fields(published, locked), allow = role("moderator"), redirect(review), layout(thread_moderate_layout) }
    } }
}
