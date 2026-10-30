#[noxide::app]
mod repeated {
    use noxide::prelude::*;

    #[derive(Resource)]
    #[resource(key = "threads", owner)]
    pub struct Thread {
        #[id]
        id: Id<Self>,
        #[field(max_bytes = 128)]
        title: String,
        #[field(initial = true)]
        published: bool,
    }
    #[derive(Resource)]
    #[resource(key = "replies", owner)]
    pub struct Reply {
        #[id]
        id: Id<Self>,
        #[field(visible(published = true), create_when(published = true))]
        thread: Id<Thread>,
        #[field(max_bytes = 128)]
        body: String,
        #[field(initial = false)]
        published: bool,
    }
    #[query(read(Thread), allow = owner)]
    struct ReadThread;
    #[query(read(Reply), allow = owner)]
    struct ReadReply;

    #[page(path = "/")]
    fn index() -> Page {
        Page::new("Replies", html! { p { "Replies" } })
    }
    #[page(path = "/threads/{thread}", access = public_optional)]
    fn thread(
        thread: Id<Thread>,
        mut read: Query<ReadThread>,
        first: Form<CreateReply>,
        second: Form<CreateAnonymousReply>,
    ) -> PageResult {
        let thread = read.get(thread).ok_or(NotFound)?;
        Ok(Page::new(
            "Thread",
            html! { p { (&thread.title) } (first) (second) },
        ))
    }
    #[page(path = "/replies/{reply}", access = public_optional)]
    fn reply(
        reply: Id<Reply>,
        mut read: Query<ReadReply>,
        edit: Form<r#EditReply>,
        secret: Form<EditSecret>,
        moderate: Form<ModerateReply>,
        delete: Form<DeleteReply>,
        remove: Form<DeleteSecret>,
    ) -> PageResult {
        let reply = read.get(reply).ok_or(NotFound)?;
        Ok(Page::new(
            "Reply",
            html! { p { (&reply.body) } (edit) (secret) (moderate) (delete) (remove) },
        ))
    }
    fn create_reply(submission: Submission<CreateReply>) -> ActionResult<CreateReply> {
        submission.apply()
    }
    fn create_layout(fields: FormFields<CreateReply>) -> FormLayout {
        form! { (fields.body.textarea().rows(8)) (fields.submit("CreateReply")) }
    }
    fn anonymous_reply(
        submission: Submission<CreateAnonymousReply>,
    ) -> ActionResult<CreateAnonymousReply> {
        submission.apply()
    }
    fn anonymous_layout(fields: FormFields<CreateAnonymousReply>) -> FormLayout {
        form! { (fields.body.textarea().rows(8)) (fields.submit("CreateAnonymousReply")) }
    }
    fn edit_reply(submission: Submission<r#EditReply>) -> ActionResult<r#EditReply> {
        submission.apply()
    }
    fn edit_layout(fields: FormFields<r#EditReply>) -> FormLayout {
        form! { (fields.body.textarea().rows(8)) (fields.submit("EditReply")) }
    }
    fn edit_secret(submission: Submission<EditSecret>) -> ActionResult<EditSecret> {
        submission.apply()
    }
    fn secret_layout(fields: FormFields<EditSecret>) -> FormLayout {
        form! { (fields.body.textarea().rows(8)) (fields.submit("EditSecret")) }
    }
    fn moderate_reply(submission: Submission<ModerateReply>) -> ActionResult<ModerateReply> {
        submission.apply()
    }
    fn moderate_layout(fields: FormFields<ModerateReply>) -> FormLayout {
        form! { (fields.published.checkbox()) (fields.submit("ModerateReply")) }
    }
    fn delete_reply(submission: Submission<DeleteReply>) -> ActionResult<DeleteReply> {
        submission.apply()
    }
    fn delete_layout(fields: FormFields<DeleteReply>) -> FormLayout {
        form! { (fields.submit("DeleteReply")) }
    }
    fn delete_secret(submission: Submission<DeleteSecret>) -> ActionResult<DeleteSecret> {
        submission.apply()
    }
    fn remove_layout(fields: FormFields<DeleteSecret>) -> FormLayout {
        form! { (fields.submit("DeleteSecret")) }
    }
    // actions
    crud! { Reply {
        create CreateReply { fields(body), bind(thread = target, eligible = ReadThread), redirect(reference(thread, thread)), handler(create_reply), layout(create_layout) }
        create CreateAnonymousReply { fields(body), bind(thread = target, eligible = ReadThread), allow = public, redirect(reply), handler(anonymous_reply), layout(anonymous_layout) }
        update r#EditReply { fields(body), redirect(reply), handler(edit_reply), layout(edit_layout) }
        update EditSecret { fields(body), allow = capability, redirect(reference(thread, thread)), handler(edit_secret), layout(secret_layout) }
        update ModerateReply { fields(published), allow = role("moderator"), redirect(reply), handler(moderate_reply), layout(moderate_layout) }
        delete DeleteReply { redirect(index), handler(delete_reply), layout(delete_layout) }
        delete DeleteSecret { allow = capability, redirect(reference(thread, thread)), handler(delete_secret), layout(remove_layout) }
    } }
}
