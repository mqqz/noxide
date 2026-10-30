mod repeated {
    use noxide::prelude::*;

    #[derive(Resource)]
    #[resource(key = "threads")]
    pub struct Thread {
        #[id]
        id: Id<Self>,
        #[field(max_bytes = 128)]
        title: String,
        #[field(initial = true)]
        published: bool,
    }
    #[derive(Resource)]
    #[resource(key = "replies")]
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
    fn create_reply(submission: Submission<CreateReply>) -> Result<Execute<CreateReply>, ActionError<CreateReply>> {
        Ok(submission.execute())
    }
    fn create_layout(fields: FormFields<CreateReply>) -> FormLayout {
        form! { (fields.body.textarea().rows(8)) (fields.submit("CreateReply")) }
    }
    fn anonymous_reply(
        submission: Submission<CreateAnonymousReply>,
    ) -> Result<Execute<CreateAnonymousReply>, ActionError<CreateAnonymousReply>> {
        Ok(submission.execute())
    }
    fn anonymous_layout(fields: FormFields<CreateAnonymousReply>) -> FormLayout {
        form! { (fields.body.textarea().rows(8)) (fields.submit("CreateAnonymousReply")) }
    }
    fn edit_reply(submission: Submission<r#EditReply>) -> Result<Execute<r#EditReply>, ActionError<r#EditReply>> {
        Ok(submission.execute())
    }
    fn edit_layout(fields: FormFields<r#EditReply>) -> FormLayout {
        form! { (fields.body.textarea().rows(8)) (fields.submit("EditReply")) }
    }
    fn edit_secret(submission: Submission<EditSecret>) -> Result<Execute<EditSecret>, ActionError<EditSecret>> {
        Ok(submission.execute())
    }
    fn secret_layout(fields: FormFields<EditSecret>) -> FormLayout {
        form! { (fields.body.textarea().rows(8)) (fields.submit("EditSecret")) }
    }
    fn moderate_reply(submission: Submission<ModerateReply>) -> Result<Execute<ModerateReply>, ActionError<ModerateReply>> {
        Ok(submission.execute())
    }
    fn moderate_layout(fields: FormFields<ModerateReply>) -> FormLayout {
        form! { (fields.published.checkbox()) (fields.submit("ModerateReply")) }
    }
    fn delete_reply(submission: Submission<DeleteReply>) -> Result<Execute<DeleteReply>, ActionError<DeleteReply>> {
        Ok(submission.execute())
    }
    fn delete_layout(fields: FormFields<DeleteReply>) -> FormLayout {
        form! { (fields.submit("DeleteReply")) }
    }
    fn delete_secret(submission: Submission<DeleteSecret>) -> Result<Execute<DeleteSecret>, ActionError<DeleteSecret>> {
        Ok(submission.execute())
    }
    fn remove_layout(fields: FormFields<DeleteSecret>) -> FormLayout {
        form! { (fields.submit("DeleteSecret")) }
    }
    #[action(create(Reply), fields(body), bind(thread = target, eligible = ReadThread), allow = owner, redirect = reference(thread, thread))]
    struct CreateReply;
    #[action(create(Reply), fields(body), bind(thread = target, eligible = ReadThread), allow = public, redirect = reply)]
    struct CreateAnonymousReply;
    #[action(update(Reply), fields(body), allow = owner, redirect = reply)]
    struct r#EditReply;
    #[action(update(Reply), fields(body), allow = capability, redirect = reference(thread, thread))]
    struct EditSecret;
    #[action(update(Reply), fields(published), allow = role("moderator"), redirect = reply)]
    struct ModerateReply;
    #[action(delete(Reply), allow = owner, redirect = index)]
    struct DeleteReply;
    #[action(delete(Reply), allow = capability, redirect = reference(thread, thread))]
    struct DeleteSecret;
    noxide::application! {
        pages: [index, thread, reply],
        actions: [CreateReply => create_reply, CreateAnonymousReply => anonymous_reply, r#EditReply => edit_reply, EditSecret => edit_secret, ModerateReply => moderate_reply, DeleteReply => delete_reply, DeleteSecret => delete_secret],
        forms: [CreateReply => create_layout, CreateAnonymousReply => anonymous_layout, r#EditReply => edit_layout, EditSecret => secret_layout, ModerateReply => moderate_layout, DeleteReply => delete_layout, DeleteSecret => remove_layout],
    }
}
pub use repeated::noxide_manifest;
