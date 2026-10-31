//! Contacts belong to a project; a ticket selects a contact and derives its
//! project through that contact's immutable reference. All forms work without JS.
#[noxide::app]
mod catalog {
    use noxide::prelude::*;
    use noxide::{__private::Revision, TargetDeclarations};

    #[derive(Resource)]
    #[resource(key = "projects", owner)]
    pub struct Project {
        #[id]
        id: Id<Self>,
        #[field(max_bytes = 160)]
        title: String,
    }
    #[derive(Resource)]
    #[resource(key = "contacts", owner)]
    pub struct Contact {
        #[id]
        id: Id<Self>,
        #[field()]
        project: Id<Project>,
        #[field(max_bytes = 160)]
        name: String,
    }
    #[derive(Resource)]
    #[resource(key = "tickets", owner)]
    pub struct Ticket {
        #[id]
        id: Id<Self>,
        #[field()]
        project: Id<Project>,
        #[field()]
        contact: Id<Contact>,
        #[field(max_bytes = 2000)]
        body: String,
    }
    #[query(read(Project), allow = owner)]
    struct ReadProject;
    #[query(read(Contact), allow = owner)]
    struct ReadContact;
    #[query(list(Contact), allow = owner, order = created_desc, page_size = 20)]
    struct ContactChoices;

    fn ticket_targets() -> TargetDeclarations {
        TargetDeclarations::new()
            .selected::<ContactChoices, ReadContact>(
                "contact",
                Revision::Identity,
                &["name", "project"],
                &["name"],
            )
            .reference::<ReadProject>(
                "project",
                "contact",
                "project",
                Revision::Identity,
                &["title"],
            )
    }
    #[action(create(Project), fields(title), allow = owner, redirect = project)]
    struct CreateProject;
    #[action(create(Contact), fields(name), bind(project = target, eligible = ReadProject), allow = owner, redirect = contact)]
    struct CreateContact;
    #[action(
        inputs(body: String = 2000), targets = ticket_targets,
        transaction(ticket = create(Ticket, set(project = project, contact = contact, body = body), eligible(project = ReadProject, contact = ReadContact))),
        allow = owner, redirect = ticket(ticket),
    )]
    struct CreateTicket;

    #[page("/")]
    fn index(
        mut projects: List<Project>,
        create: Form<CreateProject>,
        ticket: Form<CreateTicket>,
    ) -> Page {
        let projects = projects.fetch();
        Page::new(
            "Project contacts",
            html! { main {
                h1 { "Projects and tickets" }
                p { "Create a project, add a contact on its page, then select that contact below." }
                @for item in projects { p { a href=(routes::project(item.id)) { (&item.title) } } }
                h2 { "New project" } (create)
                h2 { "New ticket" } (ticket)
            } },
        )
    }
    #[page("/projects/{project}")]
    fn project(
        project: Id<Project>,
        mut read: Query<ReadProject>,
        contact: Form<CreateContact>,
    ) -> PageResult {
        let project = read.get(project).ok_or(NotFound)?;
        Ok(Page::new(
            &project.title,
            html! { main { h1 { (&project.title) } h2 { "Add contact" } (contact) a href=(routes::index()) { "Projects" } } },
        ))
    }
    #[page("/contacts/{contact}")]
    fn contact(contact: Id<Contact>, mut read: Query<ReadContact>) -> PageResult {
        let contact = read.get(contact).ok_or(NotFound)?;
        Ok(Page::new(
            &contact.name,
            html! { main { h1 { (&contact.name) } a href=(routes::index()) { "Create a ticket" } } },
        ))
    }
    #[page("/tickets/{ticket}")]
    fn ticket(ticket: Id<Ticket>, mut read: Read<Ticket>) -> PageResult {
        let ticket = read.get(ticket).ok_or(NotFound)?;
        Ok(Page::new(
            "Ticket",
            html! { main { h1 { "Ticket" } p { (&ticket.body) } a href=(routes::project(ticket.project)) { "Project" } a href=(routes::contact(ticket.contact)) { "Contact" } } },
        ))
    }
}
