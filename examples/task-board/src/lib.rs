use noxide::{
    Choice, Form, FormFields, FormLayout, Fragment, Id, NotFound, Page, PageResult, Query,
    Resource, action, form, html, page, query,
};

#[derive(Choice)]
pub enum Priority {
    #[choice(key = "normal", label = "Normal")]
    Normal,
    #[choice(key = "urgent", label = "Urgent")]
    Urgent,
}

#[derive(Resource)]
#[resource(key = "tasks")]
pub struct Task {
    #[id]
    id: Id<Self>,
    #[field(key = "title", label = "Title", max_bytes = 200)]
    title: String,
    #[field(key = "details", label = "Details", max_bytes = 4096)]
    details: Option<String>,
    #[field(key = "estimate", label = "Estimated days", min = 0, max = 365)]
    estimate: i64,
    #[field(key = "priority", label = "Priority")]
    priority: Priority,
    #[field(key = "completed", label = "Completed")]
    completed: bool,
}

#[query(list(Task), allow = owner)]
struct ListTasks;
#[query(read(Task), allow = owner)]
struct ReadTask;
#[action(create(Task), fields(title, details, estimate, priority, completed), allow = owner, redirect = show_task)]
struct CreateTask;
#[action(update(Task), fields(title, details, estimate, priority, completed), allow = owner, redirect = show_task)]
struct EditTask;
#[action(delete(Task), allow = owner, redirect = index)]
struct DeleteTask;

fn editor(
    title: FormLayout,
    details: FormLayout,
    estimate: FormLayout,
    priority: FormLayout,
    completed: FormLayout,
    submit: FormLayout,
) -> FormLayout {
    form! {
        section { (title) (details) }
        section { (estimate) (priority) (completed) }
        (submit)
    }
}
fn create_editor(fields: FormFields<CreateTask>) -> FormLayout {
    editor(
        fields.title.text_input(),
        fields.details.textarea().rows(6),
        fields.estimate.text_input(),
        fields.priority.select(),
        fields.completed.checkbox(),
        fields.submit("Create task"),
    )
}
fn edit_editor(fields: FormFields<EditTask>) -> FormLayout {
    editor(
        fields.title.text_input(),
        fields.details.textarea().rows(6),
        fields.estimate.text_input(),
        fields.priority.select(),
        fields.completed.checkbox(),
        fields.submit("Save task"),
    )
}
fn layout(title: &str, content: Fragment) -> Page {
    Page::new(
        title,
        html! { main { nav { a href=(routes::index()) { "Tasks" } } (content) } },
    )
}
#[page(path = "/")]
fn index(mut tasks: Query<ListTasks>, create: Form<CreateTask>) -> Page {
    let tasks = tasks.fetch();
    layout(
        "Tasks",
        html! {
            h1 { "Tasks" }
            @if tasks.is_empty() { p { "No tasks yet. Create your first task below." } }
            @for task in &tasks { article { a href=(routes::show_task(task.id)) { (&task.title) } } }
            (create)
        },
    )
}
#[page(path = "/tasks/{task}")]
fn show_task(
    task: Id<Task>,
    mut read: Query<ReadTask>,
    edit: Form<EditTask>,
    delete: Form<DeleteTask>,
) -> PageResult {
    let task = read.get(task).ok_or(NotFound)?;
    Ok(layout(
        &task.title,
        html! {
            h1 { (&task.title) }
            @if let Some(details) = &task.details { p { (details) } }
            p { "Estimated days: " (task.estimate) }
        p { "Priority: " (&task.priority) }
            @if task.completed { p { "Completed" } }
            (edit) (delete)
        },
    ))
}
noxide::application! {
    pages: [index, show_task],
    actions: [CreateTask, EditTask, DeleteTask],
    forms: [CreateTask => create_editor, EditTask => edit_editor],
}
