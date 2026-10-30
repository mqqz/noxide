mod notes {
use noxide::{
    Execute, ActionError, Form, FormFields, FormLayout, Fragment, Id, NotFound, Page, PageResult, Query,
    Resource, Submission, action, form, html, page, query,
};

#[derive(Resource)]
#[resource(key = "notes")]
pub struct Note {
    #[id]
    id: Id<Self>,
    #[field(key = "body", label = "Note", max_bytes = 4096)]
    body: String,
}

#[query(list(Note), allow = owner)]
struct __Noxide_list_Note;
#[query(read(Note), allow = owner)]
struct __Noxide_read_Note;

#[action(create(Note), fields(body), allow = owner, redirect = show_note)]
struct CreateNote;
#[action(update(Note), fields(body), allow = owner, redirect = show_note)]
struct EditNote;
#[action(delete(Note), allow = owner, redirect = index)]
struct DeleteNote;

fn create_note(submission: Submission<CreateNote>) -> Result<Execute<CreateNote>, ActionError<CreateNote>> {
    if submission.input().body.trim().is_empty() {
        return Err(CreateNote::body.error("Enter a note."));
    }
    Ok(submission.execute())
}
fn edit_note(submission: Submission<EditNote>) -> Result<Execute<EditNote>, ActionError<EditNote>> {
    if submission.input().body.trim().is_empty() {
        return Err(EditNote::body.error("Enter a note."));
    }
    Ok(submission.execute())
}
fn note_editor(fields: FormFields<EditNote>) -> FormLayout {
    form! {
        section { (fields.body.textarea().rows(12)) }
        (fields.submit("Save note"))
    }
}
fn layout(title: &str, content: Fragment) -> Page {
    Page::new(title, html! { main { (content) } })
}

#[page(path = "/")]
fn index(mut notes: Query<__Noxide_list_Note>, create: Form<CreateNote>) -> Page {
    let notes = notes.fetch();
    layout(
        "Private notes",
        html! {
            h1 { "Private notes" }
            @if notes.is_empty() { p { "No notes yet" } }
            @for note in &notes {
                article {
                    pre { (&note.body) }
                    a href=(routes::show_note(note.id)) { "Open note" }
                }
            }
            (create)
        },
    )
}

#[page(path = "/notes/{note}")]
fn show_note(
    note: Id<Note>,
    mut read: Query<__Noxide_read_Note>,
    edit: Form<EditNote>,
    delete: Form<DeleteNote>,
) -> PageResult {
    let note = read.get(note).ok_or(NotFound)?;
    Ok(layout(
        "Private note",
        html! {
            h1 { "Private note" }
            pre { (&note.body) }
            (edit)
            (delete)
            a href=(routes::index()) { "All notes" }
        },
    ))
}

noxide::application! {
    pages: [index, show_note],
    actions: [CreateNote => create_note, EditNote => edit_note, DeleteNote],
    forms: [EditNote => note_editor],
}

}
pub use notes::noxide_manifest;
