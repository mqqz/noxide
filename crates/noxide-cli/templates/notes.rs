#[noxide::app]
mod notes {
    use noxide::prelude::*;

    #[derive(Resource)]
    #[resource(key = "notes", owner)]
    pub struct Note {
        #[id]
        id: Id<Self>,
        #[field(label = "Note", max_bytes = 4096)]
        body: String,
    }

    fn create_note(
        submission: Submission<CreateNote>,
    ) -> Result<Execute<CreateNote>, ActionError<CreateNote>> {
        if submission.input().body.trim().is_empty() {
            return Err(CreateNote::body.error("Enter a note."));
        }
        Ok(submission.execute())
    }
    fn edit_note(
        submission: Submission<EditNote>,
    ) -> Result<Execute<EditNote>, ActionError<EditNote>> {
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

    #[page("/")]
    fn index(mut notes: List<Note>, create: Form<CreateNote>) -> Page {
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

    #[page("/notes/{note}")]
    fn show_note(
        note: Id<Note>,
        mut read: Read<Note>,
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

    crud! { Note {
        create CreateNote { fields(body), redirect(show_note), handler(create_note) }
        update EditNote { fields(body), redirect(show_note), handler(edit_note), layout(note_editor) }
        delete DeleteNote { redirect(index) }
    } }
}
