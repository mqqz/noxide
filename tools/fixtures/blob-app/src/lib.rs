//! Trusted production-admission fixture using the explicit SDK contracts.
use noxide::{
    ActionError, ActionType, ApplicationDefinition, BlobLimits, BlobPolicy, BlobRef, Context,
    Execute, Form, Fragment, Handler, Id, IntoActionResponse, NotFound, Page, PageResult, Query,
    Resource, Submission, UploadBinding, UploadHandle, WebActionType, action, download, page,
    query,
};

#[derive(Resource)]
#[resource(key = "attachments")]
pub struct Attachment {
    #[id]
    pub id: Id<Self>,
    #[field(max_bytes = 160)]
    pub title: String,
    #[field()]
    pub file: BlobRef,
    #[field()]
    pub extra: Option<BlobRef>,
}
#[query(read(Attachment), allow = owner)]
pub struct ReadAttachment;
#[action(inputs(title: String = 160, file: UploadHandle),
    transaction(attachment = create(Attachment, set(title = title, file = file))),
    allow = owner, redirect = show(attachment))]
pub struct Attach;

fn attach(submission: Submission<Attach>) -> Result<Execute<Attach>, ActionError<Attach>> {
    if submission.input().title == "reject" {
        return Err(Attach::title.error("Choose another title."));
    }
    Ok(submission.execute())
}
#[page(path = "/")]
fn index(create: Form<Attach>) -> Page {
    let mut body = Fragment::new();
    body.text("Upload one attachment");
    body.append(create);
    Page::new("Attachments", body)
}
#[page(path = "/files/{attachment}")]
fn show(attachment: Id<Attachment>, mut read: Query<ReadAttachment>) -> PageResult {
    let record = read.get(attachment).ok_or(NotFound)?;
    let mut body = Fragment::new();
    body.text(&record.title);
    body.append(download::<ReadAttachment>(&record, "file", "Download file"));
    Ok(Page::new("Attachment", body))
}

pub fn noxide_manifest() -> String {
    let mut builder = ApplicationDefinition::new();
    index::register(&mut builder);
    show::register(&mut builder);
    for resource in Attach::resources() {
        builder.resource(resource);
    }
    for operation in Attach::operations() {
        builder.operation(operation);
    }
    builder.action(Attach::definition());
    builder.web_binding(Attach::web_binding());
    builder.blobs(BlobPolicy {
        limits: BlobLimits::default(),
        anonymous: None,
        uploads: vec![UploadBinding {
            id: noxide::stable_id("upload:blob-app:file"),
            name: "attachment_file".into(),
            web_binding: Attach::web_binding().id,
            input: "file".into(),
            anonymous: None,
        }],
    });
    builder.json()
}
struct Application;
impl Handler for Application {
    fn handle(request: noxide::RequestView, _context: &mut Context) -> noxide::ResponseIntent {
        match request.kind {
            noxide::RequestKind::Route(id) if id == index::id() => index::dispatch(&request),
            noxide::RequestKind::Route(id) if id == show::id() => show::dispatch(&request),
            noxide::RequestKind::Action(id) if id == Attach::definition().id => {
                attach(Submission::<Attach>::new(&request)).into_response()
            }
            _ => noxide::ResponseIntent::NotFound(noxide::Document::new("Not found", vec![])),
        }
    }
}
noxide::export!(Application);
