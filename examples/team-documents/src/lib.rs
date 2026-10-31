//! Private workspace documents with explicit record-scoped membership authority.
use noxide::prelude::*;
use noxide::{
    AccountId, Aggregate, BlobLimits, BlobPolicy, BlobRef, QueryForm, RouteRef, Timestamp,
    UploadBinding, UploadHandle, WebActionType, download,
};
use std::collections::BTreeMap;

#[derive(Choice)]
pub enum Role {
    #[choice(key = "admin", label = "Administrator")]
    Admin,
    #[choice(key = "member", label = "Member")]
    Member,
}

#[derive(Resource)]
#[resource(key = "workspaces", expiry(expires_at, max_after_seconds = 86400))]
pub struct Workspace {
    #[id]
    pub id: Id<Self>,
    #[field(max_bytes = 160)]
    pub name: String,
    #[field()]
    pub expires_at: Timestamp,
}
#[derive(Resource)]
#[resource(
    key = "memberships",
    unique(workspace, account),
    expiry(expires_at, max_after_seconds = 86400)
)]
pub struct Membership {
    #[id]
    pub id: Id<Self>,
    #[field()]
    pub workspace: Id<Workspace>,
    #[field(scope = same_tenant)]
    pub account: AccountId,
    #[field()]
    pub role: Role,
    #[field()]
    pub active: bool,
    #[field()]
    pub expires_at: Timestamp,
}
#[derive(Resource)]
#[resource(
    key = "documents",
    expiry(expires_at, max_after_seconds = 86400),
    search(fields(title, body), max_bytes = 4096)
)]
pub struct Document {
    #[id]
    pub id: Id<Self>,
    #[field()]
    pub workspace: Id<Workspace>,
    #[field(max_bytes = 160)]
    pub title: String,
    #[field(max_bytes = 4096)]
    pub body: String,
    #[field()]
    pub expires_at: Timestamp,
}

#[derive(Resource)]
#[resource(key = "attachments", expiry(expires_at, max_after_seconds = 86400))]
pub struct Attachment {
    #[id]
    pub id: Id<Self>,
    #[field()]
    pub workspace: Id<Workspace>,
    #[field(max_bytes = 160)]
    pub title: String,
    #[field()]
    pub file: BlobRef,
    #[field()]
    pub expires_at: Timestamp,
}

#[query(list(Workspace), allow = all(same_tenant, any(owner, exists_related(Membership,
    reference = workspace, target = self_record, account = account, conditions(active = true)))),
    order = created_desc, page_size = 20)]
pub struct Workspaces;
#[query(read(Workspace), allow = all(same_tenant, any(owner, exists_related(Membership,
    reference = workspace, target = self_record, account = account, conditions(active = true)))))]
pub struct ReadWorkspace;
#[query(read(Workspace), allow = all(owner, same_tenant))]
pub struct CreatedWorkspace;
#[query(read(Workspace), allow = exists_related(Membership,
    reference = workspace, target = self_record, account = account,
    conditions(role = Role::Admin, active = true)))]
pub struct AdminWorkspace;
#[query(list(Document), scope(workspace), allow = exists_related(Membership,
    reference = workspace, target = reference(workspace), account = account,
    conditions(active = true)), order = created_desc, page_size = 10)]
pub struct Documents;
#[query(read(Document), allow = exists_related(Membership,
    reference = workspace, target = reference(workspace), account = account,
    conditions(active = true)))]
pub struct ReadDocument;
#[query(list(Document), scope(workspace), allow = exists_related(Membership,
    reference = workspace, target = reference(workspace), account = account,
    conditions(active = true)), search(fields(title, body), parameter = terms),
    order = field(title, ascending, live_view), page_size = 10)]
pub struct SearchDocuments;
#[query(count(SearchDocuments))]
pub struct CountMatches;
#[query(list(Attachment), scope(workspace), allow = exists_related(Membership,
    reference = workspace, target = reference(workspace), account = account,
    conditions(active = true)), preview, page_size = 10)]
pub struct Attachments;
#[query(read(Attachment), allow = exists_related(Membership,
    reference = workspace, target = reference(workspace), account = account,
    conditions(active = true)))]
pub struct ReadAttachment;
#[query(list(Membership), scope(workspace), allow = exists_related(Membership,
    reference = workspace, target = reference(workspace), account = account,
    conditions(role = Role::Admin, active = true)), preview, page_size = 10)]
pub struct Members;
#[query(read(Membership), allow = exists_related(Membership,
    reference = workspace, target = reference(workspace), account = account,
    conditions(role = Role::Admin, active = true)))]
pub struct ReadMember;

#[action(inputs(name: String = 160), transaction(
    workspace = create(Workspace, set(name = name, expires_at = transaction_time() + seconds(3600))),
    create(Membership, set(workspace = workspace, account = principal(), role = "admin",
        active = true, expires_at = transaction_time() + seconds(3600)),
        eligible = CreatedWorkspace, allow = principal_is(account))),
    allow = all(owner, same_tenant), redirect = workspace(workspace))]
pub struct CreateWorkspace;

#[action(inputs(title: String = 160, body: String = 4096), transaction(
    document = create(Document, set(workspace = target, title = title, body = body,
        expires_at = transaction_time() + seconds(3600)), eligible = ReadWorkspace)),
    allow = exists_related(Membership, reference = workspace, target = reference(workspace),
        account = account, conditions(active = true)), redirect = document(document))]
pub struct CreateDocument;

#[action(inputs(account: AccountId = same_tenant), transaction(
    create(Membership, set(workspace = target, account = account, role = "member", active = true,
        expires_at = transaction_time() + seconds(3600)), eligible = AdminWorkspace)),
    allow = exists_related(Membership, reference = workspace, target = reference(workspace),
        account = account, conditions(role = Role::Admin, active = true)), redirect = workspace(target))]
pub struct AddMember;

#[action(inputs(title: String = 160, file: UploadHandle = bytes(1_048_576)), transaction(
    attachment = create(Attachment, set(workspace = target, title = title, file = file,
        expires_at = transaction_time() + seconds(3600)), eligible = ReadWorkspace)),
    allow = exists_related(Membership, reference = workspace, target = reference(workspace),
        account = account, conditions(active = true)), redirect = attachment(attachment))]
pub struct UploadAttachment;

/// Explicit operator-reviewed upload authority; Blob fields alone grant none.
fn attachment_files() -> BlobPolicy {
    BlobPolicy {
        limits: BlobLimits {
            file_bytes: 1 << 20,
            app_bytes: 64 << 20,
            objects: 256,
            ..BlobLimits::default()
        },
        anonymous: None,
        uploads: vec![UploadBinding {
            id: noxide::stable_id("upload:team-documents:attachment"),
            name: "workspace_attachment".into(),
            web_binding: UploadAttachment::web_binding().id,
            input: "file".into(),
            anonymous: None,
        }],
    }
}

fn search_form(workspace: Id<Workspace>) -> QueryForm {
    QueryForm::new(RouteRef {
        route: search::id(),
        target: Some(workspace.get()),
        params: BTreeMap::new(),
    })
    .search_label("Search documents")
    .submit("Search")
}

#[action(update(Membership), fields(role, active), allow = exists_related(Membership,
    reference = workspace, target = reference(workspace), account = account,
    conditions(role = Role::Admin, active = true)), redirect = member)]
pub struct EditMember;

#[action(update(Document), fields(title, body), allow = exists_related(Membership,
    reference = workspace, target = reference(workspace), account = account,
    conditions(role = Role::Admin, active = true)), redirect = document)]
pub struct EditDocument;

#[page(path = "/")]
pub fn index(mut workspaces: Query<Workspaces>, create: Form<CreateWorkspace>) -> Page {
    let workspaces = workspaces.fetch();
    Page::new(
        "Team documents",
        html! { main {
            h1 { "Team documents" }
            p { "Create a workspace, add accounts from your tenant, and share private documents." }
            @if workspaces.is_empty() { p { "Your workspaces will appear here." } }
            @for workspace in workspaces { article { a href=(routes::workspace(workspace.id)) { (&workspace.name) } } }
            @if create.is_available() { h2 { "Create workspace" } (create) } @else { p { "Ask the operator to provision your account in a tenant before creating a workspace." } }
            p { "Workspaces, memberships and documents in this example expire after one hour." }
        } },
    )
}

// Each extractor is an independent host-checked query or form.
#[allow(clippy::too_many_arguments)]
#[page(path = "/workspaces/{workspace}")]
pub fn workspace(
    workspace: Id<Workspace>,
    mut read: Query<ReadWorkspace>,
    mut admin: Query<AdminWorkspace>,
    mut documents: Query<Documents>,
    mut members: Query<Members>,
    mut attachments: Query<Attachments>,
    create: Form<CreateDocument>,
    add_member: Form<AddMember>,
    upload: Form<UploadAttachment>,
) -> PageResult {
    let current = read.get(workspace).ok_or(NotFound)?;
    let administrator = admin.get(workspace).is_some();
    let documents = documents.fetch();
    let attachments = attachments.fetch_preview();
    let members = if administrator {
        Some(members.fetch_preview())
    } else {
        None
    };
    Ok(Page::new(
        &current.name,
        html! { main {
            h1 { (&current.name) }
            @if documents.is_empty() { p { "Create the first document for this workspace." } }
            @for document in documents { article { a href=(routes::document(document.id)) { (&document.title) } } }
            @if create.is_available() { h2 { "New document" } (create) }
            h2 { "Search" } (search_form(workspace))
            h2 { "Attachments" }
            @if attachments.items.is_empty() { p { "No attachments yet." } }
            @for attachment in attachments.items { article { a href=(routes::attachment(attachment.id)) { (&attachment.title) } } }
            @if attachments.truncated { p { "The attachment preview reached its limit." } }
            @if upload.is_available() { h2 { "Upload attachment" } p { "Files up to 1 MiB stay on this host and are shown only to active members." } (upload) }
            @if let Some(members) = members {
                h2 { "Members" }
                @for membership in members.items { article {
                    p { (membership.account.to_string()) " · " (&membership.role) }
                    a href=(routes::member(membership.id)) { "Manage membership" }
                } }
                @if members.truncated { p { "The member preview reached its limit." } }
                h2 { "Add member" }
                p { "Ask the member to share their Account ID. Each account has one membership per workspace." }
                (add_member)
            }
            a href=(routes::index()) { "All workspaces" }
        } },
    ))
}

#[page(path = "/documents/{document}")]
pub fn document(
    document: Id<Document>,
    mut read: Query<ReadDocument>,
    edit: Form<EditDocument>,
) -> PageResult {
    let document = read.get(document).ok_or(NotFound)?;
    Ok(Page::new(
        &document.title,
        html! { main {
            h1 { (&document.title) } pre { (&document.body) }
            @if edit.is_available() { h2 { "Edit document" } (edit) }
            a href=(routes::workspace(document.workspace)) { "Workspace" }
        } },
    ))
}

#[page(path = "/workspaces/{workspace}/search", params(terms))]
pub fn search(
    workspace: Id<Workspace>,
    mut read: Query<ReadWorkspace>,
    mut matches: Query<SearchDocuments>,
    mut count: Aggregate<CountMatches>,
) -> PageResult {
    let current = read.get(workspace).ok_or(NotFound)?;
    let terms = matches.param("terms").unwrap_or_default().to_owned();
    let total = count.fetch().ok();
    let results = matches.fetch();
    Ok(Page::new(
        "Search documents",
        html! { main {
            h1 { "Search " (&current.name) }
            (search_form(workspace))
            p { "Terms: " (&terms) }
            @if let Some(total) = total { p { "Matching documents: " (total) } } @else { p { "The match count is unavailable for these terms." } }
            @for document in results { article { a href=(routes::document(document.id)) { (&document.title) } } }
            a href=(routes::workspace(workspace)) { "Workspace" }
        } },
    ))
}

#[page(path = "/attachments/{attachment}")]
pub fn attachment(attachment: Id<Attachment>, mut read: Query<ReadAttachment>) -> PageResult {
    let record = read.get(attachment).ok_or(NotFound)?;
    Ok(Page::new(
        &record.title,
        html! { main {
            h1 { (&record.title) }
            p { "Downloads are checked against your current membership each time." }
            (download::<ReadAttachment>(&record, "file", "Download file"))
            a href=(routes::workspace(record.workspace)) { "Workspace" }
        } },
    ))
}

#[page(path = "/memberships/{membership}")]
pub fn member(
    membership: Id<Membership>,
    mut read: Query<ReadMember>,
    edit: Form<EditMember>,
) -> PageResult {
    let membership = read.get(membership).ok_or(NotFound)?;
    Ok(Page::new(
        "Manage membership",
        html! { main {
            h1 { "Manage membership" } p { (membership.account.to_string()) }
            p { "Administrator authority comes from the current active membership. Demoting or deactivating your last administrator removes your ability to manage members." }
            (edit) a href=(routes::workspace(membership.workspace)) { "Workspace" }
        } },
    ))
}

noxide::application! {
    pages: [index, workspace, document, search, attachment, member],
    actions: [CreateWorkspace, CreateDocument, AddMember, EditMember, EditDocument, UploadAttachment],
    blobs: [attachment_files]
}
