//! Trusted explicit SDK query fixture. All authority remains host enforced.
use noxide::{
    ActionType, Aggregate, ApplicationDefinition, Context, Execute, Form, Fragment, Handler, Id,
    IntoActionResponse, NotFound, Page, PageResult, Query, QueryForm, Resource, RouteRef,
    Submission, WebActionType, action, page, query,
};
use std::collections::BTreeMap;

#[derive(Resource)]
#[resource(key = "documents", search(fields(title, body), max_bytes = 4096))]
pub struct Document {
    #[id]
    pub id: Id<Self>,
    #[field(label = "Title <plain text>", max_bytes = 160, immutable)]
    pub title: String,
    #[field(max_bytes = 2048)]
    pub body: String,
    #[field(min = 0, max = 100, immutable)]
    pub rank: i64,
    #[field()]
    pub quantity: i64,
    #[field()]
    pub included: bool,
}
#[query(read(Document), allow = owner)]
pub struct ReadDocument;
#[query(list(Document), allow = owner, filter(included = param(included)),
    search(fields(title, body), parameter = terms), page_size = 2,
    order = field(rank, ascending, immutable),
    range(rank, lower = inclusive(param(minimum)), upper = exclusive(param(maximum))))]
pub struct SearchDocuments;
#[query(count(SearchDocuments))]
pub struct CountDocuments;
#[query(sum(SearchDocuments, quantity))]
pub struct SumQuantity;
#[query(min(SearchDocuments, quantity))]
pub struct MinimumQuantity;
#[query(max(SearchDocuments, quantity))]
pub struct MaximumQuantity;

#[action(inputs(title: String = 160, body: String = 2048, rank: i64 = 0..=100, quantity: i64, included: bool),
    transaction(document = create(Document, set(title = title, body = body,
        rank = rank, quantity = quantity, included = included))),
    allow = owner, redirect = show(document))]
pub struct CreateDocument;

fn blank_query(route: u32) -> QueryForm {
    QueryForm::new(RouteRef {
        route,
        target: None,
        // The search control is genuinely blank; no synthetic token is needed.
        params: BTreeMap::from([
            ("included".into(), "true".into()),
            ("minimum".into(), "0".into()),
            ("maximum".into(), "100".into()),
        ]),
    })
    .search_label("Search <Arabic & Rust>")
    .submit("Apply <filters>")
}
#[page(path = "/")]
fn index(create: Form<CreateDocument>) -> Page {
    let mut body = Fragment::new();
    body.text("Private document search");
    body.append(blank_query(search::id()));
    body.append(blank_query(statistics::id()));
    body.append(create);
    Page::new("Query fixture", body)
}
#[page(path = "/documents/{document}")]
fn show(document: Id<Document>, mut read: Query<ReadDocument>) -> PageResult {
    let record = read.get(document).ok_or(NotFound)?;
    let mut body = Fragment::new();
    body.text(format!(
        "Title: {} Body: {} Rank: {} Quantity: {} Included: {}",
        record.title, record.body, record.rank, record.quantity, record.included
    ));
    Ok(Page::new("Private document", body))
}
#[page(path = "/search", params(terms, minimum, maximum, included))]
fn search(mut rows: Query<SearchDocuments>) -> Page {
    let mut body = Fragment::new();
    body.text(format!("Terms: {}", rows.param("terms").unwrap()));
    for record in rows.fetch() {
        body.begin(noxide::Container::Article);
        body.text(format!(
            "Title: {} Rank: {} Quantity: {}",
            record.title, record.rank, record.quantity
        ));
        let mut link = Fragment::new();
        link.text("Open document");
        body.link(show::link(record.id), link);
        body.end();
    }
    Page::new("Search results", body)
}
fn outcome<T: std::fmt::Display>(
    name: &str,
    result: Result<T, noxide::__private::query::QueryError>,
) -> String {
    match result {
        Ok(value) => format!("{name}: {value}"),
        Err(error) => format!("{name} error: {error:?}"),
    }
}
#[page(path = "/statistics", params(terms, minimum, maximum, included))]
fn statistics(
    mut count: Aggregate<CountDocuments>,
    mut sum: Aggregate<SumQuantity>,
    mut minimum: Aggregate<MinimumQuantity>,
    mut maximum: Aggregate<MaximumQuantity>,
) -> Page {
    let mut body = Fragment::new();
    body.begin(noxide::Container::Paragraph);
    body.text(outcome("Count", count.fetch()));
    body.end();
    body.begin(noxide::Container::Paragraph);
    body.text(outcome("Sum", sum.fetch()));
    body.end();
    for (name, result) in [("Min", minimum.fetch()), ("Max", maximum.fetch())] {
        body.begin(noxide::Container::Paragraph);
        body.text(outcome(
            name,
            result.map(|value| value.map_or_else(|| "none".into(), |value| value.to_string())),
        ));
        body.end();
    }
    Page::new("Private statistics", body)
}

pub fn noxide_manifest() -> String {
    let mut builder = ApplicationDefinition::new();
    index::register(&mut builder);
    show::register(&mut builder);
    search::register(&mut builder);
    statistics::register(&mut builder);
    for resource in CreateDocument::resources() {
        builder.resource(resource);
    }
    for operation in CreateDocument::operations() {
        builder.operation(operation);
    }
    builder.action(CreateDocument::definition());
    builder.web_binding(CreateDocument::web_binding());
    builder.json()
}
struct Application;
impl Handler for Application {
    fn handle(request: noxide::RequestView, _context: &mut Context) -> noxide::ResponseIntent {
        match request.kind {
            noxide::RequestKind::Route(id) if id == index::id() => index::dispatch(&request),
            noxide::RequestKind::Route(id) if id == show::id() => show::dispatch(&request),
            noxide::RequestKind::Route(id) if id == search::id() => search::dispatch(&request),
            noxide::RequestKind::Route(id) if id == statistics::id() => {
                statistics::dispatch(&request)
            }
            noxide::RequestKind::Action(id) if id == CreateDocument::definition().id => {
                let decision: Execute<CreateDocument> =
                    Submission::<CreateDocument>::new(&request).execute();
                decision.into_response()
            }
            _ => noxide::ResponseIntent::NotFound(noxide::Document::new("Not found", vec![])),
        }
    }
}
noxide::export!(Application);
