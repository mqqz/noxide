use noxide::__private::{Access, Fields, Predicate, Record};
use noxide::{FieldValue, Id, QueryType, Resource, ResourceType, page, query};

#[derive(Resource)]
#[resource(key = "articles")]
struct Article {
    #[id]
    record: Id<Self>,
    #[field(key = "title", max_bytes = 128)]
    title: String,
    #[field(key = "published")]
    published: bool,
    #[field(key = "secret", max_bytes = 128)]
    secret: String,
    #[field(key = "id", max_bytes = 128)]
    id: String,
}

#[derive(noxide::Choice)]
enum State {
    #[choice(key = "live", label = "Published")]
    Published,
    #[choice(key = "draft", label = "Draft")]
    Draft,
}

#[derive(Resource)]
#[resource(key = "choices")]
struct ChoiceRecord {
    #[id]
    record: Id<Self>,
    #[field(key = "status")]
    state: State,
}

#[query(list(Article), allow = public, visible(published = true), fields(title, id))]
struct PublicArticles;
#[query(read(Article), allow = public, visible(published = false), fields(title))]
struct HiddenArticles;
#[query(list(Article), allow = owner)]
struct PrivateArticles;
#[query(list(ChoiceRecord), allow = public, visible(state = State::Published), fields(state))]
struct PublishedChoices;

#[page(path = "/", access = public)]
fn index(_: noxide::Query<PublicArticles>) -> noxide::Page {
    noxide::Page::new("Articles", noxide::Fragment::new())
}
#[page(path = "/optional", access = public_optional)]
fn optional() -> noxide::Page {
    noxide::Page::new("Optional", noxide::Fragment::new())
}
#[page(path = "/private")]
fn private() -> noxide::Page {
    noxide::Page::new("Private", noxide::Fragment::new())
}

#[test]
fn public_query_decodes_only_projected_fields() {
    let op = PublicArticles::operation();
    assert_eq!(op.policy.any, [vec![Predicate::Public]]);
    assert_eq!(op.fields.unwrap(), ["title", "id"]);
    assert_eq!(op.visibility.unwrap().equals, true.encode());
    let record = PublicArticles::from_record(Record {
        resource: Article::definition().id,
        id: 42,
        fields: Fields::from([
            ("title".into(), "Public".into()),
            ("id".into(), "application id".into()),
        ]),
    });
    assert_eq!(record.id().get(), 42);
    assert_eq!(record.title, "Public");
    assert_eq!(record.id, "application id");
    assert_eq!(
        HiddenArticles::operation().visibility.unwrap().equals,
        "false"
    );
    assert_eq!(
        PublishedChoices::operation().visibility.unwrap().equals,
        "live"
    );
    assert_eq!(index::definition().access, Access::Public);
    assert_eq!(optional::definition().access, Access::PublicOptional);
    assert_eq!(private::definition().access, Access::Authenticated);
    let request = noxide::RequestView {
        version: noxide::__private::VERSION,
        kind: noxide::RequestKind::Route(index::id()),
        target: None,
        input: Fields::new(),
        inspection: None,
        available_forms: vec![],
    };
    let _ = index::dispatch(&request);
    let _ = optional();
    let _ = private();
    let choice = PublishedChoices::from_record(Record {
        resource: ChoiceRecord::definition().id,
        id: 9,
        fields: Fields::from([("status".into(), "live".into())]),
    });
    assert_eq!(choice.id().get(), 9);
    assert!(matches!(choice.state, State::Published));
}

#[test]
fn private_query_still_decodes_the_complete_resource() {
    let op = PrivateArticles::operation();
    assert!(op.fields.is_none() && op.visibility.is_none());
    let article: Article = PrivateArticles::from_record(Record {
        resource: Article::definition().id,
        id: 42,
        fields: Fields::from([
            ("title".into(), "Private".into()),
            ("published".into(), "false".into()),
            ("secret".into(), "private".into()),
            ("id".into(), "application id".into()),
        ]),
    });
    assert_eq!(article.record.get(), 42);
    assert_eq!(article.title, "Private");
    assert!(!article.published);
    assert_eq!(article.secret, "private");
    assert_eq!(article.id, "application id");
    let choice = ChoiceRecord::from_record(Record {
        resource: ChoiceRecord::definition().id,
        id: 3,
        fields: Fields::from([("status".into(), "draft".into())]),
    });
    assert_eq!(choice.record.get(), 3);
    assert!(matches!(choice.state, State::Draft));
}
