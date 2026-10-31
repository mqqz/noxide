use noxide::__private::{self as p, query as q};
use noxide::prelude::*;
use noxide::{Aggregate, AggregateQuery, FieldSpec, QueryType, ResourceType, Timestamp};

#[derive(Resource)]
#[resource(key = "query_entries", search(fields(body, title), max_bytes = 4096))]
pub struct Entry {
    #[id]
    pub id: Id<Self>,
    #[field(key = "heading", max_bytes = 160, immutable)]
    pub title: String,
    #[field(max_bytes = 2048)]
    pub body: String,
    #[field(min=-100,max=100,immutable)]
    pub rank: i64,
    #[field(min=-100,max=100)]
    pub score: i64,
    #[field(immutable)]
    pub at: Timestamp,
    #[field()]
    pub published: bool,
}
#[query(list(Entry),allow=owner,search(fields(title,body),parameter=terms),order=field(rank,ascending,immutable),range(rank,lower=inclusive(-10),upper=exclusive(param(max))))]
pub struct Entries;
#[query(count(Entries))]
pub struct CountEntries;
#[query(sum(Entries, score))]
pub struct SumEntries;
#[query(min(Entries, at))]
pub struct FirstEntry;
#[query(max(Entries, rank))]
pub struct LastRank;
#[query(list(Entry),allow=public,visible(published=true),fields(title),search(fields(body),parameter=terms),disclose_search(body),order=field(score,descending,live_view),disclose_order(score))]
pub struct PublicEntries;
#[query(count(PublicEntries), disclose_aggregate)]
pub struct PublicCount;

#[page(path = "/search", params(terms, max))]
pub fn search(rows: Query<Entries>, count: Aggregate<CountEntries>) -> Page {
    let _ = (rows.param("terms"), count.param("max"));
    Page::new("Search", html! {p{"Search"}})
}

#[test]
fn declarations_equal_explicit_canonical_query_shapes() {
    assert_eq!(
        Entry::definition().search,
        Some(q::SearchIndex {
            tokenizer: q::TOKENIZER_ID.into(),
            fields: vec!["body".into(), "heading".into()],
            max_bytes: 4096
        })
    );
    const {
        assert!(<Entry as FieldSpec<{ noxide::stable_id("title") }>>::IMMUTABLE);
        assert!(!<Entry as FieldSpec<{ noxide::stable_id("score") }>>::IMMUTABLE);
    }
    assert_eq!(
        Entries::operation(),
        p::Operation {
            maintenance: false,
            query: Some(q::Query {
                search: Some(q::Search {
                    fields: vec!["body".into(), "heading".into()],
                    parameter: "terms".into()
                }),
                range: Some(q::Range {
                    field: "rank".into(),
                    lower: Some(q::Bound {
                        value: p::Operand::Literal("-10".into()),
                        inclusive: true
                    }),
                    upper: Some(q::Bound {
                        value: p::Operand::Param("max".into()),
                        inclusive: false
                    })
                }),
                aggregate: None,
                disclose: vec![]
            }),
            bind: Default::default(),
            scope: None,
            via: None,
            filter: vec![],
            disclose: vec![],
            list: Some(p::ListSettings {
                preview: None,
                order: p::ListOrder::Field {
                    field: "rank".into(),
                    direction: q::Direction::Ascending,
                    mode: q::SortMode::Immutable
                },
                page_size: 3
            }),
            id: noxide::stable_id(concat!("query:", module_path!(), "::Entries")),
            resource: Entry::definition().id,
            kind: p::OperationKind::List,
            policy: p::Policy {
                any: vec![vec![p::Predicate::Owner]]
            },
            visibility: None,
            fields: None,
        }
    );
    let aggregate = CountEntries::operation();
    assert_eq!(aggregate.kind, p::OperationKind::Aggregate);
    assert!(aggregate.list.is_none());
    assert_eq!(
        aggregate.query,
        Some(q::Query {
            aggregate: Some(q::Aggregate {
                source: Entries::operation().id,
                function: q::AggregateFunction::Count
            }),
            ..Default::default()
        })
    );
    assert_eq!(
        CountEntries::support_operations(),
        vec![Entries::operation()]
    );
    assert_eq!(CountEntries::decode(q::AggregateValue::Count(7)), 7);
    assert_eq!(SumEntries::decode(q::AggregateValue::Sum(-3)), -3);
    assert_eq!(FirstEntry::decode(q::AggregateValue::Timestamp(None)), None);
    assert_eq!(
        LastRank::decode(q::AggregateValue::Integer(Some(11))),
        Some(11)
    );
}
#[test]
fn aggregate_registration_is_metadata_only_and_public_inference_is_explicit() {
    let public = PublicEntries::operation();
    assert_eq!(public.fields, Some(vec!["heading".into()]));
    assert_eq!(
        public.query.unwrap().disclose,
        vec![
            q::Disclosure::Search {
                field: "body".into()
            },
            q::Disclosure::Order {
                field: "score".into()
            }
        ]
    );
    assert_eq!(
        PublicCount::operation().query.unwrap().disclose,
        vec![q::Disclosure::Aggregate { field: None }]
    );
    let mut builder = noxide::ApplicationDefinition::new();
    search::register(&mut builder);
    let manifest = builder.manifest();
    assert!(
        manifest
            .operations
            .iter()
            .any(|op| op.id == Entries::operation().id)
    );
    assert!(
        manifest
            .operations
            .iter()
            .any(|op| op.id == CountEntries::operation().id)
    );
    // This page explicitly has a rows query. A count-only page below must not.
    assert!(
        manifest.routes[0]
            .operations
            .contains(&Entries::operation().id)
    );
    let text = noxide::SearchText::new("العربية Rust").unwrap();
    assert_eq!(text.as_str(), "العربية Rust");
    assert!(noxide::SearchText::new("x".repeat(4097)).is_err());
}
#[page(path = "/count", params(terms, max))]
pub fn count_only(_count: Aggregate<CountEntries>) -> Page {
    Page::new("Count", html! {p{"Count"}})
}
#[test]
fn count_only_page_does_not_grant_base_row_invocation() {
    let mut builder = noxide::ApplicationDefinition::new();
    count_only::register(&mut builder);
    let manifest = builder.manifest();
    assert_eq!(
        manifest.routes[0].operations,
        vec![CountEntries::operation().id]
    );
    assert!(
        manifest
            .operations
            .iter()
            .any(|op| op.id == Entries::operation().id)
    );
}
