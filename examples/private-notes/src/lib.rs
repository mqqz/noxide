use noxide::{
    Container as C, Context, Document, Handler, Instruction as N, RequestKind, RequestView,
    ResponseIntent, RouteRef,
};

struct Notes;
impl Handler for Notes {
    fn handle(request: RequestView, context: &mut Context) -> ResponseIntent {
        match request.kind {
            RequestKind::Action(1) => {
                let record = context.create(3);
                ResponseIntent::Created {
                    resource: record.resource,
                    id: record.id,
                    destination: RouteRef {
                        route: 2,
                        target: Some(record.id),
                    },
                }
            }
            RequestKind::Route(1) => {
                let records = context.list(1);
                let mut nodes = vec![
                    N::Begin(C::Heading1),
                    N::Text("Private notes".into()),
                    N::End,
                ];
                if records.is_empty() {
                    nodes.push(N::Text("No notes yet".into()));
                }
                for record in records {
                    nodes.extend([
                        N::Begin(C::Article),
                        N::Begin(C::Pre),
                        N::Text(record.fields["body"].clone()),
                        N::End,
                        N::Link {
                            destination: RouteRef {
                                route: 2,
                                target: Some(record.id),
                            },
                            text: "Open note".into(),
                        },
                        N::End,
                    ]);
                }
                nodes.push(N::Form { action: 1 });
                ResponseIntent::Page(Document::new("Private notes", nodes))
            }
            RequestKind::Route(2) => match context.read(2, request.target.expect("record route")) {
                Some(record) => ResponseIntent::Page(Document::new(
                    "Private note",
                    vec![
                        N::Begin(C::Heading1),
                        N::Text("Private note".into()),
                        N::End,
                        N::Begin(C::Pre),
                        N::Text(record.fields["body"].clone()),
                        N::End,
                        N::Link {
                            destination: RouteRef {
                                route: 1,
                                target: None,
                            },
                            text: "All notes".into(),
                        },
                    ],
                )),
                None => ResponseIntent::NotFound(Document::new(
                    "Not found",
                    vec![N::Text("This note is not available.".into())],
                )),
            },
            _ => ResponseIntent::NotFound(Document::new(
                "Not found",
                vec![N::Text("This page is not available.".into())],
            )),
        }
    }
}
noxide::export!(Notes);
