//! Anonymous public paste creation with opaque attachments and bounded cleanup.
pub mod expiring_paste {
    use noxide::prelude::*;
    use noxide::{
        ActionType, ApplicationDefinition, BlobLimits, BlobPolicy, BlobRef, Duration, Timestamp,
        UploadHandle, WebActionType, guards, values,
    };

    #[derive(Resource)]
    #[resource(key = "pastes", expiry(expires_at, max_after_seconds = 3600))]
    pub struct Paste {
        #[id]
        id: Id<Self>,
        #[field(immutable, max_bytes = 128)]
        title: String,
        #[field(immutable, max_bytes = 4096)]
        body: String,
        #[field()]
        file: BlobRef,
        #[field(immutable, initial = true)]
        published: bool,
        #[field(immutable)]
        created_at: Timestamp,
        #[field(immutable)]
        expires_at: Timestamp,
    }

    #[query(list(Paste), allow = public, visible(published = true),
        fields(title, created_at, expires_at), order = created_desc, page_size = 20)]
    struct PublishedPastes;
    #[query(read(Paste), allow = public, visible(published = true),
        fields(title, body, file, created_at, expires_at))]
    struct PublishedPaste;

    struct CreatePaste;
    struct CreateInput {
        pub title: String,
        pub body: String,
        pub file: UploadHandle,
    }
    impl noxide::ActionInput for CreateInput {
        fn from_fields(fields: &noxide::Fields) -> Self {
            use noxide::FieldValue;
            Self {
                title: fields["title"].clone(),
                body: fields["body"].clone(),
                file: UploadHandle::decode(&fields["file"]),
            }
        }
    }
    struct CreateControls {
        pub title: noxide::ControlField<String>,
        pub body: noxide::ControlField<String>,
        pub file: noxide::ControlField<UploadHandle>,
    }
    impl ActionType for CreatePaste {
        type Resource = Paste;
        type Input = CreateInput;
        type Original = ();
        fn operations() -> Vec<noxide::__private::Operation> {
            use noxide::{__private::*, ResourceType};
            vec![Operation {
                id: noxide::stable_id(concat!("mutation:", module_path!(), "::CreatePaste:0u8")),
                resource: Paste::definition().id,
                kind: OperationKind::Create,
                policy: Policy {
                    any: vec![vec![Predicate::Public]],
                },
                maintenance: false,
                query: None,
                bind: Default::default(),
                scope: None,
                via: None,
                filter: vec![],
                disclose: vec![],
                list: None,
                visibility: None,
                fields: None,
            }]
        }
        fn definition() -> noxide::__private::Action {
            use noxide::{__private::*, CalculatedStep};
            let input = |name: &str, kind, max_bytes| Input {
                name: name.into(),
                label: match name {
                    "title" => "Title",
                    "body" => "Body",
                    _ => "File",
                }
                .into(),
                kind,
                optional: false,
                max_bytes,
            };
            Action {
                id: noxide::stable_id(concat!("action:", module_path!(), "::CreatePaste")),
                version: 1,
                name: "Create paste".into(),
                targets: vec![],
                inputs: vec![
                    input("title", FieldKind::Text, 128),
                    input("body", FieldKind::Text, 4096),
                    input(
                        "file",
                        FieldKind::UploadHandle {
                            max_bytes: 1 << 20,
                        },
                        67,
                    ),
                ],
                steps: vec![
                    CalculatedStep::new(Self::operations()[0].id, Target::None)
                        .set("title", values::input("title"))
                        .set("body", values::input("body"))
                        .set("file", values::input("file"))
                        .set("created_at", values::transaction_time())
                        .set("expires_at", expiry_due())
                        .finish(),
                ],
            }
        }
    }
    impl WebActionType for CreatePaste {
        type Controls = CreateControls;
        fn controls() -> Self::Controls {
            CreateControls {
                title: noxide::ControlField::new("title"),
                body: noxide::ControlField::new("body"),
                file: noxide::ControlField::new("file"),
            }
        }
        fn web_binding() -> noxide::__private::WebBinding {
            use noxide::__private::*;
            let action = Self::definition();
            WebBinding {
                id: action.id,
                version: action.version,
                action: action.id,
                layout: vec![],
                redirect: Redirect {
                    route: show::id(),
                    source: RedirectSource::Step(0),
                },
            }
        }
    }

    #[action(delete(Paste), allow = capability, redirect = index)]
    struct DeletePaste;

    fn publish(
        submission: Submission<CreatePaste>,
    ) -> Result<Execute<CreatePaste>, ActionError<CreatePaste>> {
        if submission.input().title.trim().is_empty() {
            return Err(ActionError::message("Choose a nonempty title."));
        }
        Ok(submission.execute())
    }
    fn create_layout(fields: FormFields<CreatePaste>) -> FormLayout {
        form! {
            (fields.title.text_input())
            (fields.body.textarea().rows(8))
            (fields.file.file())
            (fields.submit("Publish for one hour"))
        }
    }

    #[page(path = "/", access = public_optional)]
    fn index(mut pastes: Query<PublishedPastes>, create: Form<CreatePaste>) -> Page {
        Page::new(
            "Expiring paste",
            html! { main {
                h1 { "Expiring paste" }
                p { "Publish plain text and one public attachment for one hour. No JavaScript is needed." }
                p { "Anyone can read or download a published attachment. Files are downloads only; there is no inline preview." }
                p { "Keep the host-issued edit secret to delete your paste early. It does not make a public paste private." }
                p { "The published event discloses only its synthetic event name, paste identity and creation time to the operator-approved endpoint." }
                (create)
                h2 { "Recent public pastes" }
                @for paste in pastes.fetch() {
                    article { a href=(routes::show(paste.id())) { (&paste.title) } }
                }
            } },
        )
    }
    #[page(path = "/pastes/{paste}", access = public_optional)]
    fn show(
        paste: Id<Paste>,
        mut read: Query<PublishedPaste>,
        delete: Form<DeletePaste>,
    ) -> PageResult {
        let paste = read.get(paste).ok_or(NotFound)?;
        Ok(Page::new(
            &paste.title,
            html! { main {
                h1 { (&paste.title) }
                p { (&paste.body) }
                p { "This text and attachment are public for one hour. Expiry blocks new reads and downloads; stored bytes are removed later by guarded cleanup and blob maintenance." }
                (noxide::download::<PublishedPaste>(&paste, "file", "Download public attachment"))
                @if delete.is_available() { h2 { "Delete with your edit secret" } (delete) }
                a href=(routes::index()) { "All public pastes" }
            } },
        ))
    }

    const CLEANUP_WORKER: &str = "paste_cleanup";
    fn expiry_due() -> noxide::__private::Value {
        values::add(
            values::transaction_time(),
            values::duration(Duration::from_secs(3600).unwrap()),
        )
    }
    fn cleanup_operation(
        key: &str,
        kind: noxide::__private::OperationKind,
    ) -> noxide::__private::Operation {
        use noxide::{
            __private::{Policy, Predicate},
            ResourceType,
        };
        noxide::__private::Operation {
            id: noxide::stable_id(key),
            resource: Paste::definition().id,
            kind,
            policy: Policy {
                any: vec![vec![
                    Predicate::Service {
                        worker: CLEANUP_WORKER.into(),
                    },
                    Predicate::SameTenant,
                ]],
            },
            maintenance: true,
            query: None,
            bind: Default::default(),
            scope: None,
            via: None,
            filter: vec![],
            disclose: vec![],
            list: None,
            visibility: None,
            fields: None,
        }
    }
    fn cleanup_read() -> noxide::__private::Operation {
        cleanup_operation(
            "expiring-paste:cleanup:read",
            noxide::__private::OperationKind::Read,
        )
    }
    fn cleanup_candidates() -> noxide::__private::Operation {
        use noxide::__private::*;
        let mut operation = cleanup_operation("expiring-paste:cleanup:list", OperationKind::List);
        operation.list = Some(ListSettings {
            order: ListOrder::CreatedAsc,
            page_size: 20,
            preview: None,
        });
        operation.filter = vec![Condition {
            field: "published".into(),
            equals: Operand::Literal("true".into()),
        }];
        operation
    }
    struct CleanupPaste;
    impl ActionType for CleanupPaste {
        type Resource = Paste;
        type Input = ();
        type Original = ();
        fn operations() -> Vec<noxide::__private::Operation> {
            vec![
                cleanup_operation(
                    "expiring-paste:cleanup:delete",
                    noxide::__private::OperationKind::Delete,
                ),
                cleanup_read(),
            ]
        }
        fn definition() -> noxide::__private::Action {
            use noxide::{__private::*, ResourceType};
            Action {
                id: noxide::stable_id("action:expiring-paste:CleanupPaste"),
                version: 1,
                name: "Cleanup paste".into(),
                inputs: vec![],
                targets: vec![ActionTarget {
                    name: "paste".into(),
                    resource: Paste::definition().id,
                    source: TargetSource::Service {
                        eligible: cleanup_read().id,
                    },
                    revision: Revision::Identity,
                    projection: Some(Inspection {
                        operation: cleanup_read().id,
                        fields: vec!["expires_at".into()],
                    }),
                    inspect: None,
                }],
                steps: vec![Step {
                    operation: Self::operations()[0].id,
                    target: Target::Named("paste".into()),
                    assign: vec![],
                    guards: vec![guards::require(
                        guards::less_or_equal(
                            values::current("paste", "expires_at"),
                            values::transaction_time(),
                        ),
                        None,
                        "The paste has not expired.",
                    )],
                }],
            }
        }
    }
    fn jobs() -> noxide::JobContract {
        use noxide::{
            JobContract, RecurringSchedule, RecurringSelection, ResourceType, Schedule,
            ScheduledTarget, Worker, WorkerAction, WorkerTarget,
        };
        use std::collections::BTreeMap;
        JobContract {
            workers: vec![Worker {
                name: CLEANUP_WORKER.into(),
                actions: vec![WorkerAction {
                    action: CleanupPaste::definition().id,
                    targets: BTreeMap::from([(
                        "paste".into(),
                        WorkerTarget {
                            resource: Paste::definition().id,
                            eligible: cleanup_read().id,
                        },
                    )]),
                }],
            }],
            schedules: vec![Schedule {
                source_action: CreatePaste::definition().id,
                ordinal: 0,
                worker: CLEANUP_WORKER.into(),
                action: CleanupPaste::definition().id,
                targets: BTreeMap::from([("paste".into(), ScheduledTarget::Created(0))]),
                inputs: BTreeMap::new(),
                due_at: expiry_due(),
            }],
            recurring: vec![RecurringSchedule {
                name: "repair_expired_pastes".into(),
                worker: CLEANUP_WORKER.into(),
                action: CleanupPaste::definition().id,
                interval: Duration::from_secs(60).unwrap(),
                inputs: BTreeMap::new(),
                selection: Some(RecurringSelection {
                    operation: cleanup_candidates().id,
                    target: "paste".into(),
                    expiry_repair: true,
                }),
            }],
        }
    }
    fn blobs() -> BlobPolicy {
        use noxide::{AnonymousCapabilityQuota, AnonymousDeploymentQuota, UploadBinding};
        BlobPolicy {
            limits: BlobLimits {
                file_bytes: 1 << 20,
                app_bytes: 16 << 20,
                objects: 64,
                live_stages: 2,
                uploads: 1,
                downloads: 2,
            },
            anonymous: Some(AnonymousDeploymentQuota {
                stages: 4,
                bytes: 4 << 20,
            }),
            uploads: vec![UploadBinding {
                id: noxide::stable_id("upload:expiring-paste:file"),
                name: "public_paste_file".into(),
                web_binding: CreatePaste::web_binding().id,
                input: "file".into(),
                anonymous: Some(AnonymousCapabilityQuota {
                    stages: 2,
                    bytes: 2 << 20,
                }),
            }],
        }
    }
    fn effects() -> noxide::EffectContract {
        use noxide::{
            __private::{FieldKind, Input, Value},
            EffectContract, EffectEndpoint, EmitEffect, PayloadField,
        };
        let field = |name: &str, kind, max_bytes, value| PayloadField {
            schema: Input {
                name: name.into(),
                label: name.into(),
                kind,
                optional: false,
                max_bytes,
            },
            value,
        };
        EffectContract {
            endpoints: vec![EffectEndpoint {
                name: "synthetic_events".into(),
                secret_slot: Some("synthetic_events_token".into()),
            }],
            emissions: vec![EmitEffect {
                source_action: CreatePaste::definition().id,
                ordinal: 0,
                endpoint: "synthetic_events".into(),
                fields: vec![
                    field("at", FieldKind::Timestamp, 20, values::transaction_time()),
                    field("event", FieldKind::Text, 9, values::text("published")),
                    field(
                        "paste",
                        FieldKind::Reference {
                            resource: "pastes".into(),
                        },
                        19,
                        Value::Created(0),
                    ),
                ],
            }],
        }
    }

    pub mod routes {
        pub use super::index::link as index;
        pub use super::show::link as show;
    }
    fn register_web<A: WebActionType>(builder: &mut ApplicationDefinition) {
        for resource in A::resources() {
            builder.resource(resource);
        }
        for operation in A::operations() {
            builder.operation(operation);
        }
        if let Some(operation) = A::inspection() {
            builder.operation(operation);
        }
        builder.action(A::definition());
        builder.web_binding(A::web_binding());
    }
    pub fn noxide_manifest() -> String {
        let mut builder = ApplicationDefinition::new();
        index::register(&mut builder);
        show::register(&mut builder);
        register_web::<CreatePaste>(&mut builder);
        register_web::<DeletePaste>(&mut builder);
        builder.layout(
            CreatePaste::web_binding().id,
            create_layout(FormFields::new()).instructions,
        );
        for resource in CleanupPaste::resources() {
            builder.resource(resource);
        }
        for operation in CleanupPaste::operations() {
            builder.operation(operation);
        }
        builder.action(CleanupPaste::definition());
        builder.operation(cleanup_candidates());
        builder.blobs(blobs());
        builder.jobs(jobs());
        builder.effects(effects());
        builder.json()
    }
    struct Application;
    impl noxide::Handler for Application {
        fn handle(request: noxide::RequestView, _: &mut noxide::Context) -> noxide::ResponseIntent {
            use noxide::{IntoActionResponse, RequestKind, ResponseIntent};
            match request.kind {
                RequestKind::Route(id) if id == index::id() => index::dispatch(&request),
                RequestKind::Route(id) if id == show::id() => show::dispatch(&request),
                RequestKind::Action(id) if id == CreatePaste::definition().id => {
                    publish(Submission::<CreatePaste>::new(&request)).into_response()
                }
                RequestKind::Action(id) if id == DeletePaste::definition().id => {
                    Submission::<DeletePaste>::new(&request)
                        .execute()
                        .into_response()
                }
                RequestKind::Action(id) if id == CleanupPaste::definition().id => {
                    Submission::<CleanupPaste>::new(&request)
                        .execute()
                        .into_response()
                }
                _ => ResponseIntent::NotFound(noxide::Document::new("Not found", vec![])),
            }
        }
    }
    noxide::export!(Application);
}
pub use expiring_paste::noxide_manifest;
