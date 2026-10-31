//! Guest declarations only: these tests grant no host upload/download authority.
use noxide::__private::{
    Assignment, Change, Control, FieldKind, Fields, FormInstruction, Input, Instruction, Record,
    Value, blobs::DocumentDownload,
};
use noxide::{
    ActionType, ApplicationDefinition, BlobLimits, BlobPolicy, BlobRef, FieldValue, FormFields,
    Fragment, Id, IntoPageResponse, Page, QueryType, Resource, ResourceType, UploadBinding,
    UploadHandle, WebActionType, action, download, query,
};

type PendingFile = UploadHandle;
type OptionalPendingFile = Option<PendingFile>;

#[derive(Resource)]
#[resource(key = "attachments")]
pub struct Attachment {
    #[id]
    pub id: Id<Self>,
    #[field(max_bytes = 64)]
    pub title: String,
    #[field()]
    pub file: BlobRef,
    #[field()]
    pub extra: Option<BlobRef>,
}
mod show {
    pub fn id() -> u32 {
        91
    }
}
#[action(inputs(title: String = 64, file: PendingFile),
    transaction(attachment = create(Attachment, set(title = title, file = file))),
    allow = owner, redirect = show(attachment))]
struct Attach;
#[action(inputs(file: OptionalPendingFile),
    transaction(attachment = create(Attachment, set(file = file))),
    allow = owner, redirect = show(attachment))]
struct OptionalAttach;
#[action(create(Attachment), fields(file), allow = owner, redirect = show)]
struct InvalidSimpleAttach;
#[action(inputs(file: BlobRef), transaction(attachment = create(Attachment, set(file = file))),
    allow = owner, redirect = show(attachment))]
struct InvalidBlobInput;
#[query(read(Attachment), allow = owner)]
struct ReadAttachment;
struct TitleOnly;
impl QueryType for TitleOnly {
    type Resource = Attachment;
    type Output = <ReadAttachment as QueryType>::Output;
    fn operation() -> noxide::__private::Operation {
        let mut operation = ReadAttachment::operation();
        operation.fields = Some(vec!["title".into()]);
        operation
    }
    fn from_record(record: Record) -> Self::Output {
        ReadAttachment::from_record(record)
    }
    fn record_id(record: &Self::Output) -> u64 {
        ReadAttachment::record_id(record)
    }
}
impl noxide::ReadQuery for TitleOnly {}

fn blob() -> BlobRef {
    BlobRef::parse(format!("b1_{}", "a".repeat(64))).unwrap()
}

#[test]
fn opaque_types_roundtrip_and_optional_fields_keep_immutability() {
    let value = blob();
    let handle = UploadHandle::parse(format!("u1_{}", "b".repeat(64))).unwrap();
    assert_eq!(BlobRef::decode(&value.encode()), value);
    assert_eq!(UploadHandle::decode(&handle.encode()), handle);
    assert_eq!(Option::<BlobRef>::decode(""), None);
    assert_eq!(Option::<UploadHandle>::decode(""), None);
    const {
        assert!(<Option<BlobRef> as FieldValue>::IMMUTABLE);
        assert!(<Option<UploadHandle> as FieldValue>::IMMUTABLE);
        assert!(<Option<Id<Attachment>> as FieldValue>::IMMUTABLE);
        assert!(<Option<Id<Attachment>> as FieldValue>::REFERENCE);
        assert!(!<Option<String> as FieldValue>::IMMUTABLE);
    }
    let schema = Attachment::definition();
    assert_eq!(schema.fields[0].max_bytes, 64);
    for field in &schema.fields[1..] {
        assert_eq!(
            field.kind,
            FieldKind::Blob {
                max_bytes: 10 << 20
            }
        );
        assert_eq!(field.max_bytes, 67);
    }
    assert!(!schema.fields[1].optional);
    assert!(schema.fields[2].optional);
}

#[test]
fn explicit_independent_upload_input_alias_and_file_control_lower_exactly() {
    let definition = Attach::definition();
    assert_eq!(
        definition.inputs[1],
        Input {
            name: "file".into(),
            label: "File".into(),
            kind: FieldKind::UploadHandle {
                max_bytes: 10 << 20
            },
            optional: false,
            max_bytes: 67,
        }
    );
    assert_eq!(
        definition.steps[0].assign[1],
        Assignment {
            field: "file".into(),
            change: Change::Set(Value::Input("file".into())),
        }
    );
    let optional = OptionalAttach::definition();
    assert!(optional.inputs[0].optional);
    assert_eq!(optional.inputs[0].max_bytes, 67);
    assert_eq!(
        FormFields::<Attach>::new().file.file().instructions,
        vec![FormInstruction::Field {
            name: "file".into(),
            control: Control::File
        }]
    );
    assert_eq!(
        FormFields::<OptionalAttach>::new().file.file().instructions,
        vec![FormInstruction::Field {
            name: "file".into(),
            control: Control::File
        }]
    );
}

#[test]
fn policy_is_explicit_and_no_storage_field_is_inferred_into_authority() {
    let mut definition = ApplicationDefinition::new();
    definition.resource(Attachment::definition());
    assert!(definition.manifest().blobs.is_none());
    let policy = BlobPolicy {
        limits: BlobLimits::default(),
        anonymous: None,
        uploads: vec![UploadBinding {
            id: 12,
            name: "attachment_file".into(),
            web_binding: Attach::web_binding().id,
            input: "file".into(),
            anonymous: None,
        }],
    };
    let mut definition = ApplicationDefinition::new();
    definition.resource(Attachment::definition());
    definition.action(Attach::definition());
    definition.web_binding(Attach::web_binding());
    for operation in Attach::operations() {
        definition.operation(operation);
    }
    definition.blobs(policy.clone());
    let manifest = definition.manifest();
    assert_eq!(manifest.blobs, Some(policy));
    assert_eq!(manifest.resources, vec![Attachment::definition()]);
    assert_eq!(manifest.actions, vec![Attach::definition()]);
    assert_eq!(manifest.web_bindings, vec![Attach::web_binding()]);
    assert!(
        manifest
            .operations
            .iter()
            .all(|operation| operation.kind != noxide::__private::OperationKind::Read)
    );
}

#[test]
fn download_lowers_to_one_canonical_instruction_without_blob_id_or_url() {
    let record = ReadAttachment::from_record(Record {
        resource: Attachment::definition().id,
        id: 7,
        fields: Fields::from([
            ("title".into(), "Title".into()),
            ("file".into(), blob().encode()),
            ("extra".into(), String::new()),
        ]),
    });
    let expected = Instruction::Download(DocumentDownload {
        read: ReadAttachment::operation().id,
        target: 7,
        field: "file".into(),
        text: "<download>".into(),
    });
    assert_eq!(
        download::<ReadAttachment>(&record, "file", "<download>").instruction(),
        expected
    );
    let mut fragment = Fragment::new();
    fragment.append(download::<ReadAttachment>(&record, "file", "<download>"));
    let noxide::ResponseIntent::Page(document) = Page::new("Attachment", fragment).into_response()
    else {
        panic!("page")
    };
    assert_eq!(document.nodes, vec![expected]);
}

#[test]
#[should_panic(expected = "download field outside read projection")]
fn download_cannot_expand_a_read_projection() {
    let record = TitleOnly::from_record(Record {
        resource: Attachment::definition().id,
        id: 7,
        fields: Fields::from([
            ("title".into(), "Title".into()),
            ("file".into(), blob().encode()),
            ("extra".into(), String::new()),
        ]),
    });
    let _ = download::<TitleOnly>(&record, "file", "Download");
}

#[test]
#[should_panic(expected = "Blob fields require explicit UploadHandle inputs")]
fn simple_create_cannot_copy_blob_storage_kind_into_an_input() {
    let _ = InvalidSimpleAttach::definition();
}

#[test]
#[should_panic(expected = "Blob references cannot be action inputs; use UploadHandle")]
fn explicit_blob_ref_is_not_an_upload_input() {
    let _ = InvalidBlobInput::definition();
}
