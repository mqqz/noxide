//! Explicit opaque attachment declarations. Uploaded bytes stay in the host;
//! these values are neither paths, download URLs nor independent read grants.
use super::{ApplicationDefinition, ControlField, FieldValue, FormLayout, ReadQuery};
use crate::{Fragment, Instruction, Render};
pub use noxide_protocol::blobs::{
    AnonymousCapabilityQuota, AnonymousDeploymentQuota, BlobLimits, BlobPolicy, BlobRef,
    UploadBinding, UploadHandle,
};
use noxide_protocol::{Control, FieldKind, OperationKind};

impl FieldValue for BlobRef {
    const IMMUTABLE: bool = true;
    fn kind() -> FieldKind {
        FieldKind::Blob {
            max_bytes: noxide_protocol::blobs::MAX_UPLOAD_BYTES,
        }
    }
    fn encode(&self) -> String {
        self.as_str().to_owned()
    }
    fn decode(value: &str) -> Self {
        Self::parse(value.to_owned()).expect("host blob reference contract")
    }
}
impl FieldValue for UploadHandle {
    const IMMUTABLE: bool = true;
    fn kind() -> FieldKind {
        FieldKind::UploadHandle {
            max_bytes: noxide_protocol::blobs::MAX_UPLOAD_BYTES,
        }
    }
    fn encode(&self) -> String {
        self.as_str().to_owned()
    }
    fn decode(value: &str) -> Self {
        Self::parse(value.to_owned()).expect("host upload handle contract")
    }
}
impl ApplicationDefinition {
    /// Explicit requested authority. No defaults inferred from a Blob field or
    /// an action; the host independently checks bindings and operator approval.
    pub fn blobs(&mut self, policy: BlobPolicy) {
        policy.validate_limits().expect("blob policy limits");
        assert!(
            self.blobs.replace(policy).is_none(),
            "duplicate blob policy"
        );
    }
}
pub trait FileInput {}
impl FileInput for UploadHandle {}
impl FileInput for Option<UploadHandle> {}
impl<T: FileInput> ControlField<T> {
    /// Place after every other submitted control. Host admission verifies native
    /// DOM ordering and supplies the bound ticket/staged-handle hidden controls.
    pub fn file(self) -> FormLayout {
        self.control(Control::File)
    }
}

pub struct DownloadLink(noxide_protocol::blobs::DocumentDownload);
impl DownloadLink {
    pub fn instruction(self) -> Instruction {
        Instruction::Download(self.0)
    }
}
impl Render for DownloadLink {
    fn render(self, fragment: &mut Fragment) {
        fragment.nodes.push(self.instruction());
    }
}
/// Initial attachment links require a direct Read, never List/Follow/edit.
/// This lowers metadata only. The host still checks actual successful read
/// provenance, field projection and fresh endpoint authority/incarnation.
pub fn download<Q: ReadQuery>(
    record: &Q::Output,
    field: &str,
    text: impl Into<String>,
) -> DownloadLink {
    let read = Q::operation();
    assert!(
        read.kind == OperationKind::Read && read.via.is_none(),
        "downloads require a direct Read query"
    );
    assert!(noxide_protocol::identifier(field), "invalid download field");
    assert!(
        read.fields
            .as_ref()
            .is_none_or(|fields| fields.iter().any(|f| f == field)),
        "download field outside read projection"
    );
    DownloadLink(noxide_protocol::blobs::DocumentDownload {
        read: read.id,
        target: Q::record_id(record),
        field: field.into(),
        text: text.into(),
    })
}
