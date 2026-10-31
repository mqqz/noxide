//! Source-level proof that `application!` registers the explicit blob policy.
//! Host admission, membership-checked downloads and revocation run in the harness.
// Guest pages and handlers are reachable only through the wasm export.
#[allow(dead_code, unused_imports)]
#[path = "../../../examples/team-documents/src/lib.rs"]
mod proof;

use noxide::__private::{FieldKind, Manifest};

#[test]
fn registered_blob_policy_binds_only_the_member_upload() {
    let manifest: Manifest = serde_json::from_str(&proof::noxide_manifest()).unwrap();
    let blobs = manifest.blobs.as_ref().expect("explicit blob policy");
    assert_eq!(blobs.limits.file_bytes, 1 << 20);
    assert!(blobs.anonymous.is_none());
    let [upload] = blobs.uploads.as_slice() else {
        panic!("exactly one upload binding");
    };
    let binding = manifest
        .web_bindings
        .iter()
        .find(|binding| binding.id == upload.web_binding)
        .unwrap();
    let action = manifest
        .actions
        .iter()
        .find(|action| action.id == binding.action)
        .unwrap();
    assert_eq!(action.name, "Upload attachment");
    let file = action
        .inputs
        .iter()
        .find(|input| input.name == "file")
        .unwrap();
    assert_eq!(file.kind, FieldKind::UploadHandle { max_bytes: 1 << 20 });
    assert_eq!(action.inputs.last().unwrap().name, "file");
    // Document creation stays text-only; the Blob field grants no other upload.
    assert!(
        manifest
            .actions
            .iter()
            .filter(|a| a.id != action.id)
            .all(|a| a
                .inputs
                .iter()
                .all(|input| !matches!(input.kind, FieldKind::UploadHandle { .. })))
    );
}
