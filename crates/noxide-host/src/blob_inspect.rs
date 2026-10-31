//! Bounded reconciliation plans, not deletion/authorization tokens. A runtime
//! executor must reload/fence current metadata and prove committed claims before
//! I/O. Completely unknown objects NEVER produce an automatic cleanup action.
use crate::{blob_io::StoppedIo, blob_metadata::BlobRow, blob_state::State, blob_store::ObjectKey};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{blobs::MAX_UPLOAD_BYTES, time::Timestamp};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(crate) const INSPECTION_PAGE: usize = 16;
/// Facts collected through the private descriptor-relative store API, outside
/// the metadata transaction. Neither a filename nor a guest content type.
pub(crate) struct PhysicalSnapshot {
    pub(crate) key: ObjectKey,
    pub(crate) partial: Option<u64>,
    pub(crate) finalized: Option<u64>,
}
pub(crate) struct SnapshotItem {
    pub(crate) key: ObjectKey,
    pub(crate) physical: Option<PhysicalSnapshot>,
    pub(crate) metadata: Option<BlobRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FindingKind {
    RetainKnown,
    RetainActiveOrUncertainUpload,
    ClaimExpiredStage,
    ClaimUnreferenced,
    ClaimStoppedUpload,
    RecoverPriorProcessUpload,
    ResumeStoppedDeletion,
    RecoverPriorProcessDeletion,
    CleanKnownDeletedObject,
    RetainTombstone,
    QuarantineUnknown,
    MissingReferencedObject,
    PhysicalMetadataMismatch,
}
impl FindingKind {
    pub(crate) fn requires_operator(self) -> bool {
        matches!(
            self,
            Self::QuarantineUnknown
                | Self::MissingReferencedObject
                | Self::PhysicalMetadataMismatch
        )
    }
    pub(crate) fn recoverable_hint(self) -> bool {
        matches!(
            self,
            Self::ClaimExpiredStage
                | Self::ClaimUnreferenced
                | Self::ClaimStoppedUpload
                | Self::RecoverPriorProcessUpload
                | Self::ResumeStoppedDeletion
                | Self::RecoverPriorProcessDeletion
                | Self::CleanKnownDeletedObject
        )
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct Finding {
    pub(crate) object: String,
    pub(crate) slot: Option<String>,
    pub(crate) generation: Option<i64>,
    pub(crate) physical_bytes: u64,
    pub(crate) physical_paths: u8,
    pub(crate) kind: FindingKind,
}
#[derive(Serialize)]
pub(crate) struct InspectionPage {
    pub(crate) store_identity: String,
    pub(crate) observed: Timestamp,
    pub(crate) findings: Vec<Finding>,
}
impl InspectionPage {
    /// Store identity/process come from the retained EXCLUSIVE store owner and
    /// verified pairing, not user input. Metadata absence must be rechecked in a
    /// fresh tx before quarantine accounting; a scan snapshot can lag reserve.
    pub(crate) fn plan(
        store: &ObjectKey,
        process: &ObjectKey,
        items: &[SnapshotItem],
        stopped: &[&StoppedIo],
        now: Timestamp,
    ) -> Result<Self> {
        ensure!(
            items.len() <= INSPECTION_PAGE && stopped.len() <= INSPECTION_PAGE,
            "blob inspection page limit"
        );
        let mut seen = BTreeSet::new();
        let mut findings = Vec::with_capacity(items.len());
        for item in items {
            ensure!(
                seen.insert(item.key.as_str()),
                "duplicate inspection object"
            );
            let (bytes, paths) = match &item.physical {
                None => (0, 0),
                Some(physical) => {
                    ensure!(
                        physical.key == item.key
                            && (physical.partial.is_some() || physical.finalized.is_some()),
                        "foreign physical inspection"
                    );
                    let bytes = physical
                        .partial
                        .unwrap_or(0)
                        .checked_add(physical.finalized.unwrap_or(0))
                        .context("physical size overflow")?;
                    (
                        bytes,
                        u8::from(physical.partial.is_some())
                            + u8::from(physical.finalized.is_some()),
                    )
                }
            };
            let Some(row) = &item.metadata else {
                ensure!(
                    item.physical.is_some(),
                    "inspection has neither metadata nor physical evidence"
                );
                findings.push(Finding {
                    object: item.key.as_str().into(),
                    slot: None,
                    generation: None,
                    physical_bytes: bytes,
                    physical_paths: paths,
                    kind: FindingKind::QuarantineUnknown,
                });
                continue;
            };
            ensure!(row.metadata.key == item.key, "foreign metadata inspection");
            let metadata = &row.metadata;
            let proof = stopped.iter().find(|proof| {
                proof.key() == &item.key && proof.generation() == metadata.generation
            });
            let prior_process = row.process != *process;
            let complete = item.physical.as_ref().is_some_and(|physical| {
                physical.partial.is_none()
                    && physical.finalized == Some(metadata.bytes)
                    && metadata.bytes <= MAX_UPLOAD_BYTES
            });
            let kind = match metadata.state {
                State::Uploading => {
                    if prior_process {
                        FindingKind::RecoverPriorProcessUpload
                    } else if proof
                        .is_some_and(|proof| proof.failed_or_cancelled() || now >= metadata.expires)
                    {
                        FindingKind::ClaimStoppedUpload
                    } else {
                        FindingKind::RetainActiveOrUncertainUpload
                    }
                }
                State::Staged if now >= metadata.expires => FindingKind::ClaimExpiredStage,
                State::Staged | State::Attached => {
                    if complete {
                        FindingKind::RetainKnown
                    } else if item.physical.is_none() {
                        FindingKind::MissingReferencedObject
                    } else {
                        FindingKind::PhysicalMetadataMismatch
                    }
                }
                State::Unreferenced => FindingKind::ClaimUnreferenced,
                State::Deleting => {
                    if prior_process {
                        FindingKind::RecoverPriorProcessDeletion
                    } else if proof.is_some() {
                        FindingKind::ResumeStoppedDeletion
                    } else {
                        FindingKind::RetainActiveOrUncertainUpload
                    }
                }
                State::Deleted => {
                    if item.physical.is_some() {
                        FindingKind::CleanKnownDeletedObject
                    } else {
                        FindingKind::RetainTombstone
                    }
                }
            };
            findings.push(Finding {
                object: item.key.as_str().into(),
                slot: Some(metadata.binding.slot.as_str().into()),
                generation: Some(metadata.generation.value()),
                physical_bytes: bytes,
                physical_paths: paths,
                kind,
            });
        }
        findings.sort_by(|a, b| a.object.cmp(&b.object));
        Ok(Self {
            store_identity: store.as_str().into(),
            observed: now,
            findings,
        })
    }
    pub(crate) fn digest(&self) -> Result<[u8; 32]> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= 65_536, "inspection output limit");
        let mut hash = Sha256::new();
        hash.update(b"noxide/blob-inspection/v1\0");
        hash.update(bytes);
        Ok(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob_state::{Association, Commitment, Generation, Metadata, UploadBinding},
        blob_transport::AttachmentName,
    };
    use noxide_protocol::blobs::{BlobRef, UploadHandle};
    fn key(c: char) -> ObjectKey {
        ObjectKey::parse(c.to_string().repeat(64)).unwrap()
    }
    fn row(state: State, process: ObjectKey) -> BlobRow {
        let mut row = BlobRow {
            metadata: Metadata {
                blob: BlobRef::parse(format!("b1_{}", "e".repeat(64))).unwrap(),
                handle: UploadHandle::parse(format!("u1_{}", "f".repeat(64))).unwrap(),
                key: key('1'),
                binding: UploadBinding {
                    slot: Commitment::parse("a".repeat(64)).unwrap(),
                    subject: Commitment::parse("b".repeat(64)).unwrap(),
                    context: Commitment::parse("c".repeat(64)).unwrap(),
                    input: Commitment::parse("d".repeat(64)).unwrap(),
                },
                state,
                generation: Generation::parse(2).unwrap(),
                expires: Timestamp::from_unix_millis(901000).unwrap(),
                reserved: 0,
                bytes: 3,
                digest: Some([1; 32]),
                association: None,
            },
            anonymous: false,
            filename: AttachmentName::normalize("file.bin").unwrap(),
            created: Timestamp::from_unix_millis(1000).unwrap(),
            claimed: Timestamp::UNIX_EPOCH,
            process,
        };
        if state == State::Uploading {
            row.metadata.reserved = 10;
            row.metadata.bytes = 0;
            row.metadata.digest = None;
            row.metadata.generation = Generation::parse(1).unwrap();
        } else {
            row.metadata.handle = row.metadata.expected_handle(3, [1; 32]).unwrap();
            if matches!(
                state,
                State::Attached | State::Unreferenced | State::Deleting | State::Deleted
            ) {
                row.metadata.association = Some(Association {
                    resource: 1,
                    id: 2,
                    incarnation: "record_incarnation".into(),
                    field: "attachment".into(),
                });
            }
            if state == State::Deleted {
                row.metadata.bytes = 0;
            }
        }
        row
    }
    #[test]
    fn unknown_from_older_database_is_quarantined_without_cleanup_hint() {
        let object = SnapshotItem {
            key: key('1'),
            physical: Some(PhysicalSnapshot {
                key: key('1'),
                partial: None,
                finalized: Some(3),
            }),
            metadata: None,
        };
        for now in [
            Timestamp::UNIX_EPOCH,
            Timestamp::from_unix_millis(100_000_000).unwrap(),
        ] {
            let page =
                InspectionPage::plan(&key('2'), &key('3'), &[object_again(&object)], &[], now)
                    .unwrap();
            let finding = &page.findings[0];
            assert_eq!(finding.kind, FindingKind::QuarantineUnknown);
            assert!(finding.kind.requires_operator());
            assert!(!finding.kind.recoverable_hint());
            assert_eq!(finding.physical_bytes, 3);
            assert_eq!(finding.physical_paths, 1);
        }
    }
    fn object_again(item: &SnapshotItem) -> SnapshotItem {
        SnapshotItem {
            key: item.key.clone(),
            physical: item.physical.as_ref().map(|p| PhysicalSnapshot {
                key: p.key.clone(),
                partial: p.partial,
                finalized: p.finalized,
            }),
            metadata: item.metadata.clone(),
        }
    }
    #[test]
    fn known_finalize_crash_has_authoritative_reservation_recovery() {
        let current = key('3');
        let old = key('4');
        let mut known = row(State::Uploading, old);
        known.metadata.reserved = 10;
        known.metadata.bytes = 0;
        known.metadata.digest = None;
        let item = SnapshotItem {
            key: key('1'),
            physical: Some(PhysicalSnapshot {
                key: key('1'),
                partial: None,
                finalized: Some(3),
            }),
            metadata: Some(known),
        };
        let page = InspectionPage::plan(
            &key('2'),
            &current,
            &[object_again(&item)],
            &[],
            Timestamp::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(
            page.findings[0].kind,
            FindingKind::RecoverPriorProcessUpload
        );
        assert!(page.findings[0].kind.recoverable_hint());
        let mut same = object_again(&item);
        same.metadata.as_mut().unwrap().process = current.clone();
        assert_eq!(
            InspectionPage::plan(
                &key('2'),
                &current,
                &[same],
                &[],
                Timestamp::from_unix_millis(99999999).unwrap()
            )
            .unwrap()
            .findings[0]
                .kind,
            FindingKind::RetainActiveOrUncertainUpload
        );
    }
    #[test]
    fn missing_or_changed_attached_file_requires_operator_not_success() {
        for physical in [
            None,
            Some(PhysicalSnapshot {
                key: key('1'),
                partial: None,
                finalized: Some(4),
            }),
        ] {
            let item = SnapshotItem {
                key: key('1'),
                physical,
                metadata: Some(row(State::Attached, key('3'))),
            };
            let page =
                InspectionPage::plan(&key('2'), &key('3'), &[item], &[], Timestamp::UNIX_EPOCH)
                    .unwrap();
            assert!(page.findings[0].kind.requires_operator());
            assert!(!page.findings[0].kind.recoverable_hint());
        }
    }
    #[test]
    fn page_bounds_duplicate_keys_and_digest_are_concrete_and_stable() {
        let item = SnapshotItem {
            key: key('1'),
            physical: Some(PhysicalSnapshot {
                key: key('1'),
                partial: None,
                finalized: Some(3),
            }),
            metadata: None,
        };
        assert!(
            InspectionPage::plan(
                &key('2'),
                &key('3'),
                &[object_again(&item), object_again(&item)],
                &[],
                Timestamp::UNIX_EPOCH
            )
            .is_err()
        );
        let too_many = (0..INSPECTION_PAGE + 1)
            .map(|_| object_again(&item))
            .collect::<Vec<_>>();
        assert!(
            InspectionPage::plan(&key('2'), &key('3'), &too_many, &[], Timestamp::UNIX_EPOCH)
                .is_err()
        );
        let a = InspectionPage::plan(
            &key('2'),
            &key('3'),
            &[object_again(&item)],
            &[],
            Timestamp::UNIX_EPOCH,
        )
        .unwrap();
        let b = InspectionPage::plan(
            &key('2'),
            &key('3'),
            &[item],
            &[],
            Timestamp::from_unix_millis(1).unwrap(),
        )
        .unwrap();
        assert_ne!(a.digest().unwrap(), b.digest().unwrap());
        assert_eq!(a.digest().unwrap(), a.digest().unwrap());
    }
    #[test]
    fn operator_plan_omits_filenames_content_and_credentials() {
        let mut known = row(State::Staged, key('3'));
        known.filename = AttachmentName::normalize("sensitive-note.html").unwrap();
        let handle = known.metadata.handle.as_str().to_owned();
        let blob = known.metadata.blob.as_str().to_owned();
        let item = SnapshotItem {
            key: key('1'),
            physical: Some(PhysicalSnapshot {
                key: key('1'),
                partial: None,
                finalized: Some(3),
            }),
            metadata: Some(known),
        };
        let page = InspectionPage::plan(&key('2'), &key('3'), &[item], &[], Timestamp::UNIX_EPOCH)
            .unwrap();
        let json = serde_json::to_string(&page).unwrap();
        for forbidden in [
            "sensitive-note.html",
            "filename",
            "subject",
            "context",
            "input",
            "sha256",
            handle.as_str(),
            blob.as_str(),
        ] {
            assert!(!json.contains(forbidden));
        }
        assert!(json.contains("retain_known"));
        assert!(json.contains(key('1').as_str()));
    }
}
