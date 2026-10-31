use super::*;
use crate::blob_store::{BlobStore, IoGuard};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::{Duration as WallDuration, Instant},
};

fn now() -> Timestamp {
    Timestamp::from_unix_millis(1_000_000).unwrap()
}
fn binding() -> UploadBinding {
    UploadBinding {
        slot: commitment('a'),
        subject: commitment('b'),
        context: commitment('c'),
        input: commitment('d'),
    }
}
fn commitment(c: char) -> Commitment {
    Commitment::parse(c.to_string().repeat(64)).unwrap()
}
fn subject() -> SubjectUsage {
    SubjectUsage {
        live_stages: 0,
        held_bytes: 0,
        stage_limit: 4,
        byte_limit: 40 * 1024 * 1024,
    }
}
fn reserve(bytes: u64) -> (Metadata, Quota) {
    Metadata::reserve(
        BlobRef::parse(format!("b1_{}", "e".repeat(64))).unwrap(),
        UploadHandle::parse(format!("u1_{}", "f".repeat(64))).unwrap(),
        ObjectKey::random().unwrap(),
        binding(),
        now(),
        bytes,
        BlobLimits::default(),
        subject(),
        Quota {
            reserved: 0,
            used: 0,
            objects: 0,
        },
    )
    .unwrap()
}
fn durable(metadata: &Metadata, bytes: &[u8]) -> DurableObject {
    let dir = tempfile::tempdir().unwrap();
    let store = BlobStore::open(&dir.path().join("store")).unwrap();
    let mut pending = store
        .begin(
            metadata.key.clone(),
            metadata.reserved,
            IoGuard::new(
                Instant::now() + WallDuration::from_secs(10),
                Arc::new(AtomicBool::new(false)),
            ),
        )
        .unwrap();
    pending.write_chunk(bytes).unwrap();
    pending.finalize().unwrap()
}
fn staged() -> (Metadata, Quota) {
    let (metadata, quota) = reserve(100);
    let evidence = durable(&metadata, b"abc");
    let transition = metadata
        .stage(metadata.generation, evidence, now(), &binding())
        .unwrap();
    (
        transition.next,
        quota
            .apply(transition.quota, BlobLimits::default())
            .unwrap(),
    )
}
fn association() -> Association {
    Association {
        resource: 10,
        id: 20,
        incarnation: "record_incarnation".into(),
        field: "attachment".into(),
    }
}

#[test]
fn reservation_counts_full_file_ceiling_before_stream() {
    let (metadata, quota) = reserve(MAX_UPLOAD_BYTES);
    assert_eq!(metadata.state, State::Uploading);
    assert_eq!(
        metadata.expires.unix_millis(),
        now().unix_millis() + STAGE_LIFETIME_MILLIS
    );
    assert_eq!(
        quota,
        Quota {
            reserved: MAX_UPLOAD_BYTES,
            used: 0,
            objects: 1
        }
    );
    assert_eq!(metadata.generation.value(), 1);
    assert!(
        metadata
            .claim(metadata.generation, metadata.expires)
            .is_err()
    );
}

#[test]
fn reservation_rejects_app_and_subject_overbooking() {
    let (original, _) = reserve(1);
    let make = |subject, quota| {
        Metadata::reserve(
            original.blob.clone(),
            original.handle.clone(),
            original.key.clone(),
            binding(),
            now(),
            1,
            BlobLimits::default(),
            subject,
            quota,
        )
    };
    assert!(
        make(
            subject(),
            Quota {
                reserved: 0,
                used: BlobLimits::default().app_bytes,
                objects: 0
            }
        )
        .is_err()
    );
    assert!(
        make(
            SubjectUsage {
                live_stages: 4,
                ..subject()
            },
            Quota {
                reserved: 0,
                used: 0,
                objects: 0
            }
        )
        .is_err()
    );
    assert!(
        make(
            SubjectUsage {
                held_bytes: 40 * 1024 * 1024,
                ..subject()
            },
            Quota {
                reserved: 0,
                used: 0,
                objects: 0
            }
        )
        .is_err()
    );
    assert!(
        make(
            SubjectUsage {
                stage_limit: 5,
                ..subject()
            },
            Quota {
                reserved: 0,
                used: 0,
                objects: 0
            }
        )
        .is_err()
    );
    assert!(
        make(
            SubjectUsage {
                live_stages: 1,
                stage_limit: 1,
                ..subject()
            },
            Quota {
                reserved: 0,
                used: 0,
                objects: 0
            }
        )
        .is_err()
    );
    let (full, quota) = Metadata::reserve(
        original.blob,
        original.handle,
        original.key,
        binding(),
        now(),
        1,
        BlobLimits::default(),
        subject(),
        Quota {
            reserved: 0,
            used: BlobLimits::default().app_bytes - 1,
            objects: 0,
        },
    )
    .unwrap();
    assert_eq!(full.reserved, 1);
    assert_eq!(quota.used + quota.reserved, BlobLimits::default().app_bytes);
}

#[test]
fn durable_publication_converts_reservation_once() {
    let (staged, quota) = staged();
    assert_eq!(staged.state, State::Staged);
    assert_eq!(staged.generation.value(), 2);
    assert_eq!(staged.bytes, 3);
    assert_eq!(
        quota,
        Quota {
            reserved: 0,
            used: 3,
            objects: 1
        }
    );
    let (other, _) = reserve(3);
    assert!(
        staged
            .stage(
                staged.generation,
                durable(&other, b"abc"),
                now(),
                &binding()
            )
            .is_err()
    );
    let attached = staged
        .attach(
            staged.generation,
            now(),
            &binding(),
            &staged.handle,
            association(),
        )
        .unwrap();
    assert_eq!(
        quota.apply(attached.quota, BlobLimits::default()).unwrap(),
        quota
    );
    assert_eq!(attached.next.state, State::Attached);
    assert!(
        attached
            .next
            .attach(
                attached.next.generation,
                now(),
                &binding(),
                &staged.handle,
                association()
            )
            .is_err()
    );
}

#[test]
fn rollback_preserves_staged_handle_for_one_later_association() {
    let (staged, _) = staged();
    let first = staged
        .attach(
            staged.generation,
            now(),
            &binding(),
            &staged.handle,
            association(),
        )
        .unwrap();
    assert_eq!(first.expected, staged.generation);
    drop(first); // no SQL commit: original row remains untouched
    assert_eq!(staged.state, State::Staged);
    let second = staged
        .attach(
            staged.generation,
            now(),
            &binding(),
            &staged.handle,
            association(),
        )
        .unwrap();
    assert_eq!(second.next.generation.value(), 3);
    assert_eq!(second.next.association, Some(association()));
}

#[test]
fn foreign_slot_session_principal_and_input_commitments_fail() {
    let (staged, _) = staged();
    for foreign in [
        UploadBinding {
            slot: commitment('1'),
            ..binding()
        },
        UploadBinding {
            subject: commitment('1'),
            ..binding()
        },
        UploadBinding {
            context: commitment('1'),
            ..binding()
        },
        UploadBinding {
            input: commitment('1'),
            ..binding()
        },
    ] {
        assert!(
            staged
                .attach(
                    staged.generation,
                    now(),
                    &foreign,
                    &staged.handle,
                    association()
                )
                .is_err()
        );
    }
    let alternative = UploadHandle::parse(format!("u1_{}", "1".repeat(64))).unwrap();
    assert!(
        staged
            .attach(
                staged.generation,
                now(),
                &binding(),
                &alternative,
                association()
            )
            .is_err()
    );
}

#[test]
fn exact_expiry_rejects_new_attach_but_allows_gc() {
    let (staged, _) = staged();
    let before = staged
        .expires
        .checked_sub(Duration::from_millis(1).unwrap())
        .unwrap();
    staged
        .attach(
            staged.generation,
            before,
            &binding(),
            &staged.handle,
            association(),
        )
        .unwrap();
    assert!(
        staged
            .attach(
                staged.generation,
                staged.expires,
                &binding(),
                &staged.handle,
                association()
            )
            .is_err()
    );
    assert!(staged.claim(staged.generation, before).is_err());
    assert_eq!(
        staged
            .claim(staged.generation, staged.expires)
            .unwrap()
            .0
            .next
            .state,
        State::Deleting
    );
}

#[test]
fn object_identity_and_ceiling_must_match_reserved_slot() {
    let (upload, _) = reserve(10);
    let (other, _) = reserve(10);
    assert!(
        upload
            .stage(
                upload.generation,
                durable(&other, b"abc"),
                now(),
                &binding()
            )
            .is_err()
    );
    let mut larger = upload.clone();
    larger.reserved = 11;
    assert!(
        upload
            .stage(
                upload.generation,
                durable(&larger, b"abcdefghijk"),
                now(),
                &binding()
            )
            .is_err()
    );
    assert!(
        upload
            .stage(
                upload.generation,
                durable(&upload, b"abc"),
                upload.expires,
                &binding()
            )
            .is_err()
    );
}

#[test]
fn attachment_unlink_and_fenced_gc_do_not_release_bytes_early() {
    let (staged, quota) = staged();
    let attached = staged
        .attach(
            staged.generation,
            now(),
            &binding(),
            &staged.handle,
            association(),
        )
        .unwrap()
        .next;
    assert!(
        attached
            .claim(attached.generation, attached.expires)
            .is_err()
    );
    let wrong = Association {
        id: 21,
        ..association()
    };
    assert!(attached.unreference(attached.generation, &wrong).is_err());
    let unref = attached
        .unreference(attached.generation, &association())
        .unwrap();
    assert_eq!(
        quota.apply(unref.quota, BlobLimits::default()).unwrap(),
        quota
    );
    let (claiming, claim) = unref.next.claim(unref.next.generation, now()).unwrap();
    assert_eq!(
        quota.apply(claiming.quota, BlobLimits::default()).unwrap(),
        quota
    );
    assert_eq!(claim.key(), &staged.key);
    assert_eq!(claim.generation(), claiming.next.generation);
    assert!(
        claiming
            .next
            .attach(
                claiming.next.generation,
                now(),
                &binding(),
                &staged.handle,
                association()
            )
            .is_err()
    );
    assert!(
        claiming
            .next
            .deleted(&GcClaim {
                key: ObjectKey::random().unwrap(),
                generation: claim.generation
            })
            .is_err()
    );
    assert!(
        claiming
            .next
            .deleted(&GcClaim {
                key: claim.key.clone(),
                generation: Generation::parse(claim.generation.value() + 1).unwrap()
            })
            .is_err()
    );
    let deleted = claiming.next.deleted(&claim).unwrap();
    assert_eq!(
        quota.apply(deleted.quota, BlobLimits::default()).unwrap(),
        Quota {
            reserved: 0,
            used: 0,
            objects: 0
        }
    );
    assert_eq!(deleted.next.state, State::Deleted);
    assert!(deleted.next.deleted(&claim).is_err());
}

#[test]
fn generation_and_counter_arithmetic_fail_closed() {
    assert!(Generation::parse(0).is_err());
    assert!(Generation::parse(i64::MAX).unwrap().next().is_err());
    assert!(
        Quota {
            reserved: 0,
            used: 0,
            objects: 0
        }
        .apply(
            QuotaDelta {
                reserved: -1,
                used: 0,
                objects: 0
            },
            BlobLimits::default()
        )
        .is_err()
    );
    assert!(
        Quota {
            reserved: u64::MAX,
            used: 0,
            objects: 0
        }
        .apply(
            QuotaDelta {
                reserved: 1,
                used: 0,
                objects: 0
            },
            BlobLimits::default()
        )
        .is_err()
    );
    let (staged, _) = staged();
    assert!(
        staged
            .attach(
                Generation::parse(1).unwrap(),
                now(),
                &binding(),
                &staged.handle,
                association()
            )
            .is_err()
    );
    assert!(
        Metadata::reserve(
            staged.blob,
            staged.handle,
            staged.key,
            binding(),
            Timestamp::from_unix_millis(i64::MAX).unwrap(),
            1,
            BlobLimits::default(),
            subject(),
            Quota {
                reserved: 0,
                used: 0,
                objects: 0
            }
        )
        .is_err()
    );
}

#[test]
fn object_quota_counts_empty_files_and_cleanup_survives_lower_limits() {
    let (upload, quota) = reserve(100);
    let stage = upload
        .stage(upload.generation, durable(&upload, b""), now(), &binding())
        .unwrap();
    let quota = quota.apply(stage.quota, BlobLimits::default()).unwrap();
    assert_eq!(
        quota,
        Quota {
            reserved: 0,
            used: 0,
            objects: 1
        }
    );
    let original = stage.next;
    assert!(
        Metadata::reserve(
            original.blob,
            original.handle,
            original.key,
            binding(),
            now(),
            1,
            BlobLimits {
                objects: 1,
                ..BlobLimits::default()
            },
            subject(),
            quota
        )
        .is_err()
    );
    let lower = BlobLimits {
        file_bytes: 1,
        app_bytes: 1,
        objects: 1,
        ..BlobLimits::default()
    };
    let over = Quota {
        reserved: 0,
        used: 100,
        objects: 100,
    };
    assert_eq!(
        over.apply(
            QuotaDelta {
                reserved: 0,
                used: -10,
                objects: -1
            },
            lower
        )
        .unwrap(),
        Quota {
            reserved: 0,
            used: 90,
            objects: 99
        }
    );
    assert!(
        over.apply(
            QuotaDelta {
                reserved: 1,
                used: 0,
                objects: 1
            },
            lower
        )
        .is_err()
    );
}

#[test]
fn association_paths_and_invalid_identifiers_are_rejected() {
    let (staged, _) = staged();
    for bad in [
        Association {
            resource: 0,
            ..association()
        },
        Association {
            id: 0,
            ..association()
        },
        Association {
            field: "../attachment".into(),
            ..association()
        },
        Association {
            incarnation: "bad\nidentity".into(),
            ..association()
        },
    ] {
        assert!(
            staged
                .attach(staged.generation, now(), &binding(), &staged.handle, bad)
                .is_err()
        );
    }
    assert_eq!(commitment('a').as_str().len(), 64);
    assert!(Commitment::parse("A".repeat(64)).is_err());
}

#[test]
fn corrupt_metadata_cannot_wrap_signed_quota_arithmetic() {
    let (mut upload, _) = reserve(10);
    let evidence = durable(&upload, b"abc");
    upload.reserved = u64::MAX;
    assert!(
        upload
            .stage(upload.generation, evidence, now(), &binding())
            .is_err()
    );
    upload.state = State::Deleting;
    let claim = GcClaim {
        key: upload.key.clone(),
        generation: upload.generation,
    };
    assert!(upload.deleted(&claim).is_err());
    assert!(
        Quota {
            reserved: 0,
            used: i64::MAX as u64 + 1,
            objects: 0
        }
        .apply(
            QuotaDelta {
                reserved: 0,
                used: 0,
                objects: 0
            },
            BlobLimits::default()
        )
        .is_err()
    );
}

#[test]
fn canonical_handle_binds_first_finalized_slot_object_and_content() {
    let (upload, _) = reserve(100);
    let original = upload
        .stage(
            upload.generation,
            durable(&upload, b"first"),
            now(),
            &binding(),
        )
        .unwrap()
        .next;
    assert_ne!(original.handle, upload.handle);
    let identical = upload
        .stage(
            upload.generation,
            durable(&upload, b"first"),
            now(),
            &binding(),
        )
        .unwrap()
        .next;
    assert_eq!(identical.handle, original.handle);
    let different = upload
        .stage(
            upload.generation,
            durable(&upload, b"other"),
            now(),
            &binding(),
        )
        .unwrap()
        .next;
    assert_ne!(different.handle, original.handle);
    let mut other_slot = upload.clone();
    other_slot.binding.slot = commitment('1');
    assert_ne!(
        other_slot
            .stage(
                other_slot.generation,
                durable(&other_slot, b"first"),
                now(),
                &other_slot.binding
            )
            .unwrap()
            .next
            .handle,
        original.handle
    );
    let (other_object, _) = reserve(100);
    assert_ne!(
        other_object
            .stage(
                other_object.generation,
                durable(&other_object, b"first"),
                now(),
                &binding()
            )
            .unwrap()
            .next
            .handle,
        original.handle
    );
}
