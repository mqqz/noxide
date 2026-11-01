use super::*;
use std::{
    fs as stdfs,
    os::unix::fs::{PermissionsExt, symlink},
    time::Duration,
};

fn guard() -> IoGuard {
    IoGuard::new(
        Instant::now() + Duration::from_secs(5),
        Arc::new(AtomicBool::new(false)),
    )
}
fn store() -> (tempfile::TempDir, BlobStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = BlobStore::open(&dir.path().join("store")).unwrap();
    (dir, store)
}
fn pending(store: &BlobStore) -> PairRecord {
    PairRecord {
        store: store.identity().clone(),
        pair: PairId::random().unwrap(),
        phase: PairPhase::Pending,
        empty_metadata: true,
    }
}

#[test]
fn first_bind_requires_empty_unpaired_store_and_same_identity() {
    let (_dir, store) = store();
    let observed = store.observe_pair(&guard()).unwrap();
    assert_eq!(observed.decide(None).unwrap(), PairStep::CreatePending);
    let mut record = pending(&store);
    assert_eq!(
        observed.decide(Some(&record)).unwrap(),
        PairStep::InstallMarker(record.pair.clone())
    );
    record.store = ObjectKey::random().unwrap();
    assert!(observed.decide(Some(&record)).is_err());
}

#[test]
fn pairing_never_allows_new_database_to_adopt_previously_paired_empty_store() {
    let (_dir, store) = store();
    let mut record = pending(&store);
    let marker = store.install_pair(&record, &guard()).unwrap();
    assert_eq!(marker.store(), store.identity());
    assert_eq!(marker.pair(), &record.pair);
    let observed = store.observe_pair(&guard()).unwrap();
    assert_eq!(
        observed.decide(Some(&record)).unwrap(),
        PairStep::Acknowledge(record.pair.clone())
    );
    assert!(observed.decide(None).is_err());
    record.phase = PairPhase::Paired;
    assert_eq!(
        observed.decide(Some(&record)).unwrap(),
        PairStep::Ready(record.pair.clone())
    );
    let mut other = record.clone();
    other.pair = PairId::random().unwrap();
    assert!(observed.decide(Some(&other)).is_err());
}

#[test]
fn unknown_files_remain_untouched_and_pending_snapshot_cannot_adopt_populated_store() {
    let (dir, store) = store();
    let key = ObjectKey::random().unwrap();
    let mut partial = store.begin(key.clone(), 10, guard()).unwrap();
    partial.write_chunk(b"data").unwrap();
    drop(partial);
    assert!(store.observe_pair(&guard()).unwrap().decide(None).is_err());
    assert!(
        store
            .observe_pair(&guard())
            .unwrap()
            .decide(Some(&pending(&store)))
            .is_err()
    );
    assert!(dir.path().join("store/partial").join(key.as_str()).exists());
    let (_dir, paired) = super::tests::store();
    let mut record = pending(&paired);
    paired.install_pair(&record, &guard()).unwrap();
    record.phase = PairPhase::Paired;
    let object = paired
        .begin(ObjectKey::random().unwrap(), 1, guard())
        .unwrap()
        .finalize()
        .unwrap();
    assert_eq!(
        paired
            .observe_pair(&guard())
            .unwrap()
            .decide(Some(&record))
            .unwrap(),
        PairStep::Ready(record.pair.clone())
    );
    record.phase = PairPhase::Pending;
    assert!(
        paired
            .observe_pair(&guard())
            .unwrap()
            .decide(Some(&record))
            .is_err()
    );
    assert!(paired.open_object(object.key(), 0, guard()).is_ok());
}

#[test]
fn pending_pair_resumes_only_matching_private_partial_marker() {
    let (dir, store) = store();
    let record = pending(&store);
    let path = dir.path().join("store/pair.pending");
    stdfs::write(&path, &record.pair.as_str().as_bytes()[..17]).unwrap();
    stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o600)).unwrap();
    assert!(store.observe_pair(&guard()).unwrap().decide(None).is_err());
    store.install_pair(&record, &guard()).unwrap();
    assert!(!path.exists());
    assert_eq!(
        stdfs::read(dir.path().join("store/pair")).unwrap(),
        record.pair.as_str().as_bytes()
    );
    let (dir, store) = super::tests::store();
    let mut record = pending(&store);
    record.pair = PairId::parse("1".repeat(64)).unwrap();
    let path = dir.path().join("store/pair.pending");
    stdfs::write(&path, b"2222").unwrap();
    stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o600)).unwrap();
    assert!(store.install_pair(&record, &guard()).is_err());
    assert_eq!(stdfs::read(path).unwrap(), b"2222");
}

#[test]
fn paired_database_missing_marker_and_pending_nonempty_metadata_fail_closed() {
    let (_dir, store) = store();
    let mut record = pending(&store);
    record.phase = PairPhase::Paired;
    assert!(
        store
            .observe_pair(&guard())
            .unwrap()
            .decide(Some(&record))
            .is_err()
    );
    record.phase = PairPhase::Pending;
    record.empty_metadata = false;
    assert!(store.install_pair(&record, &guard()).is_err());
}

#[test]
fn marker_symlink_hardlink_mode_and_length_cannot_redirect_or_adopt() {
    for kind in 0..4 {
        let (dir, store) = store();
        let record = pending(&store);
        let outside = dir.path().join("outside");
        stdfs::write(&outside, "a".repeat(64)).unwrap();
        stdfs::set_permissions(&outside, stdfs::Permissions::from_mode(0o400)).unwrap();
        let path = dir.path().join("store/pair");
        match kind {
            0 => symlink(&outside, &path).unwrap(),
            1 => stdfs::hard_link(&outside, &path).unwrap(),
            2 => {
                stdfs::write(&path, "a".repeat(64)).unwrap();
                stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => {
                stdfs::write(&path, "a".repeat(65)).unwrap();
                stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o400)).unwrap();
            }
        }
        assert!(store.observe_pair(&guard()).is_err());
        assert!(store.install_pair(&record, &guard()).is_err());
        assert_eq!(stdfs::read(outside).unwrap(), "a".repeat(64).as_bytes());
    }
}

#[test]
fn cancellation_after_each_native_boundary_returns_no_pair_durability_evidence() {
    for fault in [
        PairPoint::FileSynced,
        PairPoint::Renamed,
        PairPoint::DirectorySynced,
    ] {
        let (_dir, store) = store();
        let record = pending(&store);
        let cancelled = Arc::new(AtomicBool::new(false));
        let limit = IoGuard::new(Instant::now() + Duration::from_secs(5), cancelled.clone());
        let result = store.install_pair_observed(&record, &limit, |point| {
            if point == fault {
                cancelled.store(true, Ordering::Release);
            }
            Ok(())
        });
        assert!(result.is_err());
        // Authoritative DB still PENDING; same ID can resume after old native
        // work actually stopped. A new/missing database is never substituted.
        let observation = store.observe_pair(&guard()).unwrap();
        assert!(observation.decide(None).is_err());
        store.install_pair(&record, &guard()).unwrap();
        assert_eq!(
            store
                .observe_pair(&guard())
                .unwrap()
                .decide(Some(&record))
                .unwrap(),
            PairStep::Acknowledge(record.pair.clone())
        );
    }
}

#[test]
fn pairing_observation_retains_exclusive_lease_and_ids_are_canonical_redacted() {
    let (dir, store) = store();
    let observed = store.observe_pair(&guard()).unwrap();
    drop(store);
    assert!(BlobStore::open(&dir.path().join("store")).is_err());
    drop(observed);
    let reopened = BlobStore::open(&dir.path().join("store")).unwrap();
    let id = PairId::random().unwrap();
    assert_eq!(format!("{id:?}"), "PairId([redacted])");
    assert!(PairId::parse("A".repeat(64)).is_err());
    assert_eq!(
        reopened
            .observe_pair(&guard())
            .unwrap()
            .decide(None)
            .unwrap(),
        PairStep::CreatePending
    );
}
