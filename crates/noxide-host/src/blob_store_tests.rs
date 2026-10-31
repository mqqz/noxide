use super::*;
use std::{
    fs as stdfs,
    os::unix::fs::{PermissionsExt, symlink},
    time::Duration,
};
use tempfile::TempDir;

fn guard() -> IoGuard {
    IoGuard::new(
        Instant::now() + Duration::from_secs(10),
        Arc::new(AtomicBool::new(false)),
    )
}
fn store() -> (TempDir, BlobStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = BlobStore::open(&dir.path().join("store")).unwrap();
    (dir, store)
}
fn object(store: &BlobStore, bytes: &[u8]) -> DurableObject {
    let mut pending = store
        .begin(ObjectKey::random().unwrap(), MAX_UPLOAD_BYTES, guard())
        .unwrap();
    for chunk in bytes.chunks(TRANSFER_BUFFER_BYTES) {
        pending.write_chunk(chunk).unwrap();
    }
    pending.finalize().unwrap()
}
fn read(store: &BlobStore, object: &DurableObject) -> Vec<u8> {
    let mut opened = store
        .open_object(&object.key, object.bytes, guard())
        .unwrap();
    let mut out = Vec::new();
    let mut buffer = [0; TRANSFER_BUFFER_BYTES];
    loop {
        let n = opened.read_chunk(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buffer[..n]);
    }
    out
}

#[test]
fn durable_roundtrip_maximum_and_empty_objects() {
    let (dir, store) = store();
    let bytes = vec![0x5a; MAX_UPLOAD_BYTES as usize];
    let durable = object(&store, &bytes);
    assert_eq!(durable.bytes, MAX_UPLOAD_BYTES);
    assert_eq!(durable.sha256, <[u8; 32]>::from(Sha256::digest(&bytes)));
    assert_eq!(read(&store, &durable), bytes);
    let empty = object(&store, b"");
    assert_eq!(read(&store, &empty), b"");
    assert_eq!(
        stdfs::metadata(dir.path().join("store/objects").join(durable.key.as_str()))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o400
    );
    assert!(
        !dir.path()
            .join("store/partial")
            .join(durable.key.as_str())
            .exists()
    );
}

#[test]
fn quotas_and_buffer_limits_are_checked_before_writes() {
    let (dir, store) = store();
    assert!(
        store
            .begin(ObjectKey::random().unwrap(), 0, guard())
            .is_err()
    );
    assert!(
        store
            .begin(ObjectKey::random().unwrap(), MAX_UPLOAD_BYTES + 1, guard())
            .is_err()
    );
    let key = ObjectKey::random().unwrap();
    let mut pending = store.begin(key.clone(), 3, guard()).unwrap();
    assert!(pending.write_chunk(b"four").is_err());
    assert!(
        pending
            .write_chunk(&vec![0; TRANSFER_BUFFER_BYTES + 1])
            .is_err()
    );
    assert_eq!(
        stdfs::metadata(dir.path().join("store/partial").join(key.as_str()))
            .unwrap()
            .len(),
        0
    );
    pending.write_chunk(b"abc").unwrap();
    assert!(pending.write_chunk(b"d").is_err());
    assert_eq!(read(&store, &pending.finalize().unwrap()), b"abc");
}

#[test]
fn no_overwrite_at_creation_or_rename() {
    let (_dir, store) = store();
    let first = object(&store, b"first");
    let mut second = store.begin(first.key.clone(), 20, guard()).unwrap();
    assert!(store.begin(first.key.clone(), 20, guard()).is_err());
    second.write_chunk(b"second").unwrap();
    assert!(second.finalize().is_err());
    assert_eq!(read(&store, &first), b"first");
}

#[test]
fn symlinks_in_root_ancestors_and_store_directories_are_denied() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    stdfs::create_dir(&real).unwrap();
    symlink(&real, dir.path().join("alias")).unwrap();
    assert!(BlobStore::open(&dir.path().join("alias/store")).is_err());
    symlink(&real, dir.path().join("root_alias")).unwrap();
    assert!(BlobStore::open(&dir.path().join("root_alias")).is_err());
    let root = dir.path().join("private");
    stdfs::create_dir(&root).unwrap();
    stdfs::set_permissions(&root, stdfs::Permissions::from_mode(0o700)).unwrap();
    symlink(&real, root.join("partial")).unwrap();
    assert!(BlobStore::open(&root).is_err());
}

#[test]
fn public_permissions_linked_files_and_missing_objects_fail_closed() {
    let (dir, store) = store();
    assert!(
        store
            .open_object(&ObjectKey::random().unwrap(), 0, guard())
            .is_err()
    );
    let durable = object(&store, b"abc");
    assert!(store.open_object(&durable.key, 2, guard()).is_err());
    let path = dir.path().join("store/objects").join(durable.key.as_str());
    stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o600)).unwrap();
    assert!(store.open_object(&durable.key, 3, guard()).is_err());
    stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o400)).unwrap();
    stdfs::hard_link(&path, dir.path().join("hardlink")).unwrap();
    assert!(store.open_object(&durable.key, 3, guard()).is_err());
    stdfs::remove_file(&path).unwrap();
    symlink(dir.path().join("hardlink"), &path).unwrap();
    assert!(store.open_object(&durable.key, 3, guard()).is_err());
    let another = dir.path().join("public");
    stdfs::create_dir(&another).unwrap();
    stdfs::set_permissions(&another, stdfs::Permissions::from_mode(0o755)).unwrap();
    assert!(BlobStore::open(&another).is_err());
}

#[test]
fn fifo_never_blocks_open_and_special_file_is_denied() {
    let (dir, store) = store();
    let key = ObjectKey::random().unwrap();
    fs::mkfifoat(&store.0.objects, key.as_str(), Mode::RUSR).unwrap();
    let before = Instant::now();
    assert!(store.open_object(&key, 0, guard()).is_err());
    assert!(before.elapsed() < Duration::from_secs(1));
    assert!(dir.path().join("store/objects").join(key.as_str()).exists());
}

#[test]
fn exclusive_store_lease_lasts_as_long_as_descriptors() {
    let (dir, store) = store();
    let identity = store.identity().clone();
    assert!(BlobStore::open(&dir.path().join("store")).is_err());
    let durable = object(&store, b"abc");
    let opened = store.open_object(&durable.key, 3, guard()).unwrap();
    drop(store);
    assert!(BlobStore::open(&dir.path().join("store")).is_err());
    drop(opened);
    let reopened = BlobStore::open(&dir.path().join("store")).unwrap();
    assert_eq!(reopened.identity(), &identity);
    assert_eq!(read(&reopened, &durable), b"abc");
}

#[test]
fn cancellation_and_deadlines_leave_no_claimable_result() {
    let (dir, store) = store();
    let cancelled = Arc::new(AtomicBool::new(true));
    assert!(
        store
            .begin(
                ObjectKey::random().unwrap(),
                4,
                IoGuard::new(Instant::now() + Duration::from_secs(1), cancelled.clone())
            )
            .is_err()
    );
    assert!(
        store
            .begin(
                ObjectKey::random().unwrap(),
                4,
                IoGuard::new(Instant::now(), Arc::new(AtomicBool::new(false)))
            )
            .is_err()
    );
    cancelled.store(false, Ordering::Release);
    let key = ObjectKey::random().unwrap();
    let mut pending = store
        .begin(
            key.clone(),
            4,
            IoGuard::new(Instant::now() + Duration::from_secs(1), cancelled.clone()),
        )
        .unwrap();
    pending.write_chunk(b"abc").unwrap();
    cancelled.store(true, Ordering::Release);
    assert!(pending.finalize().is_err());
    assert!(dir.path().join("store/partial").join(key.as_str()).exists());
    assert!(store.open_object(&key, 3, guard()).is_err());
    store.remove(&key, &guard()).unwrap();
    store.remove(&key, &guard()).unwrap();
}

#[test]
fn failures_between_durability_steps_never_return_staged_evidence() {
    for fault in [
        FinalizePoint::DataSynced,
        FinalizePoint::Renamed,
        FinalizePoint::DestinationSynced,
        FinalizePoint::SourceSynced,
    ] {
        let (dir, store) = store();
        let key = ObjectKey::random().unwrap();
        let mut pending = store.begin(key.clone(), 10, guard()).unwrap();
        pending.write_chunk(b"data").unwrap();
        let mut seen = Vec::new();
        let result = pending.finalize_observed(|point| {
            seen.push(point);
            ensure!(point != fault, "injected finalization failure");
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(seen.last(), Some(&fault));
        let partial = dir.path().join("store/partial").join(key.as_str());
        let final_path = dir.path().join("store/objects").join(key.as_str());
        assert_eq!(partial.exists(), fault == FinalizePoint::DataSynced);
        assert_eq!(final_path.exists(), fault != FinalizePoint::DataSynced);
        // Reconciliation can remove either state idempotently; metadata was
        // never given a DurableObject to publish as Staged.
        store.remove(&key, &guard()).unwrap();
        assert!(!partial.exists() && !final_path.exists());
    }
}

#[test]
fn already_open_descriptor_survives_gc_but_new_stream_fails() {
    let (_dir, store) = store();
    let durable = object(&store, b"abc");
    let mut opened = store.open_object(&durable.key, 3, guard()).unwrap();
    store.remove(&durable.key, &guard()).unwrap();
    assert!(store.open_object(&durable.key, 3, guard()).is_err());
    let mut buffer = [0; 3];
    assert_eq!(opened.read_chunk(&mut buffer).unwrap(), 3);
    assert_eq!(&buffer, b"abc");
    assert_eq!(opened.read_chunk(&mut buffer).unwrap(), 0);
}

#[test]
fn scan_is_bounded_resumable_and_does_not_follow_entries() {
    let (dir, store) = store();
    let mut expected = std::collections::BTreeSet::new();
    for _ in 0..130 {
        expected.insert(object(&store, b"").key);
    }
    let mut scan = store.scan(ObjectLocation::Final).unwrap();
    let mut found = std::collections::BTreeSet::new();
    loop {
        let batch = scan.next_batch(&guard()).unwrap();
        assert!(batch.len() <= SCAN_BATCH);
        if batch.is_empty() {
            break;
        }
        for (location, key) in batch {
            assert_eq!(location, ObjectLocation::Final);
            assert!(found.insert(key));
        }
    }
    assert_eq!(found, expected);
    let mut partial = store.scan(ObjectLocation::Partial).unwrap();
    assert!(partial.next_batch(&guard()).unwrap().is_empty());
    symlink(
        dir.path(),
        dir.path()
            .join("store/objects")
            .join(ObjectKey::random().unwrap().as_str()),
    )
    .unwrap();
    let mut invalid = store.scan(ObjectLocation::Final).unwrap();
    let mut failed = false;
    for _ in 0..4 {
        if invalid.next_batch(&guard()).is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed);
}

#[test]
fn malformed_keys_never_become_paths() {
    for bad in [
        "../x".into(),
        "x".repeat(64),
        "A".repeat(64),
        "a".repeat(63),
        "a".repeat(65),
        format!("{}\0", "a".repeat(63)),
    ] {
        assert!(ObjectKey::parse(bad).is_err());
    }
}
