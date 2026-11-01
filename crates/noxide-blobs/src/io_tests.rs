use super::*;
use crate::state::{Commitment, Metadata, Quota, SubjectUsage, UploadBinding};
use noxide_protocol::{
    blobs::{BlobLimits, BlobRef, UploadHandle},
    time::Timestamp,
};
use std::time::Duration;

fn key() -> ObjectKey {
    ObjectKey::random().unwrap()
}
fn generation() -> Generation {
    Generation::parse(1).unwrap()
}
fn flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
async fn stopped(witness: &IoWitness) -> StoppedIo {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(proof) = witness.stopped() {
                break proof;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}
fn new_metadata(object_key: ObjectKey) -> Metadata {
    let commitment = || Commitment::parse("a".repeat(64)).unwrap();
    Metadata::reserve(
        BlobRef::parse(format!("b1_{}", "b".repeat(64))).unwrap(),
        UploadHandle::parse(format!("u1_{}", "c".repeat(64))).unwrap(),
        object_key,
        UploadBinding {
            slot: commitment(),
            subject: commitment(),
            context: commitment(),
            input: commitment(),
        },
        Timestamp::UNIX_EPOCH,
        100,
        BlobLimits::default(),
        SubjectUsage {
            live_stages: 0,
            held_bytes: 0,
            stage_limit: 4,
            byte_limit: 40 * 1024 * 1024,
        },
        Quota {
            reserved: 0,
            used: 0,
            objects: 0,
        },
    )
    .unwrap()
    .0
}

#[test]
fn admission_limits_cannot_exceed_upload_download_ceilings() {
    assert!(IoPool::uploads(0).is_err());
    assert!(IoPool::uploads(5).is_err());
    assert!(IoPool::downloads(0).is_err());
    assert!(IoPool::downloads(9).is_err());
    IoPool::uploads(4).unwrap();
    IoPool::downloads(8).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_request_retains_native_worker_permit_until_exit() {
    let pool = IoPool::uploads(1).unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let cancelled = flag();
    let job = pool
        .try_start(
            key(),
            generation(),
            deadline(),
            cancelled.clone(),
            move |_| {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(())
            },
        )
        .unwrap();
    let witness = job.witness();
    started_rx.await.unwrap();
    assert!(witness.stopped().is_none());
    drop(job);
    assert!(cancelled.load(Ordering::Acquire));
    assert!(
        pool.try_start(key(), generation(), deadline(), flag(), |_| Ok(()))
            .is_err()
    );
    assert!(witness.stopped().is_none());
    release_tx.send(()).unwrap();
    assert!(stopped(&witness).await.failed_or_cancelled());
    // The stopped signal precedes dropping the permit by a few instructions;
    // bounded polling is only for this exact handoff, not queued admission.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if pool.permits.available_permits() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    pool.try_start(key(), generation(), deadline(), flag(), |_| Ok(()))
        .unwrap()
        .finish()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_returns_while_stuck_native_capacity_stays_quarantined() {
    let pool = IoPool::uploads(1).unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let job = pool
        .try_start(
            key(),
            generation(),
            Instant::now() + Duration::from_millis(100),
            flag(),
            move |_| {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(())
            },
        )
        .unwrap();
    let witness = job.witness();
    started_rx.await.unwrap();
    assert!(job.finish().await.is_err());
    assert!(witness.stopped().is_none());
    assert!(
        pool.try_start(key(), generation(), deadline(), flag(), |_| Ok(()))
            .is_err()
    );
    release_tx.send(()).unwrap();
    assert!(stopped(&witness).await.failed_or_cancelled());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panic_stops_worker_and_yields_failure_proof() {
    let pool = IoPool::uploads(1).unwrap();
    let job = pool
        .try_start::<()>(key(), generation(), deadline(), flag(), |_| {
            panic!("injected I/O worker panic")
        })
        .unwrap();
    let witness = job.witness();
    assert!(job.finish().await.is_err());
    assert!(stopped(&witness).await.failed_or_cancelled());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_upload_cleanup_needs_matching_stopped_generation() {
    let pool = IoPool::uploads(1).unwrap();
    let metadata = new_metadata(key());
    let job = pool
        .try_start::<()>(
            metadata.key.clone(),
            metadata.generation,
            deadline(),
            flag(),
            |_| anyhow::bail!("injected upload failure"),
        )
        .unwrap();
    let witness = job.witness();
    assert!(job.finish().await.is_err());
    let proof = stopped(&witness).await;
    let (claiming, claim) = metadata
        .claim_stopped_upload(metadata.generation, Timestamp::UNIX_EPOCH, &proof)
        .unwrap();
    assert_eq!(claiming.next.state, crate::state::State::Deleting);
    assert_eq!(
        Quota {
            reserved: 100,
            used: 0,
            objects: 1
        }
        .apply(claiming.quota, BlobLimits::default())
        .unwrap(),
        Quota {
            reserved: 100,
            used: 0,
            objects: 1
        }
    );
    let deleted = claiming.next.deleted(&claim).unwrap();
    assert_eq!(
        Quota {
            reserved: 100,
            used: 0,
            objects: 1
        }
        .apply(deleted.quota, BlobLimits::default())
        .unwrap(),
        Quota {
            reserved: 0,
            used: 0,
            objects: 0
        }
    );
    let foreign = new_metadata(key());
    assert!(
        foreign
            .claim_stopped_upload(foreign.generation, Timestamp::UNIX_EPOCH, &proof)
            .is_err()
    );
    let mut changed = metadata.clone();
    changed.generation = Generation::parse(2).unwrap();
    assert!(
        changed
            .claim_stopped_upload(changed.generation, Timestamp::UNIX_EPOCH, &proof)
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_unpublished_worker_waits_until_expiry_for_reconciliation() {
    let pool = IoPool::uploads(1).unwrap();
    let metadata = new_metadata(key());
    let job = pool
        .try_start(
            metadata.key.clone(),
            metadata.generation,
            deadline(),
            flag(),
            |_| Ok(()),
        )
        .unwrap();
    let witness = job.witness();
    job.finish().await.unwrap();
    let proof = stopped(&witness).await;
    assert!(!proof.failed_or_cancelled());
    assert!(
        metadata
            .claim_stopped_upload(metadata.generation, Timestamp::UNIX_EPOCH, &proof)
            .is_err()
    );
    metadata
        .claim_stopped_upload(metadata.generation, metadata.expires, &proof)
        .unwrap();
}
