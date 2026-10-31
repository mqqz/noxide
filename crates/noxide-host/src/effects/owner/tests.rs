use super::*;
use crate::effects::transport::TorProxy;
use std::{future::Future, task::Poll, time::Duration};
fn directory() -> std::path::PathBuf {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/capability-evidence/p11-owner-fixtures");
    std::fs::create_dir_all(&root).unwrap();
    let path = tempfile::Builder::new()
        .prefix("owner-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    std::fs::canonicalize(path).unwrap()
}
fn owner(path: &Path, store: &str) -> Arc<DeliveryOwner> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let directory = Arc::new(OwnerDirectory::open(path, deadline).unwrap());
    let lease = Arc::new(OwnerLease::open(directory, store, deadline).unwrap());
    DeliveryOwner::claim(
        lease,
        2,
        Transport::new(TorProxy::loopback("127.0.0.1:9050".parse().unwrap()).unwrap()),
    )
    .unwrap()
}
#[tokio::test]
async fn actual_flock_refuses_an_independent_supervisor_until_owner_drops() {
    let path = directory();
    let first = owner(&path, "stable-store");
    let deadline = Instant::now() + Duration::from_secs(5);
    let directory = Arc::new(OwnerDirectory::open(&path, deadline).unwrap());
    let second = Arc::new(OwnerLease::open(directory, "stable-store", deadline).unwrap());
    assert!(
        DeliveryOwner::claim(
            second.clone(),
            2,
            Transport::new(TorProxy::loopback("127.0.0.1:9050".parse().unwrap()).unwrap())
        )
        .is_err()
    );
    first.drain().await.unwrap();
    drop(first);
    assert!(
        DeliveryOwner::claim(
            second,
            2,
            Transport::new(TorProxy::loopback("127.0.0.1:9050".parse().unwrap()).unwrap())
        )
        .is_ok()
    );
}
#[tokio::test]
async fn physical_slot_waits_for_acknowledged_native_holder_stop() {
    let path = directory();
    let owner = owner(&path, "native-hold");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let first = owner.try_attempt(deadline).unwrap();
    first.mark_claim("effect-one");
    let second = owner.try_attempt(deadline).unwrap();
    assert!(owner.try_attempt(deadline).is_err());
    let hold = first.native_hold();
    let (reached, receive) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let worker = tokio::task::spawn_blocking(move || {
        let _hold = hold;
        reached.send(()).unwrap();
        wait.recv().unwrap();
    });
    receive.await.unwrap();
    let mut stopping = Box::pin(first.finish());
    std::future::poll_fn(|cx| {
        assert!(stopping.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(owner.active_claims(), [String::from("effect-one")]);
    assert!(owner.try_attempt(deadline).is_err());
    let other_directory = Arc::new(OwnerDirectory::open(&path, deadline.into_std()).unwrap());
    let other_lease =
        Arc::new(OwnerLease::open(other_directory, "native-hold", deadline.into_std()).unwrap());
    assert!(
        DeliveryOwner::claim(
            other_lease,
            2,
            Transport::new(TorProxy::loopback("127.0.0.1:9050".parse().unwrap()).unwrap())
        )
        .is_err()
    );
    release.send(()).unwrap();
    worker.await.unwrap();
    stopping.await.unwrap();
    second.finish().await.unwrap();
    owner.drain().await.unwrap();
    assert!(owner.active_claims().is_empty());
}
#[tokio::test]
async fn secret_files_are_owned_private_regular_and_never_follow_symlinks() {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    };
    let path = directory();
    let owner = owner(&path, "secret-metadata");
    let secret = path.join("secret");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&secret)
        .unwrap();
    file.write_all(b"host-test-token").unwrap();
    drop(file);
    let link = path.join("link");
    symlink(&secret, &link).unwrap();
    for (candidate, valid) in [(&secret, true), (&link, false)] {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let physical = owner.try_attempt(deadline).unwrap();
        let result = read_secret(candidate, deadline.into_std(), physical.native_hold());
        assert_eq!(result.is_ok(), valid);
        physical.finish().await.unwrap();
    }
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let physical = owner.try_attempt(deadline).unwrap();
    assert!(read_secret(&secret, deadline.into_std(), physical.native_hold()).is_err());
    physical.finish().await.unwrap();
    owner.drain().await.unwrap();
}
