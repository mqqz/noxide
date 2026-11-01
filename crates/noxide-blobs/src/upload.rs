//! One verified upload authority bound to a request. Repository execution holds
//! it to consume staged objects; the application layer creates it at admission.
use crate::{
    database::Transaction, io::IoPool, metadata::MetadataContext, state::UploadBinding,
    store::BlobStore,
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::time::Timestamp;
use std::sync::{Arc, atomic::AtomicBool};

#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
pub struct Barrier {
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}
#[cfg(any(test, feature = "test-support"))]
impl Barrier {
    pub async fn wait(&self) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

/// Sealed at verified web admission. It contains no guest-selected identity.
#[derive(Clone)]
pub struct UploadScope {
    pub store: BlobStore,
    pub binding: UploadBinding,
    verify: Arc<IoPool>,
    #[cfg(any(test, feature = "test-support"))]
    barrier: Option<Arc<Barrier>>,
}
#[derive(Clone)]
pub struct UploadContext {
    scope: UploadScope,
    pub now: Timestamp,
}
impl std::ops::Deref for UploadContext {
    type Target = UploadScope;
    fn deref(&self) -> &UploadScope {
        &self.scope
    }
}
impl UploadScope {
    pub fn new(store: BlobStore, verify: Arc<IoPool>, binding: UploadBinding) -> Self {
        Self {
            store,
            binding,
            verify,
            #[cfg(any(test, feature = "test-support"))]
            barrier: None,
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_barrier(mut self, barrier: Option<Arc<Barrier>>) -> Self {
        self.barrier = barrier;
        self
    }
    pub fn at(self, time: crate::lifecycle_clock::AttemptTime) -> UploadContext {
        UploadContext {
            scope: self,
            now: time.timestamp(),
        }
    }
}
impl UploadContext {
    pub async fn verify(&self, row: &crate::metadata::BlobRow) -> Result<()> {
        let deadline = crate::database::lifecycle::RequestScope::current_work_deadline()
            .context("upload outside request")?;
        let store = self.store.clone();
        let key = row.metadata.key.clone();
        let bytes = row.metadata.bytes;
        let digest = row.metadata.digest.context("upload digest missing")?;
        self.verify
            .try_start(
                key.clone(),
                row.metadata.generation,
                deadline.into_std(),
                Arc::new(AtomicBool::new(false)),
                move |guard| {
                    let mut opened = store.open_object(&key, bytes, guard)?;
                    opened.verify_digest(digest)
                },
            )?
            .finish()
            .await?;
        #[cfg(any(test, feature = "test-support"))]
        if let Some(barrier) = &self.barrier {
            barrier.wait().await;
        }
        Ok(())
    }
    pub async fn absent(&self, tx: &mut Transaction) -> Result<()> {
        ensure!(
            MetadataContext { tx }
                .slot(&self.binding.slot)
                .await?
                .is_none(),
            crate::action_contract::ReferenceUnavailable
        );
        #[cfg(any(test, feature = "test-support"))]
        if let Some(barrier) = &self.barrier {
            barrier.wait().await;
        }
        Ok(())
    }
}
