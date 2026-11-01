//! One verified upload authority bound to a request. Repository execution holds
//! it to consume staged objects; the application layer creates it at admission.
use crate::{
    blob_io::IoPool, blob_metadata::MetadataContext, blob_state::UploadBinding,
    blob_store::BlobStore, database::Transaction,
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::time::Timestamp;
use std::sync::{Arc, atomic::AtomicBool};

#[cfg(test)]
#[derive(Default)]
pub(crate) struct Barrier {
    pub(crate) entered: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
}
#[cfg(test)]
impl Barrier {
    pub(crate) async fn wait(&self) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

/// Sealed at verified web admission. It contains no guest-selected identity.
#[derive(Clone)]
pub(crate) struct UploadScope {
    pub(crate) store: BlobStore,
    pub(crate) binding: UploadBinding,
    verify: Arc<IoPool>,
    #[cfg(test)]
    barrier: Option<Arc<Barrier>>,
}
#[derive(Clone)]
pub(crate) struct UploadContext {
    scope: UploadScope,
    pub(crate) now: Timestamp,
}
impl std::ops::Deref for UploadContext {
    type Target = UploadScope;
    fn deref(&self) -> &UploadScope {
        &self.scope
    }
}
impl UploadScope {
    pub(crate) fn new(
        store: BlobStore,
        verify: Arc<IoPool>,
        #[cfg(test)] barrier: Option<Arc<Barrier>>,
        binding: UploadBinding,
    ) -> Self {
        Self {
            store,
            binding,
            verify,
            #[cfg(test)]
            barrier,
        }
    }
    pub(crate) fn at(self, time: crate::lifecycle_clock::AttemptTime) -> UploadContext {
        UploadContext {
            scope: self,
            now: time.timestamp(),
        }
    }
}
impl UploadContext {
    pub(crate) async fn verify(&self, row: &crate::blob_metadata::BlobRow) -> Result<()> {
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
        #[cfg(test)]
        if let Some(barrier) = &self.barrier {
            barrier.wait().await;
        }
        Ok(())
    }
    pub(crate) async fn absent(&self, tx: &mut Transaction) -> Result<()> {
        ensure!(
            MetadataContext { tx }
                .slot(&self.binding.slot)
                .await?
                .is_none(),
            crate::action_contract::ReferenceUnavailable
        );
        #[cfg(test)]
        if let Some(barrier) = &self.barrier {
            barrier.wait().await;
        }
        Ok(())
    }
}
