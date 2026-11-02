//! Operator effect commands and the serving application's queue binding.

use super::*;
use crate::{
    effect_deployment::EffectiveEffectDeployment,
    effects::{self, directory::DirectoryPreparation},
};
#[cfg(test)]
use noxide_effect_delivery::{EffectDelivery, EffectRunOutcome, EffectService};
#[cfg(test)]
use std::sync::Mutex;

/// What a serving application needs to bind the effect queue. Delivery itself
/// runs in [`EffectDelivery`], outside the serving process.
pub(crate) struct EffectRuntime {
    effective: EffectiveEffectDeployment,
    directory: Arc<DirectoryPreparation>,
    #[cfg(test)]
    test_roots: Mutex<Option<rustls::RootCertStore>>,
    #[cfg(test)]
    delivery: tokio::sync::OnceCell<Arc<EffectDelivery>>,
}
impl EffectRuntime {
    pub(crate) fn new(effective: EffectiveEffectDeployment) -> Self {
        Self {
            effective,
            directory: DirectoryPreparation::new(),
            #[cfg(test)]
            test_roots: Mutex::new(None),
            #[cfg(test)]
            delivery: tokio::sync::OnceCell::new(),
        }
    }
    pub(crate) fn effective(&self) -> &EffectiveEffectDeployment {
        &self.effective
    }
    pub(crate) fn owner_directory_digest(&self) -> Result<&str> {
        self.directory.digest()
    }
}
impl Application {
    /// Trusted local operator entry point; no HTTP/guest capability invokes it.
    pub async fn operate_effects(
        &self,
        command: effects::EffectOperatorCommand,
    ) -> std::result::Result<effects::EffectOperatorResult, RequestError> {
        let scope = self.request_scope(self.runtime.limits().wall_time);
        scope
            .run(async {
                let admission = self.admit_invocation(false).await?;
                admission
                    .owner
                    .run(async {
                        let mut tx = self
                            .database
                            .begin(admission.owner.work_deadline().into_std())
                            .await
                            .map_err(RequestError::database)?;
                        let time = self.temporal_attempt(&mut tx).await?.timestamp();
                        let generation = self.generation.get().ok_or(RequestError::Busy)?;
                        let output = effects::operator::run_command(
                            &mut tx,
                            effects::operator::OperatorContext {
                                generation,
                                contract: &self.contract,
                                manifest: &self.manifest,
                                effective: self.effects.as_ref().map(|runtime| &runtime.effective),
                                time,
                            },
                            command,
                        )
                        .await?;
                        Self::finish_commit(&mut tx, output).await
                    })
                    .await
            })
            .await
    }
    pub(super) async fn prepare_effect_delivery(&self, deadline: std::time::Instant) -> Result<()> {
        let Some(runtime) = &self.effects else {
            return Ok(());
        };
        DirectoryPreparation::prepare(&runtime.directory, &runtime.effective, deadline).await
    }
}
#[cfg(test)]
pub(super) mod tests;
