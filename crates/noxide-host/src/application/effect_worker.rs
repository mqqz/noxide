//! Operator effect commands and the serving application's queue binding.

use super::*;
use crate::effects::EffectOperatorTransaction as _;
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
        use effects::{EffectOperatorCommand as Command, EffectOperatorResult as Output};
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
                        let retry = matches!(&command, Command::Retry { .. });
                        let output = match command {
                            Command::Inspect { after } => Output::Effects(
                                tx.inspect_effects(generation, &after)
                                    .await
                                    .map_err(RequestError::database)?,
                            ),
                            Command::Cancel { id } => {
                                tx.cancel_effect(generation, &id)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::RevokeEndpoint { tenant, endpoint } => {
                                tx.revoke_effect_endpoint(generation, &tenant, &endpoint)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::RevokeSecret { slot } => {
                                tx.revoke_effect_secret(generation, &slot)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::GrantEndpoint { tenant, endpoint } => {
                                let runtime =
                                    self.effects.as_ref().ok_or(RequestError::Rejected)?;
                                let binding = runtime
                                    .effective
                                    .grants
                                    .iter()
                                    .find(|b| b.tenant == tenant && b.endpoint.name == endpoint)
                                    .ok_or(RequestError::Rejected)?;
                                tx.grant_effect_endpoint(generation, &self.contract, binding)
                                    .await
                                    .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::GrantSecret { slot } => {
                                let runtime =
                                    self.effects.as_ref().ok_or(RequestError::Rejected)?;
                                tx.grant_effect_secret(
                                    generation,
                                    &self.contract,
                                    &slot,
                                    &runtime.effective,
                                )
                                .await
                                .map_err(RequestError::database)?;
                                Output::Done
                            }
                            Command::Retry { id } | Command::Resume { id } => {
                                let runtime =
                                    self.effects.as_ref().ok_or(RequestError::Rejected)?;
                                let source = tx
                                    .effect_operator_source(generation, &id)
                                    .await
                                    .map_err(RequestError::database)?;
                                let action =
                                    manifest::action(&self.manifest, source.source_action().0)
                                        .map_err(RequestError::database)?;
                                tx.resume_effect(
                                    generation,
                                    &self.contract,
                                    &runtime.effective,
                                    &id,
                                    action.version,
                                    time,
                                    retry,
                                )
                                .await
                                .map_err(RequestError::database)?;
                                Output::Done
                            }
                        };
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
    #[cfg(test)]
    pub(crate) fn effect_test_parts(
        &self,
    ) -> (
        Arc<Manifest>,
        String,
        String,
        EffectiveEffectDeployment,
        u16,
        Option<rustls::RootCertStore>,
    ) {
        let runtime = self.effects.as_ref().expect("effect runtime");
        (
            self.manifest.clone(),
            self.deployment.clone(),
            self.contract.clone(),
            runtime.effective.clone(),
            self.database_statement_limit,
            runtime.test_roots.lock().unwrap().clone(),
        )
    }
    /// One delivery context per test application, standing in for the worker process.
    #[cfg(test)]
    pub(crate) async fn effect_delivery(&self) -> Arc<EffectDelivery> {
        let runtime = self.effects.as_ref().expect("effect runtime");
        runtime
            .delivery
            .get_or_init(|| async {
                let delivery =
                    Arc::new(effect_delivery_from_test_parts(self, self.database.clone()));
                delivery.activate().await.expect("activate effect delivery");
                delivery
            })
            .await
            .clone()
    }
    #[cfg(test)]
    pub(crate) async fn run_effect_once(
        &self,
    ) -> std::result::Result<Option<EffectRunOutcome>, RequestError> {
        self.effect_delivery().await.run_effect_once().await
    }
    #[cfg(test)]
    pub(crate) async fn start_effect_service(&self) -> Result<Option<EffectService>> {
        self.effect_delivery()
            .await
            .start_effect_service()
            .map(Some)
    }
}
/// A delivery context over `database`, as a worker process would build one.
#[cfg(test)]
pub(super) fn effect_delivery_from_test_parts(
    app: &Application,
    database: Database,
) -> EffectDelivery {
    let (manifest, deployment, contract, effective, limit, roots) = app.effect_test_parts();
    let delivery =
        EffectDelivery::from_parts(database, manifest, deployment, contract, effective, limit);
    *delivery.runtime.test_roots.lock().unwrap() = roots;
    delivery
}
#[cfg(test)]
mod tests;
