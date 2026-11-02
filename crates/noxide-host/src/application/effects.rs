//! Transactional captures only. Delivery and all networking belong to the outbox worker.
use super::*;
use crate::effects::{
    EffectScope, OutboxContext,
    capture::{ActionCapture, emissions_for},
};

impl Application {
    pub(super) async fn enqueue_action_effects(
        &self,
        effects: &mut Effects,
        action: ActionCore<'_>,
        snapshots: &BTreeMap<(u32, u64), StoredRecord>,
        outcomes: &[MutationOutcome],
        time: Option<crate::lifecycle_clock::AttemptTime>,
        origin: &str,
    ) -> Result<()> {
        let Some(contract) = &self.manifest.effects else {
            return Ok(());
        };
        let emissions = emissions_for(contract, action.id)?;
        if emissions.is_empty() {
            return Ok(());
        }
        let now = time.ok_or(repository::CalculationUnavailable)?.timestamp();
        let scope = EffectScope {
            deployment: self
                .generation
                .get()
                .ok_or_else(|| anyhow::anyhow!("application is not activated"))?
                .clone(),
            tenant: match &effects.principal {
                auth::Principal::Anonymous => String::new(),
                auth::Principal::User(user) => user.tenant.clone(),
                auth::Principal::Service(service) => service.tenant().to_owned(),
            },
        };
        let values = repository::ScheduleValues {
            manifest: &self.manifest,
            input: &effects.request.input,
            principal: &effects.principal,
            grants: &effects.grants,
            snapshots,
            outcomes,
            time,
            current: None,
        };
        ActionCapture {
            scope: &scope,
            contract: &self.contract,
            origin,
            source_action_version: action.version,
            now,
        }
        .enqueue(
            OutboxContext {
                tx: &mut effects.tx,
                calls: &mut effects.calls,
            },
            &emissions,
            |value| values.value(value, action),
        )
        .await
    }
}

#[cfg(test)]
pub(super) mod tests;
