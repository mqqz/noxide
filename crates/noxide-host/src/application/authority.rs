//! Construct request authority only after the existing deployment admission.
use super::*;

impl Application {
    #[cfg(test)]
    pub(super) async fn test_target_allowed(
        &self,
        action: ActionCore<'_>,
        route: Option<u32>,
        principal: &auth::Principal,
        stored: &StoredRecord,
    ) -> Result<bool> {
        let mut tx = self
            .database
            .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(30))
            .await?;
        let mut authority = crate::authority::Authority::default();
        let mut calls = repository::MAX_LIST_DATABASE_CALLS;
        self.target_allowed(
            &mut repository::ReadContext {
                tx: &mut tx,
                manifest: &self.identity.manifest,
                principal,
                authority: &mut authority,
                budget: repository::ReadBudget::Query(&mut calls),
            },
            action,
            route,
            stored,
        )
        .await
    }

    #[cfg(test)]
    pub(super) async fn test_finish_navigation(
        &self,
        prepared: navigation::Prepared,
        deadline: Instant,
    ) -> Rendered {
        let mut budget = ExecutionBudget::new(self.runtime.limits(), deadline);
        self.finish_navigation(
            prepared,
            deadline,
            budget.take_delivery_calls().expect("new fixture budget"),
        )
        .await
    }
    pub(crate) fn authority_context(
        &self,
        time: Option<crate::lifecycle_clock::AttemptTime>,
    ) -> Result<crate::authority::Authority> {
        Ok(crate::authority::Authority::new(
            time,
            crate::authority::DeploymentScope {
                contract: self.identity.deployment.clone(),
                incarnation: self.keys.incarnation().into(),
                generation: self
                    .identity
                    .generation
                    .get()
                    .ok_or_else(|| anyhow::anyhow!("application is not activated"))?
                    .clone(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn postcommit_authority_uses_only_unspent_and_reserved_calls() {
        let mut budget = ExecutionBudget::new(&Limits::default(), Instant::now());
        budget.parent_redirect_attempt(true).unwrap();
        budget.spend(3).unwrap();
        assert_eq!(budget.take_delivery_calls().unwrap(), 11);
        assert_eq!(budget.database_calls, 0);
        assert_eq!(budget.take_delivery_calls().unwrap(), 0);
        assert!(
            budget.spend(1).is_err(),
            "delivery cannot reset the original sixteen-call pool"
        );
    }
}
