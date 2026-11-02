//! Request-owned membership witnesses. Discarded on every retry and mutation.
use crate::sql::{JoinSql, sql};
use crate::{
    auth::Principal,
    database::Transaction,
    lifecycle_clock::AttemptTime,
    membership::{Deployment, LookupScope, MAX_BATCH, MAX_WITNESSES, Plan, ProtectedRow},
};
use anyhow::{Result, ensure};
use noxide_protocol::membership::ExistsRelated;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WitnessScope {
    storage_resource: i64,
    contract: String,
    incarnation: String,
    generation: String,
    declaration: ExistsRelated,
}

/// A request attempt owns this object and discards it on retry. It cannot be
/// shared across principals, attempts, or requests. No serialized cache exists.
pub struct Witnesses {
    account: String,
    tenant: String,
    attempt_time: AttemptTime,
    values: BTreeMap<(WitnessScope, String), bool>,
}

impl Witnesses {
    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    /// Requiring typed attempt time fails closed when temporal freshness cannot
    /// be established. This alone does not implement resource expiry.
    pub fn new(principal: &Principal, attempt_time: AttemptTime) -> Result<Self> {
        let user = principal.user()?;
        ensure!(
            !user.tenant.is_empty() && noxide_protocol::account_id(&user.id),
            "membership principal unavailable"
        );
        Ok(Self {
            account: user.id.clone(),
            tenant: user.tenant.clone(),
            attempt_time,
            values: BTreeMap::new(),
        })
    }

    /// Call after EVERY mutation step, including steps affecting accounts,
    /// membership status, or protected records. Retry constructs a new object.
    pub fn invalidate(&mut self) {
        self.values.clear();
    }

    /// One provider call for all uncached distinct keys, never one call per row.
    /// Caller passes the existing nonresetting request database-call allowance.
    /// No membership rows or role values cross the database boundary.
    pub async fn lookup(
        &mut self,
        tx: &mut Transaction,
        deployment: &Deployment<'_>,
        plan: &Plan,
        storage_resource: i64,
        rows: &[ProtectedRow<'_>],
        database_calls: &mut usize,
    ) -> Result<Vec<bool>> {
        ensure!(
            storage_resource > 0 && rows.len() <= MAX_BATCH,
            "membership batch limit"
        );
        let _fixed_attempt_time = self.attempt_time.timestamp();
        let scope = WitnessScope {
            storage_resource,
            contract: deployment.contract.to_owned(),
            incarnation: deployment.incarnation.to_owned(),
            generation: deployment.generation.to_owned(),
            declaration: plan.declaration().clone(),
        };
        let keys: Vec<_> = rows
            .iter()
            .map(|row| plan.key(row))
            .collect::<Result<_>>()?;
        let missing: BTreeSet<_> = rows
            .iter()
            .zip(&keys)
            .filter(|(row, key)| {
                row.tenant == self.tenant
                    && !self.values.contains_key(&(scope.clone(), (*key).clone()))
            })
            .map(|(_, key)| key.clone())
            .collect();
        ensure!(
            self.values
                .len()
                .checked_add(missing.len())
                .is_some_and(|n| n <= MAX_WITNESSES),
            "membership witness limit"
        );
        if !missing.is_empty() {
            ensure!(*database_calls > 0, "membership database call limit");
            *database_calls -= 1;
            let mut params = Vec::new();
            let requested: Vec<_> = missing
                .iter()
                .map(|key| {
                    params.push(key.clone().into());
                    sql!("SELECT ${} AS reference_id", params.len())
                })
                .collect();
            let lookup_scope = LookupScope {
                account: &self.account,
                tenant: &self.tenant,
                deployment: *deployment,
                time: self.attempt_time,
            };
            let predicate = plan.exists_sql(
                tx.query_provider()?,
                storage_resource,
                &lookup_scope,
                false,
                &mut params,
            )?;
            let witnesses = tx
                .membership_witnesses(
                    &requested.joined(" UNION ALL "),
                    &predicate,
                    MAX_BATCH,
                    &params,
                )
                .await?;
            ensure!(
                witnesses.len() == missing.len(),
                "incomplete membership batch"
            );
            for [key, value] in witnesses {
                ensure!(
                    missing.contains(&key) && matches!(value.as_str(), "0" | "1"),
                    "invalid membership witness"
                );
                self.values.insert((scope.clone(), key), value == "1");
            }
        }
        Ok(rows
            .iter()
            .zip(keys)
            .map(|(row, key)| {
                row.tenant == self.tenant
                    && self
                        .values
                        .get(&(scope.clone(), key))
                        .copied()
                        .unwrap_or(false)
            })
            .collect())
    }
}
