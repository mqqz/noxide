//! Request-attempt authority. One context, one durable time, no shared witnesses.
use crate::{
    auth::Principal,
    database::{Param, Transaction},
    expiry,
    lifecycle_clock::{AttemptTime, TemporalUnavailable},
    manifest,
    membership::{self, Deployment, LookupScope, Plan, ProtectedRow},
    policy,
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{Fields, Manifest, Operation, membership::ExistsRelated};
use std::collections::BTreeMap;
pub mod projection;
pub mod witnesses;
use witnesses::Witnesses;

#[derive(Clone)]
pub struct DeploymentScope {
    pub contract: String,
    pub incarnation: String,
    pub generation: String,
}

impl DeploymentScope {
    pub fn borrowed(&self) -> Deployment<'_> {
        Deployment {
            contract: &self.contract,
            incarnation: &self.incarnation,
            generation: &self.generation,
        }
    }
}

#[derive(Default)]
pub struct Authority {
    time: Option<AttemptTime>,
    deployment: Option<DeploymentScope>,
    storage: BTreeMap<String, i64>,
    witnesses: Option<Witnesses>,
    witness_principal: Option<crate::auth::PrincipalKey>,
    projection_epoch: std::sync::Arc<()>,
}

#[derive(Clone, Copy)]
pub struct Row<'a> {
    pub id: u64,
    pub owner: &'a str,
    pub tenant: &'a str,
    pub fields: &'a Fields,
}

pub fn uses_time(manifest: &Manifest) -> bool {
    manifest.jobs.is_some()
        || manifest.blobs.is_some()
        || manifest.resources.iter().any(|resource| {
            resource.expiry.is_some()
                || resource
                    .fields
                    .iter()
                    .any(|field| matches!(field.kind, noxide_protocol::FieldKind::Blob { .. }))
        })
        || manifest.operations.iter().any(|op| {
            op.policy
                .any
                .iter()
                .flatten()
                .any(|p| matches!(p, noxide_protocol::Predicate::ExistsRelated(_)))
        })
}

impl Authority {
    pub fn new(time: Option<AttemptTime>, deployment: DeploymentScope) -> Self {
        Self {
            time,
            deployment: Some(deployment),
            ..Self::default()
        }
    }
    pub fn contract(&self) -> Result<&str> {
        Ok(&self
            .deployment
            .as_ref()
            .context("query deployment missing")?
            .contract)
    }
    pub fn time(&self) -> Option<AttemptTime> {
        self.time
    }
    pub fn invalidate(&mut self) {
        self.projection_epoch = std::sync::Arc::new(());
        self.clear_witnesses();
    }
    fn clear_witnesses(&mut self) {
        if let Some(witnesses) = &mut self.witnesses {
            witnesses.invalidate();
        }
        self.witnesses = None;
        self.witness_principal = None;
    }

    async fn storage(
        &mut self,
        tx: &mut Transaction,
        manifest: &Manifest,
        plan: &Plan,
        calls: &mut usize,
    ) -> Result<i64> {
        let resource = plan.resource();
        if let Some(storage) = self.storage.get(&resource.name) {
            return Ok(*storage);
        }
        ensure!(*calls > 0, "membership catalog call limit");
        *calls -= 1;
        let storage = tx.storage_resource(manifest, resource.id).await?;
        ensure!(storage > 0, "membership storage unavailable");
        self.storage.insert(resource.name.clone(), storage);
        Ok(storage)
    }

    /// This method is the only row policy evaluator for enabled runtime paths.
    /// Each batch owns at most 64x2 witnesses. Unchanged facts can be reused in
    /// this transaction until mutation, principal change or bounded eviction.
    /// Principal changes (including anonymous picker evaluation) cannot
    /// inherit witnesses prepared for an authenticated principal.
    pub async fn authorize(
        &mut self,
        tx: &mut Transaction,
        manifest: &Manifest,
        principal: &Principal,
        operation: &Operation,
        rows: &[Row<'_>],
        calls: &mut usize,
    ) -> Result<Vec<bool>> {
        ensure!(rows.len() <= membership::MAX_BATCH, "authority batch limit");
        let resource = manifest::resource(manifest, operation.resource)?;
        for row in rows {
            manifest::validate_fields(resource, row.fields)?;
        }
        self.evaluate_policy_expiry(tx, manifest, principal, operation, rows, calls)
            .await
    }

    // Only full-validated rows or opaque InternalFacts enter this one evaluator.
    // Public visibility, parent gates, scope and selection remain repository
    // checks. A true result here is not a complete Read/output grant.
    async fn evaluate_policy_expiry(
        &mut self,
        tx: &mut Transaction,
        manifest: &Manifest,
        principal: &Principal,
        operation: &Operation,
        rows: &[Row<'_>],
        calls: &mut usize,
    ) -> Result<Vec<bool>> {
        ensure!(rows.len() <= membership::MAX_BATCH, "authority batch limit");
        let principal_key = Some(principal.authority_key());
        if self.witness_principal != principal_key {
            self.clear_witnesses();
        }
        self.witness_principal = principal_key.clone();
        let resource = manifest::resource(manifest, operation.resource)?;
        let visible: Vec<_> = if operation.kind == noxide_protocol::OperationKind::Create {
            for row in rows {
                expiry::check_write(resource, None, row.fields, self.time)?;
            }
            vec![true; rows.len()]
        } else {
            rows.iter()
                .map(|row| {
                    expiry::available_to(resource, row.fields, self.time, operation, principal)
                })
                .collect::<Result<_>>()?
        };
        let plans = membership::plans(manifest, operation)?;
        // Independent ordinary grants need no membership lookup. In particular,
        // a proposed create has no self identity to join before insertion.
        let ordinary: Vec<_> = rows
            .iter()
            .map(|row| {
                policy::allowed(
                    &operation.policy,
                    principal,
                    policy::Row {
                        owner: row.owner,
                        tenant: row.tenant,
                        fields: row.fields,
                    },
                )
            })
            .collect();
        let mut decisions: BTreeMap<ExistsRelated, Vec<bool>> = BTreeMap::new();
        if !plans.is_empty()
            && visible
                .iter()
                .zip(&ordinary)
                .any(|(visible, ordinary)| *visible && !*ordinary)
            && let Principal::User(user) = principal
            && !user.tenant.is_empty()
        {
            let time = self.time.ok_or(TemporalUnavailable::NotStarted)?;
            let deployment = self
                .deployment
                .clone()
                .context("membership deployment unavailable")?;
            let selected: Vec<_> = rows
                .iter()
                .zip(&visible)
                .enumerate()
                .filter(|(index, (_, visible))| **visible && !ordinary[*index])
                .map(|(index, (row, _))| {
                    Ok((
                        index,
                        ProtectedRow {
                            id: i64::try_from(row.id)?,
                            tenant: row.tenant,
                            fields: row.fields,
                        },
                    ))
                })
                .collect::<Result<_>>()?;
            let incoming = selected
                .len()
                .checked_mul(plans.len())
                .context("membership witness bound overflow")?;
            ensure!(
                incoming <= membership::MAX_WITNESSES,
                "membership witness batch limit"
            );
            if self.witnesses.as_ref().is_some_and(|witnesses| {
                witnesses
                    .len()
                    .checked_add(incoming)
                    .is_none_or(|count| count > membership::MAX_WITNESSES)
            }) {
                self.clear_witnesses();
                self.witness_principal = principal_key;
            }
            if self.witnesses.is_none() {
                self.witnesses = Some(Witnesses::new(principal, time)?);
            }
            for plan in &plans {
                let storage = self.storage(tx, manifest, plan, calls).await?;
                let protected: Vec<_> = selected
                    .iter()
                    .map(|(_, row)| ProtectedRow {
                        id: row.id,
                        tenant: row.tenant,
                        fields: row.fields,
                    })
                    .collect();
                let looked_up = self
                    .witnesses
                    .as_mut()
                    .expect("owned witness batch")
                    .lookup(tx, &deployment.borrowed(), plan, storage, &protected, calls)
                    .await?;
                let mut allowed = vec![false; rows.len()];
                for ((index, _), value) in selected.iter().zip(looked_up) {
                    allowed[*index] = value;
                }
                decisions.insert(plan.declaration().clone(), allowed);
            }
        }
        let result = rows
            .iter()
            .enumerate()
            .map(|(index, row)| {
                visible[index]
                    && policy::allowed_with(
                        &operation.policy,
                        principal,
                        policy::Row {
                            owner: row.owner,
                            tenant: row.tenant,
                            fields: row.fields,
                        },
                        |predicate| decisions.get(predicate).is_some_and(|values| values[index]),
                    )
            })
            .collect();
        Ok(result)
    }

    /// Full SQL filtering uses the same specialized clause as direct witnesses.
    /// Bounded residual candidate scans intentionally use their relaxed base
    /// policy and authorize the loaded candidates with `authorize` afterwards.
    pub async fn sql(
        &mut self,
        tx: &mut Transaction,
        manifest: &Manifest,
        principal: &Principal,
        operation: &Operation,
        params: &mut Vec<Param>,
        calls: &mut usize,
    ) -> Result<Vec<crate::sql::Sql>> {
        let mut plans = BTreeMap::new();
        for plan in membership::plans(manifest, operation)? {
            let storage = self.storage(tx, manifest, &plan, calls).await?;
            plans.insert(plan.declaration().clone(), (plan, storage));
        }
        let clauses = policy::sql_with(
            tx.query_provider()?,
            &operation.policy,
            principal,
            params,
            |predicate, params| {
                let user = principal.user()?;
                if user.tenant.is_empty() {
                    return Ok("1=0".into());
                }
                let deployment = self
                    .deployment
                    .as_ref()
                    .context("membership deployment unavailable")?;
                let (plan, storage) = plans.get(predicate).context("membership plan missing")?;
                let scope = LookupScope {
                    account: &user.id,
                    tenant: &user.tenant,
                    deployment: deployment.borrowed(),
                    time: self.time.ok_or(TemporalUnavailable::NotStarted)?,
                };
                plan.exists_sql(tx.query_provider()?, *storage, &scope, true, params)
            },
        )?;
        let resource = manifest::resource(manifest, operation.resource)?;
        let expires = if operation.maintenance && matches!(principal, Principal::Service(_)) {
            if resource.expiry.is_some() {
                self.time.ok_or(TemporalUnavailable::NotStarted)?;
            }
            crate::sql::Sql::empty()
        } else {
            expiry::sql(
                tx.query_provider()?,
                resource,
                self.time,
                "nx_records",
                params,
            )?
        };
        Ok(clauses
            .into_iter()
            .map(|clause| crate::sql::sql!("({clause}){expires}"))
            .collect())
    }
}
