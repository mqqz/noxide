//! Request-attempt authority. One context, one durable time, no shared witnesses.
use crate::{
    auth::Principal,
    database::{Param, Transaction},
    expiry,
    lifecycle_clock::{AttemptTime, TemporalUnavailable},
    manifest,
    membership::{self, Deployment, LookupScope, Plan, ProtectedRow, Witnesses},
    policy,
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{Fields, Manifest, Operation, membership::ExistsRelated};
use std::collections::BTreeMap;

#[derive(Clone)]
pub(crate) struct DeploymentScope {
    pub contract: String,
    pub incarnation: String,
    pub generation: String,
}
impl DeploymentScope {
    fn borrowed(&self) -> Deployment<'_> {
        Deployment {
            contract: &self.contract,
            incarnation: &self.incarnation,
            generation: &self.generation,
        }
    }
}

#[derive(Default)]
pub(crate) struct Authority {
    time: Option<AttemptTime>,
    deployment: Option<DeploymentScope>,
    storage: BTreeMap<String, i64>,
    witnesses: Option<Witnesses>,
}

#[derive(Clone, Copy)]
pub(crate) struct Row<'a> {
    pub id: u64,
    pub owner: &'a str,
    pub tenant: &'a str,
    pub fields: &'a Fields,
}

pub(crate) fn uses_time(manifest: &Manifest) -> bool {
    manifest
        .resources
        .iter()
        .any(|resource| resource.expiry.is_some())
        || manifest.operations.iter().any(|op| {
            op.policy
                .any
                .iter()
                .flatten()
                .any(|p| matches!(p, noxide_protocol::Predicate::ExistsRelated(_)))
        })
}

impl Authority {
    pub(crate) fn new(time: Option<AttemptTime>, deployment: DeploymentScope) -> Self {
        Self {
            time,
            deployment: Some(deployment),
            ..Self::default()
        }
    }
    pub(crate) fn time(&self) -> Option<AttemptTime> {
        self.time
    }
    pub(crate) fn invalidate(&mut self) {
        self.witnesses = None;
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
    /// Each batch owns at most 64x2 witnesses and discards them before another
    /// batch. Principal changes (including anonymous picker evaluation) cannot
    /// inherit witnesses prepared for an authenticated principal.
    pub(crate) async fn authorize(
        &mut self,
        tx: &mut Transaction,
        manifest: &Manifest,
        principal: &Principal,
        operation: &Operation,
        rows: &[Row<'_>],
        calls: &mut usize,
    ) -> Result<Vec<bool>> {
        ensure!(rows.len() <= membership::MAX_BATCH, "authority batch limit");
        self.invalidate();
        let resource = manifest::resource(manifest, operation.resource)?;
        for row in rows {
            manifest::validate_fields(resource, row.fields)?;
        }
        let visible: Vec<_> = if operation.kind == noxide_protocol::OperationKind::Create {
            for row in rows {
                expiry::check_write(resource, None, row.fields, self.time)?;
            }
            vec![true; rows.len()]
        } else {
            rows.iter()
                .map(|row| expiry::available(resource, row.fields, self.time))
                .collect::<Result<_>>()?
        };
        let plans = membership::plans(manifest, operation)?;
        let mut decisions: BTreeMap<ExistsRelated, Vec<bool>> = BTreeMap::new();
        if !plans.is_empty()
            && let Principal::User(user) = principal
            && !user.tenant.is_empty()
        {
            let time = self.time.ok_or(TemporalUnavailable::NotStarted)?;
            let deployment = self
                .deployment
                .clone()
                .context("membership deployment unavailable")?;
            self.witnesses = Some(Witnesses::new(principal, time)?);
            let selected: Vec<_> = rows
                .iter()
                .zip(&visible)
                .enumerate()
                .filter(|(_, (_, visible))| **visible)
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
        self.invalidate();
        Ok(result)
    }

    /// Full SQL filtering uses the same specialized clause as direct witnesses.
    /// Bounded residual candidate scans intentionally use their relaxed base
    /// policy and authorize the loaded candidates with `authorize` afterwards.
    pub(crate) async fn sql(
        &mut self,
        tx: &mut Transaction,
        manifest: &Manifest,
        principal: &Principal,
        operation: &Operation,
        params: &mut Vec<Param>,
        calls: &mut usize,
    ) -> Result<Vec<String>> {
        let mut plans = BTreeMap::new();
        for plan in membership::plans(manifest, operation)? {
            let storage = self.storage(tx, manifest, &plan, calls).await?;
            plans.insert(plan.declaration().clone(), (plan, storage));
        }
        let clauses = policy::sql_with(
            tx,
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
                plan.exists_sql(tx, *storage, &scope, true, params)
            },
        )?;
        let expires = expiry::sql(
            tx,
            manifest::resource(manifest, operation.resource)?,
            self.time,
            "nx_records",
            params,
        )?;
        Ok(clauses
            .into_iter()
            .map(|clause| format!("({clause}){expires}"))
            .collect())
    }
}
