//! Disabled P07 leaf: admitted one-hop membership and request-owned witnesses.
//!
//! This module grants no access until the integration in docs/membership.md is
//! complete. In particular, ordinary resource expiry is not implemented here.
use crate::{auth::Principal, database::Transaction, lifecycle_clock::AttemptTime, manifest};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{
    FieldKind, Fields, Resource, TextField,
    membership::{
        ExistsRelated, MAX_MEMBERSHIP_CONDITIONS, MAX_MEMBERSHIP_PREDICATES, MembershipLiteral,
        MembershipUnique, RelatedTarget,
    },
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_BATCH: usize = 64;
pub(crate) const MAX_WITNESSES: usize = 128;

/// Construct only from admitted resources, never from a guest request. The
/// storage ID must come from this transaction's resource catalog.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    declaration: ExistsRelated,
    reference: TextField,
    account: TextField,
    protected_reference: Option<TextField>,
}

fn field<'a>(resource: &'a Resource, name: &str) -> Result<&'a TextField> {
    ensure!(manifest::identifier(name), "invalid membership field");
    resource
        .fields
        .iter()
        .find(|f| f.name == name)
        .context("unknown membership field")
}

pub(crate) fn admit(
    resources: &[Resource],
    protected: &Resource,
    declarations: &[ExistsRelated],
) -> Result<Vec<Plan>> {
    ensure!(
        declarations.len() <= MAX_MEMBERSHIP_PREDICATES,
        "membership predicate limit"
    );
    let mut seen = BTreeSet::new();
    declarations
        .iter()
        .map(|declaration| {
            ensure!(seen.insert(declaration), "duplicate membership predicate");
            ensure!(
                manifest::identifier(&declaration.resource),
                "invalid membership resource"
            );
            let membership = resources
                .iter()
                .find(|r| r.name == declaration.resource)
                .context("unknown membership resource")?;
            ensure!(
                declaration.conditions.len() <= MAX_MEMBERSHIP_CONDITIONS,
                "membership condition limit"
            );
            let reference = field(membership, &declaration.reference)?;
            let FieldKind::Reference { resource: target } = &reference.kind else {
                anyhow::bail!("membership match requires an immutable reference");
            };
            ensure!(
                !reference.optional && reference.initial.is_none(),
                "membership reference must be required"
            );
            let protected_reference = match &declaration.target {
                RelatedTarget::SelfRecord => {
                    ensure!(
                        target == &protected.name,
                        "membership target resource mismatch"
                    );
                    None
                }
                RelatedTarget::Reference { field: name } => {
                    let f = field(protected, name)?;
                    ensure!(
                        !f.optional && f.initial.is_none(),
                        "protected reference must be required"
                    );
                    ensure!(
                        matches!(&f.kind, FieldKind::Reference { resource } if resource == target),
                        "membership target resource mismatch"
                    );
                    Some(f.clone())
                }
            };
            let account = field(membership, &declaration.account)?;
            ensure!(
                !account.optional
                    && account.initial.is_none()
                    && matches!(account.kind, FieldKind::Account { .. }),
                "membership account must be required"
            );
            for (name, literal) in &declaration.conditions {
                let condition = field(membership, name)?;
                ensure!(!condition.optional, "membership condition must be required");
                let value = literal_text(literal);
                ensure!(
                    matches!(
                        (&condition.kind, literal),
                        (FieldKind::Boolean, MembershipLiteral::Boolean(_))
                            | (FieldKind::Choice { .. }, MembershipLiteral::Choice(_))
                    ),
                    "membership condition requires a typed literal"
                );
                manifest::validate_value(condition, &value)?;
            }
            Ok(Plan {
                declaration: declaration.clone(),
                reference: reference.clone(),
                account: account.clone(),
                protected_reference,
            })
        })
        .collect()
}

fn literal_text(literal: &MembershipLiteral) -> String {
    match literal {
        MembershipLiteral::Boolean(value) => value.to_string(),
        MembershipLiteral::Choice(value) => value.clone(),
    }
}

/// The row is host-loaded/current or the fully resolved proposed create row.
/// This type supplies no authority by itself; policy evaluates the witness.
pub(crate) struct ProtectedRow<'a> {
    pub id: i64,
    pub tenant: &'a str,
    pub fields: &'a Fields,
}

impl Plan {
    fn key(&self, row: &ProtectedRow<'_>) -> Result<String> {
        match &self.protected_reference {
            Some(field) => {
                let value = row
                    .fields
                    .get(&field.name)
                    .context("missing protected reference")?;
                manifest::validate_value(field, value)?;
                Ok(value.clone())
            }
            None => {
                ensure!(row.id > 0, "invalid protected identity");
                Ok(row.id.to_string())
            }
        }
    }

    /// Independent stored-row truth table. It checks only membership, never
    /// widens ordinary read policy, and requires host-verified active account.
    #[cfg(test)]
    fn matches(
        &self,
        reference: &str,
        tenant: &str,
        fields: &Fields,
        account: &str,
        active: bool,
    ) -> bool {
        active
            && !tenant.is_empty()
            && fields
                .get(&self.reference.name)
                .is_some_and(|v| v == reference)
            && fields.get(&self.account.name).is_some_and(|v| v == account)
            && self
                .declaration
                .conditions
                .iter()
                .all(|(field, literal)| fields.get(field) == Some(&literal_text(literal)))
    }
}

/// Host deployment identity from the normal invocation fence. SQL rechecks it
/// inside the membership query, including for read-only transactions.
pub(crate) struct Deployment<'a> {
    pub contract: &'a str,
    pub incarnation: &'a str,
    pub generation: &'a str,
}

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
pub(crate) struct Witnesses {
    account: String,
    tenant: String,
    attempt_time: AttemptTime,
    values: BTreeMap<(WitnessScope, String), bool>,
}

impl Witnesses {
    /// Requiring typed attempt time fails closed when temporal freshness cannot
    /// be established. This alone does not implement resource expiry.
    pub(crate) fn new(principal: &Principal, attempt_time: AttemptTime) -> Result<Self> {
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
    pub(crate) fn invalidate(&mut self) {
        self.values.clear();
    }

    /// One provider call for all uncached distinct keys, never one call per row.
    /// Caller passes the existing nonresetting request database-call allowance.
    /// No membership rows or role values cross the database boundary.
    pub(crate) async fn lookup(
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
            declaration: plan.declaration.clone(),
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
            let mut params = vec![
                storage_resource.into(),
                self.account.as_str().into(),
                self.tenant.as_str().into(),
                deployment.contract.into(),
                deployment.incarnation.into(),
                deployment.generation.into(),
            ];
            let requested: Vec<_> = missing
                .iter()
                .map(|key| {
                    params.push(key.clone().into());
                    format!("SELECT ${} AS reference_id", params.len())
                })
                .collect();
            let reference = qualified_field(tx, &plan.reference.name)?;
            let account = qualified_field(tx, &plan.account.name)?;
            let mut conditions = Vec::new();
            for (field, literal) in &plan.declaration.conditions {
                params.push(literal_text(literal).into());
                conditions.push(format!("{}=${}", qualified_field(tx, field)?, params.len()));
            }
            let conditions = if conditions.is_empty() {
                String::new()
            } else {
                format!(" AND {}", conditions.join(" AND "))
            };
            let sql = format!(
                "WITH requested AS ({}) SELECT reference_id,CASE WHEN EXISTS(SELECT 1 FROM nx_records m JOIN nx_accounts a ON a.id={} AND a.id=$2 AND a.state='active' AND a.tenant=$3 WHERE m.resource=$1 AND m.tenant=$3 AND {}=requested.reference_id{} AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND contract=$4 AND incarnation=$5 AND generation=$6)) THEN '1' ELSE '0' END FROM requested LIMIT {}",
                requested.join(" UNION ALL "),
                account,
                reference,
                conditions,
                MAX_BATCH
            );
            let witnesses = tx.fetch::<2>(&sql, &params).await?;
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

fn qualified_field(tx: &Transaction, field: &str) -> Result<String> {
    Ok(tx
        .field_expression(field)?
        .replacen("fields", "m.fields", 1))
}

/// Provider DDL for a declared immutable tuple. Schema integration must first
/// validate all existing values canonically and fail on historical duplicates.
/// The index deliberately ignores status, owner and tenant.
pub(crate) fn unique_index_sql(
    tx: &Transaction,
    resource: &Resource,
    storage_resource: i64,
    unique: &MembershipUnique,
) -> Result<String> {
    ensure!(storage_resource > 0, "invalid membership storage resource");
    let reference = field(resource, &unique.reference)?;
    let account = field(resource, &unique.account)?;
    ensure!(
        !reference.optional
            && reference.initial.is_none()
            && matches!(reference.kind, FieldKind::Reference { .. })
            && !account.optional
            && account.initial.is_none()
            && matches!(account.kind, FieldKind::Account { .. }),
        "invalid membership unique tuple"
    );
    let digest: String = Sha256::digest(serde_json::to_vec(unique)?)[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(format!(
        "CREATE UNIQUE INDEX nx_m_{storage_resource:x}_{digest} ON nx_records(resource,{}, {}) WHERE resource={storage_resource}",
        tx.field_expression(&unique.reference)?,
        tx.field_expression(&unique.account)?
    ))
}

/// Canonical tuple validation is shared by create and schema preflight. JSON or
/// delimiter concatenation is unnecessary: providers index two scalar columns.
pub(crate) fn canonical_tuple(
    resource: &Resource,
    unique: &MembershipUnique,
    fields: &Fields,
) -> Result<(String, String)> {
    let reference = field(resource, &unique.reference)?;
    let account = field(resource, &unique.account)?;
    ensure!(
        !reference.optional
            && reference.initial.is_none()
            && !account.optional
            && account.initial.is_none()
            && matches!(reference.kind, FieldKind::Reference { .. })
            && matches!(account.kind, FieldKind::Account { .. }),
        "invalid membership tuple kinds"
    );
    let a = fields
        .get(&unique.reference)
        .context("missing membership reference")?;
    let b = fields
        .get(&unique.account)
        .context("missing membership account")?;
    manifest::validate_value(reference, a)?;
    manifest::validate_value(account, b)?;
    Ok((a.clone(), b.clone()))
}

#[cfg(test)]
mod tests;
