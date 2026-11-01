//! Disabled module: admitted one-hop membership and request-owned witnesses.
//!
//! This module grants no access until the integration in docs/membership.md is
//! complete. In particular, ordinary resource expiry is not implemented here.
use crate::{
    manifest,
    query_plan::NativeProvider,
    sql::{Param, Sql, sql},
    temporal::AttemptTime,
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{
    FieldKind, Fields, Resource, TextField,
    membership::{
        ExistsRelated, MAX_MEMBERSHIP_CONDITIONS, MAX_MEMBERSHIP_PREDICATES, MembershipLiteral,
        MembershipUnique, RelatedTarget,
    },
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_BATCH: usize = 64;
pub const MAX_WITNESSES: usize = 128;

pub fn plans(
    m: &noxide_protocol::Manifest,
    operation: &noxide_protocol::Operation,
) -> Result<Vec<Plan>> {
    let declarations: Vec<_> = operation
        .policy
        .any
        .iter()
        .flatten()
        .filter_map(|p| match p {
            noxide_protocol::Predicate::ExistsRelated(declaration) => Some(declaration.clone()),
            _ => None,
        })
        .collect();
    ensure!(
        declarations.len() <= MAX_MEMBERSHIP_PREDICATES,
        "membership predicate limit"
    );
    let declarations: BTreeSet<_> = declarations.into_iter().collect();
    admit(
        &m.resources,
        manifest::resource(m, operation.resource)?,
        &declarations.into_iter().collect::<Vec<_>>(),
    )
}

pub fn validate_unique(resource: &Resource) -> Result<()> {
    ensure!(
        resource.unique.len() <= noxide_protocol::membership::MAX_MEMBERSHIP_UNIQUE_TUPLES,
        "membership unique tuple limit"
    );
    let mut seen = BTreeSet::new();
    for unique in &resource.unique {
        ensure!(seen.insert(unique), "duplicate membership unique tuple");
        unique_fields(resource, unique)?;
    }
    Ok(())
}

fn unique_fields<'a>(
    resource: &'a Resource,
    unique: &MembershipUnique,
) -> Result<(&'a TextField, &'a TextField)> {
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
    Ok((reference, account))
}

/// Construct only from admitted resources, never from a guest request. The
/// storage ID must come from this transaction's resource catalog.
#[derive(Clone, Debug)]
pub struct Plan {
    declaration: ExistsRelated,
    reference: TextField,
    account: TextField,
    protected_reference: Option<TextField>,
    resource: Resource,
}

fn field<'a>(resource: &'a Resource, name: &str) -> Result<&'a TextField> {
    ensure!(manifest::identifier(name), "invalid membership field");
    resource
        .fields
        .iter()
        .find(|f| f.name == name)
        .context("unknown membership field")
}

pub fn admit(
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
                resource: membership.clone(),
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
pub struct ProtectedRow<'a> {
    pub id: i64,
    pub tenant: &'a str,
    pub fields: &'a Fields,
}

impl Plan {
    pub fn resource(&self) -> &Resource {
        &self.resource
    }
    pub fn declaration(&self) -> &ExistsRelated {
        &self.declaration
    }

    /// The same specialized EXISTS clause serves list filtering and batched
    /// witnesses. All SQL identifiers/aliases originate in trusted code.
    pub fn exists_sql(
        &self,
        provider: NativeProvider,
        storage: i64,
        scope: &LookupScope<'_>,
        protected_row: bool,
        params: &mut Vec<Param>,
    ) -> Result<Sql> {
        let LookupScope {
            account,
            tenant,
            deployment,
            time,
        } = *scope;
        ensure!(
            storage > 0 && noxide_protocol::account_id(account) && !tenant.is_empty(),
            "membership scope unavailable"
        );
        params.push(account.into());
        let account_parameter = params.len();
        params.push(tenant.into());
        let tenant_parameter = params.len();
        let target = if protected_row {
            match &self.protected_reference {
                Some(field) => provider.qualified_field("nx_records", &field.name)?,
                None => Sql::statement("CAST(nx_records.id AS TEXT)"),
            }
        } else {
            Sql::statement("requested.reference_id")
        };
        let mut clauses = vec![
            sql!("m.resource={storage}"),
            sql!("m.tenant=${tenant_parameter}"),
            sql!(
                "{}={target}",
                qualified_field(provider, &self.reference.name)?
            ),
            sql!(
                "{}=${account_parameter}",
                qualified_field(provider, &self.account.name)?
            ),
        ];
        for (field, literal) in &self.declaration.conditions {
            params.push(literal_text(literal).into());
            clauses.push(sql!(
                "{}=${}",
                qualified_field(provider, field)?,
                params.len()
            ));
        }
        let expiry = crate::expiry::sql(provider, &self.resource, Some(time), "m", params)?;
        clauses.push(sql!("EXISTS(SELECT 1 FROM nx_accounts a WHERE a.id=${account_parameter} AND a.tenant=${tenant_parameter} AND a.state='active')"));
        let mut fence = Vec::new();
        for (column, value) in [
            ("contract", deployment.contract),
            ("incarnation", deployment.incarnation),
            ("generation", deployment.generation),
        ] {
            params.push(value.into());
            fence.push(sql!("{column}=${}", params.len()));
        }
        clauses.push(sql!(
            "EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND {})",
            Sql::join(&fence, " AND ")
        ));
        let exists = sql!(
            "EXISTS(SELECT 1 FROM nx_records m WHERE {}{expiry} LIMIT 1)",
            Sql::join(&clauses, " AND ")
        );
        Ok(if protected_row {
            sql!("(nx_records.tenant=${tenant_parameter} AND {exists})")
        } else {
            exists
        })
    }

    pub fn key(&self, row: &ProtectedRow<'_>) -> Result<String> {
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
    #[cfg(any(test, feature = "test-support"))]
    pub fn matches(
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
#[derive(Clone, Copy)]
pub struct Deployment<'a> {
    pub contract: &'a str,
    pub incarnation: &'a str,
    pub generation: &'a str,
}

#[derive(Clone, Copy)]
pub struct LookupScope<'a> {
    pub account: &'a str,
    pub tenant: &'a str,
    pub deployment: Deployment<'a>,
    pub time: AttemptTime,
}

fn qualified_field(provider: NativeProvider, field: &str) -> Result<Sql> {
    provider.qualified_field("m", field)
}

/// Provider DDL for a declared immutable tuple. Schema integration must first
/// validate all existing values canonically and fail on historical duplicates.
/// The index deliberately ignores status, owner and tenant.
pub fn unique_index_sql(
    provider: NativeProvider,
    resource: &Resource,
    storage_resource: i64,
    unique: &MembershipUnique,
) -> Result<Sql> {
    ensure!(storage_resource > 0, "invalid membership storage resource");
    unique_fields(resource, unique)?;
    Ok(sql!(
        "CREATE UNIQUE INDEX {} ON nx_records(resource,{}, {}) WHERE resource={storage_resource}",
        Sql::identifier(&unique_index_name(storage_resource, unique)?)?,
        provider.field_expression(&unique.reference)?,
        provider.field_expression(&unique.account)?
    ))
}

pub fn unique_index_name(storage_resource: i64, unique: &MembershipUnique) -> Result<String> {
    ensure!(
        storage_resource > 0
            && manifest::identifier(&unique.reference)
            && manifest::identifier(&unique.account),
        "invalid membership unique index"
    );
    let digest: String = Sha256::digest(serde_json::to_vec(unique)?)[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(format!("nx_m_{storage_resource:x}_{digest}"))
}

/// Canonical tuple validation is shared by create and schema preflight. JSON or
/// delimiter concatenation is unnecessary: providers index two scalar columns.
pub fn canonical_tuple(
    resource: &Resource,
    unique: &MembershipUnique,
    fields: &Fields,
) -> Result<(String, String)> {
    let (reference, account) = unique_fields(resource, unique)?;
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
