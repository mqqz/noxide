//! One lifecycle rule for ordinary visibility and authorized expiry assignments.
use crate::{
    database::Transaction,
    lifecycle_clock::{AttemptTime, TemporalUnavailable},
    manifest,
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{FieldKind, Fields, Resource, expiry::MAX_EXPIRY_MILLIS, time::Timestamp};

pub(crate) fn validate(resource: &Resource) -> Result<()> {
    if let Some(expiry) = &resource.expiry {
        ensure!(manifest::identifier(&expiry.field), "invalid expiry field");
        let field = resource
            .fields
            .iter()
            .find(|f| f.name == expiry.field)
            .context("unknown expiry field")?;
        ensure!(
            !field.optional && field.initial.is_none() && field.kind == FieldKind::Timestamp,
            "expiry requires a nonoptional timestamp without an initial value"
        );
        ensure!(
            expiry.max_after.as_millis() <= MAX_EXPIRY_MILLIS,
            "expiry horizon exceeds 30 days"
        );
    }
    Ok(())
}

fn value(resource: &Resource, fields: &Fields) -> Result<Option<Timestamp>> {
    resource
        .expiry
        .as_ref()
        .map(|expiry| {
            let field = resource
                .fields
                .iter()
                .find(|f| f.name == expiry.field)
                .context("unknown expiry field")?;
            let value = fields.get(&expiry.field).context("missing expiry field")?;
            manifest::validate_value(field, value)?;
            Ok(Timestamp::from_unix_millis(value.parse()?)?)
        })
        .transpose()
}

pub(crate) fn available(
    resource: &Resource,
    fields: &Fields,
    time: Option<AttemptTime>,
) -> Result<bool> {
    match value(resource, fields)? {
        None => Ok(true),
        Some(expires) => Ok(expires > time.ok_or(TemporalUnavailable::NotStarted)?.timestamp()),
    }
}

/// This selects lifecycle visibility only. The caller must still evaluate the
/// operation's normal policy under the transaction-verified service grant.
pub(crate) fn available_to(
    resource: &Resource,
    fields: &Fields,
    time: Option<AttemptTime>,
    operation: &noxide_protocol::Operation,
    principal: &crate::auth::Principal,
) -> Result<bool> {
    if operation.maintenance && matches!(principal, crate::auth::Principal::Service(_)) {
        if resource.expiry.is_some() {
            time.ok_or(TemporalUnavailable::NotStarted)?;
            // Validate the stored expiry even for explicitly approved maintenance.
            value(resource, fields)?.context("missing expiry")?;
        }
        Ok(true)
    } else {
        available(resource, fields, time)
    }
}

/// Called after canonical assignments on create or update, before any write.
/// Past/equal expiry is valid but is immediately unavailable to ordinary reads.
pub(crate) fn check_write(
    resource: &Resource,
    before: Option<&Fields>,
    proposed: &Fields,
    time: Option<AttemptTime>,
) -> Result<()> {
    let Some(expiry) = &resource.expiry else {
        return Ok(());
    };
    let expires = value(resource, proposed)?.context("missing expiry")?;
    let time = time.ok_or(TemporalUnavailable::NotStarted)?;
    if before.is_some_and(|before| before.get(&expiry.field) == proposed.get(&expiry.field)) {
        return Ok(());
    }
    let limit = time.timestamp().checked_add(expiry.max_after)?;
    ensure!(expires <= limit, "expiry exceeds the approved horizon");
    Ok(())
}

pub(crate) fn numeric_sql(tx: &Transaction, field: &str, alias: &str) -> Result<String> {
    // Alias is a host-owned SQL identifier; fields are independently admitted.
    ensure!(manifest::identifier(alias), "invalid timestamp table alias");
    Ok(format!(
        "CAST({} AS BIGINT)",
        tx.field_expression(field)?
            .replacen("fields", &format!("{alias}.fields"), 1)
    ))
}

pub(crate) fn sql(
    tx: &Transaction,
    resource: &Resource,
    time: Option<AttemptTime>,
    alias: &str,
    params: &mut Vec<crate::database::Param>,
) -> Result<String> {
    let Some(expiry) = &resource.expiry else {
        return Ok(String::new());
    };
    params.push(
        time.ok_or(TemporalUnavailable::NotStarted)?
            .timestamp()
            .unix_millis()
            .into(),
    );
    Ok(format!(
        " AND {}>${}",
        numeric_sql(tx, &expiry.field, alias)?,
        params.len()
    ))
}
