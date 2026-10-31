//! Typed evaluation inside the existing authorized transaction executor.
use super::*;
use crate::lifecycle_clock::AttemptTime;
use noxide_protocol::time::{Duration, Timestamp};
use std::{cmp::Ordering, collections::BTreeMap};

#[derive(Debug)]
pub(crate) struct CalculationUnavailable;
impl std::fmt::Display for CalculationUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("calculation unavailable")
    }
}
impl std::error::Error for CalculationUnavailable {}

#[derive(Clone, Debug)]
pub(crate) enum Scalar {
    Text(String),
    Integer(i64),
    Boolean(bool),
    Choice(String),
    Account(String),
    Timestamp(Timestamp),
    Duration(Duration),
    Reference { resource: String, id: u64 },
    Missing(FieldKind),
}
impl Scalar {
    pub fn encode(&self) -> String {
        match self {
            Self::Text(v) | Self::Choice(v) | Self::Account(v) => v.clone(),
            Self::Integer(v) => v.to_string(),
            Self::Boolean(v) => v.to_string(),
            Self::Timestamp(v) => v.unix_millis().to_string(),
            Self::Duration(v) => v.as_millis().to_string(),
            Self::Reference { id, .. } => id.to_string(),
            Self::Missing(_) => String::new(),
        }
    }
    fn compare(&self, other: &Self) -> Result<Ordering> {
        Ok(match (self, other) {
            (Self::Text(a), Self::Text(b))
            | (Self::Choice(a), Self::Choice(b))
            | (Self::Account(a), Self::Account(b)) => a.cmp(b),
            (Self::Integer(a), Self::Integer(b)) => a.cmp(b),
            (Self::Boolean(a), Self::Boolean(b)) => a.cmp(b),
            (Self::Timestamp(a), Self::Timestamp(b)) => a.cmp(b),
            (Self::Duration(a), Self::Duration(b)) => a.cmp(b),
            (Self::Reference { resource: a, id: x }, Self::Reference { resource: b, id: y })
                if a == b =>
            {
                x.cmp(y)
            }
            (Self::Missing(a), Self::Missing(b))
                if std::mem::discriminant(a) == std::mem::discriminant(b) =>
            {
                Ordering::Equal
            }
            (Self::Missing(_), _) => Ordering::Less,
            (_, Self::Missing(_)) => Ordering::Greater,
            _ => anyhow::bail!(CalculationUnavailable),
        })
    }
}

pub(super) struct Context {
    pub snapshots: BTreeMap<(u32, u64), StoredRecord>,
    pub time: Option<AttemptTime>,
}

pub(crate) struct Values<'a> {
    pub manifest: &'a Manifest,
    pub input: &'a Fields,
    pub principal: &'a Principal,
    pub grants: &'a BTreeMap<String, RecordTarget>,
    pub snapshots: &'a BTreeMap<(u32, u64), StoredRecord>,
    pub outcomes: &'a [MutationOutcome],
    pub time: Option<AttemptTime>,
    pub current: Option<(&'a str, &'a StoredRecord)>,
}
impl Values<'_> {
    pub fn value(
        &self,
        value: &Value,
        action: crate::application::ActionCore<'_>,
    ) -> Result<Scalar> {
        Ok(match value {
            Value::Input(name) => {
                let schema = action
                    .inputs
                    .iter()
                    .find(|input| input.name == *name)
                    .ok_or(CalculationUnavailable)?;
                scalar(
                    &schema.kind,
                    schema.optional,
                    self.input.get(name).ok_or(CalculationUnavailable)?,
                )?
            }
            Value::Literal(literal) => match literal {
                Literal::Text(v) => Scalar::Text(v.clone()),
                Literal::Integer(v) => Scalar::Integer(*v),
                Literal::Boolean(v) => Scalar::Boolean(*v),
                Literal::Choice(v) => Scalar::Choice(v.clone()),
                Literal::Account(v) => Scalar::Account(v.clone()),
                Literal::Timestamp(v) => Scalar::Timestamp(*v),
                Literal::Duration(v) => Scalar::Duration(*v),
            },
            Value::Principal => Scalar::Account(
                self.principal
                    .user()
                    .map_err(|_| ReferenceUnavailable)?
                    .id
                    .clone(),
            ),
            Value::TransactionTime => {
                Scalar::Timestamp(self.time.ok_or(CalculationUnavailable)?.timestamp())
            }
            Value::Target(name) => {
                let grant = self.grants.get(name).ok_or(ReferenceUnavailable)?;
                Scalar::Reference {
                    resource: manifest::resource(self.manifest, grant.resource)?
                        .name
                        .clone(),
                    id: grant.id,
                }
            }
            Value::Created(index) => {
                let outcome = self
                    .outcomes
                    .get(usize::from(*index))
                    .ok_or(CalculationUnavailable)?;
                ensure!(
                    outcome.kind == MutationKind::Created,
                    CalculationUnavailable
                );
                Scalar::Reference {
                    resource: manifest::resource(self.manifest, outcome.resource)?
                        .name
                        .clone(),
                    id: outcome.id,
                }
            }
            Value::SnapshotField { target, field, .. } | Value::CurrentField { target, field } => {
                let grant = self.grants.get(target).ok_or(ReferenceUnavailable)?;
                let stored = if matches!(value, Value::SnapshotField { .. }) {
                    self.snapshots
                        .get(&(grant.resource, grant.id))
                        .ok_or(ReferenceUnavailable)?
                } else {
                    let (name, stored) = self.current.ok_or(CalculationUnavailable)?;
                    ensure!(name == target, CalculationUnavailable);
                    stored
                };
                let schema = manifest::resource(self.manifest, grant.resource)?
                    .fields
                    .iter()
                    .find(|candidate| candidate.name == *field)
                    .ok_or(CalculationUnavailable)?;
                scalar(
                    &schema.kind,
                    schema.optional,
                    stored
                        .record
                        .fields
                        .get(field)
                        .ok_or(CalculationUnavailable)?,
                )?
            }
            Value::Add { left, right }
            | Value::Subtract { left, right }
            | Value::Multiply { left, right } => {
                match (self.value(left, action)?, self.value(right, action)?) {
                    (Scalar::Integer(a), Scalar::Integer(b)) => Scalar::Integer(
                        if matches!(value, Value::Add { .. }) {
                            a.checked_add(b)
                        } else if matches!(value, Value::Subtract { .. }) {
                            a.checked_sub(b)
                        } else {
                            a.checked_mul(b)
                        }
                        .ok_or(CalculationUnavailable)?,
                    ),
                    (Scalar::Timestamp(timestamp), Scalar::Duration(duration))
                        if matches!(value, Value::Add { .. }) =>
                    {
                        Scalar::Timestamp(
                            timestamp
                                .checked_add(duration)
                                .map_err(|_| CalculationUnavailable)?,
                        )
                    }
                    _ => anyhow::bail!(CalculationUnavailable),
                }
            }
        })
    }
    fn condition(
        &self,
        condition: &GuardCondition,
        action: crate::application::ActionCore<'_>,
    ) -> Result<bool> {
        match condition {
            GuardCondition::All(conditions) => {
                for condition in conditions {
                    if !self.condition(condition, action)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            GuardCondition::Compare {
                left,
                comparison,
                right,
            } => {
                let order = self
                    .value(left, action)?
                    .compare(&self.value(right, action)?)?;
                Ok(match comparison {
                    Comparison::Equal => order == Ordering::Equal,
                    Comparison::NotEqual => order != Ordering::Equal,
                    Comparison::Less => order == Ordering::Less,
                    Comparison::LessOrEqual => order != Ordering::Greater,
                    Comparison::Greater => order == Ordering::Greater,
                    Comparison::GreaterOrEqual => order != Ordering::Less,
                })
            }
        }
    }
    pub fn guards(&self, step: &Step, action: crate::application::ActionCore<'_>) -> Result<()> {
        for guard in &step.guards {
            if !self.condition(&guard.condition, action)? {
                return Err(GuardFailure {
                    input: guard.rejection.input.clone(),
                    message: guard.rejection.message.clone(),
                }
                .into());
            }
        }
        Ok(())
    }
}
fn scalar(kind: &FieldKind, optional: bool, text: &str) -> Result<Scalar> {
    ensure!(
        !matches!(
            kind,
            FieldKind::Blob { .. } | FieldKind::UploadHandle { .. }
        ),
        "opaque blob identity is not a scalar operand"
    );
    if optional && text.is_empty() {
        return Ok(Scalar::Missing(kind.clone()));
    }
    Ok(match kind {
        FieldKind::Blob { .. } | FieldKind::UploadHandle { .. } => {
            anyhow::bail!("opaque blob identity is not a scalar operand")
        }
        FieldKind::Text => Scalar::Text(text.into()),
        FieldKind::Integer { .. } => Scalar::Integer(text.parse()?),
        FieldKind::Boolean => {
            ensure!(matches!(text, "true" | "false"), CalculationUnavailable);
            Scalar::Boolean(text == "true")
        }
        FieldKind::Choice { .. } => Scalar::Choice(text.into()),
        FieldKind::Account { .. } => Scalar::Account(text.into()),
        FieldKind::Timestamp => Scalar::Timestamp(Timestamp::from_unix_millis(text.parse()?)?),
        FieldKind::Duration { .. } => Scalar::Duration(Duration::from_millis(text.parse()?)?),
        FieldKind::Reference { resource } => Scalar::Reference {
            resource: resource.clone(),
            id: text.parse()?,
        },
    })
}

pub(super) fn current_field(condition: &GuardCondition) -> bool {
    match condition {
        GuardCondition::All(conditions) => conditions.iter().any(current_field),
        GuardCondition::Compare { left, right, .. } => current_value(left) || current_value(right),
    }
}
fn current_value(value: &Value) -> bool {
    match value {
        Value::CurrentField { .. } => true,
        Value::Add { left, right }
        | Value::Subtract { left, right }
        | Value::Multiply { left, right } => current_value(left) || current_value(right),
        _ => false,
    }
}

impl Effects {
    pub(super) fn computation_values<'a>(
        &'a self,
        context: &'a Context,
        outcomes: &'a [MutationOutcome],
        step: &'a Step,
        stored: Option<&'a StoredRecord>,
    ) -> Values<'a> {
        Values {
            manifest: &self.manifest,
            input: &self.request.input,
            principal: &self.principal,
            grants: &self.grants,
            snapshots: &context.snapshots,
            outcomes,
            time: context.time,
            current: match (&step.target, stored) {
                (Target::Named(name), Some(stored)) => Some((name, stored)),
                _ => None,
            },
        }
    }
    pub(super) async fn current_guard_authority(
        &mut self,
        action: crate::application::ActionCore<'_>,
        step: &Step,
        stored: Option<&StoredRecord>,
    ) -> Result<()> {
        if !step
            .guards
            .iter()
            .any(|guard| current_field(&guard.condition))
        {
            return Ok(());
        }
        let Target::Named(name) = &step.target else {
            anyhow::bail!(CalculationUnavailable)
        };
        let target = manifest::action_target(action.targets, name)?;
        let projection = target.projection.as_ref().ok_or(CalculationUnavailable)?;
        let read = manifest::operation(&self.manifest, projection.operation)?.clone();
        ensure!(
            authorize_stored_read(
                &mut self.read_context(),
                &read,
                stored.ok_or(ReferenceUnavailable)?
            )
            .await?,
            ReferenceUnavailable
        );
        Ok(())
    }
    /// P07's membership resolver joins here after references/accounts/initial
    /// values have produced the canonical candidate and before guards or writes.
    pub(super) async fn authorize_create_row(
        &mut self,
        operation: &Operation,
        fields: &Fields,
    ) -> Result<()> {
        self.authorize_candidate(operation, fields).await
    }
}
