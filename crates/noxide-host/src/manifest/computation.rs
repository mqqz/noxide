//! Type/domain and disclosure admission for the existing action executor.
use super::*;
use noxide_protocol::computation::{MAX_EXPRESSION_DEPTH, MAX_EXPRESSION_NODES, MAX_GUARDS};

#[derive(Clone, Debug)]
pub(super) struct Domain {
    pub kind: FieldKind,
    pub optional: bool,
    pub max_bytes: u32,
}
impl Domain {
    fn field(field: &TextField) -> Self {
        Self {
            kind: field.kind.clone(),
            optional: field.optional,
            max_bytes: field.max_bytes,
        }
    }
    fn input(input: &Input) -> Self {
        Self {
            kind: input.kind.clone(),
            optional: input.optional,
            max_bytes: input.max_bytes,
        }
    }
    fn integer(min: i64, max: i64) -> Self {
        Self {
            kind: FieldKind::Integer {
                min: Some(min),
                max: Some(max),
            },
            optional: false,
            max_bytes: 20,
        }
    }
    fn number(&self) -> Result<(i64, i64)> {
        ensure!(!self.optional, "optional arithmetic operand");
        let FieldKind::Integer { min, max } = self.kind else {
            anyhow::bail!("integer arithmetic required")
        };
        Ok((min.unwrap_or(i64::MIN), max.unwrap_or(i64::MAX)))
    }
}
#[derive(Default)]
pub(super) struct Admission {
    pub nodes: usize,
    pub guards: usize,
}
impl Admission {
    fn node(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        ensure!(
            self.nodes <= MAX_EXPRESSION_NODES && depth <= MAX_EXPRESSION_DEPTH,
            "expression node/depth limit"
        );
        Ok(())
    }
    pub fn value<'a>(
        &mut self,
        m: &Manifest,
        a: &'a Action,
        index: usize,
        value: &Value,
        guard: bool,
        used: &mut BTreeSet<&'a str>,
    ) -> Result<Domain> {
        self.walk(m, a, index, value, guard, used, 1)
    }
    #[allow(clippy::too_many_arguments)]
    fn walk<'a>(
        &mut self,
        m: &Manifest,
        a: &'a Action,
        index: usize,
        value: &Value,
        guard: bool,
        used: &mut BTreeSet<&'a str>,
        depth: usize,
    ) -> Result<Domain> {
        self.node(depth)?;
        Ok(match value {
            Value::Input(name) => {
                let input = a
                    .inputs
                    .iter()
                    .find(|input| input.name == *name)
                    .ok_or_else(|| anyhow::anyhow!("undeclared input"))?;
                used.insert(input.name.as_str());
                Domain::input(input)
            }
            Value::Literal(literal) => literal_domain(literal)?,
            Value::Principal => {
                ensure!(
                    !guard && operation(m, a.steps[index].operation)?.kind == OperationKind::Create,
                    "principal is create-account-only"
                );
                Domain {
                    kind: FieldKind::Account {
                        scope: AccountScope::SameTenant,
                    },
                    optional: false,
                    max_bytes: 43,
                }
            }
            Value::TransactionTime => Domain {
                kind: FieldKind::Timestamp,
                optional: false,
                max_bytes: 20,
            },
            Value::Target(name) => {
                let target = action_target(&a.targets, name)?;
                Domain {
                    kind: FieldKind::Reference {
                        resource: resource(m, target.resource)?.name.clone(),
                    },
                    optional: false,
                    max_bytes: 19,
                }
            }
            Value::Created(created) => {
                let created = usize::from(*created);
                ensure!(
                    created < index,
                    "created reference must name an earlier step"
                );
                let op = operation(m, a.steps[created].operation)?;
                ensure!(
                    op.kind == OperationKind::Create,
                    "created reference requires create step"
                );
                Domain {
                    kind: FieldKind::Reference {
                        resource: resource(m, op.resource)?.name.clone(),
                    },
                    optional: false,
                    max_bytes: 19,
                }
            }
            Value::SnapshotField { target, field, .. } | Value::CurrentField { target, field } => {
                let declaration = action_target(&a.targets, target)?;
                if matches!(value, Value::SnapshotField { reviewed: true, .. }) {
                    ensure!(
                        declaration.revision == Revision::Exact,
                        "reviewed source requires exact target revision"
                    );
                }
                if matches!(value, Value::CurrentField { .. }) {
                    ensure!(
                        guard
                            && matches!(&a.steps[index].target,Target::Named(name) if name==target),
                        "current fields are current-step guard-only"
                    );
                }
                let projection = declaration.projection.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("expression requires explicit compute projection")
                })?;
                ensure!(
                    projection.fields.contains(field),
                    "expression field outside compute projection"
                );
                let read = operation(m, projection.operation)?;
                ensure!(
                    read.kind == OperationKind::Read
                        && read.via.is_none()
                        && read.resource == declaration.resource,
                    "invalid expression read authority"
                );
                Domain::field(
                    resource(m, declaration.resource)?
                        .fields
                        .iter()
                        .find(|candidate| candidate.name == *field)
                        .ok_or_else(|| anyhow::anyhow!("unknown expression field"))?,
                )
            }
            Value::Add { left, right }
            | Value::Subtract { left, right }
            | Value::Multiply { left, right } => {
                let left = self.walk(m, a, index, left, guard, used, depth + 1)?;
                let right = self.walk(m, a, index, right, guard, used, depth + 1)?;
                if matches!(value, Value::Add { .. })
                    && left.kind == FieldKind::Timestamp
                    && matches!(right.kind, FieldKind::Duration { .. })
                {
                    ensure!(
                        !left.optional && !right.optional,
                        "optional timestamp arithmetic"
                    );
                    Domain {
                        kind: FieldKind::Timestamp,
                        optional: false,
                        max_bytes: 20,
                    }
                } else {
                    let (a, b) = left.number()?;
                    let (c, d) = right.number()?;
                    let range = if matches!(value, Value::Add { .. }) {
                        (i128::from(a) + i128::from(c), i128::from(b) + i128::from(d))
                    } else if matches!(value, Value::Subtract { .. }) {
                        (i128::from(a) - i128::from(d), i128::from(b) - i128::from(c))
                    } else {
                        let products = [
                            i128::from(a) * i128::from(c),
                            i128::from(a) * i128::from(d),
                            i128::from(b) * i128::from(c),
                            i128::from(b) * i128::from(d),
                        ];
                        (
                            *products.iter().min().unwrap(),
                            *products.iter().max().unwrap(),
                        )
                    };
                    ensure!(
                        range.0 <= i128::from(i64::MAX) && range.1 >= i128::from(i64::MIN),
                        "expression always overflows"
                    );
                    Domain::integer(
                        range.0.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64,
                        range.1.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64,
                    )
                }
            }
        })
    }
    pub fn guards<'a>(
        &mut self,
        m: &Manifest,
        a: &'a Action,
        index: usize,
        used: &mut BTreeSet<&'a str>,
    ) -> Result<()> {
        for guard in &a.steps[index].guards {
            rejection(a, &guard.rejection)?;
            self.condition(m, a, index, &guard.condition, used, 1)?;
        }
        Ok(())
    }
    fn condition<'a>(
        &mut self,
        m: &Manifest,
        a: &'a Action,
        index: usize,
        condition: &GuardCondition,
        used: &mut BTreeSet<&'a str>,
        depth: usize,
    ) -> Result<()> {
        self.guards += 1;
        ensure!(
            self.guards <= MAX_GUARDS && depth <= MAX_EXPRESSION_DEPTH,
            "guard count/depth limit"
        );
        match condition {
            GuardCondition::All(conditions) => {
                ensure!(
                    !conditions.is_empty() && conditions.len() <= MAX_GUARDS,
                    "invalid guard conjunction"
                );
                for condition in conditions {
                    self.condition(m, a, index, condition, used, depth + 1)?;
                }
            }
            GuardCondition::Compare {
                left,
                comparison,
                right,
            } => {
                let left = self.value(m, a, index, left, true, used)?;
                let right = self.value(m, a, index, right, true, used)?;
                ensure!(
                    same_type(&left.kind, &right.kind),
                    "guard comparison type mismatch"
                );
                if !matches!(comparison, Comparison::Equal | Comparison::NotEqual) {
                    ensure!(
                        !left.optional
                            && !right.optional
                            && matches!(
                                left.kind,
                                FieldKind::Integer { .. }
                                    | FieldKind::Timestamp
                                    | FieldKind::Duration { .. }
                            ),
                        "ordered guard requires nonoptional numeric/time operands"
                    );
                }
            }
        }
        Ok(())
    }
}
fn literal_domain(literal: &Literal) -> Result<Domain> {
    let (kind, encoded) = match literal {
        Literal::Text(value) => (FieldKind::Text, value.clone()),
        Literal::Integer(value) => return Ok(Domain::integer(*value, *value)),
        Literal::Boolean(value) => (FieldKind::Boolean, value.to_string()),
        Literal::Choice(value) => {
            ensure!(identifier(value), "invalid choice literal");
            (
                FieldKind::Choice {
                    variants: vec![ChoiceVariant {
                        key: value.clone(),
                        label: value.clone(),
                    }],
                },
                value.clone(),
            )
        }
        Literal::Account(value) => (
            FieldKind::Account {
                scope: AccountScope::SameTenant,
            },
            value.clone(),
        ),
        Literal::Timestamp(value) => (FieldKind::Timestamp, value.unix_millis().to_string()),
        Literal::Duration(value) => (
            FieldKind::Duration {
                max_millis: value.as_millis(),
            },
            value.as_millis().to_string(),
        ),
    };
    let field = TextField {
        name: "literal".into(),
        label: "Literal".into(),
        kind: kind.clone(),
        optional: false,
        initial: None,
        max_bytes: 4096,
    };
    ensure!(
        field
            .canonical(&encoded)
            .is_ok_and(|value| value == encoded),
        "noncanonical literal"
    );
    Ok(Domain {
        kind,
        optional: false,
        max_bytes: encoded.len() as u32,
    })
}
fn same_type(left: &FieldKind, right: &FieldKind) -> bool {
    match (left, right) {
        (FieldKind::Integer { .. }, FieldKind::Integer { .. })
        | (FieldKind::Choice { .. }, FieldKind::Choice { .. })
        | (FieldKind::Duration { .. }, FieldKind::Duration { .. }) => true,
        _ => left == right,
    }
}
pub(super) fn fits(domain: &Domain, field: &TextField) -> bool {
    let input = Input {
        name: "value".into(),
        label: "Value".into(),
        kind: domain.kind.clone(),
        optional: domain.optional,
        max_bytes: domain.max_bytes,
    };
    input_fits(&input, field)
}
pub(super) fn rejection(action: &Action, rejection: &GuardRejection) -> Result<()> {
    ensure!(
        rejection
            .input
            .as_ref()
            .is_none_or(|name| action.inputs.iter().any(|input| input.name == *name)),
        "undeclared rejection input"
    );
    ensure!(
        !rejection.message.is_empty()
            && rejection.message.len() <= 256
            && !rejection
                .message
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\t')),
        "invalid guard rejection message"
    );
    Ok(())
}

/// Operator-visible source disclosures derived from the approved action itself.
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComputationSource {
    Snapshot {
        target: String,
        field: String,
        read: u32,
        reviewed: bool,
    },
    Current {
        target: String,
        field: String,
        read: u32,
    },
    Principal,
    TransactionTime,
    Created {
        step: u8,
    },
    Target {
        name: String,
    },
    AdjustmentBound {
        target: String,
        field: String,
    },
}
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct ComputationDisclosure {
    pub step: u8,
    pub operation: u32,
    pub destination_field: Option<String>,
    pub rejection: Option<GuardRejection>,
    pub source: ComputationSource,
}
pub fn action_disclosures(manifest: &Manifest, id: u32) -> Result<Vec<ComputationDisclosure>> {
    validate(manifest)?;
    let action = action(manifest, id)?;
    let mut disclosures = Vec::new();
    fn collect(
        value: &Value,
        action: &Action,
        base: &ComputationDisclosure,
        out: &mut Vec<ComputationDisclosure>,
    ) -> Result<()> {
        let source = match value {
            Value::SnapshotField {
                target,
                field,
                reviewed,
            } => Some(ComputationSource::Snapshot {
                target: target.clone(),
                field: field.clone(),
                read: action_target(&action.targets, target)?
                    .projection
                    .as_ref()
                    .expect("admitted compute projection")
                    .operation,
                reviewed: *reviewed,
            }),
            Value::CurrentField { target, field } => Some(ComputationSource::Current {
                target: target.clone(),
                field: field.clone(),
                read: action_target(&action.targets, target)?
                    .projection
                    .as_ref()
                    .expect("admitted compute projection")
                    .operation,
            }),
            Value::Principal => Some(ComputationSource::Principal),
            Value::TransactionTime => Some(ComputationSource::TransactionTime),
            Value::Target(name) => Some(ComputationSource::Target { name: name.clone() }),
            Value::Created(step) => Some(ComputationSource::Created { step: *step }),
            Value::Add { left, right }
            | Value::Subtract { left, right }
            | Value::Multiply { left, right } => {
                collect(left, action, base, out)?;
                collect(right, action, base, out)?;
                None
            }
            Value::Input(_) | Value::Literal(_) => None,
        };
        if let Some(source) = source {
            let mut disclosure = base.clone();
            disclosure.source = source;
            out.push(disclosure);
        }
        Ok(())
    }
    fn guard(
        condition: &GuardCondition,
        action: &Action,
        base: &ComputationDisclosure,
        out: &mut Vec<ComputationDisclosure>,
    ) -> Result<()> {
        match condition {
            GuardCondition::All(conditions) => {
                for condition in conditions {
                    guard(condition, action, base, out)?;
                }
            }
            GuardCondition::Compare { left, right, .. } => {
                collect(left, action, base, out)?;
                collect(right, action, base, out)?;
            }
        }
        Ok(())
    }
    for (index, step) in action.steps.iter().enumerate() {
        let mut assignments: Vec<_> = step.assign.iter().collect();
        assignments.sort_by(|a, b| a.field.cmp(&b.field));
        for assignment in assignments {
            let mut base = ComputationDisclosure {
                step: index as u8,
                operation: step.operation,
                destination_field: Some(assignment.field.clone()),
                rejection: None,
                source: ComputationSource::Principal,
            };
            match &assignment.change {
                Change::Set(value) => collect(value, action, &base, &mut disclosures)?,
                Change::Increase { by, rejection } | Change::Decrease { by, rejection } => {
                    base.rejection = Some(rejection.clone());
                    collect(by, action, &base, &mut disclosures)?;
                    let Target::Named(target) = &step.target else {
                        unreachable!("admitted adjustment target")
                    };
                    base.source = ComputationSource::AdjustmentBound {
                        target: target.clone(),
                        field: assignment.field.clone(),
                    };
                    disclosures.push(base);
                }
            }
        }
        for condition in &step.guards {
            let base = ComputationDisclosure {
                step: index as u8,
                operation: step.operation,
                destination_field: None,
                rejection: Some(condition.rejection.clone()),
                source: ComputationSource::Principal,
            };
            guard(&condition.condition, action, &base, &mut disclosures)?;
        }
    }
    Ok(disclosures)
}
