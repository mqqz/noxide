//! Independent job admission joined to the existing action type/budget checker.
use super::*;
use noxide_protocol::jobs::{RecurringSchedule, Schedule};
use std::collections::BTreeMap;

/// Runs before the source action's unused-input check using its ONE existing
/// counter. `steps.len()` is the schedule site: current/principal/reference scalar
/// operands are refused by the common evaluator, while initial snapshots remain.
pub(super) fn action_values<'a>(
    manifest: &Manifest,
    action: &'a Action,
    admission: &mut computation::Admission,
    used: &mut BTreeSet<&'a str>,
) -> Result<()> {
    let Some(jobs) = &manifest.jobs else {
        return Ok(());
    };
    for schedule in jobs
        .schedules
        .iter()
        .filter(|schedule| schedule.source_action == action.id)
    {
        let called = super::action(manifest, schedule.action)?;
        for (name, value) in &schedule.inputs {
            let input = called
                .inputs
                .iter()
                .find(|input| input.name == *name)
                .ok_or_else(|| anyhow::anyhow!("unknown scheduled action input"))?;
            let domain =
                admission.value(manifest, action, action.steps.len(), value, false, used)?;
            ensure!(
                computation::fits_input(&domain, input),
                "scheduled input domain does not fit destination"
            );
        }
        let due = admission.value(
            manifest,
            action,
            action.steps.len(),
            &schedule.due_at,
            false,
            used,
        )?;
        ensure!(
            due.kind == FieldKind::Timestamp && !due.optional,
            "schedule due time requires a nonoptional timestamp"
        );
    }
    Ok(())
}

fn recurring_inputs(manifest: &Manifest, schedule: &RecurringSchedule) -> Result<()> {
    let called = action(manifest, schedule.action)?;
    for (name, value) in &schedule.inputs {
        let input = called
            .inputs
            .iter()
            .find(|input| input.name == *name)
            .ok_or_else(|| anyhow::anyhow!("unknown recurring action input"))?;
        ensure!(
            computation::fits_input(&computation::literal_domain(value)?, input),
            "recurring literal does not fit destination input"
        );
    }
    if let Some(selection) = &schedule.selection {
        let query = operation(manifest, selection.operation)?;
        ensure!(query.policy.any.len() == 1 && query.policy.any[0].len() == 2
            && query.policy.any[0].iter().any(|predicate| matches!(predicate, Predicate::Service { worker } if worker == &schedule.worker))
            && query.policy.any[0].contains(&Predicate::SameTenant), "recurring selection requires exactly its service and tenant predicates");
        ensure!(
            query.via.is_none()
                && query.scope.is_none()
                && query.query.is_none()
                && query.list.as_ref().is_none_or(|list| list.preview.is_none()
                    && matches!(list.order, ListOrder::CreatedAsc | ListOrder::CreatedDesc)),
            "recurring selection requires fixed creation order without search or ranges"
        );
        for condition in &query.filter {
            let field = resource(manifest, query.resource)?
                .fields
                .iter()
                .find(|field| field.name == condition.field)
                .ok_or_else(|| anyhow::anyhow!("unknown recurring filter field"))?;
            ensure!(
                matches!(field.kind, FieldKind::Boolean | FieldKind::Choice { .. })
                    && matches!(condition.equals, Operand::Literal(_)),
                "recurring filters require fixed boolean or choice literals"
            );
        }
        if selection.expiry_repair {
            let target = action_target(&called.targets, &selection.target)?;
            let eligible = match target.source {
                TargetSource::Service { eligible } => operation(manifest, eligible)?,
                _ => anyhow::bail!("recurring selection requires a service root"),
            };
            ensure!(
                query.maintenance
                    && eligible.maintenance
                    && called
                        .steps
                        .iter()
                        .all(|step| operation(manifest, step.operation)
                            .is_ok_and(|op| op.maintenance)),
                "expiry repair requires approved maintenance selection, read and mutations"
            );
        }
    }
    Ok(())
}

pub fn validate(manifest: &Manifest) -> Result<()> {
    let Some(jobs) = &manifest.jobs else {
        ensure!(
            manifest.operations.iter().all(|op| !op.maintenance
                && op
                    .policy
                    .any
                    .iter()
                    .flatten()
                    .all(|predicate| !matches!(predicate, Predicate::Service { .. })))
                && manifest
                    .actions
                    .iter()
                    .flat_map(|action| &action.targets)
                    .all(|target| !matches!(target.source, TargetSource::Service { .. })),
            "service authority requires declared workers"
        );
        return Ok(());
    };
    // Scalar typing has already run with each source action's shared node and
    // used-input state. A second expression counter here would reset its ceiling.
    job_contract::validate_contract(
        manifest,
        jobs,
        |_: &Schedule| Ok(()),
        |schedule| recurring_inputs(manifest, schedule),
    )?;
    let workers: BTreeSet<_> = jobs
        .workers
        .iter()
        .map(|worker| worker.name.as_str())
        .collect();
    let mut actions = BTreeSet::new();
    let mut service_operations: BTreeMap<&str, BTreeSet<u32>> = BTreeMap::new();
    for worker in &jobs.workers {
        let operations = service_operations.entry(worker.name.as_str()).or_default();
        for rule in &worker.actions {
            actions.insert(rule.action);
            let called = action(manifest, rule.action)?;
            operations.extend(called.steps.iter().map(|step| step.operation));
            for target in &called.targets {
                let eligible = match target.source {
                    TargetSource::Service { eligible }
                    | TargetSource::Reference { eligible, .. } => eligible,
                    _ => anyhow::bail!("worker target source is not server verified"),
                };
                operations.insert(eligible);
                operations.extend(
                    target
                        .projection
                        .iter()
                        .chain(target.inspect.iter())
                        .map(|projection| projection.operation),
                );
            }
        }
    }
    for recurring in &jobs.recurring {
        if let Some(selection) = &recurring.selection {
            service_operations
                .entry(recurring.worker.as_str())
                .or_default()
                .insert(selection.operation);
        }
    }
    for declared in &manifest.actions {
        ensure!(
            declared
                .targets
                .iter()
                .all(|target| !matches!(target.source, TargetSource::Service { .. }))
                || actions.contains(&declared.id),
            "service targets require a declared worker action"
        );
    }
    for op in &manifest.operations {
        for rule in &op.policy.any {
            for predicate in rule {
                if let Predicate::Service { worker } = predicate {
                    ensure!(
                        identifier(worker) && workers.contains(worker.as_str()),
                        "unknown service identity"
                    );
                }
            }
        }
        if op.maintenance {
            ensure!(
                matches!(
                    op.kind,
                    OperationKind::Read
                        | OperationKind::List
                        | OperationKind::Update
                        | OperationKind::Delete
                ) && op.via.is_none()
                    && op.policy.any.iter().all(|rule| {
                        let names: Vec<_> = rule
                            .iter()
                            .filter_map(|predicate| {
                                if let Predicate::Service { worker } = predicate {
                                    Some(worker.as_str())
                                } else {
                                    None
                                }
                            })
                            .collect();
                        names.len() == 1
                            && service_operations
                                .get(names[0])
                                .is_some_and(|operations| operations.contains(&op.id))
                    }),
                "maintenance requires explicit reachable service-only authority"
            );
            ensure!(
                !manifest
                    .routes
                    .iter()
                    .any(|route| route.operations.contains(&op.id)),
                "maintenance operations cannot be exposed by routes"
            );
            for binding in &manifest.web_bindings {
                let called = action(manifest, binding.action)?;
                ensure!(
                    !called.steps.iter().any(|step| step.operation == op.id)
                        && !called.targets.iter().any(|target| {
                            let eligible = match target.source {
                                TargetSource::Page { ref reads } => reads.contains(&op.id),
                                TargetSource::Service { eligible }
                                | TargetSource::Reference { eligible, .. }
                                | TargetSource::Selected { eligible, .. } => eligible == op.id,
                            };
                            eligible
                                || target
                                    .projection
                                    .iter()
                                    .chain(target.inspect.iter())
                                    .any(|projection| projection.operation == op.id)
                        }),
                    "web bindings cannot expose maintenance authority"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
