//! Independent structural authority admission. Expression domain/disclosure
//! checks are delegated to the SAME computation admission used by action steps.
use crate::manifest;
use anyhow::{Context, Result, ensure};
use noxide_protocol::{Manifest, OperationKind, TargetSource, Value, jobs::*};
use std::collections::{BTreeMap, BTreeSet};

#[allow(clippy::too_many_lines)]
pub fn validate_contract(
    manifest: &Manifest,
    contract: &JobContract,
    mut validate_schedule_values: impl FnMut(&Schedule) -> Result<()>,
    mut validate_recurring_inputs: impl FnMut(&RecurringSchedule) -> Result<()>,
) -> Result<()> {
    ensure!(
        contract.workers.len() <= 32
            && contract.schedules.len() <= 64
            && contract.recurring.len() <= 32,
        "job declaration limit"
    );
    let mut workers = BTreeMap::new();
    for worker in &contract.workers {
        ensure!(
            manifest::identifier(&worker.name)
                && !worker.actions.is_empty()
                && worker.actions.len() <= 32
                && workers.insert(&worker.name, worker).is_none(),
            "invalid or duplicate worker"
        );
        let mut actions = BTreeSet::new();
        for rule in &worker.actions {
            ensure!(actions.insert(rule.action), "duplicate worker action");
            let action = manifest::action(manifest, rule.action)?;
            ensure!(
                !manifest
                    .web_bindings
                    .iter()
                    .any(|binding| binding.action == action.id),
                "worker action cannot have a web binding"
            );
            ensure!(
                action.targets.len() == rule.targets.len(),
                "worker target rules must be exact"
            );
            for target in &action.targets {
                let binding = rule
                    .targets
                    .get(&target.name)
                    .context("missing worker target rule")?;
                ensure!(
                    binding.resource == target.resource,
                    "worker target resource mismatch"
                );
                // Central integration adds the explicit service-only source.
                ensure!(
                    match &target.source {
                        TargetSource::Service { eligible }
                        | TargetSource::Reference { eligible, .. } => *eligible == binding.eligible,
                        _ => false,
                    },
                    "worker target requires service root or approved reference binding"
                );
                let read = manifest::operation(manifest, binding.eligible)?;
                ensure!(
                    read.kind == OperationKind::Read && read.resource == binding.resource,
                    "invalid worker eligible read"
                );
            }
            for step in &action.steps {
                let operation = manifest::operation(manifest, step.operation)?;
                ensure!(
                    matches!(
                        operation.kind,
                        OperationKind::Update | OperationKind::Delete
                    ),
                    "service actions update or delete only"
                );
            }
            for input in &action.inputs {
                ensure!(
                    !matches!(
                        input.kind,
                        noxide_protocol::FieldKind::UploadHandle { .. }
                            | noxide_protocol::FieldKind::Blob { .. }
                            | noxide_protocol::FieldKind::Reference { .. }
                    ),
                    "service input cannot persist opaque browser handles"
                );
            }
        }
    }
    let mut positions = BTreeSet::new();
    let mut graph: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for schedule in &contract.schedules {
        ensure!(
            schedule.ordinal < MAX_SCHEDULES_PER_ACTION as u8
                && positions.insert((schedule.source_action, schedule.ordinal)),
            "duplicate or excessive schedule position"
        );
        let source = manifest::action(manifest, schedule.source_action)?;
        let destination = worker_action(&workers, &schedule.worker, schedule.action)?;
        ensure!(
            schedule.targets.keys().eq(destination.targets.keys()),
            "schedule target aliases differ"
        );
        let called = manifest::action(manifest, schedule.action)?;
        let inputs: BTreeSet<_> = called.inputs.iter().map(|input| &input.name).collect();
        ensure!(
            inputs == schedule.inputs.keys().collect(),
            "schedule input aliases differ"
        );
        for (alias, binding) in &schedule.targets {
            let resource = match binding {
                ScheduledTarget::Target(name) => {
                    manifest::action_target(&source.targets, name)?.resource
                }
                ScheduledTarget::Created(index) => {
                    let step = source
                        .steps
                        .get(usize::from(*index))
                        .context("schedule create index unavailable")?;
                    let operation = manifest::operation(manifest, step.operation)?;
                    ensure!(
                        operation.kind == OperationKind::Create,
                        "schedule requires a created target"
                    );
                    operation.resource
                }
            };
            ensure!(
                resource == destination.targets[alias].resource,
                "schedule target resource differs"
            );
        }
        // No persisted principal impersonation or step-current mutable reads.
        for value in schedule
            .inputs
            .values()
            .chain(std::iter::once(&schedule.due_at))
        {
            safe_value(value, 0, &mut 0)?;
        }
        validate_schedule_values(schedule)?;
        graph.entry(source.id).or_default().push(schedule.action);
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for action in graph.keys() {
        visit(*action, &graph, &mut visiting, &mut visited)?;
    }
    let mut recurring_names = BTreeSet::new();
    for schedule in &contract.recurring {
        ensure!(
            manifest::identifier(&schedule.name)
                && recurring_names.insert(&schedule.name)
                && schedule.interval.as_millis() >= MIN_RECURRENCE_MILLIS
                && schedule.interval.as_millis() <= MAX_SCHEDULE_HORIZON_MILLIS,
            "invalid recurring schedule"
        );
        let action = worker_action(&workers, &schedule.worker, schedule.action)?;
        let called = manifest::action(manifest, schedule.action)?;
        let inputs: BTreeSet<_> = called.inputs.iter().map(|input| &input.name).collect();
        ensure!(
            inputs == schedule.inputs.keys().collect(),
            "recurring input aliases differ"
        );
        match &schedule.selection {
            Some(selection) => {
                validate_recurring_targets(manifest, action, selection)?;
                let query = manifest::operation(manifest, selection.operation)?;
                ensure!(
                    query.kind == OperationKind::List
                        && query.resource == action.targets[&selection.target].resource
                        && query.scope.is_none()
                        && query.filter.iter().all(|condition| matches!(
                            condition.equals,
                            noxide_protocol::Operand::Literal(_)
                        )),
                    "invalid recurring indexed selection"
                );
                if selection.expiry_repair {
                    ensure!(
                        manifest::resource(manifest, query.resource)?
                            .expiry
                            .is_some(),
                        "expiry repair requires resource expiry"
                    );
                    // Central maintenance admission must additionally establish
                    // the exact query/action's approved expired-row authority.
                }
            }
            None => ensure!(
                action.targets.is_empty(),
                "targeted recurrence requires selection"
            ),
        }
        validate_recurring_inputs(schedule)?;
    }
    Ok(())
}
fn worker_action<'a>(
    workers: &BTreeMap<&String, &'a Worker>,
    worker: &String,
    action: u32,
) -> Result<&'a WorkerAction> {
    workers
        .get(worker)
        .context("undeclared service worker")?
        .actions
        .iter()
        .find(|rule| rule.action == action)
        .context("undeclared service action")
}
fn visit(
    action: u32,
    graph: &BTreeMap<u32, Vec<u32>>,
    visiting: &mut BTreeSet<u32>,
    visited: &mut BTreeSet<u32>,
) -> Result<()> {
    if visited.contains(&action) {
        return Ok(());
    }
    ensure!(
        visiting.insert(action),
        "schedule call graph must be acyclic"
    );
    if let Some(destinations) = graph.get(&action) {
        for destination in destinations {
            visit(*destination, graph, visiting, visited)?;
        }
    }
    visiting.remove(&action);
    visited.insert(action);
    Ok(())
}
fn safe_value(value: &Value, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    ensure!(depth < 8 && *nodes <= 64, "schedule expression limit");
    match value {
        Value::Principal | Value::CurrentField { .. } | Value::Target(_) | Value::Created(_) => {
            anyhow::bail!("invalid persisted scalar expression")
        }
        Value::Add { left, right }
        | Value::Subtract { left, right }
        | Value::Multiply { left, right } => {
            safe_value(left, depth + 1, nodes)?;
            safe_value(right, depth + 1, nodes)?;
        }
        _ => {}
    }
    Ok(())
}

/// One indexed service root may carry the action's already admitted one-hop
/// immutable bindings. Every alias retains its own independent eligible read.
pub fn validate_recurring_targets(
    m: &Manifest,
    rule: &WorkerAction,
    selection: &RecurringSelection,
) -> Result<()> {
    let action = manifest::action(m, rule.action)?;
    ensure!(
        !action.targets.is_empty()
            && action.targets.len() <= 4
            && rule.targets.len() == action.targets.len(),
        "recurrence target bound differs from action"
    );
    let root = action
        .targets
        .iter()
        .find(|target| target.name == selection.target)
        .context("recurrence service root missing")?;
    ensure!(
        matches!(root.source, TargetSource::Service { .. }),
        "recurrence must select its service root"
    );
    for target in &action.targets {
        let eligible = match &target.source {
            TargetSource::Service { eligible } if target.name == root.name => *eligible,
            TargetSource::Reference {
                target: parent,
                field,
                eligible,
            } if parent == &root.name => {
                ensure!(
                    manifest::reference_resource(m, root.resource, field)?
                        .map(|resource| resource.id)
                        == Some(target.resource),
                    "recurrence derived resource mismatch"
                );
                *eligible
            }
            _ => anyhow::bail!("recurrence requires one service root and one-hop references"),
        };
        let binding = rule
            .targets
            .get(&target.name)
            .context("recurrence binding missing")?;
        let read = manifest::operation(m, eligible)?;
        ensure!(
            binding.resource == target.resource
                && binding.eligible == eligible
                && read.kind == OperationKind::Read
                && read.resource == target.resource,
            "recurrence independent read mismatch"
        );
    }
    Ok(())
}
