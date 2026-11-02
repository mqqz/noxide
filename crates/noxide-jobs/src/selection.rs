//! Validating a recurring schedule's selection and its resumable frontier. The host
//! reads and authorizes candidates; nothing here loads a record.
use crate::{SealedTarget, VerifiedScheduleGrant, database::lifecycle::RequestScope};
use anyhow::{Result, ensure};
use noxide_admission::{manifest as admitted, query_plan::ListPlan};
use noxide_protocol::{
    Action, ListOrder, Manifest, Operand, Operation, OperationKind, Predicate, Resource,
    jobs::{MAX_RECURRENCE_FANOUT, RecurringSchedule, RecurringSelection, WorkerAction},
    query::CursorKey,
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

const CURSOR_BYTES: usize = 4096;

pub struct SelectedTarget {
    pub targets: BTreeMap<String, SealedTarget>,
    pub expiry: Option<Timestamp>,
}
pub struct SelectionPage {
    pub items: Vec<SelectedTarget>,
    pub next_cursor: Option<String>,
    pub complete: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frontier {
    version: u8,
    binding: String,
    pub after: Option<CursorKey>,
}
impl Frontier {
    fn decode(
        raw: Option<&str>,
        binding: String,
        plan: &ListPlan,
        manifest: &Manifest,
        cutoff_seq: u64,
    ) -> Result<Self> {
        RequestScope::checkpoint_current()?;
        let Some(raw) = raw else {
            return Ok(Self {
                version: 1,
                binding,
                after: None,
            });
        };
        ensure!(raw.len() <= CURSOR_BYTES, "recurring cursor byte limit");
        let value: Self = serde_json::from_str(raw)?;
        ensure!(
            value.version == 1 && value.binding == binding,
            "recurring cursor scope changed"
        );
        ensure!(
            serde_json::to_string(&value)? == raw,
            "noncanonical recurring cursor"
        );
        if let Some(key) = &value.after {
            plan.validate_cursor(manifest, key)?;
            let CursorKey::Created { sequence, .. } = key else {
                anyhow::bail!("recurring cursor order")
            };
            ensure!(
                *sequence <= cutoff_seq,
                "recurring cursor exceeds creation cutoff"
            );
        }
        RequestScope::checkpoint_current()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<String> {
        RequestScope::checkpoint_current()?;
        let raw = serde_json::to_string(self)?;
        ensure!(raw.len() <= CURSOR_BYTES, "recurring cursor byte limit");
        Ok(raw)
    }
}
fn service_selection(operation: &Operation, worker: &str) -> bool {
    operation.policy.any.len() == 1
        && operation.policy.any[0].len() == 2
        && operation.policy.any[0]
            .iter()
            .any(|atom| matches!(atom,Predicate::Service{worker:declared} if declared==worker))
        && operation.policy.any[0]
            .iter()
            .any(|atom| matches!(atom, Predicate::SameTenant))
}
/// The logical calls one eligible read may spend.
pub fn read_work(manifest: &Manifest, operation: &Operation) -> Result<u32> {
    let membership =
        u32::try_from(noxide_admission::membership::plans(manifest, operation)?.len())? * 2;
    let gate = if admitted::is_public(operation)
        && admitted::resource(manifest, operation.resource)?
            .gate
            .is_some()
    {
        2
    } else {
        0
    };
    Ok(membership + gate)
}

/// One page's request, checked against the deployment and the locked grant.
pub struct SelectionRequest<'a> {
    pub manifest: &'a Manifest,
    pub plans: &'a BTreeMap<u32, Arc<ListPlan>>,
    pub contract: &'a str,
    pub deployment: &'a str,
    pub generation: Option<&'a String>,
    pub locked: &'a VerifiedScheduleGrant,
    pub schedule: &'a RecurringSchedule,
    pub now: Timestamp,
    pub cutoff: Timestamp,
    pub cutoff_seq: u64,
    pub cursor: Option<&'a str>,
    pub limit: u8,
    pub budget: u32,
}

/// The authority a validated page runs under.
pub struct PreparedSelection<'a> {
    pub selection: &'a RecurringSelection,
    pub action: &'a WorkerAction,
    pub called: &'a Action,
    pub operation: &'a Operation,
    pub eligible: &'a Operation,
    pub resource: &'a Resource,
    pub plan: &'a ListPlan,
    pub frontier: Frontier,
    pub statements: u16,
}

pub fn prepare<'a>(request: SelectionRequest<'a>) -> Result<PreparedSelection<'a>> {
    let SelectionRequest {
        manifest,
        plans,
        contract,
        deployment,
        generation,
        locked,
        schedule,
        now,
        cutoff,
        cutoff_seq,
        cursor,
        limit,
        budget,
    } = request;
    RequestScope::checkpoint_current()?;
    ensure!(
        (1..=MAX_RECURRENCE_FANOUT).contains(&limit),
        "recurring selection limit"
    );
    ensure!(
        cutoff <= now && cutoff_seq <= i64::MAX as u64,
        "invalid recurring cutoff"
    );
    let grant = locked.grant();
    grant.validate()?;
    ensure!(
        grant.contract == contract
            && generation == Some(&grant.scope.deployment)
            && grant.worker.name == schedule.worker,
        "recurring application grant changed"
    );
    let declared = manifest
        .jobs
        .as_ref()
        .and_then(|jobs| {
            jobs.recurring
                .iter()
                .find(|candidate| candidate.name == schedule.name)
        })
        .ok_or_else(|| anyhow::anyhow!("undeclared recurring schedule"))?;
    ensure!(declared == schedule, "recurring declaration changed");
    let selection = schedule
        .selection
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("target-free schedule has no selection"))?;
    let action = grant
        .worker
        .actions
        .iter()
        .find(|action| action.action == schedule.action)
        .ok_or_else(|| anyhow::anyhow!("recurring action not granted"))?;
    crate::validate_recurring_targets(manifest, action, selection)?;
    let called = admitted::action(manifest, schedule.action)?;
    let target = action
        .targets
        .get(&selection.target)
        .ok_or_else(|| anyhow::anyhow!("recurring target not granted"))?;
    let operation = admitted::operation(manifest, selection.operation)?;
    ensure!(
        operation.kind == OperationKind::List
            && operation.resource == target.resource
            && operation.scope.is_none()
            && operation.via.is_none()
            && !admitted::is_preview(operation)
            && service_selection(operation, &schedule.worker),
        "invalid recurring selection authority"
    );
    ensure!(
        operation
            .filter
            .iter()
            .all(|condition| matches!(condition.equals, Operand::Literal(_)))
            && operation
                .query
                .as_ref()
                .is_none_or(|query| query.search.is_none()
                    && query.range.is_none()
                    && query.aggregate.is_none()),
        "recurring selection requires static filters"
    );
    let plan = plans
        .get(&operation.id)
        .ok_or_else(|| anyhow::anyhow!("recurring list plan missing"))?;
    ensure!(
        matches!(plan.order, ListOrder::CreatedAsc | ListOrder::CreatedDesc),
        "recurring selection requires creation order"
    );
    let resource = admitted::resource(manifest, operation.resource)?;
    let eligible = admitted::operation(manifest, target.eligible)?;
    ensure!(
        eligible.kind == OperationKind::Read && eligible.resource == operation.resource,
        "invalid recurring eligible Read"
    );
    if selection.expiry_repair {
        ensure!(
            resource.expiry.is_some() && operation.maintenance && eligible.maintenance,
            "expiry repair requires approved maintenance reads"
        );
    }
    let binding_bytes = serde_json::to_vec(&(
        1,
        "recurring-frontier",
        contract,
        deployment,
        grant,
        schedule,
        operation,
        cutoff,
        cutoff_seq,
    ))?;
    let binding = Sha256::digest(binding_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let frontier = Frontier::decode(cursor, binding, plan, manifest, cutoff_seq)?;
    let statements = RequestScope::statements_remaining()?;
    ensure!(
        budget >= 1 && statements >= 1,
        "recurring cursor persistence budget"
    );
    Ok(PreparedSelection {
        selection,
        action,
        called,
        operation,
        eligible,
        resource,
        plan,
        frontier,
        statements,
    })
}

#[cfg(test)]
mod tests;
