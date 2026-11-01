//! Host-only recurring selection over the canonical bounded list frontier.
//! The caller owns the locked grant, current transaction, time and work root.
use super::*;
use crate::{
    database::lifecycle::RequestScope,
    jobs::{SealedTarget, VerifiedScheduleGrant},
    lifecycle_clock::AttemptTime,
    repository::{ReadBudget, ReadContext, queries::FrontierContext},
};
use noxide_protocol::{
    ListOrder, Operand, Operation, Predicate,
    jobs::{MAX_RECURRENCE_FANOUT, RecurringSchedule},
    query::CursorKey,
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CURSOR_BYTES: usize = 4096;
// Existing QueueContext::emit_recurrence includes its enqueue, at most nine
// actual statements/two logical calls. finish_recurrence uses one of each.
const EMIT_STATEMENTS: u16 = 9;

pub(crate) struct SelectedTarget {
    pub(crate) targets: BTreeMap<String, SealedTarget>,
    pub(crate) expiry: Option<Timestamp>,
}
pub(crate) struct SelectionPage {
    pub(crate) items: Vec<SelectedTarget>,
    pub(crate) next_cursor: Option<String>,
    pub(crate) complete: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frontier {
    version: u8,
    binding: String,
    after: Option<CursorKey>,
}
impl Frontier {
    fn decode(
        raw: Option<&str>,
        binding: String,
        plan: &crate::query_plan::ListPlan,
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
    fn encode(&self) -> Result<String> {
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
fn read_work(manifest: &Manifest, operation: &Operation) -> Result<u32> {
    let membership = u32::try_from(crate::membership::plans(manifest, operation)?.len())? * 2;
    let gate = if manifest::is_public(operation)
        && manifest::resource(manifest, operation.resource)?
            .gate
            .is_some()
    {
        2
    } else {
        0
    };
    Ok(membership + gate)
}
fn candidate_cap(limit: u8, logical: u32, statements: u16, eligible_work: u32) -> usize {
    // Catalog+one native stream, complete canonical row load, independent
    // eligible Read, every possible emitted job, and final cursor persistence.
    (1..=usize::from(limit))
        .rev()
        .find(|count| {
            let count = *count as u32;
            let logical_need = 3 + count * (4 + eligible_work);
            let statement_need = 3 + count * (2 + eligible_work + u32::from(EMIT_STATEMENTS));
            logical_need <= logical && statement_need <= u32::from(statements)
        })
        .unwrap_or(0)
}
impl Application {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn select_recurring(
        &self,
        tx: &mut Transaction,
        locked: &VerifiedScheduleGrant,
        schedule: &RecurringSchedule,
        time: AttemptTime,
        cutoff: Timestamp,
        cutoff_seq: u64,
        cursor: Option<&str>,
        limit: u8,
        budget: &mut u32,
    ) -> Result<SelectionPage> {
        RequestScope::checkpoint_current()?;
        ensure!(
            (1..=MAX_RECURRENCE_FANOUT).contains(&limit),
            "recurring selection limit"
        );
        ensure!(
            cutoff <= time.timestamp() && cutoff_seq <= i64::MAX as u64,
            "invalid recurring cutoff"
        );
        let grant = locked.grant();
        grant.validate()?;
        ensure!(
            grant.contract == self.contract
                && self.generation.get() == Some(&grant.scope.deployment)
                && grant.worker.name == schedule.worker,
            "recurring application grant changed"
        );
        let declared = self
            .manifest
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
        crate::jobs::validate_recurring_targets(&self.manifest, action, selection)?;
        let called = manifest::action(&self.manifest, schedule.action)?;
        let target = action
            .targets
            .get(&selection.target)
            .ok_or_else(|| anyhow::anyhow!("recurring target not granted"))?;
        let operation = manifest::operation(&self.manifest, selection.operation)?;
        ensure!(
            operation.kind == OperationKind::List
                && operation.resource == target.resource
                && operation.scope.is_none()
                && operation.via.is_none()
                && !manifest::is_preview(operation)
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
        let plan = self
            .plans
            .get(&operation.id)
            .ok_or_else(|| anyhow::anyhow!("recurring list plan missing"))?;
        ensure!(
            matches!(plan.order, ListOrder::CreatedAsc | ListOrder::CreatedDesc),
            "recurring selection requires creation order"
        );
        let resource = manifest::resource(&self.manifest, operation.resource)?;
        let eligible = manifest::operation(&self.manifest, target.eligible)?;
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
            &self.contract,
            &self.deployment,
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
        let mut frontier = Frontier::decode(cursor, binding, plan, &self.manifest, cutoff_seq)?;
        let statements = RequestScope::statements_remaining()?;
        ensure!(
            *budget >= 1 && statements >= 1,
            "recurring cursor persistence budget"
        );
        // Authorize the source before deriving, then seal every alias using its
        // independent read. Reserve both source checks and all derived loads.
        let binding_work = called.targets.iter().try_fold(
            read_work(&self.manifest, eligible)?,
            |work, declared| -> Result<u32> {
                let binding = action
                    .targets
                    .get(&declared.name)
                    .ok_or(repository::ReferenceUnavailable)?;
                let read = manifest::operation(&self.manifest, binding.eligible)?;
                Ok(work
                    + read_work(&self.manifest, read)?
                    + if declared.name == selection.target {
                        0
                    } else {
                        2
                    })
            },
        )?;
        let cap = candidate_cap(limit.min(plan.limit), *budget, statements, binding_work);
        if cap == 0 {
            return Ok(SelectionPage {
                items: Vec::new(),
                next_cursor: Some(frontier.encode()?),
                complete: false,
            });
        }
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| anyhow::anyhow!("recurring catalog budget"))?;
        let storage = tx
            .storage_resource(&self.manifest, operation.resource)
            .await?;
        let principal = crate::jobs::locked_grant_principal(locked);
        let window = FrontierContext {
            tx,
            manifest: &self.manifest,
            principal: &principal,
            budget: ReadBudget::Action(&mut *budget),
            params: &Fields::new(),
            target: None,
            created_seq_upper: Some(cutoff_seq),
        }
        .window(operation, storage, plan, frontier.after.as_ref(), cap, None)
        .await?;
        ensure!(window.raw_work <= cap, "recurring frontier work exceeded");
        let mut authority = self.authority_context(Some(time))?;
        let mut context = ReadContext {
            tx,
            manifest: &self.manifest,
            principal: &principal,
            authority: &mut authority,
            budget: ReadBudget::Action(&mut *budget),
        };
        let mut items = Vec::new();
        for candidate in window.rows {
            RequestScope::checkpoint_current()?;
            let id = match candidate.key {
                CursorKey::Created { record, .. } => record,
                _ => anyhow::bail!("recurring frontier order"),
            };
            let Some(stored) = context.load(operation.resource, id).await? else {
                anyhow::bail!("recurring candidate disappeared")
            };
            ensure!(
                stored.incarnation == candidate.incarnation
                    && stored.revision == candidate.revision,
                "recurring candidate changed"
            );
            plan.check_selection(&stored.record.fields, &Fields::new())?;
            if !repository::authorize_stored_read(&mut context, operation, &stored).await? {
                frontier.after = Some(candidate.key);
                continue;
            }
            if !repository::authorize_stored_read(&mut context, eligible, &stored).await? {
                frontier.after = Some(candidate.key);
                continue;
            }
            let mut records =
                BTreeMap::from([((stored.record.resource, stored.record.id), stored.clone())]);
            let mut rows = BTreeMap::from([(selection.target.clone(), stored)]);
            let mut unavailable = false;
            for declared in called
                .targets
                .iter()
                .filter(|target| target.name != selection.target)
            {
                let TargetSource::Reference {
                    target: parent,
                    field,
                    ..
                } = &declared.source
                else {
                    anyhow::bail!("recurrence derived source changed");
                };
                let id = rows
                    .get(parent)
                    .and_then(|row| row.record.fields.get(field))
                    .and_then(|raw| raw.parse::<u64>().ok())
                    .filter(|id| *id > 0);
                let Some(id) = id else {
                    unavailable = true;
                    break;
                };
                let key = (declared.resource, id);
                let related = if let Some(related) = records.get(&key) {
                    related.clone()
                } else {
                    let Some(related) = context.load(declared.resource, id).await? else {
                        unavailable = true;
                        break;
                    };
                    records.insert(key, related.clone());
                    related
                };
                rows.insert(declared.name.clone(), related);
            }
            if unavailable {
                frontier.after = Some(candidate.key);
                continue;
            }
            let sealed = match self
                .seal_job_target_rows(&mut context, locked, schedule.action, &rows)
                .await
            {
                Ok(sealed) => sealed,
                Err(error)
                    if error
                        .downcast_ref::<repository::ReferenceUnavailable>()
                        .is_some() =>
                {
                    frontier.after = Some(candidate.key);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let expiry = if selection.expiry_repair {
                let field = &resource.expiry.as_ref().expect("approved expiry").field;
                let raw = rows[&selection.target]
                    .record
                    .fields
                    .get(field)
                    .ok_or_else(|| anyhow::anyhow!("recurring expiry field missing"))?;
                let expires = Timestamp::from_unix_millis(raw.parse()?)?;
                if expires > cutoff {
                    frontier.after = Some(candidate.key);
                    continue;
                }
                Some(expires)
            } else {
                None
            };
            items.push(SelectedTarget {
                targets: sealed,
                expiry,
            });
            frontier.after = Some(candidate.key);
        }
        let next_cursor = if window.exhausted {
            None
        } else {
            Some(frontier.encode()?)
        };
        Ok(SelectionPage {
            items,
            next_cursor,
            complete: window.exhausted,
        })
    }
}

#[cfg(test)]
mod tests;
