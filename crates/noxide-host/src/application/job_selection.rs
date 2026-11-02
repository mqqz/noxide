//! Host-only recurring selection over the canonical bounded list frontier.
//! The caller owns the locked grant, current transaction, time and work root.
use super::*;
use crate::{
    database::lifecycle::RequestScope,
    jobs::{
        VerifiedScheduleGrant,
        selection::{
            PreparedSelection, SelectedTarget, SelectionPage, SelectionRequest, prepare, read_work,
        },
    },
    lifecycle_clock::AttemptTime,
    repository::{ReadBudget, ReadContext, queries::FrontierContext},
};
use noxide_protocol::{jobs::RecurringSchedule, query::CursorKey, time::Timestamp};

fn candidate_cap(limit: u8, logical: u32, statements: u16, eligible_work: u32) -> usize {
    // Catalog+one native stream, complete canonical row load, independent
    // eligible Read, every possible emitted job, and final cursor persistence.
    (1..=usize::from(limit))
        .rev()
        .find(|count| {
            let count = *count as u32;
            let logical_need = 3 + count * (4 + eligible_work);
            let statement_need = 3 + count
                * (2 + eligible_work + u32::from(crate::jobs::recurrence::EMIT_STATEMENTS));
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
        let PreparedSelection {
            selection,
            action,
            called,
            operation,
            eligible,
            resource,
            plan,
            mut frontier,
            statements,
        } = prepare(SelectionRequest {
            manifest: &self.manifest,
            plans: &self.plans,
            contract: &self.contract,
            deployment: &self.deployment,
            generation: self.generation.get(),
            locked,
            schedule,
            now: time.timestamp(),
            cutoff,
            cutoff_seq,
            cursor,
            limit,
            budget: *budget,
        })?;
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
