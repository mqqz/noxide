//! List operations, for one resource or merged across several.
use super::*;

// Measure the exact cross-boundary representation, including array framing.
pub(super) fn append_prefix(
    records: &mut Vec<Record>,
    record: Record,
    limit: usize,
    empty: bool,
) -> Result<bool> {
    records.push(record);
    if serde_json::to_vec(records)?.len() <= limit {
        return Ok(true);
    }
    records.pop();
    ensure!(
        empty || !records.is_empty(),
        "record exceeds repository result budget"
    );
    Ok(false)
}

impl Effects {
    #[cfg(any(test, feature = "test-support"))]
    pub fn next_request(&mut self) {
        self.invoked.clear();
        self.provenance.clear();
        self.blob_reads.clear();
        self.follow_sources.clear();
        self.list_bytes = 0;
        self.list_calls = MAX_LIST_DATABASE_CALLS;
        self.see_all.clear();
    }
    pub fn charge_list_calls(&mut self, count: usize) -> Result<()> {
        ensure!(self.list_calls >= count, "list database call budget");
        self.list_calls -= count;
        Ok(())
    }
    pub(super) fn list_result_limit(&self, op: &Operation) -> Result<usize> {
        let RequestKind::Route(route) = self.request.kind else {
            anyhow::bail!("list outside route")
        };
        let reserve: usize = manifest::route(&self.manifest, route)?
            .operations
            .iter()
            .filter(|id| !self.invoked.contains(id))
            .filter_map(|id| manifest::operation(&self.manifest, *id).ok())
            .filter(|op| op.kind == OperationKind::List || op.via.is_some())
            .map(|op| {
                if op.via.is_some() {
                    128 // Complete twenty-slot unavailable result plus framing.
                } else if manifest::is_preview(op) {
                    64
                } else {
                    MAX_RESULT_BYTES
                }
            })
            .sum();
        let available = MAX_LIST_RESULT_BYTES
            .checked_sub(self.list_bytes + reserve)
            .ok_or_else(|| anyhow::anyhow!("list result budget"))?
            .min(MAX_RESULT_BYTES);
        let envelope = if manifest::is_preview(op) { 64 } else { 0 };
        ensure!(
            available >= if envelope == 0 { 2 } else { envelope },
            "list result budget"
        );
        Ok(available - envelope)
    }
    pub(super) async fn list_single(
        &mut self,
        op: &Operation,
        storage_resource: i64,
        plan: &crate::query_plan::ListPlan,
    ) -> Result<Vec<u8>> {
        let size = plan.limit as usize;
        let direction = plan.direction();
        let cursor = if plan.preview {
            None
        } else {
            self.cursor.clone()
        };
        let mut params = vec![Param::Number(storage_resource)];
        let filter = self.authority_filter(op, &mut params).await?;
        let visibility = self.visibility_clause(op, &mut params)?;
        let parent_clause = self.scoped_parent_clause(plan, storage_resource, &mut params)?;
        let selection =
            plan.selection_sql(self.tx.query_provider()?, &mut params, &self.request.params)?;
        let mut records = Vec::new();
        let mut last = cursor.clone();
        self.more = None;
        // At most three bounded stored rows per database transfer. The
        // approved page size bounds both iterations and total row work.
        'page: while records.len() < size {
            let batch = (size - records.len()).min(3);
            let mut page_params = params.clone();
            let keyset = plan.keyset(last.as_ref(), &mut page_params)?;
            let restrictions = sql!("{visibility}{parent_clause}{selection}{keyset}");
            let order = sql!("nx_records.created_seq {direction}");
            let scan = RecordScan {
                columns: sql!(
                    "CAST(created_seq AS TEXT),CAST(id AS TEXT),COALESCE(owner,''),tenant,{}",
                    self.tx.bounded_text("fields", 20_000)
                ),
                storage: storage_resource,
                filter: &filter,
                restrictions,
                order,
                limit: batch,
            };
            self.charge_list_calls(1)?;
            let rows = self.tx.scan_records::<5>(scan, &page_params).await?;
            let count = rows.len();
            let decisions = self.authorize_scanned(op, &rows).await?;
            for ([seq, id, _owner, _tenant, fields], permitted) in rows.into_iter().zip(decisions) {
                plan.check_selection(&serde_json::from_str(&fields)?, &self.request.params)?;
                ensure!(permitted, "policy invariant");
                let record = Record {
                    resource: op.resource,
                    id: id.parse()?,
                    fields: self.visible_fields(op, serde_json::from_str(&fields)?)?,
                };
                if !append_prefix(&mut records, record, self.result_limit, plan.preview)? {
                    self.truncated = true;
                    self.more = last.clone();
                    break 'page;
                }
                last = Some(CursorKey::Created {
                    sequence: seq.parse()?,
                    record: id.parse()?,
                });
            }
            if count < batch {
                break;
            }
        }
        if self.more.is_none() && records.len() == size {
            let mut page_params = params.clone();
            let keyset = plan.keyset(last.as_ref(), &mut page_params)?;
            self.charge_list_calls(1)?;
            let scan = RecordScan {
                columns: Sql::statement("CAST(created_seq AS TEXT)"),
                storage: storage_resource,
                filter: &filter,
                restrictions: sql!("{visibility}{parent_clause}{selection}{keyset}"),
                order: sql!("nx_records.created_seq {direction}"),
                limit: 1,
            };
            let next = self.tx.scan_records::<1>(scan, &page_params).await?;
            if !next.is_empty() {
                self.truncated = true;
                self.more = last.clone();
            }
        }
        Ok(serde_json::to_vec(&records)?)
    }
    pub(super) async fn list_merge(
        &mut self,
        op: &Operation,
        storage_resource: i64,
        plan: &crate::query_plan::ListPlan,
        scans: &[crate::policy::ScanRule],
    ) -> Result<Vec<u8>> {
        let size = plan.limit as usize;
        let cursor = if plan.preview {
            None
        } else {
            self.cursor.clone()
        };
        let (candidates, boundary, bounded_more) = self
            .merge_candidates(op, storage_resource, plan, scans, cursor.as_ref())
            .await?;
        let mut records = Vec::new();
        let mut last = cursor.clone();
        self.more = None;
        let ordered: Vec<_> = if plan.descending() {
            candidates.into_iter().rev().collect()
        } else {
            candidates.into_iter().collect()
        };
        let ordered: Vec<_> = ordered
            .into_iter()
            .take_while(|(seq, _)| {
                if plan.descending() {
                    *seq >= boundary
                } else {
                    *seq <= boundary
                }
            })
            .collect();
        'page: for group in ordered.chunks(crate::membership::MAX_BATCH) {
            let ids: Vec<_> = group.iter().map(|(_, id)| *id).collect();
            let loaded = authority::load_batch(
                &mut self.tx,
                &self.manifest,
                op.resource,
                storage_resource,
                &ids,
                &mut self.list_calls,
            )
            .await?;
            let stored: Vec<_> = group
                .iter()
                .map(|(_, id)| {
                    loaded
                        .get(id)
                        .ok_or_else(|| anyhow::anyhow!("record disappeared"))
                })
                .collect::<Result<_>>()?;
            let policy_rows: Vec<_> = stored.iter().map(|stored| stored.authority_row()).collect();
            let allowed = self.authorize_rows(op, &policy_rows).await?;
            for (((seq, _), stored), allowed) in group.iter().zip(stored).zip(allowed) {
                if !allowed {
                    last = Some(CursorKey::Created {
                        sequence: *seq,
                        record: stored.record.id,
                    });
                    continue;
                }
                if let Some(field) = &plan.scope
                    && stored
                        .record
                        .fields
                        .get(field)
                        .and_then(|value| value.parse::<u64>().ok())
                        != self.request.target
                {
                    last = Some(CursorKey::Created {
                        sequence: *seq,
                        record: stored.record.id,
                    });
                    continue;
                }
                plan.check_selection(&stored.record.fields, &self.request.params)?;
                let mut record = stored.record.clone();
                record.fields = self.visible_fields(op, record.fields)?;
                if records.len() == size
                    || !append_prefix(&mut records, record, self.result_limit, plan.preview)?
                {
                    self.truncated = true;
                    self.more = last.clone();
                    break 'page;
                }
                last = Some(CursorKey::Created {
                    sequence: *seq,
                    record: stored.record.id,
                });
            }
        }
        if self.more.is_none() && bounded_more {
            self.truncated = true;
            self.more = ordered
                .iter()
                .find(|(seq, _)| *seq == boundary)
                .map(|(seq, id)| CursorKey::Created {
                    sequence: *seq,
                    record: *id,
                });
        }
        Ok(serde_json::to_vec(&records)?)
    }
    /// Restrict a single scan to the requested parent, when the list has one.
    fn scoped_parent_clause(
        &self,
        plan: &crate::query_plan::ListPlan,
        storage_resource: i64,
        params: &mut Vec<Param>,
    ) -> Result<Sql> {
        let mut parent_clause = Sql::empty();
        if let Some(scope) = &plan.scope {
            let id = self
                .request
                .target
                .ok_or_else(|| anyhow::anyhow!("missing parent target"))?;
            params.push(id.to_string().into());
            // A catalog-derived constant lets PostgreSQL's generic plans
            // prove the partial-index predicate despite resource=$1.
            parent_clause = sql!(
                " AND resource={storage_resource} AND {}=${}",
                self.tx.field_expression(scope)?,
                params.len()
            );
        }
        Ok(parent_clause)
    }
    /// Policy decisions for one batch of scanned rows, in order.
    async fn authorize_scanned(
        &mut self,
        op: &Operation,
        rows: &[[String; 5]],
    ) -> Result<Vec<bool>> {
        let parsed: Vec<Fields> = rows
            .iter()
            .map(|row| serde_json::from_str(&row[4]))
            .collect::<std::result::Result<_, _>>()?;
        let policy_rows: Vec<_> = rows
            .iter()
            .zip(&parsed)
            .map(|(row, fields)| {
                Ok(crate::authority::Row {
                    id: row[1].parse()?,
                    owner: &row[2],
                    tenant: &row[3],
                    fields,
                })
            })
            .collect::<Result<_>>()?;
        self.authorize_rows(op, &policy_rows).await
    }
    /// Every scan's candidate rows by creation sequence, and how far a truncated inexact
    /// scan lets the merge safely go.
    async fn merge_candidates(
        &mut self,
        op: &Operation,
        storage_resource: i64,
        plan: &crate::query_plan::ListPlan,
        scans: &[crate::policy::ScanRule],
        cursor: Option<&CursorKey>,
    ) -> Result<(std::collections::BTreeMap<u64, u64>, u64, bool)> {
        let size = plan.limit as usize;
        let direction = plan.direction();
        let mut candidates = std::collections::BTreeMap::new();
        let mut boundary = if plan.descending() { 0 } else { u64::MAX };
        let mut bounded_more = false;
        for scan in scans {
            let exact = scan.exact;
            let scan_policy = crate::policy::scan_policy(&op.policy, scan);
            let mut scan_params = vec![Param::Number(storage_resource)];
            let filter = crate::policy::filter(
                self.tx.query_provider()?,
                &scan_policy,
                &self.principal,
                &mut scan_params,
            );
            let selection = plan.selection_sql(
                self.tx.query_provider()?,
                &mut scan_params,
                &self.request.params,
            )?;
            let mut parent_clause = Sql::empty();
            if let Some(parent) = &plan.scope {
                let target = self
                    .request
                    .target
                    .ok_or_else(|| anyhow::anyhow!("missing parent target"))?;
                scan_params.push(target.to_string().into());
                parent_clause = sql!(
                    " AND {}=${}",
                    self.tx.field_expression(parent)?,
                    scan_params.len()
                );
            }
            let visibility = self.visibility_clause(op, &mut scan_params)?;
            let keyset = plan.keyset(cursor, &mut scan_params)?;
            let limit = if exact {
                size + 1
            } else {
                (256 / op.policy.any.len()).min(64)
            };
            let scan = RecordScan {
                columns: Sql::statement("CAST(created_seq AS TEXT),CAST(id AS TEXT)"),
                storage: storage_resource,
                filter: &filter,
                restrictions: sql!("{visibility}{parent_clause}{selection}{keyset}"),
                order: sql!("nx_records.created_seq {direction}"),
                limit,
            };
            self.charge_list_calls(1)?;
            let rows = self.tx.scan_records::<2>(scan, &scan_params).await?;
            if !exact && rows.len() == limit {
                let last = rows.last().expect("nonempty")[0].parse()?;
                boundary = if plan.descending() {
                    boundary.max(last)
                } else {
                    boundary.min(last)
                };
                bounded_more = true;
            }
            for [seq, id] in rows {
                candidates.insert(seq.parse::<u64>()?, id.parse::<u64>()?);
            }
        }
        Ok((candidates, boundary, bounded_more))
    }
    pub(super) fn visibility_clause(&self, op: &Operation, params: &mut Vec<Param>) -> Result<Sql> {
        if !manifest::is_public(op) {
            return Ok(Sql::empty());
        }
        let visibility = op
            .visibility
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing public visibility"))?;
        let expression = self.tx.field_expression(&visibility.field)?;
        params.push(visibility.equals.as_str().into());
        Ok(sql!(" AND ({expression} = ${})", params.len()))
    }
    pub(super) fn visible_fields(&self, op: &Operation, mut fields: Fields) -> Result<Fields> {
        if manifest::is_public(op) {
            let visibility = op
                .visibility
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing public visibility"))?;
            ensure!(
                fields.get(&visibility.field) == Some(&visibility.equals),
                "public visibility invariant"
            );
        }
        manifest::validate_fields(manifest::resource(&self.manifest, op.resource)?, &fields)?;
        if manifest::is_public(op) {
            let names = op
                .fields
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing public fields"))?;
            fields.retain(|name, _| names.contains(name));
        }
        Ok(fields)
    }
}
