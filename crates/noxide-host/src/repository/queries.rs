//! Fixed bounded frontiers extending the existing list executor.
use super::*;
use crate::{
    database::lifecycle::RequestScope,
    query_plan::{ListPlan, NativeProvider},
};
use noxide_protocol::query::{AggregateFunction, AggregateResult, CursorValue};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

pub(crate) struct Candidate {
    pub(crate) key: CursorKey,
    pub(crate) incarnation: String,
    pub(crate) revision: i64,
}
pub(crate) struct Window {
    pub(crate) rows: Vec<Candidate>,
    pub(crate) exhausted: bool,
    pub(crate) raw_work: usize,
}
fn id(key: &CursorKey) -> u64 {
    match key {
        CursorKey::Created { record, .. } | CursorKey::Scalar { record, .. } => *record,
    }
}
fn compare(a: &CursorKey, b: &CursorKey) -> Ordering {
    match (a, b) {
        (
            CursorKey::Created {
                sequence: a,
                record: ai,
            },
            CursorKey::Created {
                sequence: b,
                record: bi,
            },
        ) => (a, ai).cmp(&(b, bi)),
        (
            CursorKey::Scalar {
                value: CursorValue::Integer(a),
                record: ai,
            },
            CursorKey::Scalar {
                value: CursorValue::Integer(b),
                record: bi,
            },
        ) => (a, ai).cmp(&(b, bi)),
        (
            CursorKey::Scalar {
                value: CursorValue::Binary(a),
                record: ai,
            },
            CursorKey::Scalar {
                value: CursorValue::Binary(b),
                record: bi,
            },
        ) => (a.as_bytes(), ai).cmp(&(b.as_bytes(), bi)),
        _ => unreachable!("validated single-order keys"),
    }
}
/// Borrow the existing transaction, policy identity and logical work owner.
/// A caller-supplied upper bound is host bookkeeping, never a guest query input.
pub(crate) struct FrontierContext<'a> {
    pub(crate) tx: &'a mut Transaction,
    pub(crate) manifest: &'a Manifest,
    pub(crate) principal: &'a Principal,
    pub(crate) budget: ReadBudget<'a>,
    pub(crate) params: &'a Fields,
    pub(crate) target: Option<u64>,
    pub(crate) created_seq_upper: Option<u64>,
}
impl FrontierContext<'_> {
    fn upper_clause(&self, column: &'static str, params: &mut Vec<Param>) -> Result<Sql> {
        let Some(upper) = self.created_seq_upper else {
            return Ok(Sql::empty());
        };
        params.push(i64::try_from(upper)?.into());
        Ok(sql!(" AND {column}<=${}", params.len()))
    }
    fn visibility_clause(&self, op: &Operation, params: &mut Vec<Param>) -> Result<Sql> {
        if !manifest::is_public(op) {
            return Ok(Sql::empty());
        }
        let visible = op
            .visibility
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing public visibility"))?;
        params.push(visible.equals.as_str().into());
        Ok(sql!(
            " AND {}=${}",
            self.tx.field_expression(&visible.field)?,
            params.len()
        ))
    }
    fn query_keyset(
        &self,
        plan: &ListPlan,
        after: Option<&CursorKey>,
        params: &mut Vec<Param>,
    ) -> Result<Sql> {
        match &plan.order {
            ListOrder::Field { .. } => after.map_or_else(
                || Ok(Sql::empty()),
                |key| {
                    plan.scalar(self.manifest)?
                        .keyset_sql(self.tx.query_provider()?, key, params)
                },
            ),
            _ => plan.keyset(after, params),
        }
    }
    fn query_order(&self, plan: &ListPlan) -> Result<Sql> {
        Ok(match &plan.order {
            ListOrder::Field { .. } => plan
                .scalar(self.manifest)?
                .order_sql(self.tx.query_provider()?)?,
            _ => sql!("created_seq {},id {}", plan.direction(), plan.direction()),
        })
    }
    fn query_restrictions(
        &self,
        op: &Operation,
        plan: &ListPlan,
        params: &mut Vec<Param>,
    ) -> Result<Sql> {
        let mut clause = self.visibility_clause(op, params)?;
        if let Some(scope) = &plan.scope {
            params.push(
                self.target
                    .ok_or_else(|| anyhow::anyhow!("missing scope target"))?
                    .to_string()
                    .into(),
            );
            clause.push(sql!(
                " AND {}=${}",
                self.tx.field_expression(scope)?,
                params.len()
            ));
        }
        clause.push(plan.selection_sql(self.tx.query_provider()?, params, self.params)?);
        if let Some(range) = op.query.as_ref().and_then(|q| q.range.as_ref()) {
            clause.push(plan.scalar(self.manifest)?.range_sql(
                self.tx.query_provider()?,
                range,
                self.params,
                params,
            )?);
        }
        Ok(clause)
    }
    pub(crate) async fn window(
        &mut self,
        op: &Operation,
        storage: i64,
        plan: &ListPlan,
        after: Option<&CursorKey>,
        cap: usize,
        terms: Option<&(Vec<u8>, Vec<String>)>,
    ) -> Result<Window> {
        RequestScope::checkpoint_current()?;
        ensure!(cap > 0 && cap <= 256, "query window cap");
        if let Some(key) = after {
            plan.validate_cursor(self.manifest, key)?;
        }
        let posting = terms.is_some_and(|(_, tokens)| !tokens.is_empty())
            && plan.scope.is_none()
            && !matches!(plan.order, ListOrder::Field { .. });
        let mut streams: Vec<Vec<Candidate>> = Vec::new();
        if posting {
            let (fields, tokens) = terms.expect("posting terms");
            let per = (cap / fields.len()).min(64);
            ensure!(per > 0, "search candidate limit");
            RequestScope::charge_search_candidates(per * fields.len())?;
            for field in fields {
                let mut params = vec![
                    storage.into(),
                    i64::from(*field).into(),
                    tokens[0].as_str().into(),
                ];
                let keyset = plan.keyset_on(after, &mut params, "p.created_seq", "p.record_id")?;
                let upper = self.upper_clause("p.created_seq", &mut params)?;
                // Posting index fixes resource/field/token before ordered LIMIT.
                let sql = sql!(
                    "SELECT CAST(p.created_seq AS TEXT),CAST(p.record_id AS TEXT),p.incarnation,CAST(p.revision AS TEXT) FROM nx_search_postings p WHERE p.resource=$1 AND p.field=$2 AND p.token=$3{keyset}{upper} ORDER BY p.created_seq {},p.record_id {} LIMIT {per}",
                    plan.direction(),
                    plan.direction()
                );
                self.budget.spend(1)?;
                let rows = self.tx.fetch::<4>(&sql, &params).await?;
                streams.push(
                    rows.into_iter()
                        .map(|[seq, record, inc, rev]| {
                            Ok(Candidate {
                                key: CursorKey::Created {
                                    sequence: seq.parse()?,
                                    record: record.parse()?,
                                },
                                incarnation: inc,
                                revision: rev.parse()?,
                            })
                        })
                        .collect::<Result<_>>()?,
                );
            }
            return seal_posting_streams(streams, per, plan.descending());
        }
        // Each protected prefix has its own bounded ordered stream. A policy OR
        // must never become a residual SQL filter before the frontier LIMIT.
        let crate::policy::ListStrategy::Merge(scans) =
            crate::policy::residual_strategy(&op.policy)
        else {
            unreachable!("fixed residual streams")
        };
        let policies: Vec<_> = scans
            .iter()
            .map(|scan| crate::policy::scan_policy(&op.policy, scan))
            .collect();
        let per = (cap / policies.len()).min(64);
        ensure!(per > 0, "query candidate limit");
        if terms.is_some() {
            RequestScope::charge_search_candidates(per * policies.len())?;
        }
        let order = self.query_order(plan)?;
        for policy in policies {
            let mut params = vec![storage.into()];
            let filter = crate::policy::filter(
                self.tx.query_provider()?,
                &policy,
                self.principal,
                &mut params,
            );
            let restrictions = self.query_restrictions(op, plan, &mut params)?;
            let keyset = self.query_keyset(plan, after, &mut params)?;
            let upper = self.upper_clause("created_seq", &mut params)?;
            let scalar = match &plan.order {
                ListOrder::Field { field, .. } => self.tx.field_expression(field)?,
                _ => Sql::statement("CAST(created_seq AS TEXT)"),
            };
            let scan = RecordScan {
                columns: sql!(
                    "CAST(created_seq AS TEXT),CAST(id AS TEXT),incarnation,CAST(revision AS TEXT),{scalar}"
                ),
                storage,
                filter: &filter,
                restrictions: sql!("{restrictions}{keyset}{upper}"),
                order: order.clone(),
                limit: per,
            };
            self.budget.spend(1)?;
            let rows = self.tx.scan_records::<5>(scan, &params).await?;
            streams.push(
                rows.into_iter()
                    .map(|[seq, record, inc, rev, value]| {
                        let record = record.parse()?;
                        let key = match &plan.order {
                            ListOrder::Field { field, .. } => plan
                                .scalar(self.manifest)?
                                .row_key(record, &Fields::from([(field.clone(), value)]))?,
                            _ => CursorKey::Created {
                                sequence: seq.parse()?,
                                record,
                            },
                        };
                        Ok(Candidate {
                            key,
                            incarnation: inc,
                            revision: rev.parse()?,
                        })
                    })
                    .collect::<Result<_>>()?,
            );
        }
        seal_streams(streams, per, plan.descending())
    }
}

impl Effects {
    async fn search_ready(&mut self, op: &Operation, storage: i64) -> Result<()> {
        if op.query.as_ref().is_none_or(|query| query.search.is_none()) {
            return Ok(());
        }
        let index = manifest::resource(&self.manifest, op.resource)?
            .search
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("search index missing"))?
            .clone();
        crate::search::require_tokenizer(&index.tokenizer)?;
        self.charge_list_calls(1)?;
        let rows = self.tx.fetch::<2>("SELECT tokenizer,declaration FROM nx_search_state WHERE resource=$1 AND version=1 AND state='ready'", &[storage.into()]).await?;
        ensure!(
            rows.len() == 1
                && rows[0][0] == index.tokenizer
                && serde_json::from_str::<query::SearchIndex>(&rows[0][1])? == index,
            "search index activation mismatch"
        );
        Ok(())
    }
    fn query_terms(&self, op: &Operation) -> Result<Option<(Vec<u8>, Vec<String>)>> {
        let Some(search) = op.query.as_ref().and_then(|q| q.search.as_ref()) else {
            return Ok(None);
        };
        let index = manifest::resource(&self.manifest, op.resource)?
            .search
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing search index"))?;
        let fields = search
            .fields
            .iter()
            .map(|field| {
                index
                    .fields
                    .iter()
                    .position(|name| name == field)
                    .map(|n| n as u8)
                    .ok_or_else(|| anyhow::anyhow!("undeclared search field"))
            })
            .collect::<Result<Vec<_>>>()?;
        let raw = self
            .request
            .params
            .get(&search.parameter)
            .ok_or_else(|| anyhow::anyhow!("missing search text"))?;
        let query = crate::search::canonical_query(raw, &mut RequestScope::checkpoint_current)?;
        crate::search::require_tokenizer(query.tokenizer())?;
        Ok(Some((fields, query.tokens().to_vec())))
    }
    async fn query_window(
        &mut self,
        op: &Operation,
        storage: i64,
        plan: &ListPlan,
        after: Option<&CursorKey>,
        cap: usize,
        terms: Option<&(Vec<u8>, Vec<String>)>,
    ) -> Result<Window> {
        FrontierContext {
            tx: &mut self.tx,
            manifest: &self.manifest,
            principal: &self.principal,
            budget: ReadBudget::Query(&mut self.list_calls),
            params: &self.request.params,
            target: self.request.target,
            created_seq_upper: None,
        }
        .window(op, storage, plan, after, cap, terms)
        .await
    }
    async fn search_matches(
        &mut self,
        storage: i64,
        rows: &[Candidate],
        terms: Option<&(Vec<u8>, Vec<String>)>,
    ) -> Result<BTreeSet<u64>> {
        let Some((fields, tokens)) = terms else {
            return Ok(rows.iter().map(|row| id(&row.key)).collect());
        };
        if tokens.is_empty() {
            return Ok(rows.iter().map(|row| id(&row.key)).collect());
        }
        let mut matched = BTreeSet::new();
        for group in rows.chunks(64) {
            RequestScope::checkpoint_current()?;
            let mut params = vec![storage.into()];
            let mut ids = Vec::new();
            for row in group {
                params.push(i64::try_from(id(&row.key))?.into());
                ids.push(sql!("${}", params.len()));
            }
            let fields = fields
                .iter()
                .map(|field| sql!("{field}"))
                .collect::<Vec<_>>()
                .joined(",");
            let mut slots = Vec::new();
            for token in tokens {
                params.push(token.as_str().into());
                slots.push(sql!("${}", params.len()));
            }
            // All grouping is restricted to the already sealed finite identity set.
            let sql = sql!(
                "SELECT CAST(record_id AS TEXT),incarnation,CAST(revision AS TEXT) FROM nx_search_postings WHERE resource=$1 AND record_id IN ({}) AND field IN ({fields}) AND token IN ({}) GROUP BY record_id,incarnation,revision HAVING COUNT(DISTINCT token)={} LIMIT 64",
                ids.joined(","),
                slots.joined(","),
                tokens.len()
            );
            self.charge_list_calls(1)?;
            for [record, incarnation, revision] in self.tx.fetch::<3>(&sql, &params).await? {
                let record = record.parse()?;
                let revision: i64 = revision.parse()?;
                ensure!(
                    group.iter().any(|row| id(&row.key) == record
                        && row.incarnation == incarnation
                        && row.revision == revision),
                    "stale search postings"
                );
                matched.insert(record);
            }
        }
        Ok(matched)
    }
    pub(super) async fn list_extended(
        &mut self,
        op: &Operation,
        storage: i64,
        plan: &ListPlan,
    ) -> Result<Vec<u8>> {
        self.search_ready(op, storage).await?;
        let terms = self.query_terms(op)?;
        let cap = if terms.is_some() {
            RequestScope::search_candidates_remaining()?
        } else {
            256
        };
        ensure!(cap > 0, "search candidate limit");
        let start = if plan.preview {
            None
        } else {
            self.cursor.clone()
        };
        let window = self
            .query_window(op, storage, plan, start.as_ref(), cap, terms.as_ref())
            .await?;
        let matches = self
            .search_matches(storage, &window.rows, terms.as_ref())
            .await?;
        let mut records = Vec::new();
        let mut last = start;
        self.more = None;
        for group in window.rows.chunks(crate::membership::MAX_BATCH) {
            let ids: Vec<_> = group
                .iter()
                .filter(|row| matches.contains(&id(&row.key)))
                .map(|row| id(&row.key))
                .collect();
            let loaded = authority::load_batch(
                &mut self.tx,
                &self.manifest,
                op.resource,
                storage,
                &ids,
                &mut self.list_calls,
            )
            .await?;
            let policy_rows: Vec<_> = loaded.values().map(StoredRecord::authority_row).collect();
            let allowed = self.authorize_rows(op, &policy_rows).await?;
            let allowed: BTreeMap<_, _> = loaded.keys().copied().zip(allowed).collect();
            for candidate in group {
                RequestScope::checkpoint_current()?;
                let record_id = id(&candidate.key);
                if let Some(stored) = loaded.get(&record_id) {
                    ensure!(
                        stored.incarnation == candidate.incarnation
                            && stored.revision == candidate.revision,
                        "search candidate changed"
                    );
                    if allowed[&record_id]
                        && self.query_selected(op, plan, &stored.record.fields)?
                    {
                        let record = Record {
                            resource: op.resource,
                            id: record_id,
                            fields: self.visible_fields(op, stored.record.fields.clone())?,
                        };
                        if records.len() == usize::from(plan.limit)
                            || !append_prefix(
                                &mut records,
                                record,
                                self.result_limit,
                                plan.preview,
                            )?
                        {
                            self.more = last;
                            self.truncated = true;
                            return Ok(serde_json::to_vec(&records)?);
                        }
                    }
                }
                last = Some(candidate.key.clone());
            }
        }
        if !window.exhausted {
            self.more = last;
            self.truncated = true;
        }
        Ok(serde_json::to_vec(&records)?)
    }
    fn query_selected(&self, op: &Operation, plan: &ListPlan, fields: &Fields) -> Result<bool> {
        if manifest::is_public(op) {
            let visible = op
                .visibility
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("public visibility missing"))?;
            if fields.get(&visible.field) != Some(&visible.equals) {
                return Ok(false);
            }
        }
        if let Some(scope) = &plan.scope
            && fields.get(scope).and_then(|v| v.parse::<u64>().ok()) != self.request.target
        {
            return Ok(false);
        }
        for condition in &plan.selection {
            let expected = match &condition.equals {
                Operand::Literal(value) => value,
                Operand::Param(name) => self
                    .request
                    .params
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!("missing selection parameter"))?,
            };
            if fields.get(&condition.field) != Some(expected) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
fn seal_streams(streams: Vec<Vec<Candidate>>, limit: usize, descending: bool) -> Result<Window> {
    let raw_work = streams.iter().map(Vec::len).sum();
    let mut cutoff: Option<CursorKey> = None;
    let mut merged: BTreeMap<u64, Candidate> = BTreeMap::new();
    for stream in streams {
        RequestScope::checkpoint_current()?;
        if stream.len() == limit {
            let key = &stream.last().expect("positive limit").key;
            if cutoff.as_ref().is_none_or(|old| {
                if descending {
                    compare(key, old).is_gt()
                } else {
                    compare(key, old).is_lt()
                }
            }) {
                cutoff = Some(key.clone());
            }
        }
        let mut previous = None;
        for row in stream {
            if let Some(previous) = previous.as_ref() {
                ensure!(
                    if descending {
                        compare(previous, &row.key).is_gt()
                    } else {
                        compare(previous, &row.key).is_lt()
                    },
                    "query stream order"
                );
            }
            previous = Some(row.key.clone());
            ensure!(
                row.revision > 0 && !row.incarnation.is_empty() && row.incarnation.len() <= 64,
                "query candidate metadata"
            );
            if let Some(old) = merged.insert(
                id(&row.key),
                Candidate {
                    key: row.key.clone(),
                    incarnation: row.incarnation.clone(),
                    revision: row.revision,
                },
            ) {
                ensure!(
                    old.key == row.key
                        && old.incarnation == row.incarnation
                        && old.revision == row.revision,
                    "query alias mismatch"
                );
            }
        }
    }
    let mut rows: Vec<_> = merged
        .into_values()
        .filter(|row| {
            cutoff.as_ref().is_none_or(|cutoff| {
                if descending {
                    !compare(&row.key, cutoff).is_lt()
                } else {
                    !compare(&row.key, cutoff).is_gt()
                }
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        if descending {
            compare(&b.key, &a.key)
        } else {
            compare(&a.key, &b.key)
        }
    });
    Ok(Window {
        rows,
        exhausted: cutoff.is_none(),
        raw_work,
    })
}

impl Effects {
    async fn query_gate(&mut self, op: &Operation) -> Result<bool> {
        let resource = manifest::resource(&self.manifest, op.resource)?.clone();
        if !manifest::is_public(op) {
            return Ok(true);
        }
        let Some(gate) = &resource.gate else {
            return Ok(true);
        };
        let parent = manifest::reference_resource(&self.manifest, op.resource, &gate.field)?
            .ok_or_else(|| anyhow::anyhow!("gate reference missing"))?
            .id;
        let target = self
            .request
            .target
            .ok_or_else(|| anyhow::anyhow!("gate scope target missing"))?;
        let Some(row) = self.read_context().load(parent, target).await? else {
            return Ok(false);
        };
        Ok(self.row_unexpired(&row)?
            && manifest::gate_permits(&resource, &row.record.fields, false))
    }
    async fn candidate_facts(
        &mut self,
        spec: &crate::authority::projection::Spec,
        op: &Operation,
        storage: i64,
        candidates: &[Candidate],
    ) -> Result<BTreeMap<u64, crate::authority::projection::InternalFacts>> {
        use crate::authority::projection::NativeFacts;
        let mut result = BTreeMap::new();
        let provider = self.tx.query_provider()?;
        let mut pieces = Vec::new();
        let mut width = 1024usize;
        for field in spec.fields() {
            width = width
                .checked_add(field.max_bytes as usize * 6 + field.name.len() + 8)
                .ok_or_else(|| anyhow::anyhow!("facts width overflow"))?;
            pieces.push(sql!(
                "'{}',COALESCE({},'')",
                Sql::identifier(&field.name)?,
                self.tx.field_expression(&field.name)?
            ));
        }
        let projection = if pieces.is_empty() {
            Sql::statement("'{}'")
        } else {
            sql!(
                "{}({})",
                match provider {
                    NativeProvider::Sqlite => "json_object",
                    NativeProvider::Postgres => "jsonb_build_object",
                },
                pieces.joined(",")
            )
        };
        let chunk = (60_000 / width).clamp(1, 64);
        ensure!(
            width <= 60_000,
            "eligibility facts exceed bounded projection"
        );
        for group in candidates.chunks(chunk) {
            RequestScope::checkpoint_current()?;
            let mut params = vec![storage.into()];
            let mut slots = Vec::new();
            for candidate in group {
                params.push(i64::try_from(id(&candidate.key))?.into());
                slots.push(sql!("${}", params.len()));
            }
            self.charge_list_calls(1)?;
            let sql = sql!(
                "SELECT CAST(id AS TEXT),COALESCE(owner,''),tenant,incarnation,CAST(revision AS TEXT),CAST(created_seq AS TEXT),CAST({projection} AS TEXT) FROM nx_records WHERE resource=$1 AND resource={storage} AND id IN ({}) LIMIT {chunk}",
                slots.joined(",")
            );
            for [
                record,
                owner,
                tenant,
                incarnation,
                revision,
                sequence,
                fields,
            ] in self.tx.fetch::<7>(&sql, &params).await?
            {
                let record = record.parse()?;
                let revision: i64 = revision.parse()?;
                ensure!(
                    group.iter().any(|candidate| id(&candidate.key) == record
                        && candidate.incarnation == incarnation
                        && candidate.revision == revision),
                    "facts candidate changed"
                );
                let facts = spec.validate(
                    &self.authority,
                    &self.principal,
                    NativeFacts {
                        id: record,
                        owner,
                        tenant,
                        incarnation,
                        revision,
                        created_sequence: sequence.parse()?,
                    },
                    serde_json::from_str(&fields)?,
                )?;
                ensure!(
                    result.insert(record, facts).is_none(),
                    "duplicate facts identity"
                );
            }
        }
        ensure!(result.len() == candidates.len(), "facts row disappeared");
        ensure!(
            op.resource == manifest::operation(&self.manifest, op.id)?.resource,
            "facts source changed"
        );
        Ok(result)
    }
    pub(super) async fn aggregate_query(
        &mut self,
        consumer: &Operation,
        storage: i64,
    ) -> Result<Vec<u8>> {
        use crate::query_plan::aggregate::{AuthorizedOperand, Error, Kind, Scan};
        let aggregate = consumer
            .query
            .as_ref()
            .and_then(|q| q.aggregate.as_ref())
            .ok_or_else(|| anyhow::anyhow!("aggregate source missing"))?;
        let source = manifest::operation(&self.manifest, aggregate.source)?.clone();
        let plan = self
            .plans
            .get(&source.id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("aggregate source plan missing"))?;
        let field = match &aggregate.function {
            AggregateFunction::Count => None,
            AggregateFunction::Sum { field }
            | AggregateFunction::Min { field }
            | AggregateFunction::Max { field } => Some(field.clone()),
        };
        let timestamp = field.as_ref().is_some_and(|name| {
            manifest::resource(&self.manifest, source.resource).is_ok_and(|resource| {
                resource
                    .fields
                    .iter()
                    .any(|field| &field.name == name && matches!(field.kind, FieldKind::Timestamp))
            })
        });
        let kind = match aggregate.function {
            AggregateFunction::Count => Kind::Count,
            AggregateFunction::Sum { .. } => Kind::Sum,
            AggregateFunction::Min { .. } if timestamp => Kind::MinTimestamp,
            AggregateFunction::Max { .. } if timestamp => Kind::MaxTimestamp,
            AggregateFunction::Min { .. } => Kind::MinInteger,
            AggregateFunction::Max { .. } => Kind::MaxInteger,
        };
        self.search_ready(&source, storage).await?;
        let terms = self.query_terms(&source)?;
        let mut scan = if terms.is_some() {
            Scan::search(kind, RequestScope::search_candidates_remaining()?)?
        } else {
            Scan::ordinary(kind)
        };
        let spec = crate::authority::projection::Spec::aggregate(
            &self.manifest,
            consumer,
            self.authority.contract()?,
        )?;
        let result: std::result::Result<query::AggregateValue, Error> = if !self
            .query_gate(&source)
            .await?
        {
            scan.finish(true)
        } else {
            let mut after = None;
            let mut examined = 0usize;
            loop {
                RequestScope::checkpoint_current()?;
                let cap = if terms.is_some() {
                    RequestScope::search_candidates_remaining()?
                } else {
                    (1001usize.saturating_sub(examined)).min(256)
                };
                let streams = source.policy.any.len();
                let streams = if let Some((tokens, _)) = &terms
                    && plan.scope.is_none()
                    && !matches!(plan.order, ListOrder::Field { .. })
                {
                    tokens.len()
                } else {
                    streams
                };
                if cap < streams {
                    break scan.finish(false);
                }
                let window = self
                    .query_window(&source, storage, &plan, after.as_ref(), cap, terms.as_ref())
                    .await?;
                // Raw aliases and deferred heads consume the same finite scan
                // allowance before AND/authorization. Deduplication refunds none.
                let mut raw_failure = None;
                for index in window.rows.len()..window.raw_work {
                    if index.is_multiple_of(64) {
                        RequestScope::checkpoint_current()?;
                    }
                    if let Err(error) = scan.visit(None) {
                        raw_failure = Some(error);
                        break;
                    }
                    examined += 1;
                }
                if let Some(error) = raw_failure {
                    break Err(error);
                }
                let matches = self
                    .search_matches(storage, &window.rows, terms.as_ref())
                    .await?;
                let mut failure = None;
                for group in window.rows.chunks(64) {
                    // The 1001st ordinary seed proves incompleteness before any operand read.
                    let available = if terms.is_some() {
                        group.len()
                    } else {
                        1000usize.saturating_sub(examined).min(group.len())
                    };
                    let selected: Vec<_> = group[..available]
                        .iter()
                        .filter(|candidate| matches.contains(&id(&candidate.key)))
                        .map(|candidate| Candidate {
                            key: candidate.key.clone(),
                            incarnation: candidate.incarnation.clone(),
                            revision: candidate.revision,
                        })
                        .collect();
                    let mut facts = self
                        .candidate_facts(&spec, &source, storage, &selected)
                        .await?;
                    let ordered: Vec<_> = selected
                        .iter()
                        .map(|candidate| {
                            facts
                                .remove(&id(&candidate.key))
                                .expect("validated fact identity")
                        })
                        .collect();
                    let permitted = self
                        .authority
                        .candidate_policy(
                            &mut self.tx,
                            &self.manifest,
                            &self.principal,
                            &spec,
                            &ordered,
                            &mut self.list_calls,
                        )
                        .await?;
                    let approved: BTreeMap<_, _> = ordered
                        .iter()
                        .zip(permitted)
                        .map(|(facts, allowed)| (facts.native().id, (facts, allowed)))
                        .collect();
                    for candidate in group {
                        RequestScope::checkpoint_current()?;
                        let operand = if let Some((facts, true)) = approved.get(&id(&candidate.key))
                        {
                            if self.query_selected(&source, &plan, facts.selected())? {
                                Some(match &field {
                                    None => AuthorizedOperand::Count,
                                    Some(field) => {
                                        let raw = facts.selected().get(field).ok_or_else(|| {
                                            anyhow::anyhow!("aggregate operand missing")
                                        })?;
                                        if timestamp {
                                            AuthorizedOperand::Timestamp(
                                                time::Timestamp::from_unix_millis(raw.parse()?)
                                                    .map_err(anyhow::Error::msg)?,
                                            )
                                        } else {
                                            AuthorizedOperand::Integer(raw.parse()?)
                                        }
                                    }
                                })
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        if let Err(error) = scan.visit(operand) {
                            failure = Some(error);
                            break;
                        }
                        examined += 1;
                        after = Some(candidate.key.clone());
                    }
                    if failure.is_some() {
                        break;
                    }
                }
                if let Some(error) = failure {
                    break Err(error);
                }
                if window.exhausted {
                    break scan.finish(true);
                }
                if window.rows.is_empty() {
                    break scan.finish(false);
                }
            }
        };
        let result: AggregateResult = match result {
            Ok(value) => Ok(value),
            Err(error) => Err(error.wire().ok_or(error)?),
        };
        let bytes = serde_json::to_vec(&result)?;
        self.list_bytes = self
            .list_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("aggregate result budget"))?;
        ensure!(
            self.list_bytes <= MAX_LIST_RESULT_BYTES,
            "aggregate result budget"
        );
        Ok(bytes)
    }
}

fn seal_posting_streams(
    streams: Vec<Vec<Candidate>>,
    limit: usize,
    descending: bool,
) -> Result<Window> {
    use crate::query_plan::frontier::{self, Key, Seed, Stream};
    let streams = streams
        .into_iter()
        .enumerate()
        .map(|(field, rows)| {
            Ok(Stream {
                field: u8::try_from(field)?,
                limit,
                rows: rows
                    .into_iter()
                    .map(|row| {
                        let CursorKey::Created { sequence, record } = row.key else {
                            anyhow::bail!("posting created key")
                        };
                        Ok(Seed {
                            key: Key { sequence, record },
                            incarnation: row.incarnation,
                            revision: row.revision,
                        })
                    })
                    .collect::<Result<_>>()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let frontier = frontier::seal(
        &streams,
        None,
        descending,
        &mut RequestScope::checkpoint_current,
    )?;
    ensure!(
        frontier.planned_work == limit * streams.len()
            && frontier.observed_work <= frontier.planned_work
            && frontier.exhausted == frontier.cutoff.is_none(),
        "posting frontier accounting"
    );
    Ok(Window {
        rows: frontier
            .candidates
            .into_iter()
            .map(|row| Candidate {
                key: CursorKey::Created {
                    sequence: row.key.sequence,
                    record: row.key.record,
                },
                incarnation: row.incarnation,
                revision: row.revision,
            })
            .collect(),
        exhausted: frontier.exhausted,
        raw_work: frontier.observed_work,
    })
}

#[cfg(test)]
mod tests;
