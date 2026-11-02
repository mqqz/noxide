//! Following a reference from a record the request already read.
use super::*;

impl Effects {
    pub fn follow_source(&mut self, resource: u32, id: u64) -> Result<()> {
        ensure!(
            matches!(self.request.kind, RequestKind::Route(_)),
            "storage import during action"
        );
        ensure!(self.follow_sources.len() < 20, "follow source budget");
        self.follow_sources.push((resource, id));
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    pub async fn follow(&mut self, operation: u32) -> Result<Vec<u8>> {
        ensure!(
            matches!(self.request.kind, RequestKind::Route(_)),
            "storage import during action"
        );
        ensure!(self.calls > 0, "database call budget");
        self.calls -= 1;
        let op = manifest::operation(&self.manifest, operation)?.clone();
        let via = op
            .via
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("follow declaration required"))?;
        let RequestKind::Route(route) = self.request.kind else {
            anyhow::bail!("follow outside route")
        };
        ensure!(
            manifest::route(&self.manifest, route)?
                .operations
                .contains(&operation),
            "follow outside request grant"
        );
        ensure!(self.invoked.insert(operation), "operation already invoked");
        let sources = std::mem::take(&mut self.follow_sources);
        let targets: Vec<u64> = sources
            .iter()
            .map(|(resource, id)| {
                self.provenance
                    .get(&(via.source, *resource, *id))
                    .and_then(|fields| fields.get(&via.field))
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("follow source was not returned"))
            })
            .collect::<Result<_>>()?;
        let unique: std::collections::BTreeSet<_> = targets.iter().copied().collect();
        let mut records = std::collections::BTreeMap::new();
        if !unique.is_empty() {
            self.charge_list_calls(2)?;
            let storage = self
                .tx
                .storage_resource(&self.manifest, op.resource)
                .await?;
            let ids: Vec<_> = unique.into_iter().map(|id| id as i64).collect();
            let columns = sql!(
                "CAST(id AS TEXT),COALESCE(owner,''),tenant,{}",
                self.tx.bounded_text("fields", 20_000)
            );
            let rows = self.tx.records_by_ids::<4>(&columns, storage, &ids).await?;
            // Gate target reads are batched separately below; no per-record round trips.
            let mut loaded = Vec::new();
            for [id, owner, tenant, fields] in rows {
                let fields = serde_json::from_str(&fields)?;
                manifest::validate_fields(
                    manifest::resource(&self.manifest, op.resource)?,
                    &fields,
                )?;
                let stored = StoredRecord {
                    record: Record {
                        resource: op.resource,
                        id: id.parse()?,
                        fields,
                    },
                    owner,
                    tenant,
                    incarnation: String::new(),
                    revision: 1,
                    cap_version: None,
                };
                loaded.push(stored);
            }
            let policy_rows: Vec<_> = loaded.iter().map(StoredRecord::authority_row).collect();
            let permitted = self.authorize_rows(&op, &policy_rows).await?;
            let mut candidates = Vec::new();
            for (stored, allowed) in loaded.into_iter().zip(permitted) {
                if !allowed {
                    continue;
                }
                if manifest::is_public(&op) {
                    let visibility = op
                        .visibility
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing public visibility"))?;
                    if stored.record.fields.get(&visibility.field) != Some(&visibility.equals) {
                        continue;
                    }
                }
                candidates.push(stored.record);
            }
            if manifest::is_public(&op)
                && let Some(gate) = manifest::resource(&self.manifest, op.resource)?
                    .gate
                    .clone()
            {
                let target_resource =
                    manifest::reference_resource(&self.manifest, op.resource, &gate.field)?
                        .expect("gate target")
                        .id;
                self.charge_list_calls(2)?;
                let storage = self
                    .tx
                    .storage_resource(&self.manifest, target_resource)
                    .await?;
                let mut ids = Vec::new();
                for record in &candidates {
                    ids.push(record.fields[&gate.field].parse::<i64>()?);
                }
                let mut visible = std::collections::BTreeSet::new();
                if !ids.is_empty() {
                    let columns = sql!(
                        "CAST(id AS TEXT),{}",
                        self.tx.bounded_text("fields", 20_000)
                    );
                    for [id, fields] in self.tx.records_by_ids::<2>(&columns, storage, &ids).await?
                    {
                        let fields = serde_json::from_str(&fields)?;
                        manifest::validate_fields(
                            manifest::resource(&self.manifest, target_resource)?,
                            &fields,
                        )?;
                        if crate::expiry::available(
                            manifest::resource(&self.manifest, target_resource)?,
                            &fields,
                            self.authority.time(),
                        )? && manifest::gate_permits(
                            manifest::resource(&self.manifest, op.resource)?,
                            &fields,
                            false,
                        ) {
                            visible.insert(id);
                        }
                    }
                }
                candidates.retain(|record| visible.contains(&record.fields[&gate.field]));
            }
            for mut record in candidates {
                if let Some(fields) = &op.fields {
                    record.fields.retain(|name, _| fields.contains(name));
                }
                records.insert(record.id, record);
            }
        }
        let result: Vec<_> = targets.iter().map(|id| records.get(id)).collect();
        let bytes = serde_json::to_vec(&result)?;
        ensure!(
            bytes.len() <= self.list_result_limit(&op)?,
            "follow result budget"
        );
        self.list_bytes += bytes.len();
        ensure!(
            self.list_bytes <= MAX_LIST_RESULT_BYTES,
            "list result budget"
        );
        Ok(bytes)
    }
    pub async fn picker_records(&mut self, binding: u32, name: &str) -> Result<Vec<Record>> {
        let RequestKind::Route(route) = self.request.kind else {
            anyhow::bail!("picker outside web route")
        };
        ensure!(
            manifest::route(&self.manifest, route)?
                .forms
                .contains(&binding),
            "picker outside binding grant"
        );
        let action = manifest::web_action(&self.manifest, binding)?;
        let declaration = manifest::action_target(&action.targets, name)?;
        let TargetSource::Selected { query, .. } = declaration.source else {
            anyhow::bail!("not a picker target")
        };
        let op = manifest::operation(&self.manifest, query)?.clone();
        let previous = (
            self.cursor.clone(),
            self.more.clone(),
            self.result_limit,
            self.truncated,
        );
        // Route pagination is scoped to its own query; it cannot select a
        // different window of the host-owned picker query.
        self.cursor = None;
        let result = self.invoke_internal(query, 0, true).await;
        (self.cursor, self.more, self.result_limit, self.truncated) = previous;
        let bytes = result?;
        if manifest::is_preview(&op) {
            Ok(serde_json::from_slice::<PreviewResult>(&bytes)?.items)
        } else {
            Ok(serde_json::from_slice(&bytes)?)
        }
    }
}
