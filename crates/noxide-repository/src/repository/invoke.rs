//! The guest's storage calls: one operation against one target.
use super::*;

impl Effects {
    pub async fn invoke(&mut self, operation: u32, target: u64) -> Result<Vec<u8>> {
        self.invoke_internal(operation, target, false).await
    }
    pub(super) async fn invoke_internal(
        &mut self,
        operation: u32,
        target: u64,
        picker: bool,
    ) -> Result<Vec<u8>> {
        ensure!(self.calls > 0, "database call budget");
        self.calls -= 1;
        let op = manifest::operation(&self.manifest, operation)?.clone();
        ensure!(op.via.is_none(), "follow cannot be invoked by ID");
        self.check_grant(&op, operation, target, picker)?;
        if matches!(op.kind, OperationKind::List | OperationKind::Aggregate) {
            self.charge_list_calls(1)?;
        }
        let storage_resource = self
            .tx
            .storage_resource(&self.manifest, op.resource)
            .await?;
        let value = match op.kind {
            OperationKind::Aggregate => self.aggregate_query(&op, storage_resource).await?,
            OperationKind::Create | OperationKind::Update | OperationKind::Delete => {
                anyhow::bail!("mutation outside declared transaction")
            }
            OperationKind::Read => self.read_value(&op, target).await?,
            OperationKind::List => {
                self.result_limit = self.list_result_limit(&op)?;
                self.truncated = false;
                let previous_more = self.more.clone();
                let plan = self
                    .plans
                    .get(&op.id)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing list plan"))?;
                ensure!(plan.operation == op.id, "invalid list plan");
                if let Some(empty) = self.closed_parent_list(&op, &plan, &previous_more).await? {
                    return Ok(empty);
                }
                self.open_list(&op, storage_resource, &plan, previous_more)
                    .await?
            }
        };
        if matches!(op.kind, OperationKind::Read | OperationKind::List) {
            self.record_provenance(&op, &value)?;
        }
        ensure!(value.len() <= MAX_RESULT_BYTES, "repository output budget");
        Ok(value)
    }
    /// This operation must belong to the request that invoked it, or to a picker.
    fn check_grant(
        &mut self,
        op: &Operation,
        operation: u32,
        target: u64,
        picker: bool,
    ) -> Result<()> {
        if picker {
            ensure!(
                op.kind == OperationKind::List && op.scope.is_none() && target == 0,
                "invalid picker query grant"
            );
        } else {
            match &self.request.kind {
                RequestKind::Route(id) => {
                    let route = manifest::route(&self.manifest, *id)?;
                    ensure!(
                        route.operations.contains(&operation)
                            && target
                                == if matches!(
                                    op.kind,
                                    OperationKind::List | OperationKind::Aggregate
                                ) {
                                    0
                                } else {
                                    self.request.target.unwrap_or(0)
                                },
                        "operation outside request grant"
                    );
                    ensure!(
                        matches!(
                            op.kind,
                            OperationKind::List | OperationKind::Read | OperationKind::Aggregate
                        ),
                        "read route mutation"
                    );
                    ensure!(self.invoked.insert(operation), "operation already invoked");
                }
                RequestKind::Action(_) => anyhow::bail!("storage import during action"),
            }
        }
        Ok(())
    }
    async fn read_value(&mut self, op: &Operation, target: u64) -> Result<Vec<u8>> {
        let found = read_projected_resource(&mut self.read_context(), op, target).await?;
        if let Some((record, incarnation)) = &found {
            for field in &manifest::resource(&self.manifest, op.resource)?.fields {
                if matches!(field.kind, FieldKind::Blob { .. })
                    && op
                        .fields
                        .as_ref()
                        .is_none_or(|fields| fields.contains(&field.name))
                    && let Some(raw) = record.fields.get(&field.name).filter(|v| !v.is_empty())
                {
                    let blob = noxide_protocol::blobs::BlobRef::parse(raw.clone())
                        .map_err(anyhow::Error::msg)?;
                    self.blob_reads.insert(
                        (op.id, record.id, field.name.clone()),
                        (incarnation.clone(), blob),
                    );
                }
            }
        }
        Ok(serde_json::to_vec(&found.map(|(record, _)| record))?)
    }
    /// An empty result when a public list's gated parent is missing or closed.
    async fn closed_parent_list(
        &mut self,
        op: &Operation,
        plan: &crate::query_plan::ListPlan,
        previous_more: &Option<CursorKey>,
    ) -> Result<Option<Vec<u8>>> {
        let source_resource = manifest::resource(&self.manifest, op.resource)?.clone();
        if manifest::is_public(op)
            && source_resource.gate.is_some()
            && let Some(parent) = manifest::reference_resource(
                &self.manifest,
                op.resource,
                &source_resource.gate.as_ref().expect("gate").field,
            )?
            .map(|p| p.id)
        {
            self.charge_list_calls(2)?;
            let id = self
                .request
                .target
                .ok_or_else(|| anyhow::anyhow!("missing parent target"))?;
            let field = manifest::reference_field(
                &source_resource,
                &source_resource.gate.as_ref().expect("gate").field,
            )
            .expect("parent");
            ensure!(
                plan.scope.as_deref() == Some(field.name.as_str()),
                "invalid list parent"
            );
            let record = load(&mut self.tx, &self.manifest, parent, id).await?;
            let gate_visible = match &record {
                Some(record) => {
                    self.row_unexpired(record)?
                        && manifest::gate_permits(&source_resource, &record.record.fields, false)
                }
                None => false,
            };
            if !gate_visible {
                let bytes = if plan.preview {
                    self.more = previous_more.clone();
                    serde_json::to_vec(&PreviewResult {
                        items: Vec::new(),
                        truncated: false,
                    })?
                } else {
                    self.more = None;
                    serde_json::to_vec(&Vec::<Record>::new())?
                };
                self.list_bytes += bytes.len();
                ensure!(
                    self.list_bytes <= MAX_LIST_RESULT_BYTES,
                    "list result budget"
                );
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }
    async fn open_list(
        &mut self,
        op: &Operation,
        storage_resource: i64,
        plan: &crate::query_plan::ListPlan,
        previous_more: Option<CursorKey>,
    ) -> Result<Vec<u8>> {
        let bytes = if op
            .query
            .as_ref()
            .is_some_and(|query| query.search.is_some() || query.range.is_some())
            || matches!(plan.order, ListOrder::Field { .. })
        {
            self.list_extended(op, storage_resource, plan).await?
        } else {
            match &plan.strategy {
                crate::policy::ListStrategy::Single => {
                    self.list_single(op, storage_resource, plan).await?
                }
                crate::policy::ListStrategy::Merge(scans) => {
                    self.list_merge(op, storage_resource, plan, scans).await?
                }
            }
        };
        let bytes = if plan.preview {
            let truncated = self.truncated || self.more.is_some();
            self.more = previous_more;
            if truncated
                && let Some(route) = op
                    .list
                    .as_ref()
                    .and_then(|s| s.preview.as_ref())
                    .and_then(|p| p.see_all)
            {
                let target = manifest::route(&self.manifest, route)?;
                let reference = RouteRef {
                    route,
                    target: target.resource.and(self.request.target),
                    params: target
                        .params
                        .iter()
                        .map(|name| {
                            Ok((
                                name.clone(),
                                self.request
                                    .params
                                    .get(name)
                                    .ok_or_else(|| anyhow::anyhow!("missing preview parameter"))?
                                    .clone(),
                            ))
                        })
                        .collect::<Result<_>>()?,
                };
                crate::routing::resolve(&self.manifest, &reference)?;
                self.see_all.push(reference);
            }
            serde_json::to_vec(&PreviewResult {
                items: serde_json::from_slice(&bytes)?,
                truncated,
            })?
        } else {
            bytes
        };
        self.list_bytes += bytes.len();
        ensure!(
            self.list_bytes <= MAX_LIST_RESULT_BYTES,
            "list result budget"
        );
        Ok(bytes)
    }
    /// Remember which records each returned reference came from, for later follows.
    fn record_provenance(&mut self, op: &Operation, value: &[u8]) -> Result<()> {
        let records: Vec<Record> = if op.kind == OperationKind::Read {
            serde_json::from_slice::<Option<Record>>(value)?
                .into_iter()
                .collect()
        } else if manifest::is_preview(op) {
            serde_json::from_slice::<PreviewResult>(value)?.items
        } else {
            serde_json::from_slice(value)?
        };
        for record in records {
            let references =
                manifest::reference_fields(manifest::resource(&self.manifest, op.resource)?)
                    .filter_map(|field| {
                        record
                            .fields
                            .get(&field.name)
                            .map(|value| (field.name.clone(), value))
                    })
                    .map(|(field, value)| Ok((field, value.parse::<u64>()?)))
                    .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
            if !references.is_empty() {
                self.provenance
                    .insert((op.id, op.resource, record.id), references);
                ensure!(self.provenance.len() <= 56, "follow provenance budget");
            }
        }
        Ok(())
    }
}
