//! Runtime hooks into the shared authority context; the executor remains in its
//! existing module. Registration and call sites are applied by the runtime owner.
use super::*;

#[cfg(test)]
pub(crate) async fn test_read_resource(
    tx: &mut Transaction,
    m: &Manifest,
    principal: &Principal,
    op: &Operation,
    target: u64,
) -> Result<Option<Record>> {
    let mut authority = crate::authority::Authority::default();
    let mut calls = MAX_LIST_DATABASE_CALLS;
    read_resource(
        &mut ReadContext {
            tx,
            manifest: m,
            principal,
            authority: &mut authority,
            budget: ReadBudget::Query(&mut calls),
        },
        op,
        target,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn test_authorize_page_resource(
    tx: &mut Transaction,
    m: &Manifest,
    principal: &Principal,
    route: &Route,
    resource: u32,
    id: u64,
    incarnation: Option<&str>,
) -> Result<Option<StoredRecord>> {
    let mut authority = crate::authority::Authority::default();
    let mut calls = MAX_LIST_DATABASE_CALLS;
    authorize_page_resource(
        &mut ReadContext {
            tx,
            manifest: m,
            principal,
            authority: &mut authority,
            budget: ReadBudget::Query(&mut calls),
        },
        route,
        resource,
        id,
        incarnation,
    )
    .await
}

pub(crate) enum ReadBudget<'a> {
    Action(&'a mut u32),
    Query(&'a mut usize),
}
impl ReadBudget<'_> {
    fn remaining(&self) -> usize {
        match self {
            Self::Action(value) => **value as usize,
            Self::Query(value) => **value,
        }
    }
    fn update(&mut self, remaining: usize) -> Result<()> {
        match self {
            Self::Action(value) => **value = u32::try_from(remaining)?,
            Self::Query(value) => **value = remaining,
        }
        Ok(())
    }
    pub(crate) fn spend(&mut self, count: usize) -> Result<()> {
        let remaining = self
            .remaining()
            .checked_sub(count)
            .ok_or_else(|| anyhow::anyhow!("database call budget"))?;
        self.update(remaining)
    }
}

pub(crate) struct ReadContext<'a> {
    pub tx: &'a mut Transaction,
    pub manifest: &'a Manifest,
    pub principal: &'a Principal,
    pub authority: &'a mut crate::authority::Authority,
    pub budget: ReadBudget<'a>,
}
impl ReadContext<'_> {
    pub(crate) async fn load(&mut self, resource: u32, id: u64) -> Result<Option<StoredRecord>> {
        self.budget.spend(2)?;
        load(self.tx, self.manifest, resource, id).await
    }
    pub(crate) fn unexpired(&self, stored: &StoredRecord) -> Result<bool> {
        crate::expiry::available(
            manifest::resource(self.manifest, stored.record.resource)?,
            &stored.record.fields,
            self.authority.time(),
        )
    }
    pub(crate) async fn authorize(
        &mut self,
        operation: &Operation,
        stored: &StoredRecord,
    ) -> Result<bool> {
        ensure!(
            operation.resource == stored.record.resource,
            "authority resource mismatch"
        );
        let mut remaining = self.budget.remaining();
        let result = self
            .authority
            .authorize(
                self.tx,
                self.manifest,
                self.principal,
                operation,
                &[stored.authority_row()],
                &mut remaining,
            )
            .await;
        self.budget.update(remaining)?;
        Ok(result?[0])
    }
}

/// Load one bounded candidate group using the already resolved storage catalog
/// identity. Three complete records fit the existing 64 KiB DB transfer bound;
/// membership preparation remains one separate lookup per predicate/group.
pub(super) async fn load_batch(
    tx: &mut Transaction,
    m: &Manifest,
    resource: u32,
    storage: i64,
    ids: &[u64],
    calls: &mut usize,
) -> Result<std::collections::BTreeMap<u64, StoredRecord>> {
    ensure!(
        storage > 0 && ids.len() <= crate::membership::MAX_BATCH,
        "record batch limit"
    );
    let mut records = std::collections::BTreeMap::new();
    for chunk in ids.chunks(3) {
        let mut params = vec![storage.into()];
        let mut slots = Vec::new();
        for id in chunk {
            ensure!(*id > 0 && *id <= i64::MAX as u64, "invalid resource target");
            params.push((*id as i64).into());
            slots.push(sql!("${}", params.len()));
        }
        *calls = calls
            .checked_sub(1)
            .ok_or_else(|| anyhow::anyhow!("list database call budget"))?;
        let sql = sql!(
            "SELECT CAST(id AS TEXT),COALESCE(owner,''),tenant,{},{},CAST(revision AS TEXT),COALESCE(CAST(cap_version AS TEXT),'') FROM nx_records WHERE resource=$1 AND resource={storage} AND id IN ({}) LIMIT 3",
            tx.bounded_text("fields", 20_000),
            tx.bounded_text("incarnation", 64),
            slots.joined(",")
        );
        for [
            id,
            owner,
            tenant,
            fields,
            incarnation,
            revision,
            cap_version,
        ] in tx.fetch::<7>(&sql, &params).await?
        {
            let id = id.parse()?;
            ensure!(chunk.contains(&id), "unexpected batch record");
            let fields = serde_json::from_str(&fields)?;
            manifest::validate_fields(manifest::resource(m, resource)?, &fields)?;
            let revision = revision.parse()?;
            ensure!(
                revision > 0 && !incarnation.is_empty(),
                "invalid record metadata"
            );
            let stored = StoredRecord {
                record: Record {
                    resource,
                    id,
                    fields,
                },
                owner,
                tenant,
                incarnation,
                revision,
                cap_version: if cap_version.is_empty() {
                    None
                } else {
                    Some(cap_version.parse()?)
                },
            };
            ensure!(
                records.insert(id, stored).is_none(),
                "duplicate batch record"
            );
        }
    }
    Ok(records)
}

impl StoredRecord {
    pub(crate) fn authority_row(&self) -> crate::authority::Row<'_> {
        crate::authority::Row {
            id: self.record.id,
            owner: &self.owner,
            tenant: &self.tenant,
            fields: &self.record.fields,
        }
    }
}

impl Effects {
    pub(crate) fn read_context(&mut self) -> ReadContext<'_> {
        let budget = if matches!(self.request.kind, RequestKind::Action(_)) {
            ReadBudget::Action(&mut self.calls)
        } else {
            ReadBudget::Query(&mut self.list_calls)
        };
        ReadContext {
            tx: &mut self.tx,
            manifest: &self.manifest,
            principal: &self.principal,
            authority: &mut self.authority,
            budget,
        }
    }
    pub(crate) async fn authorize_rows(
        &mut self,
        operation: &Operation,
        rows: &[crate::authority::Row<'_>],
    ) -> Result<Vec<bool>> {
        let action = matches!(self.request.kind, RequestKind::Action(_));
        let mut calls = if action {
            self.calls as usize
        } else {
            self.list_calls
        };
        let result = self
            .authority
            .authorize(
                &mut self.tx,
                &self.manifest,
                &self.principal,
                operation,
                rows,
                &mut calls,
            )
            .await;
        if action {
            self.calls = u32::try_from(calls)?;
        } else {
            self.list_calls = calls;
        }
        result
    }

    pub(crate) async fn authorize_existing(
        &mut self,
        operation: &Operation,
        stored: &StoredRecord,
    ) -> Result<bool> {
        ensure!(
            operation.resource == stored.record.resource,
            "authority resource mismatch"
        );
        Ok(self
            .authorize_rows(operation, &[stored.authority_row()])
            .await?[0])
    }

    pub(crate) async fn authorize_candidate(
        &mut self,
        operation: &Operation,
        fields: &Fields,
    ) -> Result<()> {
        let principal = self.principal.clone();
        let (owner, tenant) = match &principal {
            Principal::Anonymous => ("", ""),
            Principal::Service(_) => anyhow::bail!(ReferenceUnavailable),
            Principal::User(user) => (user.id.as_str(), user.tenant.as_str()),
        };
        // Creation of an immediately expired row is legal. Its policy still
        // evaluates the proposed canonical values; expiry hides later reads.
        let mut calls = self.calls as usize;
        let result = self
            .authority
            .authorize(
                &mut self.tx,
                &self.manifest,
                &self.principal,
                operation,
                &[crate::authority::Row {
                    id: 0,
                    owner,
                    tenant,
                    fields,
                }],
                &mut calls,
            )
            .await;
        self.calls = u32::try_from(calls)?;
        ensure!(result?[0], ReferenceUnavailable);
        Ok(())
    }

    pub(crate) fn check_expiry_update(
        &self,
        operation: &Operation,
        before: &Fields,
        proposed: &Fields,
    ) -> Result<()> {
        crate::expiry::check_write(
            manifest::resource(&self.manifest, operation.resource)?,
            Some(before),
            proposed,
            self.authority.time(),
        )
    }

    pub(crate) fn row_unexpired(&self, stored: &StoredRecord) -> Result<bool> {
        crate::expiry::available(
            manifest::resource(&self.manifest, stored.record.resource)?,
            &stored.record.fields,
            self.authority.time(),
        )
    }

    pub(crate) async fn authority_sql(
        &mut self,
        operation: &Operation,
        params: &mut Vec<Param>,
    ) -> Result<Vec<Sql>> {
        let mut calls = self.list_calls;
        let result = self
            .authority
            .sql(
                &mut self.tx,
                &self.manifest,
                &self.principal,
                operation,
                params,
                &mut calls,
            )
            .await;
        self.list_calls = calls;
        result
    }
}
