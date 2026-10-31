//! Runtime hooks into the shared authority context; the executor remains in its
//! existing module. Registration and call sites are applied by the runtime owner.
use super::*;

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
    ) -> Result<Vec<String>> {
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
