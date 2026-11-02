use crate::sql::{Sql, sql};
use noxide_store::statements::records as stmt;
mod authority;
mod computation;
mod follow;
mod invoke;
mod lists;
pub mod queries;
pub mod search;
mod transaction;
use crate::{
    auth::Principal,
    database::{Param, RecordScan, Transaction},
    manifest,
    security::RecordTarget,
};
use anyhow::{Result, ensure};
pub use authority::{ReadBudget, ReadContext};
#[cfg(any(test, feature = "test-support"))]
pub use authority::{test_authorize_page_resource, test_read_resource};
pub use computation::{CalculationUnavailable, Scalar as ScheduleScalar, Values as ScheduleValues};
use noxide_protocol::query::CursorKey;
use noxide_protocol::*;
use std::sync::Arc;

pub use crate::action_contract::ReferenceUnavailable;

#[derive(Debug)]
pub struct GuardFailure {
    pub input: Option<String>,
    pub message: String,
}
impl std::fmt::Display for GuardFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("transaction guard rejected")
    }
}
impl std::error::Error for GuardFailure {}

pub use crate::database::ConditionalConflict;

/// Candidate-dependent predicates are unknown until the proposed row resolves.
/// Every other prerequisite remains checked before guest execution and guards.
pub fn create_prerequisites(operation: &Operation, principal: &Principal) -> bool {
    if manifest::is_public(operation) {
        return true;
    }
    let Ok(user) = principal.user() else {
        return false;
    };
    operation.policy.any.iter().any(|rule| {
        !rule.is_empty()
            && rule.iter().all(|predicate| match predicate {
                Predicate::PrincipalIs { .. } | Predicate::ExistsRelated(_) => true,
                Predicate::Public
                | Predicate::Service { .. }
                | Predicate::Capability
                | Predicate::Owner
                | Predicate::SameTenant
                | Predicate::Role { .. } => allowed(
                    &Policy {
                        any: vec![vec![predicate.clone()]],
                    },
                    principal,
                    crate::policy::Row {
                        owner: &user.id,
                        tenant: &user.tenant,
                        fields: &Fields::new(),
                    },
                ),
            })
    })
}

impl noxide_host_calls::HostCalls for Effects {
    /// Accounts and service workers never share. Anonymous visitors share a worker for
    /// reading pages, whose URLs an escaped guest could then see; anything they submit,
    /// or reach through a capability, gets a worker of its own.
    fn isolation(&self) -> noxide_host_calls::Isolation {
        use crate::auth::PrincipalKey;
        use noxide_host_calls::Isolation;
        match self.principal.authority_key() {
            PrincipalKey::User { id, tenant } => Isolation::Shared(format!("user\0{id}\0{tenant}")),
            PrincipalKey::Service {
                deployment, tenant, ..
            } => Isolation::Shared(format!("service\0{deployment}\0{tenant}")),
            PrincipalKey::Anonymous => {
                if self.request.input.is_empty()
                    && self.request.inspection.is_empty()
                    && self.capability_grant.is_none()
                {
                    Isolation::Shared("anonymous".into())
                } else {
                    Isolation::Single
                }
            }
        }
    }
    fn storage_allowed(&self) -> bool {
        matches!(self.request.kind, RequestKind::Route(_))
    }
    async fn invoke(&mut self, operation: u32, target: u64) -> Result<Vec<u8>> {
        Effects::invoke(self, operation, target).await
    }
    fn follow_source(&mut self, resource: u32, id: u64) -> Result<()> {
        Effects::follow_source(self, resource, id)
    }
    async fn follow(&mut self, operation: u32) -> Result<Vec<u8>> {
        Effects::follow(self, operation).await
    }
}

pub const MAX_LIST_DATABASE_CALLS: usize = 4096;

pub struct Effects {
    pub authority: crate::authority::Authority,
    pub upload: Option<noxide_blobs::upload::UploadContext>,
    pub blob_reads:
        std::collections::BTreeMap<(u32, u64, String), (String, noxide_protocol::blobs::BlobRef)>,
    pub provenance:
        std::collections::BTreeMap<(u32, u32, u64), std::collections::BTreeMap<String, u64>>,
    pub follow_sources: Vec<(u32, u64)>,
    pub invoked: std::collections::BTreeSet<u32>,
    pub list_bytes: usize,
    pub list_calls: usize,
    pub result_limit: usize,
    pub truncated: bool,
    pub see_all: Vec<RouteRef>,
    pub tx: Transaction,
    pub manifest: Arc<Manifest>,
    pub plans: std::collections::BTreeMap<u32, Arc<crate::query_plan::ListPlan>>,
    pub principal: Principal,
    pub request: RequestView,
    pub grants: std::collections::BTreeMap<String, RecordTarget>,
    pub target_rows: std::collections::BTreeMap<(u32, u64), StoredRecord>,
    /// Final rows this transaction wrote. Its own write locks keep them current,
    /// so later steps and job sealing reuse their data, never their authority.
    pub written_rows: std::collections::BTreeMap<(u32, u64), StoredRecord>,
    pub capability_grant: Option<RecordTarget>,
    pub calls: u32,
    pub cursor: Option<CursorKey>,
    pub more: Option<CursorKey>,
}

#[derive(Clone)]
#[cfg_attr(any(test, feature = "test-support"), derive(Debug, PartialEq, Eq))]
pub struct StoredRecord {
    pub record: Record,
    pub owner: String,
    pub tenant: String,
    pub incarnation: String,
    pub revision: i64,
    pub cap_version: Option<i64>,
}

pub async fn load(
    tx: &mut Transaction,
    m: &Manifest,
    resource: u32,
    id: u64,
) -> Result<Option<StoredRecord>> {
    ensure!(id > 0 && id <= i64::MAX as u64, "invalid resource target");
    let storage_resource = tx.storage_resource(m, resource).await?;
    let query = stmt::record_by_id(tx);
    let rows = tx
        .rows(
            &query,
            &[Param::Number(storage_resource), Param::Number(id as i64)],
        )
        .await?;
    rows.into_iter()
        .next()
        .map(
            |[owner, tenant, fields, incarnation, revision, cap_version]| {
                let fields = serde_json::from_str(&fields)?;
                manifest::validate_fields(manifest::resource(m, resource)?, &fields)?;
                let revision = revision.parse()?;
                ensure!(
                    revision > 0 && !incarnation.is_empty(),
                    "invalid record metadata"
                );
                Ok(StoredRecord {
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
                })
            },
        )
        .transpose()
}

pub use crate::policy::allowed;

/// Common host read authorization and projection; no guest code is executed.
async fn read_projected_resource(
    context: &mut ReadContext<'_>,
    op: &Operation,
    target: u64,
) -> Result<Option<(Record, String)>> {
    let Some(stored) = context.load(op.resource, target).await? else {
        return Ok(None);
    };
    if !authorize_stored_read(context, op, &stored).await? {
        return Ok(None);
    }
    let mut record = stored.record;
    if manifest::is_public(op) {
        let projection = op
            .fields
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing read projection"))?;
        record.fields.retain(|name, _| projection.contains(name));
    }
    Ok(Some((record, stored.incarnation)))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn read_resource(
    context: &mut ReadContext<'_>,
    op: &Operation,
    target: u64,
) -> Result<Option<Record>> {
    Ok(read_projected_resource(context, op, target)
        .await?
        .map(|(record, _)| record))
}

pub async fn authorize_stored_read(
    context: &mut ReadContext<'_>,
    op: &Operation,
    stored: &StoredRecord,
) -> Result<bool> {
    ensure!(
        matches!(op.kind, OperationKind::Read | OperationKind::List),
        "invalid row read authority"
    );
    if !read_allowed(context, op, stored).await? {
        return Ok(false);
    }
    let source = manifest::resource(context.manifest, op.resource)?;
    if manifest::is_public(op)
        && let Some(gate) = &source.gate
    {
        let parent = manifest::reference_resource(context.manifest, op.resource, &gate.field)?
            .expect("admitted gate reference");
        let id = stored.record.fields[&gate.field].parse()?;
        let Some(parent) = context.load(parent.id, id).await? else {
            return Ok(false);
        };
        if !context.unexpired(&parent)?
            || !manifest::gate_permits(source, &parent.record.fields, false)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub async fn read_allowed(
    context: &mut ReadContext<'_>,
    op: &Operation,
    stored: &StoredRecord,
) -> Result<bool> {
    ensure!(
        matches!(op.kind, OperationKind::Read | OperationKind::List)
            && op.resource == stored.record.resource,
        "invalid read binding"
    );
    if !context.authorize(op, stored).await? {
        return Ok(false);
    }
    if manifest::is_public(op) {
        let visibility = op
            .visibility
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing visibility"))?;
        ensure!(op.fields.is_some(), "missing read projection");
        if stored.record.fields.get(&visibility.field) != Some(&visibility.equals) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub async fn authorize_page_resource(
    context: &mut ReadContext<'_>,
    route: &Route,
    resource: u32,
    id: u64,
    incarnation: Option<&str>,
) -> Result<Option<StoredRecord>> {
    ensure!(route.resource == Some(resource), "route resource differs");
    let Some(stored) = context.load(resource, id).await? else {
        return Ok(None);
    };
    if incarnation.is_some_and(|value| value != stored.incarnation) {
        return Ok(None);
    }
    let mut reads = 0;
    let mut public_read = false;
    let mut private_read = false;
    for operation in &route.operations {
        let op = manifest::operation(context.manifest, *operation)?;
        if op.kind == OperationKind::Read && op.via.is_none() && op.resource == resource {
            reads += 1;
            if read_allowed(context, op, &stored).await? {
                if manifest::is_public(op) {
                    public_read = true;
                } else {
                    private_read = true;
                }
            }
        }
    }
    ensure!(reads > 0, "missing resource read");
    if !public_read && !private_read {
        return Ok(None);
    }
    if !private_read && let Some(gate) = &manifest::resource(context.manifest, resource)?.gate {
        let parent = manifest::reference_resource(context.manifest, resource, &gate.field)?
            .expect("admitted gate reference");
        let id = stored.record.fields[&gate.field].parse()?;
        let Some(parent) = context.load(parent.id, id).await? else {
            return Ok(None);
        };
        if !context.unexpired(&parent)?
            || !manifest::gate_permits(
                manifest::resource(context.manifest, resource)?,
                &parent.record.fields,
                false,
            )
        {
            return Ok(None);
        }
    }
    Ok(Some(stored))
}

#[cfg(test)]
mod tests;
