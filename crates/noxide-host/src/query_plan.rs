use crate::{
    manifest,
    policy::{self, ListStrategy},
};
use anyhow::{Result, ensure};
use noxide_protocol::{ListOrder, Manifest, Operation, OperationKind};
use std::{collections::BTreeMap, sync::Arc};

/// Compiled from an admitted list operation. Grants nothing; authorization
/// and visibility are always read from the operation itself.
pub(crate) struct ListPlan {
    pub operation: u32,
    pub parent: Option<String>,
    pub strategy: ListStrategy,
    pub selection: Vec<CompiledCondition>,
    pub order: ListOrder,
    pub limit: u8,
}
pub(crate) enum CompiledCondition {}

pub(crate) fn compile(m: &Manifest, op: &Operation) -> Result<ListPlan> {
    ensure!(op.kind == OperationKind::List, "expected list operation");
    let resource = manifest::resource(m, op.resource)?;
    let parent = manifest::parent_field(resource).map(|f| f.name.clone());
    Ok(ListPlan {
        operation: op.id,
        strategy: policy::list_strategy(&op.policy, parent.is_some()),
        parent,
        selection: Vec::new(),
        order: op
            .list
            .as_ref()
            .map_or(ListOrder::CreatedAsc, |s| s.order.clone()),
        limit: op.list.as_ref().map_or(3, |s| s.page_size),
    })
}
pub(crate) fn compile_all(m: &Manifest) -> Result<BTreeMap<u32, Arc<ListPlan>>> {
    m.operations
        .iter()
        .filter(|op| op.kind == OperationKind::List)
        .map(|op| Ok((op.id, Arc::new(compile(m, op)?))))
        .collect()
}

impl ListPlan {
    pub(crate) fn descending(&self) -> bool {
        self.order == ListOrder::CreatedDesc
    }
    pub(crate) fn direction(&self) -> &'static str {
        if self.descending() { "DESC" } else { "ASC" }
    }
    pub(crate) fn keyset(
        &self,
        after: Option<u64>,
        params: &mut Vec<crate::database::Param>,
    ) -> String {
        after.map_or_else(String::new, |after| {
            params.push((after as i64).into());
            format!(
                " AND created_seq{}${}",
                if self.descending() { "<" } else { ">" },
                params.len()
            )
        })
    }
}
