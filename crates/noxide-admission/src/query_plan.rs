use crate::{
    manifest,
    policy::{self, ListStrategy},
};
use anyhow::{Result, ensure};
use noxide_protocol::{ListOrder, Manifest, Operation, OperationKind};
use std::{collections::BTreeMap, sync::Arc};
pub mod aggregate;
pub mod frontier;
pub mod scalar;

/// Compiled from an admitted list operation. Grants nothing; authorization
/// and visibility are always read from the operation itself.
pub struct ListPlan {
    pub operation: u32,
    pub resource: u32,
    pub preview: bool,
    pub scope: Option<String>,
    pub strategy: ListStrategy,
    pub selection: Vec<CompiledCondition>,
    pub order: ListOrder,
    pub limit: u8,
}
pub struct CompiledCondition {
    pub field: String,
    pub equals: noxide_protocol::Operand,
}

pub fn compile(m: &Manifest, op: &Operation) -> Result<ListPlan> {
    ensure!(op.kind == OperationKind::List, "expected list operation");
    let resource = manifest::resource(m, op.resource)?;
    let scope = op.scope.clone();
    Ok(ListPlan {
        operation: op.id,
        resource: op.resource,
        preview: op.list.as_ref().is_some_and(|s| s.preview.is_some()),
        strategy: if resource.expiry.is_some() {
            policy::residual_strategy(&op.policy)
        } else {
            policy::list_strategy(&op.policy, scope.is_some())
        },
        scope,
        selection: op
            .filter
            .iter()
            .map(|c| CompiledCondition {
                field: c.field.clone(),
                equals: c.equals.clone(),
            })
            .collect(),
        order: op
            .list
            .as_ref()
            .map_or(ListOrder::CreatedAsc, |s| s.order.clone()),
        limit: op.list.as_ref().map_or(3, |s| s.page_size),
    })
}
pub fn compile_all(m: &Manifest) -> Result<BTreeMap<u32, Arc<ListPlan>>> {
    m.operations
        .iter()
        .filter(|op| op.kind == OperationKind::List)
        .map(|op| Ok((op.id, Arc::new(compile(m, op)?))))
        .collect()
}

impl ListPlan {
    pub fn descending(&self) -> bool {
        matches!(
            self.order,
            ListOrder::CreatedDesc
                | ListOrder::Field {
                    direction: noxide_protocol::query::Direction::Descending,
                    ..
                }
        )
    }
    pub fn direction(&self) -> &'static str {
        if self.descending() { "DESC" } else { "ASC" }
    }
    pub fn validate_cursor(
        &self,
        manifest: &Manifest,
        key: &noxide_protocol::query::CursorKey,
    ) -> Result<()> {
        use noxide_protocol::query::CursorKey;
        match (&self.order, key) {
            (
                ListOrder::CreatedAsc | ListOrder::CreatedDesc,
                CursorKey::Created { sequence, record },
            ) => {
                ensure!(
                    *sequence > 0
                        && *sequence <= i64::MAX as u64
                        && *record > 0
                        && *record <= i64::MAX as u64,
                    "invalid created cursor"
                );
                Ok(())
            }
            (ListOrder::Field { .. }, _) => self.scalar(manifest)?.validate_key(key),
            _ => anyhow::bail!("cursor/order mismatch"),
        }
    }
    pub fn scalar(&self, manifest: &Manifest) -> Result<scalar::Scalar> {
        let ListOrder::Field {
            field, direction, ..
        } = &self.order
        else {
            anyhow::bail!("expected scalar order")
        };
        let resource = manifest::resource(manifest, self.resource)?;
        scalar::Scalar::new(
            resource
                .fields
                .iter()
                .find(|candidate| &candidate.name == field)
                .ok_or_else(|| anyhow::anyhow!("unknown scalar field"))?,
            *direction,
        )
    }
    pub fn keyset(
        &self,
        after: Option<&noxide_protocol::query::CursorKey>,
        params: &mut Vec<crate::sql::Param>,
    ) -> Result<String> {
        let Some(key) = after else {
            return Ok(String::new());
        };
        let noxide_protocol::query::CursorKey::Created { sequence, record } = key else {
            anyhow::bail!("created cursor required")
        };
        ensure!(
            *sequence > 0
                && *sequence <= i64::MAX as u64
                && *record > 0
                && *record <= i64::MAX as u64,
            "invalid created cursor"
        );
        params.push((*sequence as i64).into());
        let sequence = params.len();
        params.push((*record as i64).into());
        let record = params.len();
        let cmp = if self.descending() { "<" } else { ">" };
        Ok(format!(" AND (created_seq,id){cmp}(${sequence},${record})"))
    }
}

impl ListPlan {
    pub fn selection_sql(
        &self,
        provider: NativeProvider,
        params: &mut Vec<crate::sql::Param>,
        values: &noxide_protocol::Fields,
    ) -> Result<String> {
        let mut sql = String::new();
        for condition in &self.selection {
            let value = operand_value(&condition.equals, values)?;
            params.push(value.as_str().into());
            sql.push_str(&format!(
                " AND {}=${}",
                provider.field_expression(&condition.field)?,
                params.len()
            ));
        }
        Ok(sql)
    }
    pub fn check_selection(
        &self,
        fields: &noxide_protocol::Fields,
        values: &noxide_protocol::Fields,
    ) -> Result<()> {
        for condition in &self.selection {
            let value = operand_value(&condition.equals, values)?;
            ensure!(
                fields.get(&condition.field) == Some(value),
                "selection invariant"
            );
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
pub use indexes::IndexTable;
pub use indexes::{
    IndexOrder, IndexRequirement, NativeProvider, ScalarRepresentation, required_indexes,
};
mod indexes;

fn operand_value<'a>(
    operand: &'a noxide_protocol::Operand,
    values: &'a noxide_protocol::Fields,
) -> Result<&'a String> {
    match operand {
        noxide_protocol::Operand::Literal(value) => Ok(value),
        noxide_protocol::Operand::Param(name) => values
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("missing query parameter")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_rejects_ninth_derived_shape() {
        use noxide_protocol::*;
        let mut m = noxide_test_support::manifest();
        for name in ["a", "b", "c", "d"] {
            m.resources[0].fields.push(TextField {
                immutable: false,
                name: name.into(),
                label: name.into(),
                kind: FieldKind::Boolean,
                optional: false,
                initial: None,
                max_bytes: 5,
            });
            m.actions[0].inputs.push(Input {
                name: name.into(),
                label: name.into(),
                kind: FieldKind::Boolean,
                optional: false,
                max_bytes: 5,
            });
            m.actions[0].steps[0].assign.push(Assignment {
                field: name.into(),
                change: Change::Set(Value::Input(name.into())),
            });
        }
        for mask in 1..=9u32 {
            let mut op = m.operations[0].clone();
            op.id = mask + 10;
            op.filter = ["a", "b", "c", "d"]
                .into_iter()
                .enumerate()
                .filter(|(bit, _)| mask & (1 << bit) != 0)
                .map(|(_, field)| Condition {
                    field: field.into(),
                    equals: Operand::Literal("false".into()),
                })
                .collect();
            m.routes.push(Route {
                params: Vec::new(),
                id: op.id,
                path: format!("/shape{mask}"),
                resource: None,
                operations: vec![op.id],
                forms: vec![],
                access: Access::Authenticated,
            });
            m.operations.push(op);
            if mask <= 8 {
                crate::manifest::validate(&m).unwrap();
            }
        }
        let error = crate::manifest::validate(&m).unwrap_err().to_string();
        assert!(
            error.contains("derived index limit") && error.contains("notes"),
            "{error}"
        );
    }
}
