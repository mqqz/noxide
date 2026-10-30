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
    pub preview: bool,
    pub parent: Option<String>,
    pub strategy: ListStrategy,
    pub selection: Vec<CompiledCondition>,
    pub order: ListOrder,
    pub limit: u8,
}
pub(crate) struct CompiledCondition {
    pub field: String,
    pub equals: noxide_protocol::Operand,
}

pub(crate) fn compile(m: &Manifest, op: &Operation) -> Result<ListPlan> {
    ensure!(op.kind == OperationKind::List, "expected list operation");
    let resource = manifest::resource(m, op.resource)?;
    let parent = manifest::parent_field(resource).map(|f| f.name.clone());
    Ok(ListPlan {
        operation: op.id,
        preview: op.list.as_ref().is_some_and(|s| s.preview.is_some()),
        strategy: policy::list_strategy(&op.policy, parent.is_some()),
        parent,
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

impl ListPlan {
    pub(crate) fn selection_sql(
        &self,
        tx: &crate::database::Transaction,
        params: &mut Vec<crate::database::Param>,
        values: &noxide_protocol::Fields,
    ) -> Result<String> {
        let mut sql = String::new();
        for condition in &self.selection {
            let value = operand_value(&condition.equals, values)?;
            params.push(value.as_str().into());
            sql.push_str(&format!(
                " AND {}=${}",
                tx.field_expression(&condition.field)?,
                params.len()
            ));
        }
        Ok(sql)
    }
    pub(crate) fn check_selection(
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

pub(crate) struct IndexRequirement {
    pub resource: String,
    pub columns: Vec<policy::IndexColumn>,
    pub queries: Vec<u32>,
}
impl IndexRequirement {
    pub(crate) fn name(&self, storage: i64) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(serde_json::to_vec(&self.columns).expect("index key"));
        let suffix: String = digest[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("nx_q_{storage:x}_{suffix}")
    }
    pub(crate) fn sql(&self, tx: &crate::database::Transaction, storage: i64) -> Result<String> {
        let mut columns = vec!["resource".to_owned()];
        for column in &self.columns {
            columns.push(match column {
                policy::IndexColumn::Owner => "owner".into(),
                policy::IndexColumn::Tenant => "tenant".into(),
                policy::IndexColumn::Field(field) => format!("({})", tx.field_expression(field)?),
            });
        }
        columns.push("created_seq".into());
        Ok(format!(
            "CREATE INDEX {} ON nx_records({}) WHERE resource={storage}",
            self.name(storage),
            columns.join(",")
        ))
    }
}
pub(crate) fn required_indexes(m: &Manifest) -> Result<Vec<IndexRequirement>> {
    use policy::IndexColumn;
    let mut keys: BTreeMap<(String, Vec<IndexColumn>), Vec<u32>> = BTreeMap::new();
    for op in m
        .operations
        .iter()
        .filter(|op| op.kind == OperationKind::List)
    {
        // Unfiltered contracts retain their existing static/parent/account indexes.
        if op.filter.is_empty() {
            continue;
        }
        let plan = compile(m, op)?;
        let resource = manifest::resource(m, op.resource)?;
        let scans: Vec<_> = match &plan.strategy {
            ListStrategy::Single => vec![None],
            ListStrategy::Merge(scans) => scans.iter().map(Some).collect(),
        };
        for scan in scans {
            let mut columns = policy::index_prefix(&op.policy, scan);
            if matches!(plan.strategy, ListStrategy::Single) {
                if let Some(parent) = &plan.parent {
                    columns.push(IndexColumn::Field(parent.clone()));
                }
                if let Some(visibility) = &op.visibility {
                    columns.push(IndexColumn::Field(visibility.field.clone()));
                }
            }
            let mut fields: Vec<_> = op.filter.iter().map(|c| c.field.clone()).collect();
            fields.sort();
            columns.extend(fields.into_iter().map(IndexColumn::Field));
            keys.entry((resource.name.clone(), columns))
                .or_default()
                .push(op.id);
        }
    }
    for resource in &m.resources {
        let shapes: Vec<_> = keys
            .iter()
            .filter(|((name, _), _)| name == &resource.name)
            .collect();
        ensure!(
            shapes.len() <= 8,
            "derived index limit for resource {} queries {:?}",
            resource.name,
            shapes
                .iter()
                .flat_map(|(_, queries)| queries.iter())
                .collect::<Vec<_>>()
        );
    }
    Ok(keys
        .into_iter()
        .map(|((resource, columns), queries)| IndexRequirement {
            resource,
            columns,
            queries,
        })
        .collect())
}

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
        let mut m = crate::test_support::manifest();
        for name in ["a", "b", "c", "d"] {
            m.resources[0].fields.push(TextField {
                name: name.into(),
                label: name.into(),
                kind: FieldKind::Boolean,
                optional: false,
                initial: None,
                max_bytes: 5,
            });
            m.actions[0].fields.push(name.into());
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

    #[test]
    fn existing_contracts_require_no_derived_indexes() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/fixtures/queries");
        for line in include_str!("../../../tools/fixtures/queries/digests.txt").lines() {
            let name = line.split_once(' ').unwrap().0;
            let m = crate::manifest::parse(&std::fs::read(root.join(name)).unwrap()).unwrap();
            assert!(super::required_indexes(&m).unwrap().is_empty(), "{name}");
        }
    }
}
