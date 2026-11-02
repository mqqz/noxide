//! One canonical registry for record, membership and normalized posting shapes.
use super::*;
use noxide_protocol::{FieldKind, query::Direction};
use policy::IndexColumn;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum IndexTable {
    Records,
    Postings,
}
impl IndexTable {
    pub fn name(self) -> &'static str {
        match self {
            Self::Records => "nx_records",
            Self::Postings => "nx_search_postings",
        }
    }
}
#[derive(Clone, Copy)]
pub enum NativeProvider {
    Sqlite,
    Postgres,
}
impl NativeProvider {
    pub fn field_expression(self, field: &str) -> Result<Sql> {
        self.field_on("fields", field)
    }
    /// A field of a row under a host-owned table alias.
    pub fn qualified_field(self, alias: &str, field: &str) -> Result<Sql> {
        ensure!(manifest::identifier(alias), "invalid table alias");
        self.field_on(&format!("{alias}.fields"), field)
    }
    fn field_on(self, column: &str, field: &str) -> Result<Sql> {
        ensure!(manifest::identifier(field), "invalid field");
        let field = Sql::identifier(field)?;
        let column = Sql::join(
            column
                .split('.')
                .map(Sql::identifier)
                .collect::<Result<Vec<_>>>()?,
            ".",
        );
        Ok(match self {
            Self::Sqlite => sql!("json_extract({column}, '$.\"{field}\"')"),
            Self::Postgres => sql!("({column}::jsonb ->> '{field}')"),
        })
    }
    pub fn binary_collation(self) -> &'static str {
        match self {
            Self::Sqlite => "BINARY",
            Self::Postgres => "\"C\"",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ScalarRepresentation {
    Numeric,
    Binary,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum IndexOrder {
    Created,
    Scalar {
        field: String,
        representation: ScalarRepresentation,
    },
}
#[derive(Debug)]
pub struct IndexRequirement {
    pub resource: String,
    pub table: IndexTable,
    /// Equality prefix; ordered key and stable ID tie are separate below.
    pub columns: Vec<IndexColumn>,
    pub order: IndexOrder,
    pub queries: Vec<u32>,
}
impl IndexRequirement {
    pub fn shape_hash(&self) -> String {
        let fixed_prefix: &[&str] = match self.table {
            IndexTable::Records => &["resource:numeric"],
            IndexTable::Postings => &["resource:numeric", "field:numeric", "token:binary"],
        };
        let tie = match self.table {
            IndexTable::Records => "id",
            IndexTable::Postings => "record_id",
        };
        let shape = (
            self.table,
            fixed_prefix,
            &self.columns,
            &self.order,
            // Physical ordering is ASC; reversing both keys satisfies DESC.
            Direction::Ascending,
            tie,
        );
        let digest = Sha256::digest(serde_json::to_vec(&shape).expect("index shape"));
        digest[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    pub fn name(&self, storage: i64) -> String {
        match self.table {
            // One physical index, accounted once for every searchable resource.
            IndexTable::Postings => "nx_search_tokens".into(),
            IndexTable::Records => format!("nx_q_{storage:x}_{}", self.shape_hash()),
        }
    }
    pub fn native_sql(&self, provider: NativeProvider, storage: i64) -> Result<Sql> {
        self.sql_with(
            storage,
            |field| provider.field_expression(field),
            provider.binary_collation(),
        )
    }
    fn sql_with(
        &self,
        storage: i64,
        field_expression: impl Fn(&str) -> Result<Sql>,
        binary_collation: &'static str,
    ) -> Result<Sql> {
        ensure!(storage > 0, "invalid storage identity");
        if self.table == IndexTable::Postings {
            ensure!(
                self.columns.is_empty() && self.order == IndexOrder::Created,
                "unsupported posting index shape"
            );
            return Ok(sql!(
                "CREATE INDEX nx_search_tokens ON {}(resource,field,token,created_seq,record_id)",
                self.table.name()
            ));
        }
        let mut columns = vec![Sql::statement("resource")];
        for column in &self.columns {
            columns.push(match column {
                IndexColumn::Owner => Sql::statement("owner"),
                IndexColumn::Tenant => Sql::statement("tenant"),
                IndexColumn::Field(field) => sql!("({})", field_expression(field)?),
                IndexColumn::Timestamp(field) => {
                    sql!("(CAST({} AS BIGINT))", field_expression(field)?)
                }
            });
        }
        columns.push(match &self.order {
            IndexOrder::Created => Sql::statement("created_seq"),
            IndexOrder::Scalar {
                field,
                representation,
            } => {
                let expression = field_expression(field)?;
                match representation {
                    ScalarRepresentation::Numeric => sql!("(CAST({expression} AS BIGINT))"),
                    ScalarRepresentation::Binary => {
                        sql!("(({expression}) COLLATE {})", binary_collation)
                    }
                }
            }
        });
        columns.push(Sql::statement("id"));
        Ok(sql!(
            "CREATE INDEX {} ON {}({}) WHERE resource={storage}",
            Sql::identifier(&self.name(storage))?,
            self.table.name(),
            Sql::join(&columns, ",")
        ))
    }
}

type Shape = (String, IndexTable, Vec<IndexColumn>, IndexOrder);
#[allow(clippy::too_many_lines)]
pub fn required_indexes(m: &Manifest) -> Result<Vec<IndexRequirement>> {
    let mut keys: BTreeMap<Shape, Vec<u32>> = BTreeMap::new();
    for resource in m
        .resources
        .iter()
        .filter(|resource| resource.search.is_some())
    {
        keys.insert(
            (
                resource.name.clone(),
                IndexTable::Postings,
                vec![],
                IndexOrder::Created,
            ),
            vec![],
        );
    }
    for op in m
        .operations
        .iter()
        .filter(|op| op.kind == OperationKind::List)
    {
        let search = op
            .query
            .as_ref()
            .is_some_and(|query| query.search.is_some());
        let scalar = matches!(
            op.list.as_ref().map(|list| &list.order),
            Some(ListOrder::Field { .. })
        );
        let aggregate_source = m.operations.iter().any(|consumer| {
            consumer
                .query
                .as_ref()
                .and_then(|query| query.aggregate.as_ref())
                .is_some_and(|aggregate| aggregate.source == op.id)
        });
        let extended = search || scalar || aggregate_source;
        // Broad created search seals postings, not a second unused record scan.
        if search && !scalar && op.scope.is_none() {
            let resource = manifest::resource(m, op.resource)?;
            let key = (
                resource.name.clone(),
                IndexTable::Postings,
                vec![],
                IndexOrder::Created,
            );
            keys.get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("search declaration required"))?
                .push(op.id);
            continue;
        }
        if op.filter.is_empty() && !extended {
            continue;
        }
        let plan = compile(m, op)?;
        let resource = manifest::resource(m, op.resource)?;
        let order = match &plan.order {
            ListOrder::CreatedAsc | ListOrder::CreatedDesc => IndexOrder::Created,
            ListOrder::Field { field, .. } => {
                let schema = resource
                    .fields
                    .iter()
                    .find(|schema| &schema.name == field)
                    .ok_or_else(|| anyhow::anyhow!("unknown scalar field"))?;
                IndexOrder::Scalar {
                    field: field.clone(),
                    representation: match schema.kind {
                        FieldKind::Integer { .. }
                        | FieldKind::Timestamp
                        | FieldKind::Duration { .. }
                        | FieldKind::Reference { .. } => ScalarRepresentation::Numeric,
                        FieldKind::Text
                        | FieldKind::Boolean
                        | FieldKind::Choice { .. }
                        | FieldKind::Account { .. } => ScalarRepresentation::Binary,
                        _ => anyhow::bail!("unsupported scalar index"),
                    },
                }
            }
        };
        let bounded = policy::residual_strategy(&op.policy);
        let mut scans: Vec<_> = match if extended { &bounded } else { &plan.strategy } {
            ListStrategy::Single => vec![None],
            ListStrategy::Merge(scans) => scans.iter().map(Some).collect(),
        };
        // A routed ordinary source still uses its canonical existing List
        // strategy. Retain its filtered shape as well as aggregate frontiers.
        if aggregate_source && !search && !scalar && !op.filter.is_empty() {
            match &plan.strategy {
                ListStrategy::Single => scans.push(None),
                ListStrategy::Merge(legacy) => scans.extend(legacy.iter().map(Some)),
            }
        }
        for scan in scans {
            let mut columns = policy::index_prefix(&op.policy, scan);
            if extended || matches!(plan.strategy, ListStrategy::Single) {
                if let Some(parent) = &plan.scope {
                    columns.push(IndexColumn::Field(parent.clone()));
                }
                if let Some(visibility) = &op.visibility {
                    columns.push(IndexColumn::Field(visibility.field.clone()));
                }
            }
            let mut fields: Vec<_> = op
                .filter
                .iter()
                .map(|condition| condition.field.clone())
                .collect();
            fields.sort();
            columns.extend(fields.into_iter().map(IndexColumn::Field));
            keys.entry((
                resource.name.clone(),
                IndexTable::Records,
                columns,
                order.clone(),
            ))
            .or_default()
            .push(op.id);
        }
    }
    for op in &m.operations {
        for plan in crate::membership::plans(m, op)? {
            let related = plan.declaration();
            let mut columns = vec![
                IndexColumn::Tenant,
                IndexColumn::Field(related.reference.clone()),
                IndexColumn::Field(related.account.clone()),
            ];
            columns.extend(related.conditions.keys().cloned().map(IndexColumn::Field));
            if let Some(expiry) = &plan.resource().expiry {
                columns.push(IndexColumn::Timestamp(expiry.field.clone()));
            }
            keys.entry((
                related.resource.clone(),
                IndexTable::Records,
                columns,
                IndexOrder::Created,
            ))
            .or_default()
            .push(op.id);
        }
    }
    for resource in &m.resources {
        let shapes: Vec<_> = keys
            .iter()
            .filter(|((name, ..), _)| name == &resource.name)
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
        .map(|((resource, table, columns, order), mut queries)| {
            queries.sort_unstable();
            queries.dedup();
            IndexRequirement {
                resource,
                table,
                columns,
                order,
                queries,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxide_protocol::{FieldKind, ListSettings, TextField, query::SortMode};

    fn scalar(representation: ScalarRepresentation) -> IndexRequirement {
        IndexRequirement {
            resource: "notes".into(),
            table: IndexTable::Records,
            columns: vec![IndexColumn::Owner],
            order: IndexOrder::Scalar {
                field: "title".into(),
                representation,
            },
            queries: vec![1],
        }
    }
    #[test]
    fn native_ddl_pins_record_table_scalar_type_collation_and_id_tie() {
        let binary = scalar(ScalarRepresentation::Binary);
        let name = binary.name(7);
        assert_eq!(
            binary.native_sql(NativeProvider::Sqlite, 7).unwrap(),
            format!(
                "CREATE INDEX {name} ON nx_records(resource,owner,((json_extract(fields, '$.\"title\"')) COLLATE BINARY),id) WHERE resource=7"
            )
        );
        assert_eq!(
            binary.native_sql(NativeProvider::Postgres, 7).unwrap(),
            format!(
                "CREATE INDEX {name} ON nx_records(resource,owner,(((fields::jsonb ->> 'title')) COLLATE \"C\"),id) WHERE resource=7"
            )
        );
        let numeric = scalar(ScalarRepresentation::Numeric);
        assert_eq!(
            numeric.native_sql(NativeProvider::Postgres, 7).unwrap(),
            format!(
                "CREATE INDEX {} ON nx_records(resource,owner,(CAST((fields::jsonb ->> 'title') AS BIGINT)),id) WHERE resource=7",
                numeric.name(7)
            )
        );
        assert_ne!(binary.shape_hash(), numeric.shape_hash());
        let mut created = scalar(ScalarRepresentation::Binary);
        created.order = IndexOrder::Created;
        assert_ne!(binary.shape_hash(), created.shape_hash());
        assert!(binary.native_sql(NativeProvider::Sqlite, 0).is_err());
        let mut forged = scalar(ScalarRepresentation::Binary);
        forged.order = IndexOrder::Scalar {
            field: "title');DROP TABLE nx_records".into(),
            representation: ScalarRepresentation::Binary,
        };
        assert!(forged.native_sql(NativeProvider::Postgres, 7).is_err());
    }

    #[test]
    fn common_posting_index_has_one_pinned_physical_identity_for_all_resources() {
        let a = IndexRequirement {
            resource: "a".into(),
            table: IndexTable::Postings,
            columns: vec![],
            order: IndexOrder::Created,
            queries: vec![1],
        };
        let b = IndexRequirement {
            resource: "b".into(),
            table: IndexTable::Postings,
            columns: vec![],
            order: IndexOrder::Created,
            queries: vec![2],
        };
        assert_eq!(a.name(1), "nx_search_tokens");
        assert_eq!(a.name(1), b.name(99));
        assert_eq!(a.shape_hash(), b.shape_hash());
        for provider in [NativeProvider::Sqlite, NativeProvider::Postgres] {
            assert_eq!(
                a.native_sql(provider, 1).unwrap(),
                "CREATE INDEX nx_search_tokens ON nx_search_postings(resource,field,token,created_seq,record_id)"
            );
        }
        let mut invalid = a;
        invalid.columns.push(IndexColumn::Owner);
        assert!(invalid.native_sql(NativeProvider::Sqlite, 1).is_err());
        assert_ne!(
            invalid.shape_hash(),
            scalar(ScalarRepresentation::Numeric).shape_hash()
        );
    }

    #[test]
    fn global_postings_and_custom_records_share_the_same_eight_shape_limit() {
        let mut manifest = noxide_test_support::manifest();
        manifest.resources[0].search = Some(noxide_protocol::query::SearchIndex {
            tokenizer: noxide_protocol::query::TOKENIZER_ID.into(),
            fields: vec!["title".into()],
            max_bytes: 16_384,
        });
        let template = manifest.operations[0].clone();
        for number in 0..8 {
            let field = format!("key{number}");
            manifest.resources[0].fields.push(TextField {
                immutable: false,
                kind: FieldKind::Integer {
                    min: Some(i64::MIN),
                    max: Some(i64::MAX),
                },
                optional: false,
                initial: None,
                name: field.clone(),
                label: field.clone(),
                max_bytes: 20,
            });
            let mut operation = template.clone();
            operation.id = 100 + number;
            operation.list = Some(ListSettings {
                preview: None,
                order: ListOrder::Field {
                    field,
                    direction: Direction::Ascending,
                    mode: SortMode::LiveView,
                },
                page_size: 3,
            });
            manifest.operations.push(operation);
            if number < 7 {
                let required = required_indexes(&manifest).unwrap();
                assert_eq!(required.len(), number as usize + 2);
                assert_eq!(
                    required
                        .iter()
                        .filter(|index| index.table == IndexTable::Postings)
                        .count(),
                    1
                );
            }
        }
        assert!(
            required_indexes(&manifest)
                .unwrap_err()
                .to_string()
                .contains("derived index limit")
        );
    }
}
