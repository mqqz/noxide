//! Independent canonical P09 admission. Execution remains denied until all bridges land.
use super::*;
use noxide_protocol::query::{AggregateFunction, CursorValue, Disclosure, SortMode};
use std::collections::BTreeSet;

pub(super) fn uses_extensions(m: &Manifest) -> bool {
    m.resources.iter().any(|r| r.search.is_some())
        || m.operations.iter().any(|op| {
            op.query.is_some()
                || op.kind == OperationKind::Aggregate
                || op
                    .list
                    .as_ref()
                    .is_some_and(|list| matches!(list.order, ListOrder::Field { .. }))
        })
}
pub(super) fn canonicalize(m: &mut Manifest) {
    for resource in &mut m.resources {
        if let Some(index) = &mut resource.search {
            index.fields.sort();
        }
    }
    for operation in &mut m.operations {
        if let Some(query) = &mut operation.query {
            if let Some(search) = &mut query.search {
                search.fields.sort();
            }
            query.disclose.sort();
        }
    }
}
pub(crate) fn scalar(field: &TextField, value: &str) -> Result<CursorValue> {
    ensure!(!field.optional, "optional query scalar");
    ensure!(
        field
            .canonical(value)
            .as_ref()
            .is_ok_and(|canonical| canonical == value),
        "noncanonical query scalar"
    );
    match field.kind {
        FieldKind::Integer { .. }
        | FieldKind::Timestamp
        | FieldKind::Duration { .. }
        | FieldKind::Reference { .. } => Ok(CursorValue::Integer(value.parse()?)),
        FieldKind::Text
        | FieldKind::Boolean
        | FieldKind::Choice { .. }
        | FieldKind::Account { .. } => Ok(CursorValue::Binary(value.into())),
        _ => anyhow::bail!("query scalar kind is unsupported"),
    }
}
pub(crate) fn scalar_field(field: &TextField) -> Result<()> {
    ensure!(!field.optional, "optional sort/range key");
    match field.kind {
        FieldKind::Text => ensure!(
            field.max_bytes <= 512,
            "Text sort/range key exceeds512 UTF8 bytes"
        ),
        FieldKind::Integer { .. }
        | FieldKind::Timestamp
        | FieldKind::Duration { .. }
        | FieldKind::Reference { .. }
        | FieldKind::Boolean
        | FieldKind::Choice { .. }
        | FieldKind::Account { .. } => {}
        _ => anyhow::bail!("query scalar kind is unsupported"),
    }
    Ok(())
}
fn field<'a>(resource: &'a Resource, name: &str) -> Result<&'a TextField> {
    resource
        .fields
        .iter()
        .find(|field| field.name == name)
        .ok_or_else(|| anyhow::anyhow!("unknown query field"))
}
fn names(fields: &[String], limit: usize) -> Result<()> {
    ensure!(
        !fields.is_empty() && fields.len() <= limit,
        "query field limit"
    );
    ensure!(
        fields.iter().all(|name| identifier(name))
            && fields.iter().collect::<BTreeSet<_>>().len() == fields.len(),
        "duplicate or invalid query field"
    );
    Ok(())
}
fn operand(field: &TextField, value: &Operand) -> Result<()> {
    match value {
        Operand::Literal(value) => {
            scalar(field, value)?;
        }
        Operand::Param(name) => ensure!(
            identifier(name) && name != "cursor",
            "invalid range parameter"
        ),
    }
    Ok(())
}
fn envelope_equal(left: &Operation, right: &Operation) -> bool {
    left.resource == right.resource
        && left.policy == right.policy
        && left.scope == right.scope
        && left.via == right.via
        && left.bind == right.bind
        && left.filter == right.filter
        && left.disclose == right.disclose
        && left.visibility == right.visibility
        && left.fields == right.fields
}
pub(super) fn validate_declarations(m: &Manifest) -> Result<()> {
    for resource in &m.resources {
        if let Some(index) = &resource.search {
            ensure!(
                index.tokenizer == noxide_protocol::query::TOKENIZER_ID,
                "unsupported search tokenizer; explicit rebuild required"
            );
            names(&index.fields, 4)?;
            ensure!(
                (1..=16384).contains(&index.max_bytes),
                "indexed input byte declaration"
            );
            for name in &index.fields {
                ensure!(
                    matches!(field(resource, name)?.kind, FieldKind::Text),
                    "search index requires Text fields"
                );
            }
        }
    }
    for operation in &m.operations {
        let resource = resource(m, operation.resource)?;
        let mut inferred = BTreeSet::new();
        let unprojected = |name: &str| {
            is_public(operation)
                && operation
                    .fields
                    .as_ref()
                    .is_none_or(|projection| !projection.iter().any(|field| field == name))
        };
        let query = operation.query.as_ref();
        if let Some(query) = query {
            ensure!(!query.is_empty(), "empty query extension");
        }
        if let Some(ListSettings {
            order: ListOrder::Field {
                field: name, mode, ..
            },
            ..
        }) = &operation.list
        {
            ensure!(
                operation.kind == OperationKind::List,
                "scalar order requires list"
            );
            let key = field(resource, name)?;
            scalar_field(key)?;
            ensure!(
                *mode == SortMode::LiveView || key.is_immutable(),
                "mutable order requires explicit live_view"
            );
            if unprojected(name) {
                inferred.insert(Disclosure::Order {
                    field: name.clone(),
                });
            }
        }
        if let Some(search) = query.and_then(|query| query.search.as_ref()) {
            ensure!(
                operation.kind == OperationKind::List,
                "search requires list"
            );
            names(&search.fields, 4)?;
            ensure!(
                identifier(&search.parameter) && search.parameter != "cursor",
                "invalid search parameter"
            );
            let index = resource
                .search
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("search index is not declared"))?;
            for name in &search.fields {
                ensure!(index.fields.contains(name), "search field is not indexed");
                if unprojected(name) {
                    inferred.insert(Disclosure::Search {
                        field: name.clone(),
                    });
                }
            }
        }
        if let Some(range) = query.and_then(|query| query.range.as_ref()) {
            ensure!(operation.kind == OperationKind::List, "range requires list");
            ensure!(
                operation.list.as_ref().is_some_and(
                    |list| matches!(&list.order,ListOrder::Field{field,..} if field==&range.field)
                ),
                "range must use the ordered scalar"
            );
            let key = field(resource, &range.field)?;
            scalar_field(key)?;
            ensure!(
                range.lower.is_some() || range.upper.is_some(),
                "range requires a bound"
            );
            for bound in [&range.lower, &range.upper].into_iter().flatten() {
                operand(key, &bound.value)?;
            }
            if let (Some(lower), Some(upper)) = (&range.lower, &range.upper)
                && let (Operand::Literal(lower_value), Operand::Literal(upper_value)) =
                    (&lower.value, &upper.value)
            {
                let order = match (scalar(key, lower_value)?, scalar(key, upper_value)?) {
                    (CursorValue::Integer(left), CursorValue::Integer(right)) => left.cmp(&right),
                    (CursorValue::Binary(left), CursorValue::Binary(right)) => {
                        left.as_bytes().cmp(right.as_bytes())
                    }
                    _ => unreachable!(),
                };
                ensure!(
                    order.is_lt() || order.is_eq() && lower.inclusive && upper.inclusive,
                    "empty or inverted range"
                );
            }
            if unprojected(&range.field) {
                inferred.insert(Disclosure::Range {
                    field: range.field.clone(),
                });
            }
        }
        let aggregate = query.and_then(|query| query.aggregate.as_ref());
        ensure!(
            (operation.kind == OperationKind::Aggregate) == aggregate.is_some(),
            "aggregate kind/source declaration mismatch"
        );
        if let Some(aggregate) = aggregate {
            let query = query.unwrap();
            ensure!(
                query.search.is_none() && query.range.is_none() && operation.list.is_none(),
                "aggregate cannot override list search/range/order"
            );
            let source = super::operation(m, aggregate.source)?;
            ensure!(
                source.id != operation.id
                    && source.kind == OperationKind::List
                    && source.via.is_none()
                    && source
                        .query
                        .as_ref()
                        .is_none_or(|query| query.aggregate.is_none()),
                "aggregate source must be a direct List"
            );
            ensure!(
                source
                    .list
                    .as_ref()
                    .is_none_or(|list| list.preview.is_none()),
                "aggregate source cannot be a preview"
            );
            ensure!(
                envelope_equal(operation, source),
                "aggregate source authority/selection mismatch"
            );
            let operand = match &aggregate.function {
                AggregateFunction::Count => None,
                AggregateFunction::Sum { field: name } => {
                    let key = field(resource, name)?;
                    ensure!(
                        !key.optional && matches!(key.kind, FieldKind::Integer { .. }),
                        "sum requires required i64 field"
                    );
                    Some(name)
                }
                AggregateFunction::Min { field: name } | AggregateFunction::Max { field: name } => {
                    let key = field(resource, name)?;
                    ensure!(
                        !key.optional
                            && matches!(key.kind, FieldKind::Integer { .. } | FieldKind::Timestamp),
                        "min/max require required i64 or Timestamp field"
                    );
                    Some(name)
                }
            };
            if is_public(operation) {
                inferred.insert(Disclosure::Aggregate {
                    field: operand.cloned(),
                });
            }
        }
        let declared = query.map_or(&[][..], |query| query.disclose.as_slice());
        let actual: BTreeSet<_> = declared.iter().cloned().collect();
        ensure!(
            actual.len() == declared.len() && actual == inferred,
            "invalid query inference disclosure"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxide_protocol::query::{Aggregate, Direction, Search, SearchIndex};
    fn declarations() -> Manifest {
        let mut m = crate::test_support::manifest();
        m.resources[0].search = Some(SearchIndex {
            tokenizer: noxide_protocol::query::TOKENIZER_ID.into(),
            fields: vec!["body".into()],
            max_bytes: 4096,
        });
        m.operations[0].query = Some(noxide_protocol::query::Query {
            search: Some(Search {
                fields: vec!["body".into()],
                parameter: "terms".into(),
            }),
            ..Default::default()
        });
        m
    }
    #[test]
    fn canonical_contract_is_valid_but_partial_runtime_is_unavailable() {
        let m = declarations();
        validate_declarations(&m).unwrap();
        assert!(
            super::super::validate(&m)
                .unwrap_err()
                .to_string()
                .contains("P09 query runtime is not available")
        );
        for change in 0..4 {
            let mut bad = m.clone();
            match change {
                0 => bad.resources[0].search.as_mut().unwrap().tokenizer = "unknown".into(),
                1 => bad.resources[0]
                    .search
                    .as_mut()
                    .unwrap()
                    .fields
                    .push("body".into()),
                2 => bad.resources[0].search.as_mut().unwrap().max_bytes = 16385,
                _ => {
                    bad.operations[0]
                        .query
                        .as_mut()
                        .unwrap()
                        .search
                        .as_mut()
                        .unwrap()
                        .fields = vec!["unknown".into()]
                }
            };
            assert!(validate_declarations(&bad).is_err());
        }
    }
    #[test]
    fn mutable_optional_and_oversized_text_keys_fail_independently() {
        let mut m = crate::test_support::manifest();
        m.resources[0].fields[0].max_bytes = 512;
        m.operations[0].list = Some(ListSettings {
            preview: None,
            order: ListOrder::CreatedAsc,
            page_size: 3,
        });
        m.operations[0].list.as_mut().unwrap().order = ListOrder::Field {
            field: "body".into(),
            direction: Direction::Ascending,
            mode: SortMode::Immutable,
        };
        assert!(
            validate_declarations(&m)
                .unwrap_err()
                .to_string()
                .contains("mutable order")
        );
        m.resources[0].fields[0].immutable = true;
        validate_declarations(&m).unwrap();
        m.resources[0].fields[0].max_bytes = 513;
        assert!(validate_declarations(&m).is_err());
        m.resources[0].fields[0].max_bytes = 512;
        m.resources[0].fields[0].optional = true;
        assert!(validate_declarations(&m).is_err());
        m.resources[0].fields[0].optional = false;
        m.resources[0].fields[0].immutable = false;
        m.operations[0].list.as_mut().unwrap().order = ListOrder::Field {
            field: "body".into(),
            direction: Direction::Ascending,
            mode: SortMode::LiveView,
        };
        validate_declarations(&m).unwrap();
    }
    #[test]
    fn aggregate_cannot_override_its_source_or_smuggle_search() {
        let mut m = declarations();
        let mut aggregate = m.operations[0].clone();
        aggregate.id = 999;
        aggregate.kind = OperationKind::Aggregate;
        aggregate.list = None;
        aggregate.query = Some(noxide_protocol::query::Query {
            aggregate: Some(Aggregate {
                source: m.operations[0].id,
                function: AggregateFunction::Count,
            }),
            ..Default::default()
        });
        m.operations.push(aggregate);
        validate_declarations(&m).unwrap();
        let last = m.operations.len() - 1;
        let mut bad = m.clone();
        bad.operations[last].policy.any = vec![vec![Predicate::Public]];
        assert!(
            validate_declarations(&bad)
                .unwrap_err()
                .to_string()
                .contains("authority/selection mismatch")
        );
        let mut bad = m.clone();
        bad.operations[last].query.as_mut().unwrap().search =
            m.operations[0].query.as_ref().unwrap().search.clone();
        assert!(validate_declarations(&bad).is_err());
        let mut bad = m.clone();
        bad.operations[last]
            .query
            .as_mut()
            .unwrap()
            .aggregate
            .as_mut()
            .unwrap()
            .source = 999;
        assert!(validate_declarations(&bad).is_err());
    }
    #[test]
    fn public_search_inference_needs_its_own_explicit_disclosure() {
        let mut m = declarations();
        let operation = &mut m.operations[0];
        operation.policy.any = vec![vec![Predicate::Public]];
        operation.fields = Some(vec!["published".into()]);
        assert!(
            validate_declarations(&m)
                .unwrap_err()
                .to_string()
                .contains("query inference disclosure")
        );
        m.operations[0].query.as_mut().unwrap().disclose = vec![Disclosure::Search {
            field: "body".into(),
        }];
        validate_declarations(&m).unwrap();
    }
    #[test]
    fn declared_immutable_is_enforced_without_treating_initial_as_immutable() {
        let mut m = crate::test_support::manifest();
        let mut operation = m.operations[2].clone();
        operation.id = 4;
        operation.kind = OperationKind::Update;
        m.operations.push(operation);
        let action = crate::test_support::action(
            2,
            "Edit",
            4,
            Target::Named("target".into()),
            &m.resources[0],
            &["body"],
            2,
        );
        crate::test_support::register_action(&mut m, action);
        m.routes[1].forms.push(2);
        super::super::validate(&m).unwrap();
        m.resources[0].fields[0].immutable = true;
        assert!(
            super::super::validate(&m)
                .unwrap_err()
                .to_string()
                .contains("declared immutable field")
        );
    }
}
