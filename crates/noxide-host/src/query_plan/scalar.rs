//! Typed stable-key SQL for the existing record query executor.
use super::{NativeProvider, ScalarRepresentation};
use crate::database::Param;
use anyhow::{Result, ensure};
use noxide_protocol::{
    FieldKind, Fields, Operand, TextField,
    query::{CursorKey, CursorValue, Direction, Range},
};
use std::cmp::Ordering;

pub(crate) struct Scalar {
    field: TextField,
    direction: Direction,
    representation: ScalarRepresentation,
}
impl Scalar {
    pub(crate) fn new(field: &TextField, direction: Direction) -> Result<Self> {
        ensure!(
            !field.optional && crate::manifest::identifier(&field.name),
            "invalid scalar key"
        );
        let representation = match field.kind {
            FieldKind::Integer { .. }
            | FieldKind::Timestamp
            | FieldKind::Duration { .. }
            | FieldKind::Reference { .. } => ScalarRepresentation::Numeric,
            FieldKind::Text => {
                ensure!(field.max_bytes <= 512, "scalar Text key exceeds512 bytes");
                ScalarRepresentation::Binary
            }
            FieldKind::Boolean | FieldKind::Choice { .. } | FieldKind::Account { .. } => {
                ScalarRepresentation::Binary
            }
            _ => anyhow::bail!("unsupported scalar key"),
        };
        Ok(Self {
            field: field.clone(),
            direction,
            representation,
        })
    }
    pub(crate) fn value(&self, value: &str) -> Result<CursorValue> {
        ensure!(
            self.field.canonical(value).is_ok_and(|v| v == value),
            "noncanonical scalar value"
        );
        Ok(match self.representation {
            ScalarRepresentation::Numeric => CursorValue::Integer(value.parse()?),
            ScalarRepresentation::Binary => CursorValue::Binary(value.into()),
        })
    }
    pub(crate) fn validate_key(&self, key: &CursorKey) -> Result<()> {
        let CursorKey::Scalar { value, record } = key else {
            anyhow::bail!("scalar cursor key required");
        };
        ensure!(
            *record > 0 && *record <= i64::MAX as u64,
            "invalid cursor identity"
        );
        let canonical = match value {
            CursorValue::Integer(value) => self.value(&value.to_string())?,
            CursorValue::Binary(value) => self.value(value)?,
        };
        ensure!(&canonical == value, "cursor scalar representation mismatch");
        Ok(())
    }
    pub(crate) fn row_key(&self, id: u64, fields: &Fields) -> Result<CursorKey> {
        let value = fields
            .get(&self.field.name)
            .ok_or_else(|| anyhow::anyhow!("missing scalar key"))?;
        let key = CursorKey::Scalar {
            value: self.value(value)?,
            record: id,
        };
        self.validate_key(&key)?;
        Ok(key)
    }
    pub(crate) fn expression(&self, provider: NativeProvider) -> Result<String> {
        let field = provider.field_expression(&self.field.name)?;
        Ok(match self.representation {
            ScalarRepresentation::Numeric => format!("CAST({field} AS BIGINT)"),
            ScalarRepresentation::Binary => {
                format!("({field}) COLLATE {}", provider.binary_collation())
            }
        })
    }
    fn direction(&self) -> &'static str {
        match self.direction {
            Direction::Ascending => "ASC",
            Direction::Descending => "DESC",
        }
    }
    pub(crate) fn order_sql(&self, provider: NativeProvider) -> Result<String> {
        let direction = self.direction();
        Ok(format!(
            "{} {direction},id {direction}",
            self.expression(provider)?
        ))
    }
    pub(crate) fn keyset_sql(
        &self,
        provider: NativeProvider,
        key: &CursorKey,
        params: &mut Vec<Param>,
    ) -> Result<String> {
        self.validate_key(key)?;
        let CursorKey::Scalar { value, record } = key else {
            unreachable!()
        };
        let expression = self.expression(provider)?;
        let comparison = match self.direction {
            Direction::Ascending => ">",
            Direction::Descending => "<",
        };
        params.push(parameter(value));
        let scalar = params.len();
        params.push((*record as i64).into());
        let id = params.len();
        Ok(format!(
            " AND (({expression}){comparison}${scalar} OR (({expression})=${scalar} AND id{comparison}${id}))"
        ))
    }
    pub(crate) fn range_sql(
        &self,
        provider: NativeProvider,
        range: &Range,
        values: &Fields,
        params: &mut Vec<Param>,
    ) -> Result<String> {
        ensure!(range.field == self.field.name, "range/order mismatch");
        ensure!(
            range.lower.is_some() || range.upper.is_some(),
            "empty range"
        );
        let resolve = |operand: &Operand| -> Result<CursorValue> {
            let value = match operand {
                Operand::Literal(value) => value,
                Operand::Param(name) => values
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!("missing range parameter"))?,
            };
            self.value(value)
        };
        let lower = range
            .lower
            .as_ref()
            .map(|bound| resolve(&bound.value))
            .transpose()?;
        let upper = range
            .upper
            .as_ref()
            .map(|bound| resolve(&bound.value))
            .transpose()?;
        if let (Some(lower), Some(upper)) = (&lower, &upper) {
            let order = compare(lower, upper)?;
            ensure!(
                order == Ordering::Less
                    || (order == Ordering::Equal
                        && range.lower.as_ref().unwrap().inclusive
                        && range.upper.as_ref().unwrap().inclusive),
                "inverted or empty range"
            );
        }
        let expression = self.expression(provider)?;
        let mut sql = String::new();
        for (bound, value, comparison) in [(&range.lower, lower, ">"), (&range.upper, upper, "<")] {
            if let (Some(bound), Some(value)) = (bound, value) {
                params.push(parameter(&value));
                sql.push_str(&format!(
                    " AND ({expression}){comparison}{}${}",
                    if bound.inclusive { "=" } else { "" },
                    params.len()
                ));
            }
        }
        Ok(sql)
    }
}
fn parameter(value: &CursorValue) -> Param {
    match value {
        CursorValue::Integer(value) => Param::Number(*value),
        CursorValue::Binary(value) => Param::Text(value.clone()),
    }
}
fn compare(left: &CursorValue, right: &CursorValue) -> Result<Ordering> {
    match (left, right) {
        (CursorValue::Integer(left), CursorValue::Integer(right)) => Ok(left.cmp(right)),
        (CursorValue::Binary(left), CursorValue::Binary(right)) => {
            Ok(left.as_bytes().cmp(right.as_bytes()))
        }
        _ => anyhow::bail!("scalar comparison kind mismatch"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxide_protocol::query::Bound;
    fn field(kind: FieldKind) -> TextField {
        TextField {
            immutable: true,
            kind,
            optional: false,
            initial: None,
            name: "rank".into(),
            label: "Rank".into(),
            max_bytes: 512,
        }
    }
    fn number() -> TextField {
        field(FieldKind::Integer {
            min: None,
            max: None,
        })
    }
    #[test]
    fn keyset_orders_scalar_and_id_tie_together_without_numeric_string_order() {
        let key = CursorKey::Scalar {
            value: CursorValue::Integer(10),
            record: 7,
        };
        let mut params = vec![Param::Number(1)];
        let scalar = Scalar::new(&number(), Direction::Ascending).unwrap();
        assert_eq!(
            scalar
                .keyset_sql(NativeProvider::Postgres, &key, &mut params)
                .unwrap(),
            " AND ((CAST((fields::jsonb ->> 'rank') AS BIGINT))>$2 OR ((CAST((fields::jsonb ->> 'rank') AS BIGINT))=$2 AND id>$3))"
        );
        assert!(matches!(
            params.as_slice(),
            [Param::Number(1), Param::Number(10), Param::Number(7)]
        ));
        let descending = Scalar::new(&number(), Direction::Descending).unwrap();
        assert_eq!(
            descending.order_sql(NativeProvider::Sqlite).unwrap(),
            "CAST(json_extract(fields, '$.\"rank\"') AS BIGINT) DESC,id DESC"
        );
        assert!(
            descending
                .keyset_sql(NativeProvider::Sqlite, &key, &mut vec![])
                .unwrap()
                .contains("id<$2")
        );
        let binary = Scalar::new(&field(FieldKind::Text), Direction::Ascending).unwrap();
        assert_eq!(
            binary.order_sql(NativeProvider::Sqlite).unwrap(),
            "(json_extract(fields, '$.\"rank\"')) COLLATE BINARY ASC,id ASC"
        );
        assert_eq!(
            binary.order_sql(NativeProvider::Postgres).unwrap(),
            "((fields::jsonb ->> 'rank')) COLLATE \"C\" ASC,id ASC"
        );
    }
    #[test]
    fn forged_key_representation_domain_and_identity_fail_closed() {
        let scalar = Scalar::new(&number(), Direction::Ascending).unwrap();
        for key in [
            CursorKey::Created {
                sequence: 1,
                record: 1,
            },
            CursorKey::Scalar {
                value: CursorValue::Binary("10".into()),
                record: 1,
            },
            CursorKey::Scalar {
                value: CursorValue::Integer(1),
                record: 0,
            },
            CursorKey::Scalar {
                value: CursorValue::Integer(1),
                record: u64::MAX,
            },
        ] {
            assert!(scalar.validate_key(&key).is_err());
        }
        assert!(scalar.value("01").is_err());
        let timestamp = Scalar::new(&field(FieldKind::Timestamp), Direction::Ascending).unwrap();
        assert!(
            timestamp
                .validate_key(&CursorKey::Scalar {
                    value: CursorValue::Integer(-1),
                    record: 1
                })
                .is_err()
        );
        let mut optional = number();
        optional.optional = true;
        assert!(Scalar::new(&optional, Direction::Ascending).is_err());
        let mut wide = field(FieldKind::Text);
        wide.max_bytes = 513;
        assert!(Scalar::new(&wide, Direction::Ascending).is_err());
        let key = scalar
            .row_key(3, &Fields::from([("rank".into(), "-4".into())]))
            .unwrap();
        assert_eq!(
            key,
            CursorKey::Scalar {
                value: CursorValue::Integer(-4),
                record: 3
            }
        );
    }
    #[test]
    fn dynamic_ranges_validate_before_binding_and_never_overflow_endpoints() {
        let scalar = Scalar::new(&number(), Direction::Ascending).unwrap();
        let range = Range {
            field: "rank".into(),
            lower: Some(Bound {
                value: Operand::Param("low".into()),
                inclusive: true,
            }),
            upper: Some(Bound {
                value: Operand::Literal(i64::MAX.to_string()),
                inclusive: false,
            }),
        };
        let mut params = vec![];
        assert_eq!(
            scalar
                .range_sql(
                    NativeProvider::Postgres,
                    &range,
                    &Fields::from([("low".into(), i64::MIN.to_string())]),
                    &mut params
                )
                .unwrap(),
            " AND (CAST((fields::jsonb ->> 'rank') AS BIGINT))>=$1 AND (CAST((fields::jsonb ->> 'rank') AS BIGINT))<$2"
        );
        assert!(matches!(
            params.as_slice(),
            [Param::Number(i64::MIN), Param::Number(i64::MAX)]
        ));
        for low in [
            i64::MAX.to_string(),
            "9223372036854775808".into(),
            "00".into(),
        ] {
            let mut params = vec![];
            assert!(
                scalar
                    .range_sql(
                        NativeProvider::Sqlite,
                        &range,
                        &Fields::from([("low".into(), low)]),
                        &mut params
                    )
                    .is_err()
            );
            assert!(params.is_empty());
        }
        let closed = Range {
            upper: Some(Bound {
                inclusive: true,
                ..range.upper.unwrap()
            }),
            ..range
        };
        assert!(
            scalar
                .range_sql(
                    NativeProvider::Sqlite,
                    &closed,
                    &Fields::from([("low".into(), i64::MAX.to_string())]),
                    &mut vec![]
                )
                .is_ok()
        );
    }
    #[test]
    fn binary_ranges_use_utf8_bytes_and_boolean_domains_remain_canonical() {
        let text = Scalar::new(&field(FieldKind::Text), Direction::Ascending).unwrap();
        let range = Range {
            field: "rank".into(),
            lower: Some(Bound {
                value: Operand::Literal("Z".into()),
                inclusive: true,
            }),
            upper: Some(Bound {
                value: Operand::Literal("عربي".into()),
                inclusive: false,
            }),
        };
        let mut params = vec![];
        assert_eq!(
            text.range_sql(NativeProvider::Sqlite, &range, &Fields::new(), &mut params)
                .unwrap(),
            " AND ((json_extract(fields, '$.\"rank\"')) COLLATE BINARY)>=$1 AND ((json_extract(fields, '$.\"rank\"')) COLLATE BINARY)<$2"
        );
        assert!(
            matches!(params.as_slice(),[Param::Text(low),Param::Text(high)] if low=="Z" && high=="عربي")
        );
        let boolean = Scalar::new(&field(FieldKind::Boolean), Direction::Ascending).unwrap();
        assert_eq!(
            boolean.value("false").unwrap(),
            CursorValue::Binary("false".into())
        );
        for invalid in ["FALSE", "0", "true "] {
            assert!(boolean.value(invalid).is_err());
        }
        assert!(
            text.validate_key(&CursorKey::Scalar {
                value: CursorValue::Binary("ع".repeat(257)),
                record: 1
            })
            .is_err()
        );
    }
}
