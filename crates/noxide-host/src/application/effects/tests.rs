use super::*;
use noxide_protocol::{
    effects::PayloadField,
    time::{Duration, Timestamp},
};
use repository::ScheduleScalar as Scalar;
fn schema(kind: FieldKind) -> Input {
    Input {
        name: "value".into(),
        label: "Value".into(),
        kind,
        optional: false,
        max_bytes: 4096,
    }
}
#[test]
fn typed_json_has_no_string_numeric_or_identity_coercion() {
    let integer = schema(FieldKind::Integer {
        min: Some(0),
        max: Some(9),
    });
    assert_eq!(
        scalar_json(Scalar::Integer(7), &integer).unwrap(),
        serde_json::json!(7)
    );
    assert!(scalar_json(Scalar::Text("7".into()), &integer).is_err());
    assert!(scalar_json(Scalar::Integer(10), &integer).is_err());
    let reference = schema(FieldKind::Reference {
        resource: "notes".into(),
    });
    assert_eq!(
        scalar_json(
            Scalar::Reference {
                resource: "notes".into(),
                id: 7
            },
            &reference
        )
        .unwrap(),
        serde_json::json!(7)
    );
    assert!(
        scalar_json(
            Scalar::Reference {
                resource: "other".into(),
                id: 7
            },
            &reference
        )
        .is_err()
    );
    assert!(
        scalar_json(
            Scalar::Reference {
                resource: "notes".into(),
                id: 0
            },
            &reference
        )
        .is_err()
    );
    let account = schema(FieldKind::Account {
        scope: AccountScope::SameTenant,
    });
    assert!(scalar_json(Scalar::Account("x".into()), &account).is_err());
    assert_eq!(
        scalar_json(Scalar::Account("A".repeat(43)), &account).unwrap(),
        serde_json::json!("A".repeat(43))
    );
    assert_eq!(
        scalar_json(
            Scalar::Timestamp(Timestamp::from_unix_millis(1234).unwrap()),
            &schema(FieldKind::Timestamp)
        )
        .unwrap(),
        serde_json::json!(1234)
    );
    assert_eq!(
        scalar_json(
            Scalar::Duration(Duration::from_millis(1200).unwrap()),
            &schema(FieldKind::Duration { max_millis: 1200 })
        )
        .unwrap(),
        serde_json::json!(1200)
    );
}
#[test]
fn missing_is_null_but_empty_or_noncanonical_text_never_becomes_missing() {
    let mut optional = schema(FieldKind::Text);
    optional.optional = true;
    assert_eq!(
        scalar_json(Scalar::Missing(FieldKind::Text), &optional).unwrap(),
        serde_json::Value::Null
    );
    assert!(scalar_json(Scalar::Text(String::new()), &optional).is_err());
    assert!(scalar_json(Scalar::Missing(FieldKind::Boolean), &optional).is_err());
    assert!(scalar_json(Scalar::Text("a\r\nb".into()), &optional).is_err());
    optional.optional = false;
    assert!(scalar_json(Scalar::Missing(FieldKind::Text), &optional).is_err());
    let mut opaque = schema(FieldKind::Blob { max_bytes: 10 });
    opaque.optional = true;
    assert!(scalar_json(Scalar::Missing(opaque.kind.clone()), &opaque).is_err());
}
fn mapped(name: &str, kind: FieldKind, value: Value) -> PayloadField {
    PayloadField {
        schema: Input {
            name: name.into(),
            ..schema(kind)
        },
        value,
    }
}
#[test]
fn payload_is_one_sorted_canonical_object_with_initial_snapshot_values() {
    let m = crate::test_support::manifest();
    let input = Fields::from([("body".into(), "caller".into())]);
    let principal = auth::Principal::Anonymous;
    let grants = BTreeMap::from([(
        "record".into(),
        RecordTarget {
            resource: 1,
            id: 7,
            incarnation: "record".into(),
            revision: 1,
            route: None,
        },
    )]);
    let snapshots = BTreeMap::from([(
        (1, 7),
        StoredRecord {
            record: Record {
                resource: 1,
                id: 7,
                fields: Fields::from([("body".into(), "initial".into())]),
            },
            owner: "owner".into(),
            tenant: "team".into(),
            incarnation: "record".into(),
            revision: 1,
            cap_version: None,
        },
    )]);
    let outcomes = vec![MutationOutcome {
        kind: MutationKind::Created,
        resource: 1,
        id: 9,
        incarnation: "created".into(),
    }];
    let values = repository::ScheduleValues {
        manifest: &m,
        input: &input,
        principal: &principal,
        grants: &grants,
        snapshots: &snapshots,
        outcomes: &outcomes,
        time: None,
        current: None,
    };
    let mut emission = EmitEffect {
        source_action: 1,
        ordinal: 0,
        endpoint: "events".into(),
        fields: vec![
            mapped("z", FieldKind::Text, Value::Input("body".into())),
            mapped(
                "a",
                FieldKind::Text,
                Value::SnapshotField {
                    target: "record".into(),
                    field: "body".into(),
                    reviewed: false,
                },
            ),
            mapped(
                "record",
                FieldKind::Reference {
                    resource: "notes".into(),
                },
                Value::Created(0),
            ),
        ],
    };
    let expected = br#"{"a":"initial","record":9,"z":"caller"}"#;
    assert_eq!(
        payload(&values, ActionCore::of(&m.actions[0]).unwrap(), &emission).unwrap(),
        expected
    );
    emission.fields.reverse();
    assert_eq!(
        payload(&values, ActionCore::of(&m.actions[0]).unwrap(), &emission).unwrap(),
        expected
    );
    emission.fields[0].value = Value::CurrentField {
        target: "record".into(),
        field: "body".into(),
    };
    assert!(payload(&values, ActionCore::of(&m.actions[0]).unwrap(), &emission).is_err());
}
#[test]
fn encoded_body_limit_includes_escaping_and_never_truncates() {
    let m = crate::test_support::manifest();
    let input = Fields::from([("body".into(), "\"".repeat(4096))]);
    let values = repository::ScheduleValues {
        manifest: &m,
        input: &input,
        principal: &auth::Principal::Anonymous,
        grants: &BTreeMap::new(),
        snapshots: &BTreeMap::new(),
        outcomes: &[],
        time: None,
        current: None,
    };
    let mut emission = EmitEffect {
        source_action: 1,
        ordinal: 0,
        endpoint: "events".into(),
        fields: (0..7)
            .map(|i| {
                mapped(
                    &format!("field_{i}"),
                    FieldKind::Text,
                    Value::Input("body".into()),
                )
            })
            .collect(),
    };
    let body = payload(&values, ActionCore::of(&m.actions[0]).unwrap(), &emission).unwrap();
    assert!(body.len() < MAX_EFFECT_BODY_BYTES);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["field_0"],
        "\"".repeat(4096)
    );
    emission.fields.push(mapped(
        "field_7",
        FieldKind::Text,
        Value::Input("body".into()),
    ));
    assert!(payload(&values, ActionCore::of(&m.actions[0]).unwrap(), &emission).is_err());
}
