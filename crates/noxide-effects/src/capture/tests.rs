use super::*;
use noxide_protocol::{
    AccountScope,
    time::{Duration, Timestamp},
};

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
