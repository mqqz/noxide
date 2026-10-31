use noxide_protocol::{ListOrder, query::*};

#[test]
fn review_scalar_order_unknown_wire_fields_are_rejected() {
    let wire = serde_json::json!({"field": {
        "field":"rank", "direction":"ascending", "mode":"immutable",
        "unchecked_authority": true
    }});
    assert!(
        serde_json::from_value::<ListOrder>(wire).is_err(),
        "new scalar-order contract silently discards unknown fields"
    );
}

#[test]
fn review_new_query_shapes_reject_unknown_wire_fields() {
    assert!(
        serde_json::from_value::<SearchIndex>(serde_json::json!({
            "tokenizer":TOKENIZER_ID,"fields":["body"],"max_bytes":4096,"unchecked":true
        }))
        .is_err()
    );
    assert!(serde_json::from_value::<Range>(serde_json::json!({
        "field":"rank","lower":{"value":{"literal":"0"},"inclusive":true,"unchecked":true},"upper":null
    })).is_err());
    assert!(
        serde_json::from_value::<Aggregate>(serde_json::json!({
            "source":1,"function":{"sum":{"field":"score","unchecked":true}}
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<CursorKey>(serde_json::json!({
            "scalar":{"value":{"integer":2},"record":1,"unchecked":true}
        }))
        .is_err()
    );
}
