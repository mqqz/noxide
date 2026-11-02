use super::*;
#[test]
fn selected_proofs_have_separate_slots_but_share_the_form_byte_budget() {
    let mut fields: Vec<_> = (0..32)
        .map(|index| (format!("input{index}"), "v".into()))
        .collect();
    fields.extend([
        ("_csrf".into(), "csrf".into()),
        ("_submission".into(), "submission".into()),
        ("_capability".into(), "credential".into()),
    ]);
    fields.extend((0..4).map(|index| {
        (
            format!("_target_{}{}", "a".repeat(31), index),
            "opaque".into(),
        )
    }));
    let encode = |fields: &[(String, String)]| {
        let mut body = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in fields {
            body.append_pair(key, value);
        }
        body.finish()
    };
    assert_eq!(decode_form(encode(&fields).as_bytes()).unwrap().len(), 39);
    let mut excessive = fields.clone();
    excessive.push(("_target_fifth".into(), "opaque".into()));
    assert!(decode_form(encode(&excessive).as_bytes()).is_err());
    let mut excessive = fields.clone();
    excessive.push(("extra_scalar".into(), "v".into()));
    assert!(decode_form(encode(&excessive).as_bytes()).is_err());
    let mut duplicate = fields.clone();
    duplicate.pop();
    duplicate.push(duplicate[35].clone());
    assert!(decode_form(encode(&duplicate).as_bytes()).is_err());
    let mut oversized = fields.clone();
    oversized[35].0.push('x');
    assert!(decode_form(encode(&oversized).as_bytes()).is_err());
    fields[0].1 = "x".repeat(noxide_protocol::MAX_INPUT_BYTES);
    assert!(decode_form(encode(&fields).as_bytes()).is_err());
}
