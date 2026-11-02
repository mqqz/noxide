use super::*;
use super::{lists::append_prefix, transaction::adjust};

#[test]
fn transaction_adjustments_guard_overflow_and_both_bounds() {
    let rejection = GuardRejection {
        input: Some("quantity".into()),
        message: "Not enough stock".into(),
    };
    for (current, amount, min, max, increase) in [
        (i64::MAX, 1, i64::MIN, i64::MAX, true),
        (i64::MIN, 1, i64::MIN, i64::MAX, false),
        (5, 6, 0, 10, false),
        (5, 6, 0, 10, true),
    ] {
        let error = adjust(current, amount, min, max, increase, &rejection).unwrap_err();
        let guard = error
            .downcast_ref::<GuardFailure>()
            .expect("declared rejection");
        assert_eq!(guard.input, rejection.input);
        assert_eq!(guard.message, rejection.message);
    }
    assert_eq!(adjust(5, 5, 0, 10, false, &rejection).unwrap(), 0);
    assert_eq!(adjust(5, 5, 0, 10, true, &rejection).unwrap(), 10);
    assert_eq!(
        adjust(i64::MIN, i64::MAX, i64::MIN, i64::MAX, true, &rejection).unwrap(),
        -1
    );
    assert_eq!(
        adjust(i64::MAX, i64::MAX, i64::MIN, i64::MAX, false, &rejection).unwrap(),
        0
    );
}

#[test]
fn byte_prefix_counts_protocol_framing_and_fails_on_first_row_overflow() {
    let mut record = Record {
        resource: 1,
        id: 42,
        fields: Fields::from([("body".into(), String::new())]),
    };
    let overhead = serde_json::to_vec(&vec![record.clone()]).unwrap().len();
    record
        .fields
        .insert("body".into(), "x".repeat(MAX_RESULT_BYTES - overhead));
    let mut rows = Vec::new();
    assert!(append_prefix(&mut rows, record.clone(), MAX_RESULT_BYTES, false).unwrap());
    assert_eq!(serde_json::to_vec(&rows).unwrap().len(), MAX_RESULT_BYTES);
    assert!(!append_prefix(&mut rows, record.clone(), MAX_RESULT_BYTES, false).unwrap());
    assert_eq!(rows.len(), 1);
    record
        .fields
        .insert("body".into(), "\\".repeat(MAX_RESULT_BYTES));
    let mut empty = Vec::new();
    assert!(append_prefix(&mut empty, record, MAX_RESULT_BYTES, false).is_err());
    assert!(empty.is_empty());
}

#[test]
fn policy_is_scoped_and_empty_rules_deny() {
    let alice = Principal::User(crate::auth::User {
        id: "alice".into(),
        tenant: "one".into(),
        roles: vec![("admin".into(), "one".into())],
    });
    assert!(!allowed(
        &Policy { any: vec![] },
        &alice,
        crate::policy::Row {
            owner: "alice",
            tenant: "one",
            fields: &Default::default()
        }
    ));
    assert!(!allowed(
        &Policy { any: vec![vec![]] },
        &alice,
        crate::policy::Row {
            owner: "alice",
            tenant: "one",
            fields: &Default::default()
        }
    ));
    let owner = Policy {
        any: vec![vec![Predicate::Owner]],
    };
    assert!(allowed(
        &owner,
        &alice,
        crate::policy::Row {
            owner: "alice",
            tenant: "one",
            fields: &Default::default()
        }
    ));
    assert!(!allowed(
        &owner,
        &alice,
        crate::policy::Row {
            owner: "bob",
            tenant: "one",
            fields: &Default::default()
        }
    ));
    let role = Policy {
        any: vec![vec![Predicate::Role {
            name: "admin".into(),
            tenant_scoped: true,
        }]],
    };
    assert!(allowed(
        &role,
        &alice,
        crate::policy::Row {
            owner: "bob",
            tenant: "one",
            fields: &Default::default()
        }
    ));
    assert!(!allowed(
        &role,
        &alice,
        crate::policy::Row {
            owner: "bob",
            tenant: "two",
            fields: &Default::default()
        }
    ));
}
