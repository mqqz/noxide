use super::*;
use crate::database::lifecycle::Registry;
use std::time::Duration;

fn owner() -> RequestScope {
    RequestScope::new(
        Arc::new(Registry::default()),
        tokio::time::Instant::now() + Duration::from_secs(2),
        Duration::from_secs(2),
        256,
    )
}
#[tokio::test]
async fn internal_cursor_is_canonical_bound_and_has_no_browser_expiry() {
    let m = noxide_test_support::manifest();
    let plan = noxide_admission::query_plan::compile(&m, &m.operations[0]).unwrap();
    owner()
        .run(async {
            let cursor = Frontier {
                version: 1,
                binding: "alpha-worker-declaration-cutoff".into(),
                after: Some(CursorKey::Created {
                    sequence: 4,
                    record: 42,
                }),
            };
            let raw = cursor.encode().unwrap();
            assert!(raw.len() <= 4096);
            assert_eq!(
                Frontier::decode(Some(&raw), cursor.binding.clone(), &plan, &m, 10)
                    .unwrap()
                    .encode()
                    .unwrap(),
                raw
            );
            assert!(
                Frontier::decode(
                    Some(&raw),
                    "beta-worker-declaration-cutoff".into(),
                    &plan,
                    &m,
                    10
                )
                .is_err()
            );
            assert!(Frontier::decode(Some(&raw), cursor.binding.clone(), &plan, &m, 3).is_err());
            assert!(
                Frontier::decode(
                    Some(&(raw.clone() + " ")),
                    cursor.binding.clone(),
                    &plan,
                    &m,
                    10
                )
                .is_err()
            );
            let forged = raw.replace("\"version\":1", "\"version\":1,\"cookie\":\"forged\"");
            assert!(
                Frontier::decode(Some(&forged), cursor.binding.clone(), &plan, &m, 10).is_err()
            );
            assert!(
                Frontier::decode(
                    Some(&"x".repeat(4097)),
                    cursor.binding.clone(),
                    &plan,
                    &m,
                    10
                )
                .is_err()
            );
            let zero = Frontier {
                version: 1,
                binding: cursor.binding.clone(),
                after: Some(CursorKey::Created {
                    sequence: 1,
                    record: 0,
                }),
            }
            .encode()
            .unwrap();
            assert!(Frontier::decode(Some(&zero), cursor.binding.clone(), &plan, &m, 10).is_err());
            let scalar = Frontier {
                version: 1,
                binding: cursor.binding.clone(),
                after: Some(CursorKey::Scalar {
                    value: noxide_protocol::query::CursorValue::Integer(1),
                    record: 1,
                }),
            }
            .encode()
            .unwrap();
            assert!(
                Frontier::decode(Some(&scalar), cursor.binding.clone(), &plan, &m, 10).is_err()
            );
            let start = Frontier::decode(None, "initial-scan".into(), &plan, &m, 0)
                .unwrap()
                .encode()
                .unwrap();
            assert!(
                Frontier::decode(Some(&start), "initial-scan".into(), &plan, &m, 0)
                    .unwrap()
                    .after
                    .is_none(),
                "budget yield never invents row progress"
            );
        })
        .await;
    assert!(
        Frontier {
            version: 1,
            binding: "scope".into(),
            after: None
        }
        .encode()
        .is_err(),
        "CPU work needs its existing host root"
    );
}
#[test]
fn recurrence_policy_has_one_explicit_worker_and_tenant_conjunction() {
    let mut m = noxide_test_support::manifest();
    let op = &mut m.operations[0];
    op.policy.any = vec![vec![
        Predicate::SameTenant,
        Predicate::Service {
            worker: "expiry".into(),
        },
    ]];
    assert!(service_selection(op, "expiry"));
    assert!(!service_selection(op, "other"));
    op.policy.any.push(op.policy.any[0].clone());
    assert!(!service_selection(op, "expiry"));
    op.policy.any.truncate(1);
    op.policy.any[0].push(Predicate::Owner);
    assert!(!service_selection(op, "expiry"));
    op.policy.any = vec![vec![Predicate::Service {
        worker: "expiry".into(),
    }]];
    assert!(!service_selection(op, "expiry"));
}
