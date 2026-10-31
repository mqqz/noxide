//! The proof application uses only public SDK registration and job declarations.
//! Runtime/clock/worker/provider acceptance belongs to the host integration lane.
// Guest pages and handlers are reachable only through the wasm export.
#[allow(dead_code, unused_imports)]
#[path = "../../../examples/reservations/src/lib.rs"]
mod proof;

use noxide::__private::{Change, ListOrder, OperationKind, Predicate, Revision, TargetSource};
use noxide::{Duration, values};
use serde_json::json;

#[test]
fn reservation_expiry_registers_exact_sealed_jobs_without_browser_authority() {
    let manifest: noxide::__private::Manifest =
        serde_json::from_str(&proof::noxide_manifest()).unwrap();
    let resource = |name| manifest.resources.iter().find(|r| r.name == name).unwrap();
    let operation = |id| manifest.operations.iter().find(|o| o.id == id).unwrap();
    let reserve = manifest
        .actions
        .iter()
        .find(|a| a.name == "Reserve")
        .unwrap();
    let expire = manifest
        .actions
        .iter()
        .find(|a| a.name == "Expire reservation")
        .unwrap();
    let cancel = manifest
        .actions
        .iter()
        .find(|a| a.name == "Cancel")
        .unwrap();
    let expiry = resource("orders").expiry.as_ref().unwrap();
    assert_eq!(expiry.field, "expires_at");
    assert_eq!(expiry.max_after, Duration::from_secs(900).unwrap());
    for name in [
        "quantity",
        "unit_price_minor",
        "currency",
        "total_minor",
        "reserved_at",
        "expires_at",
    ] {
        assert!(
            resource("orders")
                .fields
                .iter()
                .find(|field| field.name == name)
                .unwrap()
                .immutable
        );
    }
    let due = values::add(
        values::transaction_time(),
        values::duration(expiry.max_after),
    );
    assert_eq!(
        reserve.steps[1]
            .assign
            .iter()
            .find(|a| a.field == "expires_at")
            .unwrap()
            .change,
        Change::Set(due)
    );
    assert!(expire.inputs.is_empty());
    assert!(cancel.inputs.is_empty());
    assert!(!manifest.web_bindings.iter().any(|b| b.action == expire.id));
    assert!(manifest.web_bindings.iter().any(|b| b.action == cancel.id));
    assert_eq!(expire.targets.len(), 2);
    let order = expire.targets.iter().find(|t| t.name == "order").unwrap();
    let product = expire.targets.iter().find(|t| t.name == "product").unwrap();
    assert_eq!(
        order.source,
        TargetSource::Service {
            eligible: noxide::stable_id("reservations:expiry:order-read")
        }
    );
    assert_eq!(
        product.source,
        TargetSource::Reference {
            target: "order".into(),
            field: "product".into(),
            eligible: noxide::stable_id("reservations:expiry:product-read")
        }
    );
    assert_eq!(order.revision, Revision::Identity);
    assert_eq!(product.revision, Revision::Identity);
    assert_eq!(expire.steps[0].guards.len(), 2);
    assert_eq!(
        expire.steps[0].assign[0].change,
        Change::Set(values::choice("expired"))
    );
    let Change::Increase { by, .. } = &expire.steps[1].assign[0].change else {
        panic!("expiry must restock")
    };
    assert_eq!(*by, values::snapshot("order", "quantity"));
    let candidate = operation(noxide::stable_id("reservations:expiry:candidates"));
    assert!(candidate.maintenance);
    assert_eq!(
        candidate.list.as_ref().unwrap().order,
        ListOrder::CreatedAsc
    );
    assert_eq!(candidate.list.as_ref().unwrap().page_size, 20);
    assert_eq!(
        serde_json::to_value(&candidate.filter).unwrap(),
        json!([{"field":"status", "equals":{"literal":"pending"}}])
    );
    for id in [
        "reservations:expiry:order-read",
        "reservations:expiry:product-read",
        "reservations:expiry:order-update",
        "reservations:expiry:product-update",
        "reservations:expiry:candidates",
    ] {
        let op = operation(noxide::stable_id(id));
        assert_eq!(
            op.policy.any,
            vec![vec![
                Predicate::Service {
                    worker: "reservation_expiry".into()
                },
                Predicate::SameTenant
            ]]
        );
        assert!(
            !manifest
                .routes
                .iter()
                .any(|r| r.operations.contains(&op.id))
        );
    }
    for step in &expire.steps {
        assert!(operation(step.operation).maintenance);
    }
    assert!(operation(noxide::stable_id("reservations:expiry:order-read")).maintenance);
    let read_product = noxide::stable_id("reservations:expiry:product-read");
    assert_eq!(operation(read_product).kind, OperationKind::Read);
    assert_ne!(
        read_product,
        noxide::stable_id("reservations:expiry:order-read")
    );
    assert_eq!(
        serde_json::to_value(manifest.jobs.as_ref().unwrap()).unwrap(),
        json!({
            "workers":[{"name":"reservation_expiry", "actions":[{"action":expire.id, "targets":{
                "order":{"resource":resource("orders").id, "eligible":noxide::stable_id("reservations:expiry:order-read")},
                "product":{"resource":resource("products").id, "eligible":read_product}
            }}]}],
            "schedules":[{"source_action":reserve.id, "ordinal":0, "worker":"reservation_expiry", "action":expire.id,
                "targets":{"order":{"created":1}, "product":{"target":"product"}}, "inputs":{},
                "due_at":{"add":{"left":"transaction_time", "right":{"literal":{"duration":900000}}}}}],
            "recurring":[{"name":"repair_expired_reservations", "worker":"reservation_expiry", "action":expire.id,
                "interval":60000, "inputs":{}, "selection":{"operation":candidate.id, "target":"order", "expiry_repair":true}}]
        })
    );
    // Every stock mutation remains inside a reserve/cancel/expiry plan. Routes
    // and web bindings never expose a separate stock mutation operation.
    for action in &manifest.actions {
        if action.steps.iter().any(|s| {
            s.assign
                .iter()
                .any(|a| a.field == "stock" && !matches!(a.change, Change::Set(_)))
        }) {
            assert!([reserve.id, cancel.id, expire.id].contains(&action.id));
        }
    }
}
