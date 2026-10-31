//! Source-level proof of the public SDK's anonymous upload/jobs/effects lowering.
//! Host admission, limits, handover and actual delivery require integration tests.
// Guest pages and handlers are reachable only through the wasm export.
#[allow(dead_code, unused_imports)]
#[path = "../../../examples/expiring-paste/src/lib.rs"]
mod proof;

use noxide::__private::{
    Change, FieldKind, ListOrder, OperationKind, Predicate, Revision, TargetSource,
};
use noxide::{Duration, values};
use serde_json::json;

#[test]
fn paste_upload_cleanup_and_synthetic_disclosures_lower_exactly() {
    let manifest: noxide::__private::Manifest =
        serde_json::from_str(&proof::noxide_manifest()).unwrap();
    assert_eq!(manifest.resources.len(), 1);
    let paste = &manifest.resources[0];
    assert_eq!(paste.name, "pastes");
    let expiry = paste.expiry.as_ref().unwrap();
    assert_eq!(expiry.field, "expires_at");
    assert_eq!(expiry.max_after, Duration::from_secs(3600).unwrap());
    assert!(paste.fields.iter().all(|field| field.is_immutable()));
    assert_eq!(
        paste
            .fields
            .iter()
            .find(|field| field.name == "published")
            .unwrap()
            .initial
            .as_deref(),
        Some("true")
    );
    assert!(matches!(
        paste
            .fields
            .iter()
            .find(|field| field.name == "file")
            .unwrap()
            .kind,
        FieldKind::Blob { .. }
    ));
    let create = manifest
        .actions
        .iter()
        .find(|action| action.name == "Create paste")
        .unwrap();
    let cleanup = manifest
        .actions
        .iter()
        .find(|action| action.name == "Cleanup paste")
        .unwrap();
    let delete = manifest
        .actions
        .iter()
        .find(|action| action.name == "Delete paste")
        .unwrap();
    let operation = |id| manifest.operations.iter().find(|op| op.id == id).unwrap();
    assert_eq!(
        create.steps.len(),
        1,
        "anonymous creation remains a single mutation"
    );
    assert_eq!(
        operation(create.steps[0].operation).kind,
        OperationKind::Create
    );
    assert_eq!(
        operation(create.steps[0].operation).policy.any,
        vec![vec![Predicate::Public]]
    );
    assert_eq!(
        create
            .inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect::<Vec<_>>(),
        ["title", "body", "file"]
    );
    assert!(matches!(
        create.inputs[2].kind,
        FieldKind::UploadHandle { .. }
    ));
    assert!(
        !create.steps[0]
            .assign
            .iter()
            .any(|assignment| assignment.field == "published")
    );
    let due = values::add(
        values::transaction_time(),
        values::duration(expiry.max_after),
    );
    assert_eq!(
        create.steps[0]
            .assign
            .iter()
            .find(|a| a.field == "expires_at")
            .unwrap()
            .change,
        Change::Set(due)
    );
    assert_eq!(
        create.steps[0]
            .assign
            .iter()
            .find(|a| a.field == "file")
            .unwrap()
            .change,
        Change::Set(values::input("file"))
    );
    assert_eq!(
        operation(delete.steps[0].operation).policy.any,
        vec![vec![Predicate::Capability]]
    );
    assert!(cleanup.inputs.is_empty());
    assert_eq!(cleanup.steps.len(), 1);
    assert_eq!(
        operation(cleanup.steps[0].operation).kind,
        OperationKind::Delete
    );
    assert!(cleanup.steps[0].assign.is_empty());
    assert_eq!(cleanup.steps[0].guards.len(), 1);
    assert_eq!(cleanup.targets.len(), 1);
    assert_eq!(cleanup.targets[0].revision, Revision::Identity);
    assert_eq!(
        cleanup.targets[0].source,
        TargetSource::Service {
            eligible: noxide::stable_id("expiring-paste:cleanup:read")
        }
    );
    assert!(
        !manifest
            .web_bindings
            .iter()
            .any(|binding| binding.action == cleanup.id)
    );
    for key in [
        "expiring-paste:cleanup:read",
        "expiring-paste:cleanup:list",
        "expiring-paste:cleanup:delete",
    ] {
        let op = operation(noxide::stable_id(key));
        assert!(op.maintenance);
        assert_eq!(
            op.policy.any,
            vec![vec![
                Predicate::Service {
                    worker: "paste_cleanup".into()
                },
                Predicate::SameTenant
            ]]
        );
        assert!(
            !manifest
                .routes
                .iter()
                .any(|route| route.operations.contains(&op.id))
        );
    }
    let candidates = operation(noxide::stable_id("expiring-paste:cleanup:list"));
    assert_eq!(
        candidates.list.as_ref().unwrap().order,
        ListOrder::CreatedAsc
    );
    assert_eq!(candidates.list.as_ref().unwrap().page_size, 20);
    assert_eq!(
        serde_json::to_value(&candidates.filter).unwrap(),
        json!([{"field":"published","equals":{"literal":"true"}}])
    );
    assert_eq!(
        serde_json::to_value(&manifest.blobs).unwrap(),
        json!({
            "limits":{"file_bytes":1048576,"app_bytes":16777216,"objects":64,"live_stages":2,"uploads":1,"downloads":2},
            "anonymous":{"stages":4,"bytes":4194304},
            "uploads":[{"id":noxide::stable_id("upload:expiring-paste:file"),"name":"public_paste_file","web_binding":create.id,"input":"file","anonymous":{"stages":2,"bytes":2097152}}]
        })
    );
    assert_eq!(
        serde_json::to_value(&manifest.jobs).unwrap(),
        json!({
            "workers":[{"name":"paste_cleanup","actions":[{"action":cleanup.id,"targets":{"paste":{"resource":paste.id,"eligible":noxide::stable_id("expiring-paste:cleanup:read")}}}]}],
            "schedules":[{"source_action":create.id,"ordinal":0,"worker":"paste_cleanup","action":cleanup.id,"targets":{"paste":{"created":0}},"inputs":{},
                "due_at":{"add":{"left":"transaction_time","right":{"literal":{"duration":3600000}}}}}],
            "recurring":[{"name":"repair_expired_pastes","worker":"paste_cleanup","action":cleanup.id,"interval":60000,"inputs":{},"selection":{"operation":candidates.id,"target":"paste","expiry_repair":true}}]
        })
    );
    assert_eq!(
        serde_json::to_value(&manifest.effects).unwrap(),
        json!({
            "endpoints":[{"name":"synthetic_events","secret_slot":"synthetic_events_token"}],
            "emissions":[{"source_action":create.id,"ordinal":0,"endpoint":"synthetic_events","fields":[
                {"schema":{"name":"at","label":"at","kind":"timestamp","optional":false,"max_bytes":20},"value":"transaction_time"},
                {"schema":{"name":"event","label":"event","kind":"text","optional":false,"max_bytes":9},"value":{"literal":{"text":"published"}}},
                {"schema":{"name":"paste","label":"paste","kind":{"reference":{"resource":"pastes"}},"optional":false,"max_bytes":19},"value":{"created":0}}
            ]}]
        })
    );
    let binding = manifest
        .web_bindings
        .iter()
        .find(|binding| binding.action == create.id)
        .unwrap();
    let fields = binding
        .layout
        .iter()
        .filter_map(|node| match node {
            noxide::__private::FormInstruction::Field { name, control } => {
                Some((name.as_str(), control))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 3);
    assert_eq!(
        fields.last(),
        Some(&("file", &noxide::__private::Control::File))
    );
    assert_eq!(
        manifest.effects.unwrap().emissions[0].fields.len(),
        3,
        "paste contents and handles are not external disclosures"
    );
}
