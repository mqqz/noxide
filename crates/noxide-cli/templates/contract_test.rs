// Keep the starter's privacy policy explicit as the application grows.
#[test]
fn notes_remain_owner_scoped() {
    use noxide::__private::{Manifest, Predicate};
    let manifest: Manifest = serde_json::from_str(&__CRATE__::noxide_manifest()).unwrap();
    let notes = manifest
        .resources
        .iter()
        .find(|resource| resource.name == "notes")
        .unwrap();
    let operations: Vec<_> = manifest
        .operations
        .iter()
        .filter(|operation| operation.resource == notes.id)
        .collect();
    assert_eq!(operations.len(), 5);
    for operation in operations {
        assert!(!operation.policy.any.is_empty());
        assert!(
            operation
                .policy
                .any
                .iter()
                .all(|rule| rule.contains(&Predicate::Owner))
        );
    }
}
