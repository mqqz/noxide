use super::*;
#[test]
fn candidate_classification_uses_memory_effective_time_without_database_access() {
    let temp = tempfile::tempdir().unwrap();
    let m = crate::test_support::manifest();
    let app = Application::new(
        &crate::test_support::component(None),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        Database::sqlite(temp.path().join("absent.db")),
        HostKeys::generate().unwrap(),
        Limits::default(),
        crate::DeploymentResources {
            effects: None,
            jobs: None,
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap();
    let now = security::now().unwrap();
    let (_, cookie) = app
        .keys
        .issue(TokenKind::Session, "alice", now, 10)
        .unwrap();
    assert!(app.keys.verify(&cookie, now).is_ok());
    assert!(app.session_envelope(&cookie));
    app.clock.fetch_max(now + 20, Ordering::Relaxed);
    assert!(!app.session_envelope(&cookie));
    assert!(!temp.path().join("absent.db").exists());
}
