use super::*;

#[test]
fn cursor_scopes_bind_canonical_parameters_and_account() {
    let params = Fields::from([("category".into(), "books".into())]);
    let scope = cursor_scope(
        ("contract", "deployment"),
        1,
        None,
        None,
        None,
        "alice",
        &params,
    )
    .unwrap();
    let other = Fields::from([("category".into(), "games".into())]);
    assert_ne!(
        scope,
        cursor_scope(
            ("contract", "deployment"),
            1,
            None,
            None,
            None,
            "alice",
            &other
        )
        .unwrap()
    );
    assert_ne!(
        scope,
        cursor_scope(
            ("contract", "deployment"),
            1,
            None,
            None,
            None,
            "bob",
            &params
        )
        .unwrap()
    );
}

#[test]
fn cursor_scopes_bind_canonical_search_and_every_identity() {
    let canonical = |raw| {
        crate::search::canonical_query(raw, &mut || Ok(()))
            .unwrap()
            .tokens()
            .join(" ")
    };
    let params = Fields::from([("terms".into(), canonical("BETA alpha ALPHA"))]);
    let same = Fields::from([("terms".into(), canonical("alpha beta"))]);
    let different = Fields::from([("terms".into(), canonical("alpha gamma"))]);
    let scope = |identity, route, target, incarnation: &str, subject, params: &Fields| {
        cursor_scope(
            identity,
            route,
            target,
            Some(incarnation.into()),
            None,
            subject,
            params,
        )
        .unwrap()
    };
    let expected = scope(
        ("contract", "deployment"),
        1,
        Some(9),
        "one",
        "alice",
        &params,
    );
    assert_eq!(
        expected,
        scope(
            ("contract", "deployment"),
            1,
            Some(9),
            "one",
            "alice",
            &same
        )
    );
    assert_ne!(
        expected,
        scope(
            ("contract", "deployment"),
            1,
            Some(9),
            "one",
            "alice",
            &different
        )
    );
    for (identity, route, target, incarnation, subject) in [
        (("new-contract", "deployment"), 1, Some(9), "one", "alice"),
        (("contract", "new-deployment"), 1, Some(9), "one", "alice"),
        (("contract", "deployment"), 2, Some(9), "one", "alice"),
        (("contract", "deployment"), 1, Some(10), "one", "alice"),
        (("contract", "deployment"), 1, Some(9), "two", "alice"),
        (("contract", "deployment"), 1, Some(9), "one", "bob"),
    ] {
        assert_ne!(
            expected,
            scope(identity, route, target, incarnation, subject, &params)
        );
    }
}

#[test]
fn cursor_scope_strings_match_recorded_fixtures() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/fixtures/queries");
    for (name, parented) in [
        ("private-notes", false),
        ("forum", true),
        ("private-inbox", false),
    ] {
        let manifest =
            manifest::parse(&std::fs::read(root.join(format!("example-{name}.json"))).unwrap())
                .unwrap();
        let list = manifest
            .operations
            .iter()
            .find(|op| {
                op.kind == OperationKind::List
                    && op
                        .scope
                        .as_deref()
                        .and_then(|field| {
                            manifest::reference_resource(&manifest, op.resource, field).unwrap()
                        })
                        .is_some()
                        == parented
            })
            .unwrap();
        let route = manifest
            .routes
            .iter()
            .find(|r| r.operations.contains(&list.id))
            .unwrap();
        let scope = cursor_scope(
            ("contract", "deployment"),
            route.id,
            parented.then_some(42),
            parented.then(|| "parent-incarnation".into()),
            Some(list),
            "account-id",
            &Fields::new(),
        )
        .unwrap();
        assert_eq!(
            scope,
            std::fs::read_to_string(root.join(format!("{name}.scope"))).unwrap(),
            "{name}"
        );
    }
}
