use crate::{Application, Database, HostKeys, manifest};
use noxide_protocol::*;
use std::sync::Arc;

fn declarations() -> Manifest {
    let mut m = crate::parent_tests::declarations();
    let mut field = m.resources[0].fields[1].clone();
    field.name = "archived".into();
    m.resources[0].fields.push(field);
    m.actions[0].fields.push("archived".into());
    m.operations[0].filter.push(Condition {
        field: "archived".into(),
        equals: Operand::Param("flag".into()),
    });
    m.operations[0].disclose.push("archived".into());
    m.routes[2].params.push("flag".into());
    m
}
#[test]
fn host_rejects_required_parameters_on_index_route() {
    let mut m = crate::test_support::manifest();
    m.resources[0].fields.push(TextField {
        name: "flag".into(),
        label: "Flag".into(),
        kind: FieldKind::Boolean,
        optional: false,
        initial: None,
        max_bytes: 5,
    });
    m.actions[0].fields.push("flag".into());
    m.operations[0].filter.push(Condition {
        field: "flag".into(),
        equals: Operand::Param("flag".into()),
    });
    m.routes[0].params.push("flag".into());
    m.routes[0].path = "/filtered".into();
    m.routes.push(Route {
        id: 3,
        path: "/".into(),
        resource: None,
        operations: vec![],
        forms: vec![],
        access: Access::Authenticated,
        params: vec![],
    });
    manifest::validate(&m).unwrap();
    let home = RouteRef {
        route: 3,
        target: None,
        params: Fields::new(),
    };
    assert_eq!(crate::routing::resolve(&m, &home).unwrap(), "/");
    assert!(crate::render::unavailable(&crate::Presentation::default(), &m).is_ok());
    m.routes.pop();
    m.routes[0].path = "/".into();
    let error = manifest::parse(&serde_json::to_vec(&m).unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("index route cannot declare parameters"),
        "{error}"
    );
}

#[test]
fn host_rejects_parameterized_mutation_redirects() {
    let boolean = |name: &str| TextField {
        name: name.into(),
        label: name.into(),
        kind: FieldKind::Boolean,
        optional: false,
        initial: None,
        max_bytes: 5,
    };
    let reject = |m: &Manifest| {
        let error = manifest::parse(&serde_json::to_vec(m).unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("mutation redirect requires an unparameterized route"),
            "{error}"
        );
    };
    for kind in [OperationKind::Create, OperationKind::Update] {
        let mut m = crate::test_support::manifest();
        m.resources[0].fields.push(boolean("published"));
        m.actions[0].fields.push("published".into());
        m.operations[2].kind = kind.clone();
        m.resources.push(Resource {
            gate: None,
            id: 2,
            name: "children".into(),
            fields: vec![
                TextField {
                    name: "note".into(),
                    label: "Note".into(),
                    max_bytes: 20,
                    optional: false,
                    initial: None,
                    kind: FieldKind::Reference {
                        resource: "notes".into(),
                    },
                },
                boolean("flag"),
            ],
        });
        let mut list = m.operations[0].clone();
        list.id = 4;
        list.resource = 2;
        list.scope = Some("note".into());
        list.filter.push(Condition {
            field: "flag".into(),
            equals: Operand::Param("flag".into()),
        });
        m.operations.push(list);
        m.routes[1].params.push("flag".into());
        m.routes[1].operations.push(4);
        m.routes.push(Route {
            id: 3,
            path: "/plain/{note}".into(),
            resource: Some(1),
            operations: vec![2],
            forms: vec![],
            access: Access::Authenticated,
            params: vec![],
        });
        if kind == OperationKind::Update {
            m.routes[0].forms.clear();
            m.routes[1].forms.push(1);
        }
        m.actions[0].redirect = Redirect::Page(3);
        manifest::validate(&m).unwrap();
        m.actions[0].redirect = Redirect::Page(2);
        reject(&m);
    }
    let mut m = crate::test_support::manifest();
    m.resources[0].fields.push(boolean("flag"));
    m.operations[0].filter.push(Condition {
        field: "flag".into(),
        equals: Operand::Param("flag".into()),
    });
    m.routes[0].params.push("flag".into());
    m.routes[0].path = "/filtered".into();
    m.routes[0].forms.clear();
    m.routes[1].forms.push(1);
    m.operations[2].kind = OperationKind::Delete;
    m.actions[0].fields.clear();
    m.routes.push(Route {
        id: 3,
        path: "/".into(),
        resource: None,
        operations: vec![],
        forms: vec![],
        access: Access::Authenticated,
        params: vec![],
    });
    m.actions[0].redirect = Redirect::Page(3);
    manifest::validate(&m).unwrap();
    m.actions[0].redirect = Redirect::Page(1);
    reject(&m);

    for kind in [
        OperationKind::Create,
        OperationKind::Update,
        OperationKind::Delete,
    ] {
        let mut m = declarations();
        m.routes.push(Route {
            id: 4,
            path: "/plain/{thread}".into(),
            resource: Some(2),
            operations: vec![4],
            forms: vec![],
            access: Access::Public,
            params: vec![],
        });
        m.operations[2].kind = kind.clone();
        if kind != OperationKind::Create {
            m.actions[0].bind = None;
            m.operations[2].policy = Policy {
                any: vec![vec![Predicate::Owner]],
            };
            m.routes[2].forms.clear();
            m.routes[1].forms.push(1);
            m.routes[1].access = Access::PublicOptional;
        }
        if kind == OperationKind::Delete {
            m.actions[0].fields.clear();
        }
        m.actions[0].redirect = Redirect::Reference {
            field: "thread".into(),
            route: 4,
        };
        manifest::validate(&m).unwrap();
        m.actions[0].redirect = Redirect::Reference {
            field: "thread".into(),
            route: 3,
        };
        reject(&m);
    }
}

#[test]
fn host_rejects_forged_route_parameters() {
    let m = declarations();
    manifest::validate(&m).unwrap();
    for params in [
        vec![],
        vec!["flag", "unused"],
        vec!["flag", "flag"],
        vec!["cursor"],
        vec!["bad-name"],
        vec!["a", "b", "c", "d", "e"],
    ] {
        let mut bad = m.clone();
        bad.routes[2].params = params.into_iter().map(str::to_owned).collect();
        assert!(manifest::validate(&bad).is_err());
    }
    let mut bad = m.clone();
    bad.operations[0].disclose.clear();
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.operations[0].filter[0].equals = Operand::Param("other".into());
    assert!(manifest::validate(&bad).is_err());
    let mut both = m.clone();
    let mut field = both.resources[0].fields.last().unwrap().clone();
    field.name = "second".into();
    both.resources[0].fields.push(field);
    both.actions[0].fields.push("second".into());
    both.operations[0].filter.push(Condition {
        field: "second".into(),
        equals: Operand::Param("flag".into()),
    });
    both.operations[0].disclose.push("second".into());
    manifest::validate(&both).unwrap();
    both.resources[0].fields.last_mut().unwrap().kind = FieldKind::Choice {
        variants: vec![ChoiceVariant {
            key: "x".into(),
            label: "X".into(),
        }],
    };
    assert!(
        manifest::validate(&both)
            .unwrap_err()
            .to_string()
            .contains("inconsistent parameter kind")
    );
    both.resources[0].fields[3].kind = FieldKind::Choice {
        variants: vec![ChoiceVariant {
            key: "y".into(),
            label: "Y".into(),
        }],
    };
    assert!(manifest::validate(&both).is_err());
}
#[test]
fn parameter_links_preserve_target_checks_and_canonical_values() {
    let m = declarations();
    let reference = RouteRef {
        route: 3,
        target: Some(10),
        params: Fields::from([("flag".into(), "false".into())]),
    };
    assert_eq!(
        crate::routing::resolve(&m, &reference).unwrap(),
        "/threads/10?flag=false"
    );
    for target in [None, Some(0), Some(u64::MAX)] {
        let mut bad = reference.clone();
        bad.target = target;
        assert!(crate::routing::resolve(&m, &bad).is_err());
    }
    let mut bad = reference.clone();
    bad.route = 1;
    assert!(crate::routing::resolve(&m, &bad).is_err());
    for value in ["False", "0", ""] {
        let mut bad = reference.clone();
        bad.params.insert("flag".into(), value.into());
        assert!(crate::routing::resolve(&m, &bad).is_err());
    }
    let mut bad = reference.clone();
    bad.params.clear();
    let response = ResponseIntent::Page(Document::new(
        "Invalid link",
        vec![Instruction::Link {
            destination: bad.clone(),
            text: "Open".into(),
        }],
    ));
    let context = crate::render::RenderContext {
        manifest: Some(&m),
        ..crate::render::RenderContext::empty()
    };
    assert!(crate::render::render(&response, &context).is_err());
    assert!(crate::routing::resolve(&m, &bad).is_err());
    let mut bad = reference;
    bad.params.insert("other".into(), "true".into());
    assert!(crate::routing::resolve(&m, &bad).is_err());
}
#[tokio::test]
async fn invalid_parameters_are_not_found_before_database_or_session_lookup() {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    let m = declarations();
    let tmp = tempfile::tempdir().unwrap();
    let keys = HostKeys::generate().unwrap();
    let (_, cookie) = keys
        .issue(
            crate::security::TokenKind::Session,
            &crate::security::random_id().unwrap(),
            crate::security::now().unwrap(),
            900,
        )
        .unwrap();
    let app = Application::new(
        &crate::test_support::component(None),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        Database::sqlite(tmp.path().join("missing/db")),
        keys,
        Default::default(),
    )
    .unwrap();
    let router = crate::http::router(
        Arc::new(app),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    let mut expected = None;
    for path in [
        "/missing",
        "/threads/10",
        "/threads/10?flag=False",
        "/threads/10?other=true",
        "/threads/10?flag=true&flag=false",
        "/threads/10?flag=true&other=x",
        "/threads/10?flag=%GG",
        "/threads/10?flag=",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", "localhost:8080")
                    .header(
                        "cookie",
                        if path == "/missing" {
                            String::new()
                        } else {
                            format!("session={cookie}")
                        },
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 404, "{path}");
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        if let Some(expected) = &expected {
            assert_eq!(&bytes, expected);
        } else {
            expected = Some(bytes);
        }
    }
    assert!(!tmp.path().join("missing").exists());
    for query in ["flag=false", "flag=tr%75e", "cursor=token&flag=true"] {
        assert!(crate::http::parse_query(&m, &m.routes[2], Some(query)).is_ok());
    }
    assert!(crate::http::parse_query(&m, &m.routes[2], Some(&"x".repeat(1025))).is_err());
}
