//! Real browser-admitted actions, receipts and sequential witness boundaries.
use super::{computation_tests::Case, *};
use crate::Database;
use noxide_protocol::*;
use std::time::{Duration, Instant};

fn declarations() -> Manifest {
    let bytes = include_bytes!("../../../../../tools/fixtures/queries/example-team-documents.json");
    manifest::parse(bytes).unwrap()
}
fn resource(m: &Manifest, name: &str) -> u32 {
    m.resources.iter().find(|r| r.name == name).unwrap().id
}
fn read(m: &Manifest, name: &str) -> u32 {
    m.operations
        .iter()
        .find(|op| {
            op.resource == resource(m, name)
                && op.kind == OperationKind::Read
                && op
                    .policy
                    .any
                    .iter()
                    .flatten()
                    .any(|p| matches!(p, Predicate::ExistsRelated(_)))
        })
        .unwrap()
        .id
}
fn route(m: &Manifest, name: &str) -> u32 {
    m.routes
        .iter()
        .find(|r| r.resource == Some(resource(m, name)))
        .unwrap()
        .id
}
async fn replace_fields(case: &Case, name: &str, id: u64, change: impl FnOnce(&mut Fields)) {
    let mut tx = case
        .db
        .begin(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let schema = resource(&case.app.manifest, name);
    let storage = tx
        .storage_resource(&case.app.manifest, schema)
        .await
        .unwrap();
    let mut fields = repository::load(&mut tx, &case.app.manifest, schema, id)
        .await
        .unwrap()
        .unwrap()
        .record
        .fields;
    change(&mut fields);
    tx.execute(
        "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2 AND id=$3",
        &[
            serde_json::to_string(&fields).unwrap().into(),
            storage.into(),
            (id as i64).into(),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}
async fn bootstrap_contract(db: Option<Database>) {
    let case = Case::indexed(db, declarations()).await;
    let create = case.form(&case.alice, "Create workspace", 0).await;
    let input = Fields::from([("name".into(), "Private team".into())]);
    let response = case
        .submit(&case.alice, "Create workspace", &create, input.clone())
        .await
        .unwrap();
    assert_eq!(response.status, 303);
    let workspaces = case.records("workspaces").await;
    let memberships = case.records("memberships").await;
    assert_eq!((workspaces.len(), memberships.len()), (1, 1));
    assert_eq!(memberships[0].1["workspace"], workspaces[0].0.to_string());
    assert_eq!(memberships[0].1["account"], case.accounts["alice"]);
    assert_eq!(memberships[0].1["role"], "admin");
    assert_eq!(memberships[0].1["active"], "true");
    assert_eq!(case.counts().await, (2, 1));
    assert_eq!(
        case.submit(&case.alice, "Create workspace", &create, input)
            .await
            .unwrap()
            .status,
        303
    );
    assert_eq!(
        case.counts().await,
        (2, 1),
        "receipt replay cannot create another workspace"
    );
    let workspace = workspaces[0].0;
    assert!(matches!(
        case.app
            .view(
                &case.bob,
                route(&case.app.manifest, "workspaces"),
                Some(workspace)
            )
            .await,
        Ok(crate::render::Rendered { status: 404, .. })
    ));
    let add = case.form(&case.alice, "Add member", workspace).await;
    assert_eq!(
        case.submit(
            &case.alice,
            "Add member",
            &add,
            Fields::from([("account".into(), case.accounts["bob"].clone())])
        )
        .await
        .unwrap()
        .status,
        303
    );
    let count = case.counts().await;
    let duplicate = case.form(&case.alice, "Add member", workspace).await;
    let result = case
        .submit(
            &case.alice,
            "Add member",
            &duplicate,
            Fields::from([("account".into(), case.accounts["bob"].clone())]),
        )
        .await;
    assert!(
        matches!(result, Err(RequestError::Rejected)),
        "native tuple prohibits duplicate action creation"
    );
    assert_eq!(
        case.counts().await,
        count,
        "duplicate failure rolls back receipt"
    );
    let foreign = case.form(&case.alice, "Add member", workspace).await;
    let denied_start = Instant::now();
    let (result, roots) = crate::database::lifecycle::observe_roots(case.submit(
        &case.alice,
        "Add member",
        &foreign,
        Fields::from([("account".into(), case.accounts["eve"].clone())]),
    ))
    .await;
    if let Err(error) = &result {
        eprintln!(
            "foreign membership denial error={error:?}, elapsed={:?}, root statements={:?}, persisted counts={:?}, expected counts={count:?}",
            denied_start.elapsed(),
            roots
                .iter()
                .map(|root| root.statement_snapshot())
                .collect::<Vec<_>>(),
            case.counts().await,
        );
    }
    assert_eq!(result.unwrap().status, 404);
    assert_eq!(
        case.counts().await,
        count,
        "cross-tenant recipient cannot be replaced by the principal"
    );
    let document = case.form(&case.bob, "Create document", workspace).await;
    assert_eq!(
        case.submit(
            &case.bob,
            "Create document",
            &document,
            Fields::from([
                ("title".into(), "Shared".into()),
                ("body".into(), "Private content".into())
            ])
        )
        .await
        .unwrap()
        .status,
        303
    );
    let document = case.records("documents").await[0].0;
    assert_eq!(
        case.app
            .view(
                &case.bob,
                route(&case.app.manifest, "documents"),
                Some(document)
            )
            .await
            .unwrap()
            .status,
        200
    );
    let member = case
        .records("memberships")
        .await
        .into_iter()
        .find(|r| r.1["account"] == case.accounts["bob"])
        .unwrap()
        .0;
    // Ownership is real and still grants no administrator management policy.
    let mut tx = case
        .db
        .begin(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let storage = tx
        .storage_resource(
            &case.app.manifest,
            resource(&case.app.manifest, "memberships"),
        )
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_records SET owner=$1 WHERE resource=$2 AND id=$3",
        &[
            case.accounts["bob"].as_str().into(),
            storage.into(),
            (member as i64).into(),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        case.app
            .view(
                &case.bob,
                route(&case.app.manifest, "memberships"),
                Some(member)
            )
            .await,
        Ok(crate::render::Rendered { status: 404, .. })
    ));
    let form = case.form(&case.alice, "Edit member", member).await;
    assert_eq!(
        case.submit(
            &case.alice,
            "Edit member",
            &form,
            Fields::from([
                ("role".into(), "member".into()),
                ("active".into(), "false".into())
            ])
        )
        .await
        .unwrap()
        .status,
        303
    );
    assert!(matches!(
        case.app
            .view(
                &case.bob,
                route(&case.app.manifest, "documents"),
                Some(document)
            )
            .await,
        Ok(crate::render::Rendered { status: 404, .. })
    ));
    case.close().await;
}

#[derive(Clone, Copy)]
enum Boundary {
    Revoke,
    Expire,
}
#[derive(Clone, Copy)]
enum After {
    Mutation,
    CurrentRead,
    Snapshot,
}
fn sequential_manifest(boundary: Boundary, after: After) -> Manifest {
    let mut m = declarations();
    let member = resource(&m, "memberships");
    let read = read(&m, "memberships");
    let field = TextField {
        immutable: false,
        name: "note".into(),
        label: "Note".into(),
        kind: FieldKind::Text,
        optional: false,
        max_bytes: 160,
        initial: None,
    };
    m.resources
        .iter_mut()
        .find(|r| r.id == member)
        .unwrap()
        .fields
        .push(field.clone());
    m.resources.push(Resource {
        search: None,
        id: 900,
        name: "archives".into(),
        gate: None,
        expiry: None,
        unique: vec![],
        fields: vec![field],
    });
    let mut update = m
        .operations
        .iter()
        .find(|op| op.resource == member && op.kind == OperationKind::Update)
        .unwrap()
        .clone();
    update.id = 901;
    let mut second = update.clone();
    second.id = 902;
    if matches!(after, After::CurrentRead) {
        second.policy = Policy {
            any: vec![vec![Predicate::Owner]],
        };
    }
    let mut archive = second.clone();
    archive.id = 903;
    archive.resource = 900;
    archive.kind = OperationKind::Create;
    archive.policy = Policy {
        any: vec![vec![Predicate::Owner]],
    };
    m.operations.extend([update, second, archive]);
    let first = Step {
        operation: 901,
        target: Target::Named("source".into()),
        guards: vec![],
        assign: vec![Assignment {
            field: if matches!(boundary, Boundary::Revoke) {
                "active"
            } else {
                "expires_at"
            }
            .into(),
            change: Change::Set(if matches!(boundary, Boundary::Revoke) {
                Value::Literal(Literal::Boolean(false))
            } else {
                Value::TransactionTime
            }),
        }],
    };
    let second = if matches!(after, After::Snapshot) {
        Step {
            operation: 903,
            target: Target::None,
            guards: vec![],
            assign: vec![Assignment {
                field: "note".into(),
                change: Change::Set(Value::SnapshotField {
                    target: "source".into(),
                    field: "note".into(),
                    reviewed: false,
                }),
            }],
        }
    } else {
        Step {
            operation: 902,
            target: Target::Named("source".into()),
            assign: vec![Assignment {
                field: "note".into(),
                change: Change::Set(Value::Literal(Literal::Text("changed".into()))),
            }],
            guards: if matches!(after, After::CurrentRead) {
                vec![Guard {
                    condition: GuardCondition::Compare {
                        left: Value::CurrentField {
                            target: "source".into(),
                            field: "note".into(),
                        },
                        comparison: Comparison::Equal,
                        right: Value::Literal(Literal::Text("initial secret".into())),
                    },
                    rejection: GuardRejection {
                        input: None,
                        message: "unavailable".into(),
                    },
                }]
            } else {
                vec![]
            },
        }
    };
    m.actions = vec![Action {
        id: 904,
        version: 1,
        name: "Sequential".into(),
        inputs: vec![],
        targets: vec![ActionTarget {
            name: "source".into(),
            resource: member,
            revision: Revision::Exact,
            source: TargetSource::Page { reads: vec![read] },
            projection: Some(Inspection {
                operation: read,
                fields: vec!["note".into()],
            }),
            inspect: None,
        }],
        steps: vec![first, second],
    }];
    let member_route = route(&m, "memberships");
    m.web_bindings = vec![WebBinding {
        id: 905,
        version: 1,
        action: 904,
        layout: vec![],
        redirect: Redirect {
            route: member_route,
            source: RedirectSource::Target("source".into()),
        },
    }];
    for route in &mut m.routes {
        route.forms = if route.id == member_route {
            vec![905]
        } else {
            vec![]
        };
    }
    manifest::validate(&m).unwrap();
    m
}
async fn sequential_contract(db: Option<Database>, boundary: Boundary, after: After) {
    let case = Case::indexed(db, sequential_manifest(boundary, after)).await;
    let mut tx = case
        .db
        .begin(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let workspace = tx
        .storage_resource(
            &case.app.manifest,
            resource(&case.app.manifest, "workspaces"),
        )
        .await
        .unwrap();
    let member = tx
        .storage_resource(
            &case.app.manifest,
            resource(&case.app.manifest, "memberships"),
        )
        .await
        .unwrap();
    let time = case.app.temporal_after_admission(&mut tx).await.unwrap();
    let expires = (time.timestamp().unix_millis() + 3600000).to_string();
    for (storage, id, fields) in [
        (
            workspace,
            1i64,
            Fields::from([
                ("name".into(), "Private".into()),
                ("expires_at".into(), expires.clone()),
            ]),
        ),
        (
            member,
            2i64,
            Fields::from([
                ("workspace".into(), "1".into()),
                ("account".into(), case.accounts["alice"].clone()),
                ("role".into(), "admin".into()),
                ("active".into(), "true".into()),
                ("expires_at".into(), expires.clone()),
                ("note".into(), "initial secret".into()),
            ]),
        ),
    ] {
        tx.allocate_creation().await.unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,'team',$4,'membership-proof',1,(SELECT value FROM nx_creation_counter WHERE singleton=1))",&[storage.into(),id.into(),case.accounts["alice"].as_str().into(),serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
    }
    tx.commit().await.unwrap();
    let before = case.records("memberships").await;
    let form = case.form(&case.alice, "Sequential", 2).await;
    let response = case
        .submit(&case.alice, "Sequential", &form, Fields::new())
        .await;
    if matches!(after, After::Snapshot) {
        let response = response.unwrap();
        assert_eq!(response.status, 200);
        assert!(
            String::from_utf8(response.body)
                .unwrap()
                .contains("Changes saved")
        );
        assert_eq!(
            case.records("archives").await[0].1["note"],
            "initial secret"
        );
        assert_eq!(case.counts().await, (3, 1));
        assert!(matches!(
            case.app
                .view(
                    &case.alice,
                    route(&case.app.manifest, "memberships"),
                    Some(2)
                )
                .await,
            Ok(crate::render::Rendered { status: 404, .. })
        ));
    } else {
        assert_eq!(response.unwrap().status, 404);
        assert_eq!(
            case.records("memberships").await,
            before,
            "later fresh denial rolls back earlier mutation"
        );
        assert!(case.records("archives").await.is_empty());
        assert_eq!(case.counts().await, (2, 0));
    }
    case.close().await;
}
async fn temporal_routes_contract(db: Option<Database>) {
    let mut case = Case::indexed(db, declarations()).await;
    let bootstrap = case.form(&case.alice, "Create workspace", 0).await;
    assert_eq!(
        case.submit(
            &case.alice,
            "Create workspace",
            &bootstrap,
            Fields::from([("name".into(), "Temporal".into())])
        )
        .await
        .unwrap()
        .status,
        303
    );
    let workspace = case.records("workspaces").await[0].0;
    let create = case.form(&case.alice, "Create document", workspace).await;
    let input = Fields::from([
        ("title".into(), "Temporal".into()),
        ("body".into(), "Do not expose".into()),
    ]);
    assert_eq!(
        case.submit(&case.alice, "Create document", &create, input.clone())
            .await
            .unwrap()
            .status,
        303
    );
    let document = case.records("documents").await[0].0;
    let edit = case.form(&case.alice, "Edit document", document).await;
    replace_fields(&case, "documents", document, |fields| {
        fields.insert("expires_at".into(), "0".into());
    })
    .await;
    let before = case.counts().await;
    case.clock.take().unwrap().shutdown().await.unwrap();
    let mut tx = case
        .db
        .begin_read(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let clock_before = tx.fetch::<2>("SELECT CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock WHERE singleton=1", &[]).await.unwrap();
    tx.commit().await.unwrap();
    let root = case
        .app
        .manifest
        .routes
        .iter()
        .find(|route| route.resource.is_none())
        .unwrap()
        .id;
    assert_eq!(
        case.app.view(&case.alice, root, None).await.unwrap().status,
        200
    );
    assert_eq!(
        case.app
            .view(
                &case.alice,
                route(&case.app.manifest, "documents"),
                Some(document)
            )
            .await
            .unwrap()
            .status,
        404
    );
    assert_eq!(
        case.submit(
            &case.alice,
            "Edit document",
            &edit,
            Fields::from([
                ("title".into(), "forged revival".into()),
                ("body".into(), "forged".into())
            ])
        )
        .await
        .unwrap()
        .status,
        404
    );
    assert_eq!(case.counts().await, before);
    let mut tx = case
        .db
        .begin_read(Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(tx.fetch::<2>("SELECT CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock WHERE singleton=1", &[]).await.unwrap(),clock_before,"ordinary GET does not advance durable lifecycle time");
    tx.commit().await.unwrap();
    // A committed receipt is authoritative even if its former target expired.
    assert_eq!(
        case.submit(&case.alice, "Create document", &create, input.clone())
            .await
            .unwrap()
            .status,
        200
    );
    assert_eq!(case.counts().await, before);
    tokio::time::sleep(Duration::from_millis(5_100)).await;
    assert!(
        matches!(
            case.app.view(&case.alice, root, None).await,
            Err(RequestError::Busy)
        ),
        "stale temporal freshness must fail closed"
    );
    assert_eq!(
        case.submit(&case.alice, "Create document", &create, input)
            .await
            .unwrap()
            .status,
        200,
        "receipt recovery precedes temporal guards"
    );
    assert_eq!(case.counts().await, before);
    case.close().await;
}
#[tokio::test]
async fn sqlite_expired_routes_targets_recovery_and_no_get_clock_writes() {
    temporal_routes_contract(None).await;
}

async fn anonymous_picker_contract(db: Option<Database>) {
    let mut m = declarations();
    let workspace = resource(&m, "workspaces");
    let eligible = m
        .operations
        .iter()
        .find(|op| {
            op.resource == workspace
                && op.kind == OperationKind::Read
                && op.policy.any
                    == vec![vec![Predicate::ExistsRelated(
                        noxide_protocol::membership::ExistsRelated {
                            resource: "memberships".into(),
                            reference: "workspace".into(),
                            target: noxide_protocol::membership::RelatedTarget::SelfRecord,
                            account: "account".into(),
                            conditions: std::collections::BTreeMap::from([
                                (
                                    "active".into(),
                                    noxide_protocol::membership::MembershipLiteral::Boolean(true),
                                ),
                                (
                                    "role".into(),
                                    noxide_protocol::membership::MembershipLiteral::Choice(
                                        "admin".into(),
                                    ),
                                ),
                            ]),
                        },
                    )]]
        })
        .unwrap()
        .clone();
    let mut picker = eligible.clone();
    picker.id = 910;
    picker.kind = OperationKind::List;
    picker.list = Some(ListSettings {
        order: ListOrder::CreatedAsc,
        page_size: 10,
        preview: None,
    });
    m.resources.push(Resource {
        search: None,
        id: 911,
        name: "selected_links".into(),
        gate: None,
        expiry: None,
        unique: vec![],
        fields: vec![TextField {
            immutable: false,
            name: "workspace".into(),
            label: "Workspace".into(),
            kind: FieldKind::Reference {
                resource: "workspaces".into(),
            },
            optional: false,
            initial: None,
            max_bytes: 20,
        }],
    });
    let mut create = eligible.clone();
    create.id = 912;
    create.resource = 911;
    create.kind = OperationKind::Create;
    create.policy = Policy {
        any: vec![vec![Predicate::Public]],
    };
    create.bind = std::collections::BTreeMap::from([("workspace".into(), eligible.id)]);
    let mut private = create.clone();
    private.id = 913;
    private.policy = Policy {
        any: vec![vec![Predicate::Owner]],
    };
    m.operations.extend([picker, create, private]);
    let target = ActionTarget {
        name: "selected".into(),
        resource: workspace,
        source: TargetSource::Selected {
            query: 910,
            eligible: eligible.id,
            label: vec!["name".into()],
        },
        revision: Revision::Identity,
        projection: Some(Inspection {
            operation: eligible.id,
            fields: vec!["name".into()],
        }),
        inspect: None,
    };
    for (id, operation) in [(914, 912), (915, 913)] {
        m.actions.push(Action {
            id,
            version: 1,
            name: format!("Picker {id}"),
            inputs: vec![],
            targets: vec![target.clone()],
            steps: vec![Step {
                operation,
                target: Target::None,
                guards: vec![],
                assign: vec![Assignment {
                    field: "workspace".into(),
                    change: Change::Set(Value::Target("selected".into())),
                }],
            }],
        });
        let root = route(&m, "workspaces");
        m.web_bindings.push(WebBinding {
            id,
            version: 1,
            action: id,
            layout: vec![],
            redirect: Redirect {
                route: root,
                source: RedirectSource::Target("selected".into()),
            },
        });
    }
    let member_route = route(&m, "workspaces");
    m.routes
        .iter_mut()
        .find(|r| r.id == member_route)
        .unwrap()
        .forms = vec![914, 915];
    m.routes
        .iter_mut()
        .find(|r| r.id == member_route)
        .unwrap()
        .operations = vec![eligible.id];
    manifest::validate(&m).unwrap();
    let case = Case::indexed(db, m).await;
    let bootstrap = case.form(&case.alice, "Create workspace", 0).await;
    assert_eq!(
        case.submit(
            &case.alice,
            "Create workspace",
            &bootstrap,
            Fields::from([("name".into(), "Picker secret".into())])
        )
        .await
        .unwrap()
        .status,
        303
    );
    let member = case.records("workspaces").await[0].0;
    // The guest invokes the authenticated administrator workspace Read before
    // form completion, warming the exact self-record declaration/key used by
    // both picker queries.
    let page = case
        .app
        .view_page(Some(&case.alice), member_route, Some(member), None)
        .await
        .unwrap();
    assert_eq!(page.status, 200);
    let html = String::from_utf8(page.body).unwrap();
    let public = html
        .split_once("action=\"/actions/914\"")
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    let private = html
        .split_once("action=\"/actions/915\"")
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert_eq!(
        public.matches("<option ").count(),
        1,
        "anonymous picker must contain only its empty placeholder"
    );
    assert!(
        !public.contains("Picker secret"),
        "anonymous picker must not inherit the authenticated membership witness"
    );
    assert_eq!(private.matches("<option ").count(), 2);
    assert!(
        private.contains("Picker secret"),
        "authenticated picker must regain its independent grant after the swap"
    );
    let handle = private
        .split("<option value=\"")
        .nth(2)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    assert!(
        matches!(
            case.app
                .submit(
                    page.anonymous_cookie.as_ref().unwrap(),
                    914,
                    &crate::test_support::hidden(public, "_submission"),
                    &crate::test_support::hidden(public, "_csrf"),
                    Fields::from([("_target_selected".into(), handle.into())])
                )
                .await,
            Err(RequestError::InvalidRequest)
        ),
        "private selection proof cannot be replayed into the anonymous action"
    );
    assert_eq!(case.counts().await, (2, 1));
    case.close().await;
}
#[tokio::test]
async fn sqlite_anonymous_picker_cannot_reuse_authenticated_page_membership() {
    anonymous_picker_contract(None).await;
}

#[tokio::test]
async fn sqlite_workspace_bootstrap_membership_and_native_uniqueness() {
    bootstrap_contract(None).await;
}
#[tokio::test]
async fn sqlite_sequential_membership_and_expiry_boundaries() {
    for boundary in [Boundary::Revoke, Boundary::Expire] {
        for after in [After::Mutation, After::CurrentRead, After::Snapshot] {
            sequential_contract(None, boundary, after).await;
        }
    }
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable server"]
async fn postgres_workspace_bootstrap_and_sequential_boundaries() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for index in 0..9 {
        let name = format!("nx_p07_actions_{}_{}", std::process::id(), index);
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&url).unwrap();
        url.set_path(&format!("/{name}"));
        let db = Some(Database::postgres(url.as_str()).unwrap());
        if index == 0 {
            bootstrap_contract(db).await;
        } else if index == 7 {
            temporal_routes_contract(db).await;
        } else if index == 8 {
            anonymous_picker_contract(db).await;
        } else {
            let n = index - 1;
            sequential_contract(
                db,
                if n < 3 {
                    Boundary::Revoke
                } else {
                    Boundary::Expire
                },
                [After::Mutation, After::CurrentRead, After::Snapshot][n % 3],
            )
            .await;
        }
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}

/// Artifact gate, deliberately separate from the WAT decision guest used above.
#[tokio::test]
#[ignore = "requires built P07 SDK bundle/CLI and NOXIDE_TEST_POSTGRES"]
async fn postgres_actual_sdk_nojs_http_workspace() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let bundle = std::env::var("NOXIDE_TEST_TEAM_DOCUMENTS_BUNDLE").unwrap();
    let cli = std::env::var("NOXIDE_TEST_HOST_CLI").unwrap();
    let output = std::env::var("NOXIDE_TEST_NOJS_OUTPUT").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_p07_http_{}", std::process::id());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    eprintln!("P07 NoJS disposable PostgreSQL fixture: {name}");
    let mut parsed = url::Url::parse(&url).unwrap();
    parsed.set_path(&format!("/{name}"));
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/test_team_documents.py");
    let status = std::process::Command::new("python3")
        .arg(script)
        .args([
            "--bundle",
            &bundle,
            "--host-cli",
            &cli,
            "--output",
            &output,
            "--postgres",
            parsed.as_str(),
        ])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "retained failed fixture {name}; inspect {output}"
    );
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
