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
    let result = case
        .submit(
            &case.alice,
            "Add member",
            &foreign,
            Fields::from([("account".into(), case.accounts["eve"].clone())]),
        )
        .await;
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
    for index in 0..8 {
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
