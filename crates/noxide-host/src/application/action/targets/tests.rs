use super::*;
use crate::{Database, HostKeys, runtime::Limits, test_support as fixture};
use noxide_protocol::*;
use std::{sync::Arc, time::Duration};

fn selected(name: &str, revision: Revision) -> ActionTarget {
    ActionTarget {
        name: name.into(),
        resource: 1,
        source: TargetSource::Selected {
            query: 1,
            eligible: 2,
            label: vec!["body".into()],
        },
        revision,
        projection: Some(Inspection {
            operation: 2,
            fields: vec!["body".into()],
        }),
        inspect: None,
    }
}
fn declarations() -> Manifest {
    let mut m = fixture::manifest();
    m.operations[0].list = Some(ListSettings {
        preview: None,
        order: ListOrder::CreatedAsc,
        page_size: 2,
    });
    let names = ["a", "b", "c", "d"];
    m.resources.push(Resource {
        search: None,
        expiry: None,
        unique: Vec::new(),
        id: 2,
        name: "links".into(),
        gate: None,
        fields: names
            .iter()
            .map(|name| TextField {
                immutable: false,
                name: (*name).into(),
                label: (*name).into(),
                kind: FieldKind::Reference {
                    resource: "notes".into(),
                },
                optional: false,
                initial: None,
                max_bytes: 20,
            })
            .collect(),
    });
    let mut create = m.operations[2].clone();
    create.id = 4;
    create.resource = 2;
    create.bind = names.iter().map(|name| ((*name).into(), 2)).collect();
    let mut read = m.operations[1].clone();
    read.id = 5;
    read.resource = 2;
    m.operations.extend([create, read]);
    m.routes.push(Route {
        id: 3,
        path: "/links/{link}".into(),
        resource: Some(2),
        operations: vec![5],
        forms: vec![],
        params: vec![],
        access: Access::Authenticated,
    });
    m.web_bindings[0].redirect.route = 3;
    m.actions[0].inputs.clear();
    m.actions[0].targets = names
        .iter()
        .map(|name| selected(name, Revision::Identity))
        .collect();
    m.actions[0].steps = vec![Step {
        guards: vec![],
        operation: 4,
        target: Target::None,
        assign: names
            .iter()
            .map(|name| Assignment {
                field: (*name).into(),
                change: Change::Set(Value::Target((*name).into())),
            })
            .collect(),
    }];
    let mut delete = m.operations[2].clone();
    delete.id = 6;
    delete.kind = OperationKind::Delete;
    m.operations.push(delete);
    m.actions.push(Action {
        id: 2,
        version: 1,
        name: "Delete note".into(),
        inputs: vec![],
        targets: vec![selected("a", Revision::Exact)],
        steps: vec![Step {
            guards: vec![],
            operation: 6,
            target: Target::Named("a".into()),
            assign: vec![],
        }],
    });
    m.web_bindings.push(WebBinding {
        id: 2,
        version: 1,
        action: 2,
        layout: vec![],
        redirect: Redirect {
            route: 1,
            source: RedirectSource::Step(0),
        },
    });
    m.routes[0].forms.push(2);
    manifest::validate(&m).unwrap();
    m
}
struct Case {
    _temp: tempfile::TempDir,
    db: Database,
    app: Arc<Application>,
    alice: String,
    bob: String,
}
impl Case {
    async fn new(db: Option<Database>, m: Manifest) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let db = db.unwrap_or_else(|| Database::sqlite(temp.path().join("targets.db")));
        db.initialize().await.unwrap();
        let user = db
            .create_account("alice", "target test password", "team")
            .await
            .unwrap();
        db.create_account("bob", "target test password", "team")
            .await
            .unwrap();
        let app = Arc::new(
            Application::new(
                &fixture::component(None),
                &serde_json::to_vec(&m).unwrap(),
                manifest::digest(&m).unwrap(),
                db.clone(),
                HostKeys::generate().unwrap(),
                Limits::default(),
                crate::DeploymentResources {
                    assets: crate::assets::AssetBundle::default(),
                    blobs: None,
                },
            )
            .unwrap(),
        );
        app.activate().await.unwrap();
        let mut tx = db
            .begin(std::time::Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let storage = tx.storage_resource(&m, 1).await.unwrap();
        for id in 1i64..=2 {
            tx.allocate_creation().await.unwrap();
            let mut fields = Fields::from([(
                "body".into(),
                if id == 1 {
                    "<script>private label</script>".into()
                } else {
                    "second".into()
                },
            )]);
            for field in &m.resources[0].fields {
                if let Some(value) = &field.initial {
                    fields.insert(field.name.clone(), value.clone());
                }
            }
            tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,'team',$4,'seed',1,(SELECT value FROM nx_creation_counter WHERE singleton=1))",&[storage.into(),id.into(),user.as_str().into(),serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
        }
        tx.commit().await.unwrap();
        let mut cookies = Vec::new();
        for name in ["alice", "bob"] {
            let c = app.login_challenge().await.unwrap();
            cookies.push(
                app.login(&c.cookie, &c.csrf, name, "target test password")
                    .await
                    .unwrap(),
            );
        }
        Self {
            _temp: temp,
            db,
            app,
            alice: cookies.remove(0),
            bob: cookies.remove(0),
        }
    }
    async fn page(&self, cookie: &str) -> String {
        String::from_utf8(self.app.view(cookie, 1, None).await.unwrap().body).unwrap()
    }
}
fn handles(page: &str, name: &str) -> Vec<String> {
    page.split_once(&format!("name=\"_target_{name}\""))
        .unwrap()
        .1
        .split_once("</select>")
        .unwrap()
        .0
        .split("<option value=\"")
        .skip(2)
        .map(|option| option.split('"').next().unwrap().into())
        .collect()
}
fn input(page: &str) -> Fields {
    ["a", "b", "c", "d"]
        .into_iter()
        .map(|name| (format!("_target_{name}"), handles(page, name)[0].clone()))
        .collect()
}
async fn submit(
    case: &Case,
    page: &str,
    fields: Fields,
) -> Result<crate::render::Rendered, RequestError> {
    case.app
        .submit(
            &case.alice,
            1,
            &fixture::hidden(page, "_submission"),
            &fixture::hidden(page, "_csrf"),
            fields,
        )
        .await
}

#[tokio::test]
async fn four_picker_targets_create_all_refs_and_recover_equivalent_expired_handles() {
    contract(None).await;
}
async fn contract(db: Option<Database>) {
    let case = Case::new(db, declarations()).await;
    let page = case.page(&case.alice).await;
    assert!(
        page.contains("&lt;script&gt;private label&lt;/script&gt;") && !page.contains("<script>")
    );
    let fields = input(&page);
    let first = submit(&case, &page, fields.clone()).await.unwrap();
    assert_eq!(first.status, 303);
    let mut renewed = fields.clone();
    for handle in renewed.values_mut() {
        let proof = case
            .app
            .keys
            .verify_selection(handle, security::now().unwrap())
            .unwrap();
        let mut kind = proof.kind;
        if let security::TokenKind::Selection { targets, .. } = &mut kind {
            for target in targets.values_mut() {
                target.revision += 7;
            }
        }
        *handle = case
            .app
            .keys
            .issue(kind, &proof.subject, proof.issued - 1000, 600)
            .unwrap()
            .1;
    }
    let replay = submit(&case, &page, renewed.clone()).await.unwrap();
    assert_eq!(first.location, replay.location);
    let fresh = case.page(&case.alice).await;
    assert!(
        submit(&case, &fresh, renewed)
            .await
            .map_or(true, |response| response.status >= 400)
    );
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let storage = tx.storage_resource(&case.app.manifest, 2).await.unwrap();
    let rows = tx
        .fetch::<1>(
            "SELECT fields FROM nx_records WHERE resource=$1",
            &[storage.into()],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let refs: Fields = serde_json::from_str(&rows[0][0]).unwrap();
    assert_eq!(
        refs,
        ["a", "b", "c", "d"]
            .into_iter()
            .map(|name| (name.into(), "1".into()))
            .collect()
    );
    tx.commit().await.unwrap();
}
#[tokio::test]
async fn picker_handles_reject_raw_ids_subject_binding_resource_incarnation_and_expiry() {
    let case = Case::new(None, declarations()).await;
    let page = case.page(&case.alice).await;
    let original = input(&page);
    let now = security::now().unwrap();
    for mutation in [
        "raw",
        "subject",
        "binding",
        "query",
        "eligible",
        "resource",
        "incarnation",
        "expiry",
    ] {
        let mut fields = original.clone();
        let handle = fields.get_mut("_target_a").unwrap();
        if mutation == "raw" {
            *handle = "1".into();
        } else {
            let proof = case.app.keys.verify_selection(handle, now).unwrap();
            let mut kind = proof.kind;
            if let security::TokenKind::Selection {
                binding,
                query,
                eligible,
                targets,
                ..
            } = &mut kind
            {
                if mutation == "binding" {
                    *binding = 91;
                }
                if mutation == "query" {
                    *query = 91;
                }
                if mutation == "eligible" {
                    *eligible = 91;
                }
                let target = targets.get_mut("a").unwrap();
                if mutation == "resource" {
                    target.resource = 2;
                }
                if mutation == "incarnation" {
                    target.incarnation = "replacement".into();
                }
            }
            *handle = case
                .app
                .keys
                .issue(
                    kind,
                    if mutation == "subject" {
                        "bob"
                    } else {
                        &proof.subject
                    },
                    if mutation == "expiry" {
                        now - 1000
                    } else {
                        now
                    },
                    600,
                )
                .unwrap()
                .1;
        }
        assert!(
            submit(&case, &page, fields)
                .await
                .map_or(true, |response| response.status >= 400),
            "accepted {mutation}"
        );
    }
    let bob = case.page(&case.bob).await;
    assert!(
        case.app
            .submit(
                &case.bob,
                1,
                &fixture::hidden(&bob, "_submission"),
                &fixture::hidden(&bob, "_csrf"),
                original
            )
            .await
            .is_err()
    );
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
            .await
            .unwrap()[0][0],
        "2"
    );
    tx.commit().await.unwrap();
}
#[test]
fn named_maps_reorder_but_steps_remain_semantic() {
    let mut m = declarations();
    let digest = manifest::digest(&m).unwrap();
    m.actions[0].targets.reverse();
    assert_eq!(digest, manifest::digest(&m).unwrap());
    m.actions[0].targets[0].name = "a".into();
    assert!(manifest::validate(&m).is_err());
    let mut m = declarations();
    let mut extra = m.actions[0].steps[0].clone();
    extra.assign[0].change = Change::Set(Value::Target("b".into()));
    m.actions[0].steps.push(extra);
    let digest = manifest::digest(&m).unwrap();
    m.actions[0].steps.swap(0, 1);
    assert_ne!(digest, manifest::digest(&m).unwrap());
}
#[test]
fn derived_graph_is_order_independent_and_depth_is_one() {
    let mut m = declarations();
    m.actions[0].targets = vec![
        ActionTarget {
            name: "parent".into(),
            resource: 1,
            source: TargetSource::Reference {
                target: "link".into(),
                field: "a".into(),
                eligible: 2,
            },
            revision: Revision::Identity,
            projection: Some(Inspection {
                operation: 2,
                fields: vec!["body".into()],
            }),
            inspect: None,
        },
        ActionTarget {
            name: "link".into(),
            resource: 2,
            source: TargetSource::Selected {
                query: 7,
                eligible: 5,
                label: vec!["a".into()],
            },
            revision: Revision::Identity,
            projection: Some(Inspection {
                operation: 5,
                fields: vec!["a".into()],
            }),
            inspect: None,
        },
    ];
    let mut list = m.operations[0].clone();
    list.id = 7;
    list.resource = 2;
    m.operations.push(list);
    for assignment in &mut m.actions[0].steps[0].assign {
        assignment.change = Change::Set(Value::Target("parent".into()));
    }
    manifest::validate(&m).unwrap();
    let digest = manifest::digest(&m).unwrap();
    m.actions[0].targets.reverse();
    assert_eq!(digest, manifest::digest(&m).unwrap());
    m.actions[0].targets[1].source = TargetSource::Reference {
        target: "parent".into(),
        field: "a".into(),
        eligible: 2,
    };
    assert!(manifest::validate(&m).is_err());
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable server"]
async fn postgres_four_picker_targets_and_receipt_recovery() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_targets_{}", security::now().unwrap());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&format!("/{name}"));
    contract(Some(Database::postgres(case.as_str()).unwrap())).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn aliases_keep_independent_read_authority_and_exact_review() {
    let mut m = declarations();
    m.actions[0].targets[1].revision = Revision::Exact;
    let case = Case::new(None, m).await;
    let page = case.page(&case.alice).await;
    let mut fields = input(&page);
    let now = security::now().unwrap();
    let proof = case
        .app
        .keys
        .verify_selection(&fields["_target_b"], now)
        .unwrap();
    let mut kind = proof.kind;
    if let security::TokenKind::Selection { targets, .. } = &mut kind {
        targets.get_mut("b").unwrap().revision += 1;
    }
    fields.insert(
        "_target_b".into(),
        case.app
            .keys
            .issue(kind, &proof.subject, now, 600)
            .unwrap()
            .1,
    );
    assert_eq!(submit(&case, &page, fields).await.unwrap().status, 409);
    // The same physical record through a weaker alias does not authorize the
    // other alias after ownership changes, even before review conflict reporting.
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    tx.execute("UPDATE nx_records SET owner=(SELECT id FROM nx_accounts WHERE login_name='bob'),revision=revision+1 WHERE id=1",&[]).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        submit(&case, &page, input(&page)).await.unwrap().status,
        404
    );
}

#[tokio::test]
async fn http_picker_submits_and_replays_without_javascript() {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    let case = Case::new(None, declarations()).await;
    let router = crate::http::router(
        case.app.clone(),
        crate::http::Origin::parse("http://localhost:8080").unwrap(),
    );
    let page = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header("Host", "localhost:8080")
                .header("Cookie", format!("session={}", case.alice))
                .extension(crate::http::Peer::Local)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let page = String::from_utf8(
        to_bytes(page.into_body(), MAX_RESULT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let mut fields = input(&page);
    fields.insert("_submission".into(), fixture::hidden(&page, "_submission"));
    fields.insert("_csrf".into(), fixture::hidden(&page, "_csrf"));
    let mut body = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        body.append_pair(&name, &value);
    }
    let body = body.finish();
    let mut location = None;
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/actions/1")
                    .header("Host", "localhost:8080")
                    .header("Origin", "http://localhost:8080")
                    .header("Cookie", format!("session={}", case.alice))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .extension(crate::http::Peer::Local)
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 303);
        let next = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        if let Some(location) = &location {
            assert_eq!(location, &next);
        }
        location = Some(next);
    }
}

async fn delete_credentials(case: &Case, page: &str) -> (crate::render::FormCredentials, Fields) {
    let now = security::now().unwrap();
    let session = case.app.keys.verify(&case.alice, now).unwrap();
    let proof = case
        .app
        .keys
        .verify_selection(&handles(page, "a")[0], now)
        .unwrap();
    let security::TokenKind::Selection { targets, .. } = proof.kind else {
        unreachable!()
    };
    let handle = case
        .app
        .keys
        .issue(
            security::TokenKind::Selection {
                contract: case.app.submission_contract(),
                action: 2,
                binding: 2,
                name: "a".into(),
                query: 1,
                eligible: 2,
                targets,
            },
            &proof.subject,
            now,
            600,
        )
        .unwrap()
        .1;
    let credentials = case
        .app
        .credentials(
            &manifest::web_action(&case.app.manifest, 2).unwrap(),
            &session,
            now,
            Default::default(),
            Default::default(),
        )
        .unwrap();
    (credentials, Fields::from([("_target_a".into(), handle)]))
}
#[tokio::test]
async fn every_reference_restricts_delete_and_concurrent_create_delete_has_no_orphan() {
    reference_integrity(None).await;
}
async fn reference_integrity(db: Option<Database>) {
    // Put the endangered row only in each reference in turn: no first-field shortcut.
    let case = Case::new(db, declarations()).await;
    let page = case.page(&case.alice).await;
    let original = input(&page);
    for name in ["a", "b", "c", "d"] {
        let mut fields = original.clone();
        for other in ["a", "b", "c", "d"] {
            if other != name {
                fields.insert(format!("_target_{other}"), handles(&page, other)[1].clone());
            }
        }
        let fresh = case.page(&case.alice).await;
        assert_eq!(submit(&case, &fresh, fields).await.unwrap().status, 303);
        let (credentials, fields) = delete_credentials(&case, &page).await;
        assert!(
            case.app
                .submit(
                    &case.alice,
                    2,
                    &credentials.submission,
                    &credentials.csrf,
                    fields
                )
                .await
                .map_or(true, |response| response.status >= 400)
        );
        let mut tx = case
            .db
            .begin(std::time::Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        let storage = tx.storage_resource(&case.app.manifest, 2).await.unwrap();
        tx.execute(
            "DELETE FROM nx_records WHERE resource=$1",
            &[storage.into()],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let indexes=tx.fetch::<1>(if case.db.is_sqlite(){"SELECT name FROM sqlite_master WHERE type='index' AND substr(name,1,5)='nx_r_'"}else{"SELECT indexname FROM pg_indexes WHERE schemaname='public' AND substr(indexname,1,5)='nx_r_'"},&[]).await.unwrap();
    assert_eq!(indexes.len(), 4);
    tx.commit().await.unwrap();
    let fresh = case.page(&case.alice).await;
    assert_eq!(
        submit(&case, &fresh, original.clone())
            .await
            .unwrap()
            .status,
        303
    );
    let mut target = (*case.app.manifest).clone();
    target.resources[0].fields[0].max_bytes = 2048;
    let migration = crate::schema::Migration {
        version: 1,
        from: crate::schema::digest(&case.app.manifest.resources).unwrap(),
        to: crate::schema::digest(&target.resources).unwrap(),
        operations: vec![crate::schema::MigrationOp::ChangeField {
            resource: "notes".into(),
            field: "body".into(),
        }],
    };
    for name in ["a", "b", "c", "d"] {
        let mut refs: Fields = ["a", "b", "c", "d"]
            .into_iter()
            .map(|name| (name.into(), "1".into()))
            .collect();
        refs.insert(name.into(), "999".into());
        let mut tx = case
            .db
            .begin(std::time::Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        let storage = tx.storage_resource(&case.app.manifest, 2).await.unwrap();
        tx.execute(
            "UPDATE nx_records SET fields=$1 WHERE resource=$2",
            &[serde_json::to_string(&refs).unwrap().into(), storage.into()],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert!(
            case.db
                .schema_check(&target, &migration)
                .await
                .unwrap_err()
                .to_string()
                .contains("orphan")
        );
    }
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let storage = tx.storage_resource(&case.app.manifest, 2).await.unwrap();
    tx.execute(
        "DELETE FROM nx_records WHERE resource=$1",
        &[storage.into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (credentials, deleted) = delete_credentials(&case, &page).await;
    let fresh = case.page(&case.alice).await;
    let (created, deleted) = tokio::join!(
        submit(&case, &fresh, original),
        case.app.submit(
            &case.alice,
            2,
            &credentials.submission,
            &credentials.csrf,
            deleted
        )
    );
    let created = created.is_ok_and(|r| r.status == 303);
    let deleted = deleted.is_ok_and(|r| r.status == 303);
    assert_ne!(created, deleted);
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let notes = tx.storage_resource(&case.app.manifest, 1).await.unwrap();
    let links = tx.storage_resource(&case.app.manifest, 2).await.unwrap();
    let rows=tx.fetch::<2>("SELECT CAST((SELECT COUNT(*) FROM nx_records WHERE resource=$1 AND id=1) AS TEXT),CAST((SELECT COUNT(*) FROM nx_records WHERE resource=$2) AS TEXT)",&[notes.into(),links.into()]).await.unwrap();
    assert_eq!(rows[0][0], rows[0][1]);
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn created_step_references_and_account_inputs_share_the_existing_executor() {
    created_contract(None).await;
}
async fn created_contract(db: Option<Database>) {
    let mut m = declarations();
    m.resources[1].fields.push(TextField {
        immutable: false,
        name: "recipient".into(),
        label: "Recipient".into(),
        kind: FieldKind::Account {
            scope: AccountScope::SameTenant,
        },
        optional: false,
        initial: None,
        max_bytes: 43,
    });
    m.actions[0].inputs.push(Input {
        name: "recipient".into(),
        label: "Recipient".into(),
        kind: FieldKind::Account {
            scope: AccountScope::SameTenant,
        },
        optional: false,
        max_bytes: 43,
    });
    m.actions[0].targets.remove(0);
    m.actions[0].steps[0].assign[0].change = Change::Set(Value::Created(0));
    m.actions[0].steps[0].assign.push(Assignment {
        field: "recipient".into(),
        change: Change::Set(Value::Input("recipient".into())),
    });
    m.actions[0].steps.insert(
        0,
        Step {
            guards: vec![],
            operation: 3,
            target: Target::None,
            assign: vec![Assignment {
                field: "body".into(),
                change: Change::Set(Value::Literal(noxide_protocol::Literal::Text(
                    "created inside transaction".into(),
                ))),
            }],
        },
    );
    m.web_bindings[0].redirect.source = RedirectSource::Step(1);
    manifest::validate(&m).unwrap();
    let case = Case::new(db, m).await;
    let page = case.page(&case.alice).await;
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let account = tx
        .fetch::<1>("SELECT id FROM nx_accounts WHERE login_name='bob'", &[])
        .await
        .unwrap()[0][0]
        .clone();
    tx.commit().await.unwrap();
    let mut fields: Fields = ["b", "c", "d"]
        .into_iter()
        .map(|name| (format!("_target_{name}"), handles(&page, name)[0].clone()))
        .collect();
    fields.insert("recipient".into(), account.clone());
    assert_eq!(
        submit(&case, &page, fields.clone()).await.unwrap().status,
        303
    );
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let storage = tx.storage_resource(&case.app.manifest, 2).await.unwrap();
    let rows = tx
        .fetch::<1>(
            "SELECT fields FROM nx_records WHERE resource=$1",
            &[storage.into()],
        )
        .await
        .unwrap();
    let stored: Fields = serde_json::from_str(&rows[0][0]).unwrap();
    assert_ne!(stored["a"], "1");
    assert_eq!(stored["recipient"], account);
    tx.commit().await.unwrap();
    let fresh = case.page(&case.alice).await;
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_accounts SET state='disabled' WHERE id=$1",
        &[account.into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(
        submit(&case, &fresh, fields)
            .await
            .map_or(true, |r| r.status >= 400)
    );
}
#[tokio::test]
async fn derived_target_seals_reference_projection_and_rechecks_destination_authority() {
    let mut m = declarations();
    let mut list = m.operations[0].clone();
    list.id = 7;
    list.resource = 2;
    m.operations.push(list);
    m.actions[0].targets = vec![
        ActionTarget {
            name: "a_parent".into(),
            resource: 1,
            source: TargetSource::Reference {
                target: "z_link".into(),
                field: "a".into(),
                eligible: 2,
            },
            revision: Revision::Identity,
            projection: Some(Inspection {
                operation: 2,
                fields: vec!["body".into()],
            }),
            inspect: None,
        },
        ActionTarget {
            name: "z_link".into(),
            resource: 2,
            source: TargetSource::Selected {
                query: 7,
                eligible: 5,
                label: vec!["a".into()],
            },
            revision: Revision::Identity,
            projection: Some(Inspection {
                operation: 5,
                fields: vec!["a".into()],
            }),
            inspect: None,
        },
    ];
    for assignment in &mut m.actions[0].steps[0].assign {
        assignment.change = Change::Set(Value::Target("a_parent".into()));
    }
    manifest::validate(&m).unwrap();
    let case = Case::new(None, m).await;
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let storage = tx.storage_resource(&case.app.manifest, 2).await.unwrap();
    tx.allocate_creation().await.unwrap();
    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,10,(SELECT id FROM nx_accounts WHERE login_name='alice'),'team',$2,'link',1,(SELECT value FROM nx_creation_counter WHERE singleton=1))",&[storage.into(),r#"{"a":"1","b":"1","c":"1","d":"1"}"#.into()]).await.unwrap();
    tx.commit().await.unwrap();
    let page = case.page(&case.alice).await;
    let fields = Fields::from([("_target_z_link".into(), handles(&page, "z_link")[0].clone())]);
    assert_eq!(
        submit(&case, &page, fields.clone()).await.unwrap().status,
        303
    );
    let fresh = case.page(&case.alice).await;
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let storage = tx.storage_resource(&case.app.manifest, 1).await.unwrap();
    tx.execute("UPDATE nx_records SET owner=(SELECT id FROM nx_accounts WHERE login_name='bob') WHERE resource=$1",&[storage.into()]).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        submit(&case, &page, fields.clone()).await.unwrap().status,
        303
    );
    assert_eq!(submit(&case, &fresh, fields).await.unwrap().status, 404);
}

#[tokio::test]
async fn duplicate_row_aliases_reauthorize_each_policy_after_receipt_lookup() {
    let mut m = declarations();
    let mut stronger = m.operations[1].clone();
    stronger.id = 7;
    stronger.policy = Policy {
        any: vec![vec![Predicate::Role {
            name: "auditor".into(),
            tenant_scoped: false,
        }]],
    };
    m.operations.push(stronger);
    m.actions[0].targets[1].source = TargetSource::Selected {
        query: 1,
        eligible: 7,
        label: vec!["body".into()],
    };
    m.actions[0].targets[1]
        .projection
        .as_mut()
        .unwrap()
        .operation = 7;
    m.operations
        .iter_mut()
        .find(|op| op.id == 4)
        .unwrap()
        .bind
        .insert("b".into(), 7);
    let case = Case::new(None, m).await;
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    tx.execute("INSERT INTO nx_roles(principal,name,tenant) VALUES((SELECT id FROM nx_accounts WHERE login_name='alice'),'auditor','')",&[]).await.unwrap();
    tx.commit().await.unwrap();
    let page = case.page(&case.alice).await;
    let fresh = case.page(&case.alice).await;
    let fields = input(&page);
    assert_eq!(
        submit(&case, &page, fields.clone()).await.unwrap().status,
        303
    );
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    tx.execute("DELETE FROM nx_roles WHERE name='auditor'", &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        submit(&case, &page, fields.clone()).await.unwrap().status,
        303
    );
    assert_eq!(submit(&case, &fresh, fields).await.unwrap().status, 404);
}
#[tokio::test]
async fn sequential_alias_mutations_share_identity_without_self_conflicting() {
    let mut m = declarations();
    let mut update = m.operations[2].clone();
    update.id = 7;
    update.kind = OperationKind::Update;
    m.operations.push(update);
    m.actions[0].targets = vec![
        selected("a", Revision::Exact),
        selected("b", Revision::Exact),
    ];
    m.actions[0].steps = [("a", "first"), ("b", "second")]
        .into_iter()
        .map(|(name, value)| Step {
            guards: vec![],
            operation: 7,
            target: Target::Named(name.into()),
            assign: vec![Assignment {
                field: "body".into(),
                change: Change::Set(Value::Literal(noxide_protocol::Literal::Text(value.into()))),
            }],
        })
        .collect();
    m.web_bindings[0].redirect = Redirect {
        route: 2,
        source: RedirectSource::Target("a".into()),
    };
    manifest::validate(&m).unwrap();
    let case = Case::new(None, m).await;
    let page = case.page(&case.alice).await;
    let fields = ["a", "b"]
        .into_iter()
        .map(|name| (format!("_target_{name}"), handles(&page, name)[0].clone()))
        .collect();
    assert_eq!(submit(&case, &page, fields).await.unwrap().status, 303);
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let storage = tx.storage_resource(&case.app.manifest, 1).await.unwrap();
    let row = tx
        .fetch::<2>(
            "SELECT fields,CAST(revision AS TEXT) FROM nx_records WHERE resource=$1 AND id=1",
            &[storage.into()],
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Fields>(&row[0][0]).unwrap()["body"],
        "second"
    );
    assert_eq!(row[0][1], "3");
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable server"]
async fn postgres_all_reference_indexes_orphans_and_create_delete_race() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_ref_race_{}", security::now().unwrap());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&format!("/{name}"));
    reference_integrity(Some(Database::postgres(case.as_str()).unwrap())).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable server"]
async fn postgres_created_references_and_active_account_inputs() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_created_refs_{}", security::now().unwrap());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&format!("/{name}"));
    created_contract(Some(Database::postgres(case.as_str()).unwrap())).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn public_picker_visibility_does_not_revoke_explicit_private_eligibility() {
    let mut m = declarations();
    m.resources[0].fields.push(TextField {
        immutable: false,
        name: "published".into(),
        label: "Published".into(),
        kind: FieldKind::Boolean,
        optional: false,
        initial: Some("true".into()),
        max_bytes: 5,
    });
    m.operations[0].policy = Policy {
        any: vec![vec![Predicate::Public]],
    };
    m.operations[0].visibility = Some(Visibility {
        field: "published".into(),
        equals: "true".into(),
    });
    m.operations[0].fields = Some(vec!["body".into()]);
    let case = Case::new(None, m).await;
    let page = case.page(&case.alice).await;
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let storage = tx.storage_resource(&case.app.manifest, 1).await.unwrap();
    let fields = Fields::from([
        ("body".into(), "hidden from public query".into()),
        ("published".into(), "false".into()),
    ]);
    tx.execute(
        "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2",
        &[
            serde_json::to_string(&fields).unwrap().into(),
            storage.into(),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        submit(&case, &page, input(&page)).await.unwrap().status,
        303
    );
}

#[test]
fn target_proof_namespace_cannot_collide_with_declared_scalar_inputs() {
    let mut m = fixture::manifest();
    m.actions[0].inputs[0].name = "_target_a".into();
    m.actions[0].steps[0].assign[0].change = Change::Set(Value::Input("_target_a".into()));
    assert!(manifest::validate(&m).is_err());
    let mut m = declarations();
    let fifth = selected("fifth", Revision::Identity);
    m.actions[0].targets.push(fifth);
    assert!(manifest::validate(&m).is_err());
    let mut m = declarations();
    let mut field = m.resources[1].fields[0].clone();
    field.name = "fifth".into();
    m.resources[1].fields.push(field);
    assert!(manifest::validate(&m).is_err());
}
#[tokio::test]
async fn unknown_proof_aliases_fail_before_any_target_resolution() {
    let case = Case::new(None, declarations()).await;
    let page = case.page(&case.alice).await;
    let mut fields = input(&page);
    fields.remove("_target_a");
    fields.insert("_target_unknown".into(), "1".into());
    assert!(matches!(
        submit(&case, &page, fields).await,
        Err(RequestError::InvalidRequest)
    ));
}

#[tokio::test]
async fn follow_provenance_keeps_each_reference_field_separate() {
    let mut m = declarations();
    for (id, field) in [(7, "a"), (8, "b")] {
        let mut follow = m.operations[1].clone();
        follow.id = id;
        follow.via = Some(Via {
            source: 5,
            field: field.into(),
        });
        m.operations.push(follow);
        m.routes[2].operations.push(id);
    }
    let case = Case::new(None, m).await;
    let page = case.page(&case.alice).await;
    let mut fields = input(&page);
    fields.insert("_target_b".into(), handles(&page, "b")[1].clone());
    assert_eq!(submit(&case, &page, fields).await.unwrap().status, 303);
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let storage = tx.storage_resource(&case.app.manifest, 2).await.unwrap();
    let id: u64 = tx
        .fetch::<1>(
            "SELECT CAST(id AS TEXT) FROM nx_records WHERE resource=$1",
            &[storage.into()],
        )
        .await
        .unwrap()[0][0]
        .parse()
        .unwrap();
    let (_, principal) = auth::authenticate(
        &mut tx,
        &case.app.keys,
        &case.alice,
        security::now().unwrap(),
    )
    .await
    .unwrap();
    let mut effects = Effects {
        authority: Default::default(),
        upload: None,
        blob_reads: Default::default(),
        provenance: Default::default(),
        follow_sources: vec![],
        invoked: Default::default(),
        list_bytes: 0,
        list_calls: repository::MAX_LIST_DATABASE_CALLS,
        result_limit: MAX_RESULT_BYTES,
        truncated: false,
        see_all: vec![],
        tx,
        manifest: case.app.manifest.clone(),
        plans: case.app.plans.clone(),
        principal,
        request: RequestView {
            version: VERSION,
            kind: RequestKind::Route(3),
            target: Some(id),
            params: Default::default(),
            input: Default::default(),
            inspection: Default::default(),
            available_forms: vec![],
        },
        grants: Default::default(),
        target_rows: Default::default(),
        capability_grant: None,
        calls: 16,
        cursor: None,
        more: None,
    };
    let source: Option<Record> =
        serde_json::from_slice(&effects.invoke(5, id).await.unwrap()).unwrap();
    let mut forged = source.unwrap();
    forged.fields.insert("a".into(), "2".into());
    for (operation, expected) in [(7, 1), (8, 2)] {
        effects.follow_source(2, forged.id).unwrap();
        let records: Vec<Option<Record>> =
            serde_json::from_slice(&effects.follow(operation).await.unwrap()).unwrap();
        assert_eq!(records[0].as_ref().unwrap().id, expected);
    }
    effects.tx.commit().await.unwrap();
}

#[tokio::test]
async fn anonymous_picker_uses_its_own_principal_on_an_authenticated_page() {
    let mut m = declarations();
    m.resources[0].fields.push(TextField {
        immutable: false,
        name: "published".into(),
        label: "Published".into(),
        kind: FieldKind::Boolean,
        optional: false,
        initial: Some("true".into()),
        max_bytes: 5,
    });
    for id in [1, 2] {
        let op = m.operations.iter_mut().find(|op| op.id == id).unwrap();
        op.policy = Policy {
            any: vec![vec![Predicate::Public]],
        };
        op.visibility = Some(Visibility {
            field: "published".into(),
            equals: "true".into(),
        });
        op.fields = Some(vec!["body".into()]);
    }
    m.operations
        .iter_mut()
        .find(|op| op.id == 4)
        .unwrap()
        .policy = Policy {
        any: vec![vec![Predicate::Public]],
    };
    m.routes[0].access = Access::PublicOptional;
    let case = Case::new(None, m).await;
    let page = case
        .app
        .view_page(Some(&case.alice), 1, None, None)
        .await
        .unwrap();
    let cookie = page.anonymous_cookie.as_ref().unwrap();
    let html = String::from_utf8(page.body.clone()).unwrap();
    let form = html.split_once("action=\"/actions/1\"").unwrap().1;
    let saved = case
        .app
        .submit(
            cookie,
            1,
            &fixture::hidden(form, "_submission"),
            &fixture::hidden(form, "_csrf"),
            input(&html),
        )
        .await
        .unwrap();
    assert_eq!(saved.status, 200);
    assert!(String::from_utf8(saved.body).unwrap().contains("<pre>"));
}

#[tokio::test]
async fn picker_query_ignores_and_preserves_unrelated_route_pagination() {
    let case = Case::new(None, declarations()).await;
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let (_, principal) = auth::authenticate(
        &mut tx,
        &case.app.keys,
        &case.alice,
        security::now().unwrap(),
    )
    .await
    .unwrap();
    let mut effects = Effects {
        authority: Default::default(),
        upload: None,
        blob_reads: Default::default(),
        provenance: Default::default(),
        follow_sources: vec![],
        invoked: Default::default(),
        list_bytes: 0,
        list_calls: repository::MAX_LIST_DATABASE_CALLS,
        result_limit: 321,
        truncated: true,
        see_all: vec![],
        tx,
        manifest: case.app.manifest.clone(),
        plans: case.app.plans.clone(),
        principal,
        request: RequestView {
            version: VERSION,
            kind: RequestKind::Route(1),
            target: None,
            params: Default::default(),
            input: Default::default(),
            inspection: Default::default(),
            available_forms: vec![],
        },
        grants: Default::default(),
        target_rows: Default::default(),
        capability_grant: None,
        calls: 16,
        cursor: Some(noxide_protocol::query::CursorKey::Created {
            sequence: 9999,
            record: 9999,
        }),
        more: Some(noxide_protocol::query::CursorKey::Created {
            sequence: 777,
            record: 777,
        }),
    };
    assert_eq!(
        effects
            .picker_records(1, "a")
            .await
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        (
            effects.cursor,
            effects.more,
            effects.result_limit,
            effects.truncated
        ),
        (
            Some(noxide_protocol::query::CursorKey::Created {
                sequence: 9999,
                record: 9999
            }),
            Some(noxide_protocol::query::CursorKey::Created {
                sequence: 777,
                record: 777
            }),
            321,
            true,
        )
    );
    effects.tx.commit().await.unwrap();
}
