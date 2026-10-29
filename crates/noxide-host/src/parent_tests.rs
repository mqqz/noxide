use crate::{
    Application, Database, HostKeys, auth::Principal, database::Param, manifest,
    repository::Effects, runtime::Limits, test_support as fixture,
};
use noxide_protocol::*;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

fn boolean(name: &str) -> TextField {
    TextField {
        name: name.into(),
        label: name.into(),
        kind: FieldKind::Boolean,
        optional: false,
        max_bytes: 5,
    }
}
fn declarations() -> Manifest {
    let mut m = fixture::manifest();
    m.resources[0].fields.extend([
        boolean("published"),
        TextField {
            name: "thread".into(),
            label: "Thread".into(),
            max_bytes: 20,
            optional: false,
            kind: FieldKind::Parent {
                resource: "threads".into(),
                visible: Visibility {
                    field: "published".into(),
                    equals: "true".into(),
                },
                create_when: Visibility {
                    field: "locked".into(),
                    equals: "false".into(),
                },
            },
        },
    ]);
    m.resources.push(Resource {
        id: 2,
        name: "threads".into(),
        fields: vec![boolean("published"), boolean("locked")],
    });
    for op in &mut m.operations {
        op.policy.any = vec![vec![Predicate::Public]];
        if op.kind != OperationKind::Create {
            op.visibility = Some(Visibility {
                field: "published".into(),
                equals: "true".into(),
            });
            op.fields = Some(vec!["body".into()]);
        }
    }
    m.operations.push(Operation {
        id: 4,
        resource: 2,
        kind: OperationKind::Read,
        policy: Policy {
            any: vec![vec![Predicate::Public]],
        },
        visibility: Some(Visibility {
            field: "published".into(),
            equals: "true".into(),
        }),
        fields: Some(vec!["locked".into()]),
    });
    m.routes[0].operations.clear();
    m.routes[0].forms.clear();
    m.routes[0].access = Access::Public;
    m.routes[1].access = Access::Public;
    m.routes.push(Route {
        id: 3,
        path: "/threads/{thread}".into(),
        resource: Some(2),
        operations: vec![4, 1],
        forms: vec![1],
        access: Access::PublicOptional,
    });
    m.actions[0].fields.push("published".into());
    m
}
async fn seed(db: &Database, m: &Manifest) {
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.bind_schema(m).await.unwrap();
    let parent = tx.storage_resource(m, 2).await.unwrap();
    for id in [10i64, 20] {
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision) VALUES($1,$2,NULL,'',$3,'parent',1)", &[parent.into(),id.into(),r#"{"published":"true","locked":"false"}"#.into()]).await.unwrap();
    }
    let child = tx.storage_resource(m, 1).await.unwrap();
    for id in 1i64..=12 {
        let fields = Fields::from([
            ("body".into(), format!("reply {id}")),
            ("published".into(), "true".into()),
            (
                "thread".into(),
                if id % 2 == 0 { "10" } else { "20" }.into(),
            ),
        ]);
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version) VALUES($1,$2,NULL,'',$3,'child',1,1)", &[child.into(),id.into(),serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
    }
    tx.commit().await.unwrap();
}
async fn effects(db: &Database, m: &Manifest, route: u32, target: u64) -> Effects {
    Effects {
        tx: db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap(),
        manifest: Arc::new(m.clone()),
        principal: Principal::Anonymous,
        request: RequestView {
            version: VERSION,
            kind: RequestKind::Route(route),
            target: Some(target),
            input: Fields::new(),
            inspection: None,
            available_forms: vec![],
        },
        outcome: None,
        grant: None,
        capability_grant: None,
        record: None,
        calls: 64,
        cursor: None,
        more: None,
    }
}
async fn set_parent(db: &Database, m: &Manifest, published: bool, locked: bool) {
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let storage = tx.storage_resource(m, 2).await.unwrap();
    let fields = serde_json::to_string(&Fields::from([
        ("published".into(), published.to_string()),
        ("locked".into(), locked.to_string()),
    ]))
    .unwrap();
    tx.execute(
        "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2 AND id=10",
        &[fields.into(), storage.into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}
#[test]
fn parent_admission_rejects_unbound_or_mutable_relationships() {
    let m = declarations();
    manifest::validate(&m).unwrap();
    let mut bad = m.clone();
    bad.actions[0].fields.push("thread".into());
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.routes[0].forms.push(1);
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.routes[0].operations.push(1);
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.resources[0].fields[2].optional = true;
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.resources[1]
        .fields
        .push(m.resources[0].fields[2].clone());
    assert!(manifest::validate(&bad).is_err());
    let field = m.resources[0].fields[2].clone();
    let mut bad = m;
    bad.resources[0].fields.push(field);
    assert!(manifest::validate(&bad).is_err());
}
#[tokio::test]
async fn child_updates_cannot_move_parent_and_missing_parents_hide_children() {
    let tmp = tempfile::tempdir().unwrap();
    mutation_case(Database::sqlite(tmp.path().join("mutation.db"))).await;
}

async fn mutation_case(db: Database) {
    db.initialize().await.unwrap();
    let mut m = declarations();
    m.operations.push(Operation {
        id: 5,
        resource: 1,
        kind: OperationKind::Update,
        policy: Policy {
            any: vec![vec![Predicate::Role {
                name: "moderator".into(),
                tenant_scoped: false,
            }]],
        },
        visibility: None,
        fields: None,
    });
    m.actions.push(Action {
        id: 2,
        version: 1,
        name: "Edit reply".into(),
        operation: 5,
        redirect: 2,
        fields: vec!["body".into()],
        inspect: None,
        layout: vec![],
    });
    m.routes[1].forms.push(2);
    m.routes[1].access = Access::PublicOptional;
    manifest::validate(&m).unwrap();
    let mut invalid = m.clone();
    invalid.actions[1].fields.push("thread".into());
    assert!(
        manifest::validate(&invalid)
            .unwrap_err()
            .to_string()
            .contains("immutable")
    );
    seed(&db, &m).await;
    let mut e = effects(&db, &m, 2, 12).await;
    let stored = crate::repository::load(&mut e.tx, &m, 1, 12)
        .await
        .unwrap()
        .unwrap();
    e.grant = Some(crate::security::RecordTarget {
        resource: 1,
        id: 12,
        route: 2,
        incarnation: stored.incarnation.clone(),
        revision: stored.revision,
    });
    e.record = Some(stored);
    e.request.kind = RequestKind::Action(2);
    e.principal = Principal::User(crate::auth::User {
        id: "moderator".into(),
        tenant: "".into(),
        roles: vec![("moderator".into(), "".into())],
    });
    e.request.input = Fields::from([
        ("body".into(), "edited".into()),
        ("thread".into(), "20".into()),
    ]);
    assert!(e.invoke(5, 0).await.is_err());
    e.request.input.remove("thread");
    e.invoke(5, 0).await.unwrap();
    e.tx.commit().await.unwrap();
    let mut e = effects(&db, &m, 2, 12).await;
    let stored = crate::repository::load(&mut e.tx, &m, 1, 12)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.record.fields["thread"], "10");
    assert_eq!(stored.record.fields["body"], "edited");
    // Simulate storage corruption outside the host's guarded deletion API.
    let parent = e.tx.storage_resource(&m, 2).await.unwrap();
    e.tx.execute(
        "DELETE FROM nx_records WHERE resource=$1 AND id=10",
        &[parent.into()],
    )
    .await
    .unwrap();
    e.tx.commit().await.unwrap();
    let mut e = effects(&db, &m, 2, 12).await;
    assert!(
        serde_json::from_slice::<Option<Record>>(&e.invoke(2, 12).await.unwrap())
            .unwrap()
            .is_none()
    );
    e.request.kind = RequestKind::Route(3);
    e.request.target = Some(10);
    assert!(
        serde_json::from_slice::<Vec<Record>>(&e.invoke(1, 0).await.unwrap())
            .unwrap()
            .is_empty()
    );
    e.tx.rollback().await.unwrap();
}

#[tokio::test]
async fn concurrent_parent_changes_precede_child_mutation_checks() {
    let tmp = tempfile::tempdir().unwrap();
    concurrent_case(Database::sqlite(tmp.path().join("concurrent.db"))).await;
}

async fn concurrent_case(db: Database) {
    db.initialize().await.unwrap();
    let m = declarations();
    seed(&db, &m).await;
    for (published, locked) in [(false, false), (true, true)] {
        set_parent(&db, &m, true, false).await;
        let mut e = effects(&db, &m, 3, 10).await;
        let stored = crate::repository::load(&mut e.tx, &m, 2, 10)
            .await
            .unwrap()
            .unwrap();
        let grant = crate::security::RecordTarget {
            resource: 2,
            id: 10,
            route: 3,
            incarnation: stored.incarnation.clone(),
            revision: stored.revision,
        };
        e.tx.rollback().await.unwrap();
        let mut writer = db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let storage = writer.storage_resource(&m, 2).await.unwrap();
        let fields = Fields::from([
            ("published".into(), published.to_string()),
            ("locked".into(), locked.to_string()),
        ]);
        writer
            .execute(
                "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2 AND id=10",
                &[
                    serde_json::to_string(&fields).unwrap().into(),
                    storage.into(),
                ],
            )
            .await
            .unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (committed, resume) = tokio::sync::oneshot::channel();
        let child_db = db.clone();
        let child_manifest = m.clone();
        let child = tokio::spawn(async move {
            // SQLite waits for the writer here; PostgreSQL may begin before commit.
            started.send(()).unwrap();
            let mut e = effects(&child_db, &child_manifest, 3, 10).await;
            resume.await.unwrap();
            e.request.kind = RequestKind::Action(1);
            e.request.input = Fields::from([
                ("body".into(), "racing reply".into()),
                ("published".into(), "true".into()),
            ]);
            e.grant = Some(grant);
            assert!(
                e.invoke(3, 0)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("parent unavailable or locked")
            );
            e.tx.rollback().await.unwrap();
        });
        ready.await.unwrap();
        writer.commit().await.unwrap();
        committed.send(()).unwrap();
        child.await.unwrap();
        let mut e = effects(&db, &m, 3, 10).await;
        let storage = e.tx.storage_resource(&m, 1).await.unwrap();
        let rows =
            e.tx.fetch::<1>(
                "SELECT CAST(COUNT(*) AS TEXT) FROM nx_records WHERE resource=$1",
                &[storage.into()],
            )
            .await
            .unwrap();
        assert_eq!(rows[0][0], "12");
        e.tx.rollback().await.unwrap();
    }
}

#[tokio::test]
async fn scoped_pages_and_direct_reads_obey_parent_visibility() {
    let tmp = tempfile::tempdir().unwrap();
    parents_case(Database::sqlite(tmp.path().join("parents.db")), true).await;
}
async fn parents_case(db: Database, sqlite: bool) {
    db.initialize().await.unwrap();
    let m = declarations();
    seed(&db, &m).await;
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let storage = tx.storage_resource(&m, 1).await.unwrap();
    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision) VALUES($1,$2,NULL,'',$3,'maximum-id',1)", &[storage.into(), i64::MAX.into(), r#"{"body":"maximum ID","published":"true","thread":"20"}"#.into()]).await.unwrap();
    tx.commit().await.unwrap();
    for (parent, expected) in [
        (10, vec![12, 10, 8, 6, 4, 2]),
        (20, vec![i64::MAX as u64, 11, 9, 7, 5, 3, 1]),
    ] {
        let mut e = effects(&db, &m, 3, parent).await;
        let mut seen = vec![];
        loop {
            let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            seen.extend(rows.iter().map(|r| r.id));
            assert!(rows.iter().all(|r| r.fields.len() == 1));
            e.cursor = e.more.take();
            if e.cursor.is_none() {
                break;
            }
        }
        assert_eq!(seen, expected);
        assert!(
            e.invoke(1, 20).await.is_err(),
            "guest cannot change parent target"
        );
        let indexes =
            e.tx.fetch::<1>(
                if sqlite { "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'nx_parent_%'" }
                else { "SELECT indexname FROM pg_indexes WHERE schemaname='public' AND indexname LIKE 'nx_parent_%'" },
                &[],
            )
            .await
            .unwrap();
        assert_eq!(indexes.len(), 1);
        e.tx.rollback().await.unwrap();
    }
    set_parent(&db, &m, false, false).await;
    let mut e = effects(&db, &m, 3, 10).await;
    assert!(
        serde_json::from_slice::<Vec<Record>>(&e.invoke(1, 0).await.unwrap())
            .unwrap()
            .is_empty()
    );
    e.request.kind = RequestKind::Route(2);
    e.request.target = Some(12);
    assert!(
        serde_json::from_slice::<Option<Record>>(&e.invoke(2, 12).await.unwrap())
            .unwrap()
            .is_none()
    );
    e.request.target = Some(11);
    assert!(
        serde_json::from_slice::<Option<Record>>(&e.invoke(2, 11).await.unwrap())
            .unwrap()
            .is_some()
    );
    e.tx.rollback().await.unwrap();
}
#[tokio::test]
async fn signed_parent_forms_recheck_lock_and_preserve_idempotency() {
    let tmp = tempfile::tempdir().unwrap();
    forms_case(Database::sqlite(tmp.path().join("forms.db")), true).await;
}
async fn forms_case(db: Database, _sqlite: bool) {
    db.initialize().await.unwrap();
    let m = declarations();
    let app = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
    )
    .unwrap();
    app.activate().await.unwrap();
    seed(&db, &m).await;
    let input = Fields::from([
        ("body".into(), "new reply".into()),
        ("published".into(), "true".into()),
    ]);
    let page = app.view_page(None, 3, Some(10), None).await.unwrap();
    let cookie = page.anonymous_cookie.unwrap();
    let text = String::from_utf8(page.body).unwrap();
    let token = fixture::hidden(&text, "_submission");
    let csrf = fixture::hidden(&text, "_csrf");
    let mut forged = input.clone();
    forged.insert("thread".into(), "20".into());
    assert!(app.submit(&cookie, 1, &token, &csrf, forged).await.is_err());
    set_parent(&db, &m, true, true).await;
    let denied = app
        .submit(&cookie, 1, &token, &csrf, input.clone())
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&denied.body).contains("<pre>"));
    set_parent(&db, &m, true, false).await;
    let conflict = app
        .submit(&cookie, 1, &token, &csrf, input.clone())
        .await
        .unwrap();
    assert_eq!(conflict.status, 409);
    // The parent's revision changed: recover a fresh form, never silently retarget.
    let page = app.view_page(None, 3, Some(10), None).await.unwrap();
    let cookie = page.anonymous_cookie.unwrap();
    let text = String::from_utf8(page.body).unwrap();
    let token = fixture::hidden(&text, "_submission");
    let csrf = fixture::hidden(&text, "_csrf");
    let saved = app
        .submit(&cookie, 1, &token, &csrf, input.clone())
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&saved.body).contains("<pre>"));
    let replay = app.submit(&cookie, 1, &token, &csrf, input).await.unwrap();
    assert_eq!(saved.body, replay.body);
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let child = tx.storage_resource(&m, 1).await.unwrap();
    let rows = tx
        .fetch::<1>(
            "SELECT fields FROM nx_records WHERE resource=$1 AND id>12",
            &[Param::Number(child)],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        serde_json::from_str::<Fields>(&rows[0][0]).unwrap()["thread"],
        "10"
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn parent_deletion_and_orphaning_migrations_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    integrity_case(Database::sqlite(tmp.path().join("integrity.db")), true).await;
}
async fn integrity_case(db: Database, _sqlite: bool) {
    db.initialize().await.unwrap();
    let mut m = declarations();
    let role = Predicate::Role {
        name: "moderator".into(),
        tenant_scoped: false,
    };
    m.operations.push(Operation {
        id: 5,
        resource: 2,
        kind: OperationKind::Delete,
        policy: Policy {
            any: vec![vec![role]],
        },
        visibility: None,
        fields: None,
    });
    m.actions.push(Action {
        id: 2,
        version: 1,
        name: "Delete thread".into(),
        operation: 5,
        redirect: 1,
        fields: vec![],
        inspect: None,
        layout: vec![],
    });
    m.routes[2].forms.push(2);
    manifest::validate(&m).unwrap();
    seed(&db, &m).await;
    let mut e = effects(&db, &m, 3, 10).await;
    let stored = crate::repository::load(&mut e.tx, &m, 2, 10)
        .await
        .unwrap()
        .unwrap();
    e.grant = Some(crate::security::RecordTarget {
        resource: 2,
        id: 10,
        route: 3,
        incarnation: stored.incarnation.clone(),
        revision: stored.revision,
    });
    e.record = Some(stored);
    e.request.kind = RequestKind::Action(2);
    e.principal = Principal::User(crate::auth::User {
        id: "moderator".into(),
        tenant: "".into(),
        roles: vec![("moderator".into(), "".into())],
    });
    assert!(
        e.invoke(5, 0)
            .await
            .unwrap_err()
            .to_string()
            .contains("parent has children")
    );
    e.tx.rollback().await.unwrap();
    // Retargeting a declared relationship to an empty resource must fail atomically.
    let mut target = m.clone();
    let mut replacement = target.resources[1].clone();
    replacement.id = 3;
    replacement.name = "replacement".into();
    target.resources.push(replacement);
    let FieldKind::Parent { resource, .. } = &mut target.resources[0].fields[2].kind else {
        unreachable!()
    };
    *resource = "replacement".into();
    // Match the new parent route so the destination manifest itself is valid.
    target.operations[3].resource = 3;
    target.routes[2].resource = Some(3);
    target.routes[2].forms.retain(|id| *id == 1);
    target.actions.retain(|a| a.id == 1);
    target.operations.retain(|o| o.id != 5);
    manifest::validate(&target).unwrap();
    let migration = crate::schema::Migration {
        version: 1,
        from: crate::schema::digest(&m.resources).unwrap(),
        to: crate::schema::digest(&target.resources).unwrap(),
        operations: vec![
            crate::schema::MigrationOp::AddResource {
                resource: "replacement".into(),
            },
            crate::schema::MigrationOp::ChangeField {
                resource: "notes".into(),
                field: "thread".into(),
            },
        ],
    };
    assert!(
        db.schema_apply(&target, &migration)
            .await
            .unwrap_err()
            .to_string()
            .contains("orphan")
    );
    let mut e = effects(&db, &m, 3, 10).await;
    e.tx.check_schema(&m).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Vec<Record>>(&e.invoke(1, 0).await.unwrap())
            .unwrap()
            .len(),
        3
    );
    e.tx.rollback().await.unwrap();
    // A valid field rename rebuilds the index and preserves the relationship.
    let mut renamed = m.clone();
    renamed.resources[0].fields[2].name = "parent_thread".into();
    let migration = crate::schema::Migration {
        version: 1,
        from: crate::schema::digest(&m.resources).unwrap(),
        to: crate::schema::digest(&renamed.resources).unwrap(),
        operations: vec![crate::schema::MigrationOp::RenameField {
            resource: "notes".into(),
            from: "thread".into(),
            to: "parent_thread".into(),
        }],
    };
    db.schema_apply(&renamed, &migration).await.unwrap();
    let mut e = effects(&db, &renamed, 3, 10).await;
    let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
    assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), [12, 10, 8]);
    e.tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_relationships_pagination_forms_and_migrations() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for case in [
        "parents",
        "forms",
        "integrity",
        "index_scope",
        "mutation",
        "concurrent",
    ] {
        let name = format!(
            "nx_parent_{case}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut case_url = url::Url::parse(&url).unwrap();
        case_url.set_path(&format!("/{name}"));
        let db = Database::postgres(case_url.as_str()).unwrap();
        match case {
            "parents" => parents_case(db, false).await,
            "forms" => forms_case(db, false).await,
            "integrity" => integrity_case(db, false).await,
            "mutation" => mutation_case(db).await,
            "concurrent" => concurrent_case(db).await,
            _ => index_scope_case(db, false).await,
        }
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn optional_auth_pages_omit_declared_owner_forms_for_anonymous_visitors() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(tmp.path().join("optional.db"));
    db.initialize().await.unwrap();
    let mut m = declarations();
    m.operations[2].policy.any = vec![vec![Predicate::Owner]];
    let app = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
    )
    .unwrap();
    app.activate().await.unwrap();
    seed(&db, &m).await;
    let page = app.view_page(None, 3, Some(10), None).await.unwrap();
    assert_eq!(page.status, 200);
    assert!(!String::from_utf8_lossy(&page.body).contains("/actions/1"));
}

#[tokio::test]
async fn parent_indexes_do_not_index_unrelated_text_fields() {
    let tmp = tempfile::tempdir().unwrap();
    index_scope_case(Database::sqlite(tmp.path().join("index-scope.db")), true).await;
}

async fn index_scope_case(db: Database, sqlite: bool) {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    // Base64 of independent hashes is deterministic but does not compress below
    // PostgreSQL's B-tree tuple limit, unlike repeated or hexadecimal text.
    let text = |seed: u8| {
        let bytes: Vec<u8> = (0..96u8)
            .flat_map(|block| Sha256::digest([seed, block]))
            .collect();
        let value = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert_eq!(value.len(), 4096);
        value
    };
    db.initialize().await.unwrap();
    let mut m = declarations();
    m.resources.push(Resource {
        id: 3,
        name: "unrelated".into(),
        fields: ["thread", "parent_thread"]
            .map(|name| TextField {
                kind: FieldKind::Text,
                optional: false,
                name: name.into(),
                label: name.into(),
                max_bytes: 4096,
            })
            .to_vec(),
    });
    manifest::validate(&m).unwrap();
    seed(&db, &m).await;
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let unrelated = tx.storage_resource(&m, 3).await.unwrap();
    for (id, value) in [(1i64, text(1)), (2, "short".into())] {
        let fields = Fields::from([
            ("thread".into(), value.clone()),
            ("parent_thread".into(), value),
        ]);
        manifest::validate_fields(&m.resources[2], &fields).unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision) VALUES($1,$2,NULL,'',$3,'unrelated',1)", &[unrelated.into(), id.into(), serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
    }
    let fields = Fields::from([
        ("thread".into(), text(2)),
        ("parent_thread".into(), text(3)),
    ]);
    manifest::validate_fields(&m.resources[2], &fields).unwrap();
    tx.execute(
        "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2 AND id=2",
        &[
            serde_json::to_string(&fields).unwrap().into(),
            unrelated.into(),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Rebuild the parent index while same-named, large text already exists.
    let mut renamed = m.clone();
    renamed.resources[0].fields[2].name = "parent_thread".into();
    let migration = crate::schema::Migration {
        version: 1,
        from: crate::schema::digest(&m.resources).unwrap(),
        to: crate::schema::digest(&renamed.resources).unwrap(),
        operations: vec![crate::schema::MigrationOp::RenameField {
            resource: "notes".into(),
            from: "thread".into(),
            to: "parent_thread".into(),
        }],
    };
    db.schema_apply(&renamed, &migration).await.unwrap();
    let mut e = effects(&db, &renamed, 3, 10).await;
    let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
    assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), [12, 10, 8]);
    let stored =
        e.tx.fetch::<1>(
            "SELECT fields FROM nx_records WHERE resource=$1 AND id=2",
            &[unrelated.into()],
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Fields>(&stored[0][0]).unwrap(),
        fields
    );
    if !sqlite {
        // Generic prepared plans must still be able to use the scoped index.
        let storage = e.tx.storage_resource(&renamed, 1).await.unwrap();
        let expression = e.tx.parent_expression("parent_thread").unwrap();
        e.tx.execute("SET LOCAL plan_cache_mode=force_generic_plan", &[])
            .await
            .unwrap();
        e.tx.execute("SET LOCAL enable_seqscan=off", &[])
            .await
            .unwrap();
        e.tx.execute(&format!("PREPARE parent_index_scope(bigint,text,bigint) AS SELECT id FROM nx_records WHERE resource=$1 AND resource={storage} AND {expression}=$2 AND id<$3 ORDER BY id DESC LIMIT 3"), &[]).await.unwrap();
        let plan =
            e.tx.fetch::<1>(
                &format!("EXPLAIN EXECUTE parent_index_scope({storage},'10',9223372036854775807)"),
                &[],
            )
            .await
            .unwrap();
        assert!(
            plan.iter()
                .any(|line| line[0].contains(&format!("nx_parent_{storage}"))),
            "{plan:?}"
        );
        e.tx.execute("DEALLOCATE parent_index_scope", &[])
            .await
            .unwrap();
    }
    e.tx.rollback().await.unwrap();
}
