use super::*;
use crate::{Application, HostKeys, auth, policy, runtime::Limits, test_support as fixture};
use noxide_protocol::{Fields, Policy, Predicate};
use std::sync::Arc;

async fn seed(db: &Database, count: usize) {
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    for n in 0..count {
        tx.execute(
            "INSERT INTO nx_roles(principal,name,tenant) VALUES('alice',$1,'')",
            &[format!("role{n}").into()],
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}
async fn basics(db: &Database) {
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "one")
        .await
        .unwrap();
    assert!(db.list_roles("alice").await.unwrap().is_empty());
    for scope in [RoleScope::Global, RoleScope::Tenant("one")] {
        assert!(db.grant_role("alice", "moderator", scope).await.unwrap());
        assert!(!db.grant_role("alice", "moderator", scope).await.unwrap());
    }
    // A global assignment alone cannot satisfy a tenant-scoped predicate.
    let global_only = auth::Principal::User(auth::User {
        id: "alice".into(),
        tenant: "one".into(),
        roles: vec![("moderator".into(), "".into())],
    });
    for tenant_scoped in [false, true] {
        let policy = Policy {
            any: vec![vec![Predicate::Role {
                name: "moderator".into(),
                tenant_scoped,
            }]],
        };
        assert_eq!(
            policy::allowed(&policy, &global_only, "alice", "one"),
            !tenant_scoped
        );
    }
    let roles = db.list_roles("alice").await.unwrap();
    assert_eq!(roles.len(), 2);
    assert_eq!(roles[0].tenant, "");
    assert_eq!(roles[1].tenant, "one");
    for (scope, tenant_scoped) in [(RoleScope::Global, false), (RoleScope::Tenant("one"), true)] {
        assert!(db.revoke_role("alice", "moderator", scope).await.unwrap());
        assert!(!db.revoke_role("alice", "moderator", scope).await.unwrap());
        let roles = db.list_roles("alice").await.unwrap();
        let principal = auth::Principal::User(auth::User {
            id: "alice".into(),
            tenant: "one".into(),
            roles: roles.into_iter().map(|r| (r.name, r.tenant)).collect(),
        });
        let p = |scoped| Policy {
            any: vec![vec![Predicate::Role {
                name: "moderator".into(),
                tenant_scoped: scoped,
            }]],
        };
        assert!(!policy::allowed(
            &p(tenant_scoped),
            &principal,
            "alice",
            "one"
        ));
        if !tenant_scoped {
            assert!(policy::allowed(&p(true), &principal, "alice", "one"));
            assert!(!policy::allowed(&p(true), &principal, "alice", "two"));
        }
    }
    for user in ["missing", "bad-user", ""] {
        assert!(
            db.grant_role(user, "moderator", RoleScope::Global)
                .await
                .is_err()
        );
        assert!(
            db.revoke_role(user, "moderator", RoleScope::Global)
                .await
                .is_err()
        );
        assert!(db.list_roles(user).await.is_err());
    }
    for scope in [
        RoleScope::Tenant("two"),
        RoleScope::Tenant(""),
        RoleScope::Tenant("bad-tenant"),
    ] {
        assert!(db.grant_role("alice", "moderator", scope).await.is_err());
    }
    assert!(
        db.grant_role("alice", "bad-role", RoleScope::Global)
            .await
            .is_err()
    );
    assert!(
        db.grant_role("alice", "moderator", RoleScope::Tenant("one"))
            .await
            .unwrap()
    );
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.execute("UPDATE nx_accounts SET tenant='two' WHERE id='alice'", &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        db.revoke_role("alice", "moderator", RoleScope::Tenant("one"))
            .await
            .unwrap()
    );
    seed(db, 31).await;
    let gate = Arc::new(tokio::sync::Barrier::new(2));
    let attempt = |name: &'static str| {
        let db = db.clone();
        let gate = gate.clone();
        async move {
            gate.wait().await;
            db.grant_role("alice", name, RoleScope::Global).await
        }
    };
    let (a, b) = tokio::join!(attempt("nexta"), attempt("nextb"));
    assert!(a.is_ok() || b.is_ok());
    assert!(!(a.is_ok() && b.is_ok()));
    assert_eq!(db.list_roles("alice").await.unwrap().len(), 32);
    assert!(
        !db.grant_role("alice", "role0", RoleScope::Global)
            .await
            .unwrap()
    );
    assert!(
        db.grant_role("alice", "overflow", RoleScope::Global)
            .await
            .is_err()
    );
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.execute(
        "INSERT INTO nx_roles(principal,name,tenant) VALUES('alice','manual','')",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(db.list_roles("alice").await.is_err());
    assert!(
        !db.grant_role("alice", "role0", RoleScope::Global)
            .await
            .unwrap()
    );
    assert!(
        db.grant_role("alice", "overflow", RoleScope::Global)
            .await
            .is_err()
    );
    assert!(
        db.revoke_role("alice", "manual", RoleScope::Global)
            .await
            .unwrap()
    );
    assert_eq!(db.list_roles("alice").await.unwrap().len(), 32);
}

async fn fresh_forms(db: &Database) {
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "")
        .await
        .unwrap();
    let mut m = fixture::manifest();
    m.operations[2].policy = Policy {
        any: vec![vec![Predicate::Role {
            name: "moderator".into(),
            tenant_scoped: false,
        }]],
    };
    let app = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&m).unwrap(),
        crate::manifest::digest(&m).unwrap(),
        db.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
    )
    .unwrap();
    app.activate().await.unwrap();
    let c = app.login_challenge().await.unwrap();
    let cookie = app
        .login(&c.cookie, &c.csrf, "alice", "private test password")
        .await
        .unwrap();
    let page = String::from_utf8(app.view(&cookie, 1, None).await.unwrap().body).unwrap();
    assert!(!page.contains("name=\"_submission\""));
    db.grant_role("alice", "moderator", RoleScope::Global)
        .await
        .unwrap();
    let form = || async {
        let page = String::from_utf8(app.view(&cookie, 1, None).await.unwrap().body).unwrap();
        (
            fixture::hidden(&page, "_submission"),
            fixture::hidden(&page, "_csrf"),
        )
    };
    let (used, csrf) = form().await;
    let input = Fields::from([("body".into(), "hello".into())]);
    app.submit(&cookie, 1, &used, &csrf, input.clone())
        .await
        .unwrap();
    let (unused, unused_csrf) = form().await;
    db.revoke_role("alice", "moderator", RoleScope::Global)
        .await
        .unwrap();
    assert!(
        app.submit(&cookie, 1, &unused, &unused_csrf, input.clone())
            .await
            .is_err()
    );
    app.submit(&cookie, 1, &used, &csrf, input).await.unwrap();
    let page = String::from_utf8(app.view(&cookie, 1, None).await.unwrap().body).unwrap();
    assert!(!page.contains("name=\"_submission\""));
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
            .await
            .unwrap()[0][0],
        "1"
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn sqlite_roles() {
    let temp = tempfile::tempdir().unwrap();
    basics(&Database::sqlite(temp.path().join("roles.db"))).await;
}
#[tokio::test]
async fn sqlite_fresh_forms() {
    let temp = tempfile::tempdir().unwrap();
    fresh_forms(&Database::sqlite(temp.path().join("forms.db"))).await;
}
#[tokio::test]
async fn missing_storage_is_not_initialized() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("missing.db"));
    assert!(db.list_roles("alice").await.is_err());
    assert!(
        db.grant_role("alice", "moderator", RoleScope::Global)
            .await
            .is_err()
    );
    assert!(
        db.revoke_role("alice", "moderator", RoleScope::Global)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn sqlite_contention_and_rollback() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("busy.db"));
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "")
        .await
        .unwrap();
    let mut held = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    held.execute(
        "INSERT INTO nx_roles(principal,name,tenant) VALUES('alice','pending','')",
        &[],
    )
    .await
    .unwrap();
    assert!(
        db.grant_role("alice", "other", RoleScope::Global)
            .await
            .is_err()
    );
    held.rollback().await.unwrap();
    assert!(db.list_roles("alice").await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on disposable cluster"]
async fn postgres_roles() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for kind in ["roles", "forms", "predicate"] {
        let name = format!(
            "nx_operator_{kind}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut case = url::Url::parse(&url).unwrap();
        case.set_path(&format!("/{name}"));
        let db = Database::postgres(case.as_str()).unwrap();
        match kind {
            "roles" => basics(&db).await,
            "forms" => fresh_forms(&db).await,
            _ => predicate_race(&db).await,
        }
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}
tokio::task_local! { static READ_BARRIER: Arc<tokio::sync::Barrier>; }
pub(super) async fn after_assignments() {
    if let Ok(gate) = READ_BARRIER.try_with(Clone::clone) {
        gate.wait().await;
    }
}
async fn predicate_race(db: &Database) {
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "")
        .await
        .unwrap();
    seed(db, 31).await;
    // PostgreSQL only: both real grant transactions have read the 31-row
    // predicate before either insert. SQLite synchronizes before admission above.
    let gate = Arc::new(tokio::sync::Barrier::new(2));
    let (a, b) = tokio::join!(
        READ_BARRIER.scope(
            gate.clone(),
            db.grant_role("alice", "racea", RoleScope::Global)
        ),
        READ_BARRIER.scope(gate, db.grant_role("alice", "raceb", RoleScope::Global)),
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(db.list_roles("alice").await.unwrap().len(), 32);
}

#[tokio::test]
async fn lost_commit_ack_is_reported_and_reconciled() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("ack.db"));
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "")
        .await
        .unwrap();
    let result = crate::failure_tests::lose_commit_ack(db.grant_role(
        "alice",
        "moderator",
        RoleScope::Global,
    ))
    .await;
    assert!(result.unwrap_err().to_string().contains("indeterminate"));
    assert_eq!(db.list_roles("alice").await.unwrap().len(), 1);
    assert!(
        !db.grant_role("alice", "moderator", RoleScope::Global)
            .await
            .unwrap()
    );
    let result = crate::failure_tests::lose_commit_ack(db.revoke_role(
        "alice",
        "moderator",
        RoleScope::Global,
    ))
    .await;
    assert!(result.unwrap_err().to_string().contains("indeterminate"));
    assert!(db.list_roles("alice").await.unwrap().is_empty());
}

#[tokio::test]
async fn ordinary_actions_cannot_write_moderator_fields_or_reuse_credential() {
    use noxide_protocol::*;
    for capability in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let db = Database::sqlite(temp.path().join("authority.db"));
        db.initialize().await.unwrap();
        db.create_account("alice", "private test password", "")
            .await
            .unwrap();
        let mut m = fixture::record_actions::declarations();
        m.resources[0].fields.push(TextField {
            name: "published".into(),
            label: "Published".into(),
            kind: FieldKind::Boolean,
            optional: false,
            initial: None,
            max_bytes: 5,
        });
        m.operations[0].visibility = Some(Visibility {
            field: "published".into(),
            equals: "true".into(),
        });
        m.operations[0].fields = Some(vec!["body".into(), "tag".into(), "published".into()]);
        m.routes[1].access = Access::PublicOptional;
        m.operations[0].policy = Policy {
            any: vec![vec![Predicate::Public]],
        };
        m.operations[1].policy = Policy {
            any: vec![vec![if capability {
                Predicate::Capability
            } else {
                Predicate::Owner
            }]],
        };
        m.operations[2].kind = OperationKind::Update;
        m.operations[2].policy = Policy {
            any: vec![vec![Predicate::Role {
                name: "moderator".into(),
                tenant_scoped: false,
            }]],
        };
        m.actions[0].inspect = None;
        m.actions[1].fields = vec!["tag".into()];
        m.actions[1].redirect = Redirect::Page(2);
        let keys = HostKeys::generate().unwrap();
        let secret = keys
            .edit_secret(keys.signing_edit_key().unwrap(), 1, 42, 1)
            .unwrap();
        let app = Application::new(
            &fixture::record_actions::component(""),
            &serde_json::to_vec(&m).unwrap(),
            crate::manifest::digest(&m).unwrap(),
            db.clone(),
            keys,
            Limits::default(),
        )
        .unwrap();
        app.activate().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        tx.allocate_creation().await.unwrap();
        let owner = if capability { "NULL" } else { "'alice'" };
        tx.execute(&format!("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES(1,42,{owner},'','{{\"body\":\"original\",\"tag\":\"moderator only\",\"published\":\"true\"}}','record',1,1,(SELECT value FROM nx_creation_counter WHERE singleton=1))"),&[]).await.unwrap();
        tx.commit().await.unwrap();
        db.grant_role("alice", "moderator", RoleScope::Global)
            .await
            .unwrap();
        let challenge = app.login_challenge().await.unwrap();
        let cookie = app
            .login(
                &challenge.cookie,
                &challenge.csrf,
                "alice",
                "private test password",
            )
            .await
            .unwrap();
        let page = String::from_utf8(app.view(&cookie, 2, Some(42)).await.unwrap().body).unwrap();
        let form = |action| {
            let html = page
                .split_once(&format!("action=\"/actions/{action}\""))
                .unwrap()
                .1;
            (
                fixture::hidden(html, "_submission"),
                fixture::hidden(html, "_csrf"),
            )
        };
        let (moderator, mod_csrf) = form(3);
        let (ordinary, csrf) = form(2);
        let forged = Fields::from([
            ("body".into(), "changed".into()),
            ("tag".into(), "forged moderation".into()),
        ]);
        assert!(
            app.submit_with_capability(
                &cookie,
                2,
                &ordinary,
                &csrf,
                forged,
                capability.then_some(secret.as_str())
            )
            .await
            .is_err()
        );
        db.revoke_role("alice", "moderator", RoleScope::Global)
            .await
            .unwrap();
        assert!(
            app.submit_with_capability(
                &cookie,
                2,
                &moderator,
                &mod_csrf,
                Fields::from([("body".into(), "changed".into())]),
                capability.then_some(secret.as_str())
            )
            .await
            .is_err()
        );
        let denied = app
            .submit_with_capability(
                &cookie,
                3,
                &moderator,
                &mod_csrf,
                Fields::from([("tag".into(), "forged moderation".into())]),
                capability.then_some(secret.as_str()),
            )
            .await;
        assert!(denied.is_err() || denied.unwrap().status >= 400);

        let mut tx = db
            .begin_read(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            tx.fetch::<1>("SELECT fields FROM nx_records WHERE id=42", &[])
                .await
                .unwrap()[0][0],
            "{\"body\":\"original\",\"tag\":\"moderator only\",\"published\":\"true\"}"
        );
        tx.commit().await.unwrap();
    }
}
