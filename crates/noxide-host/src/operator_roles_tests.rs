//! Role behaviour that needs a running application. Database-level role tests
//! live in noxide-authority.
use crate::Database;
use crate::auth::AccountAdmin as _;
use crate::operator_roles::*;
use crate::{Application, HostKeys, runtime::Limits, test_support as fixture};
use noxide_protocol::{Fields, Policy, Predicate};
use std::time::{Duration, Instant};

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
        crate::DeploymentResources {
            effects: None,
            jobs: None,
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
        },
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
    db.grant_role(
        &crate::test_account(db, "alice").await,
        "moderator",
        RoleScope::Global,
    )
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
    db.revoke_role(
        &crate::test_account(db, "alice").await,
        "moderator",
        RoleScope::Global,
    )
    .await
    .unwrap();
    assert_eq!(
        app.submit(&cookie, 1, &unused, &unused_csrf, input.clone())
            .await
            .unwrap()
            .status,
        404
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
async fn sqlite_fresh_forms() {
    let temp = tempfile::tempdir().unwrap();
    fresh_forms(&Database::sqlite(temp.path().join("forms.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on disposable cluster"]
async fn postgres_fresh_forms() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_operator_forms_{}",
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
    fresh_forms(&Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
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
            immutable: false,
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
        m.actions[0].targets[0].inspect = None;
        m.actions[1].inputs = vec![Input {
            name: "tag".into(),
            label: "Tag".into(),
            kind: FieldKind::Text,
            optional: false,
            max_bytes: 128,
        }];
        m.actions[1].steps[0].assign = vec![Assignment {
            field: "tag".into(),
            change: Change::Set(Value::Input("tag".into())),
        }];
        m.web_bindings[1].redirect = Redirect {
            route: 2,
            source: RedirectSource::Target("target".into()),
        };
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
            crate::DeploymentResources {
                effects: None,
                jobs: None,
                assets: crate::assets::AssetBundle::default(),
                blobs: None,
            },
        )
        .unwrap();
        app.activate().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        tx.allocate_creation().await.unwrap();
        let owner = if capability {
            "NULL"
        } else {
            "(SELECT id FROM nx_accounts WHERE login_name='alice')"
        };
        tx.execute(&format!("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES(1,42,{owner},'','{{\"body\":\"original\",\"tag\":\"moderator only\",\"published\":\"true\"}}','record',1,1,(SELECT value FROM nx_creation_counter WHERE singleton=1))"),&[]).await.unwrap();
        tx.commit().await.unwrap();
        db.grant_role(
            &crate::test_account(&db, "alice").await,
            "moderator",
            RoleScope::Global,
        )
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
        db.revoke_role(
            &crate::test_account(&db, "alice").await,
            "moderator",
            RoleScope::Global,
        )
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
