use crate::auth::{self, AccountAdmin as _};
use crate::operator_roles::*;
use noxide_admission::policy;
use noxide_protocol::{Policy, Predicate};
use noxide_store::Database;
use std::sync::Arc;
use std::time::{Duration, Instant};

async fn test_account(db: &Database, login: &str) -> String {
    db.account_id(login)
        .await
        .unwrap_or_else(|_| "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into())
}

async fn seed(db: &Database, count: usize) {
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    for n in 0..count {
        tx.execute(
            "INSERT INTO nx_roles(principal,name,tenant) VALUES((SELECT id FROM nx_accounts WHERE login_name='alice'),$1,'')",
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
    assert!(
        db.list_roles(&test_account(db, "alice").await)
            .await
            .unwrap()
            .is_empty()
    );
    for scope in [RoleScope::Global, RoleScope::Tenant("one")] {
        assert!(
            db.grant_role(&test_account(db, "alice").await, "moderator", scope)
                .await
                .unwrap()
        );
        assert!(
            !db.grant_role(&test_account(db, "alice").await, "moderator", scope)
                .await
                .unwrap()
        );
    }
    // A global assignment alone cannot satisfy a tenant-scoped predicate.
    let global_only = auth::Principal::User(auth::User {
        id: test_account(db, "alice").await,
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
            policy::allowed(
                &policy,
                &global_only,
                policy::Row {
                    owner: "alice",
                    tenant: "one",
                    fields: &Default::default()
                }
            ),
            !tenant_scoped
        );
    }
    let roles = db
        .list_roles(&test_account(db, "alice").await)
        .await
        .unwrap();
    assert_eq!(roles.len(), 2);
    assert_eq!(roles[0].tenant, "");
    assert_eq!(roles[1].tenant, "one");
    for (scope, tenant_scoped) in [(RoleScope::Global, false), (RoleScope::Tenant("one"), true)] {
        assert!(
            db.revoke_role(&test_account(db, "alice").await, "moderator", scope)
                .await
                .unwrap()
        );
        assert!(
            !db.revoke_role(&test_account(db, "alice").await, "moderator", scope)
                .await
                .unwrap()
        );
        let roles = db
            .list_roles(&test_account(db, "alice").await)
            .await
            .unwrap();
        let principal = auth::Principal::User(auth::User {
            id: test_account(db, "alice").await,
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
            policy::Row {
                owner: "alice",
                tenant: "one",
                fields: &Default::default()
            }
        ));
        if !tenant_scoped {
            assert!(policy::allowed(
                &p(true),
                &principal,
                policy::Row {
                    owner: "alice",
                    tenant: "one",
                    fields: &Default::default()
                }
            ));
            assert!(!policy::allowed(
                &p(true),
                &principal,
                policy::Row {
                    owner: "alice",
                    tenant: "two",
                    fields: &Default::default()
                }
            ));
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
        assert!(
            db.grant_role(&test_account(db, "alice").await, "moderator", scope)
                .await
                .is_err()
        );
    }
    assert!(
        db.grant_role(
            &test_account(db, "alice").await,
            "bad-role",
            RoleScope::Global
        )
        .await
        .is_err()
    );
    assert!(
        db.grant_role(
            &test_account(db, "alice").await,
            "moderator",
            RoleScope::Tenant("one")
        )
        .await
        .unwrap()
    );
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.execute("UPDATE nx_accounts SET tenant='two' WHERE id=(SELECT id FROM nx_accounts WHERE login_name='alice')", &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        db.revoke_role(
            &test_account(db, "alice").await,
            "moderator",
            RoleScope::Tenant("one")
        )
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
            db.grant_role(&test_account(&db, "alice").await, name, RoleScope::Global)
                .await
        }
    };
    let (a, b) = tokio::join!(attempt("nexta"), attempt("nextb"));
    assert!(a.is_ok() || b.is_ok());
    assert!(!(a.is_ok() && b.is_ok()));
    assert_eq!(
        db.list_roles(&test_account(db, "alice").await)
            .await
            .unwrap()
            .len(),
        32
    );
    assert!(
        !db.grant_role(&test_account(db, "alice").await, "role0", RoleScope::Global)
            .await
            .unwrap()
    );
    assert!(
        db.grant_role(
            &test_account(db, "alice").await,
            "overflow",
            RoleScope::Global
        )
        .await
        .is_err()
    );
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.execute(
        "INSERT INTO nx_roles(principal,name,tenant) VALUES((SELECT id FROM nx_accounts WHERE login_name='alice'),'manual','')",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(
        db.list_roles(&test_account(db, "alice").await)
            .await
            .is_err()
    );
    assert!(
        !db.grant_role(&test_account(db, "alice").await, "role0", RoleScope::Global)
            .await
            .unwrap()
    );
    assert!(
        db.grant_role(
            &test_account(db, "alice").await,
            "overflow",
            RoleScope::Global
        )
        .await
        .is_err()
    );
    assert!(
        db.revoke_role(
            &test_account(db, "alice").await,
            "manual",
            RoleScope::Global
        )
        .await
        .unwrap()
    );
    assert_eq!(
        db.list_roles(&test_account(db, "alice").await)
            .await
            .unwrap()
            .len(),
        32
    );
}

#[tokio::test]
async fn sqlite_roles() {
    let temp = tempfile::tempdir().unwrap();
    basics(&Database::sqlite(temp.path().join("roles.db"))).await;
}
#[tokio::test]
async fn missing_storage_is_not_initialized() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("missing.db"));
    assert!(
        db.list_roles(&test_account(&db, "alice").await)
            .await
            .is_err()
    );
    assert!(
        db.grant_role(
            &test_account(&db, "alice").await,
            "moderator",
            RoleScope::Global
        )
        .await
        .is_err()
    );
    assert!(
        db.revoke_role(
            &test_account(&db, "alice").await,
            "moderator",
            RoleScope::Global
        )
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
        "INSERT INTO nx_roles(principal,name,tenant) VALUES((SELECT id FROM nx_accounts WHERE login_name='alice'),'pending','')",
        &[],
    )
    .await
    .unwrap();
    assert!(
        db.grant_role(
            &test_account(&db, "alice").await,
            "other",
            RoleScope::Global
        )
        .await
        .is_err()
    );
    held.rollback().await.unwrap();
    assert!(
        db.list_roles(&test_account(&db, "alice").await)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on disposable cluster"]
async fn postgres_roles() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for kind in ["roles", "predicate"] {
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
            _ => predicate_race(&db).await,
        }
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}
use crate::operator_roles::READ_BARRIER;
async fn predicate_race(db: &Database) {
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "")
        .await
        .unwrap();
    seed(db, 31).await;
    // PostgreSQL only: both real grant transactions have read the 31-row
    // predicate before either insert. SQLite synchronizes before admission above.
    let gate = Arc::new(tokio::sync::Barrier::new(2));
    let alice = test_account(db, "alice").await;
    let (a, b) = tokio::join!(
        READ_BARRIER.scope(
            gate.clone(),
            db.grant_role(&alice, "racea", RoleScope::Global)
        ),
        READ_BARRIER.scope(gate, db.grant_role(&alice, "raceb", RoleScope::Global)),
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(
        db.list_roles(&test_account(db, "alice").await)
            .await
            .unwrap()
            .len(),
        32
    );
}

#[tokio::test]
async fn lost_commit_ack_is_reported_and_reconciled() {
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("ack.db"));
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "")
        .await
        .unwrap();
    let result = noxide_store::database::fault::lose_commit_ack(db.grant_role(
        &test_account(&db, "alice").await,
        "moderator",
        RoleScope::Global,
    ))
    .await;
    assert!(result.unwrap_err().to_string().contains("indeterminate"));
    assert_eq!(
        db.list_roles(&test_account(&db, "alice").await)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        !db.grant_role(
            &test_account(&db, "alice").await,
            "moderator",
            RoleScope::Global
        )
        .await
        .unwrap()
    );
    let result = noxide_store::database::fault::lose_commit_ack(db.revoke_role(
        &test_account(&db, "alice").await,
        "moderator",
        RoleScope::Global,
    ))
    .await;
    assert!(result.unwrap_err().to_string().contains("indeterminate"));
    assert!(
        db.list_roles(&test_account(&db, "alice").await)
            .await
            .unwrap()
            .is_empty()
    );
}
