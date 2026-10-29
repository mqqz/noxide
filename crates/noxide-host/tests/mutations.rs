#[allow(dead_code)]
mod support;

use noxide_host::{Application, Database, HostKeys, manifest, runtime::Limits};
use noxide_protocol::{Fields, Manifest, RequestKind, RequestView};
use sqlx::{Connection, Row};
use std::sync::Arc;

use support::record_actions::{component, declarations};

async fn application(db: &Database, keys: &[u8], mode: &str) -> Arc<Application> {
    application_with(db, keys, mode, declarations()).await
}

async fn application_with(db: &Database, keys: &[u8], mode: &str, m: Manifest) -> Arc<Application> {
    let app = Arc::new(
        Application::new(
            &component(mode),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db.clone(),
            serde_json::from_slice(keys).unwrap(),
            Limits::default(),
        )
        .unwrap(),
    );
    app.activate().await.unwrap();
    app
}

async fn login(app: &Application, user: &str) -> String {
    let c = app.login_challenge().await.unwrap();
    app.login(&c.cookie, &c.csrf, user, "twelve word password")
        .await
        .unwrap()
}

async fn form(app: &Application, cookie: &str, action: u32) -> (String, String) {
    let html = String::from_utf8(app.view(cookie, 2, Some(42)).await.unwrap().body).unwrap();
    let part = html
        .split_once(&format!("action=\"/actions/{action}\""))
        .unwrap()
        .1;
    (
        support::hidden(part, "_submission"),
        support::hidden(part, "_csrf"),
    )
}

enum InspectDb {
    Sqlite(sqlx::SqliteConnection),
    Postgres(sqlx::PgConnection),
}
impl InspectDb {
    async fn execute(&mut self, sql: &str) {
        match self {
            Self::Sqlite(c) => {
                sqlx::query(sql).execute(c).await.unwrap();
            }
            Self::Postgres(c) => {
                sqlx::query(sql).execute(c).await.unwrap();
            }
        }
    }
    async fn state(&mut self) -> (i64, String, i64) {
        let sql = "SELECT (SELECT COUNT(*) FROM nx_receipts) AS receipts, fields, revision FROM nx_records WHERE id=42";
        match self {
            Self::Sqlite(c) => {
                let row = sqlx::query(sql).fetch_one(c).await.unwrap();
                (row.get("receipts"), row.get("fields"), row.get("revision"))
            }
            Self::Postgres(c) => {
                let row = sqlx::query(sql).fetch_one(c).await.unwrap();
                (row.get("receipts"), row.get("fields"), row.get("revision"))
            }
        }
    }
}

async fn conformance(db: Database, mut inspect: InspectDb) {
    manifest::validate(&declarations()).unwrap();
    db.initialize().await.unwrap();
    for name in ["alice", "bob"] {
        db.create_account(name, "twelve word password", "one")
            .await
            .unwrap();
    }
    let keys = serde_json::to_vec(&HostKeys::generate().unwrap()).unwrap();
    let app = application(&db, &keys, "ok").await;
    inspect
        .execute("INSERT INTO nx_roles(principal,name,tenant) VALUES('alice','writer','')")
        .await;
    inspect.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision) VALUES(1,42,'alice','one','{\"body\":\"original\",\"tag\":\"private tag\"}','first-incarnation',1),(1,43,'alice','one','{\"body\":\"other\",\"tag\":\"other tag\"}','other-incarnation',1)").await;
    let alice = login(&app, "alice").await;
    let bob = login(&app, "bob").await;
    let page = String::from_utf8(app.view(&alice, 2, Some(42)).await.unwrap().body).unwrap();
    assert!(page.contains("required>\noriginal</textarea>"));
    assert!(!page.contains("private tag"));
    let bob_page = String::from_utf8(app.view(&bob, 2, Some(42)).await.unwrap().body).unwrap();
    assert!(!bob_page.contains("_submission"));
    let (token, csrf) = form(&app, &alice, 2).await;
    let (stale, _) = form(&app, &alice, 2).await;
    let (old_delete, _) = form(&app, &alice, 3).await;
    let fields = Fields::from([("body".into(), "first edit".into())]);
    assert!(
        app.submit(&bob, 2, &token, &csrf, fields.clone())
            .await
            .is_err()
    );
    assert!(
        app.submit(&alice, 3, &token, &csrf, Fields::new())
            .await
            .is_err()
    );
    let before = inspect.state().await;
    for invalid in [
        Fields::new(),
        Fields::from([("body".into(), String::new())]),
        Fields::from([
            ("body".into(), "edit".into()),
            ("tag".into(), "ungranted field".into()),
        ]),
        Fields::from([
            ("body".into(), "edit".into()),
            ("owner".into(), "bob".into()),
        ]),
    ] {
        assert!(
            app.submit(&alice, 2, &token, &csrf, invalid).await.is_err(),
            "input must contain exactly the writable fields"
        );
    }
    assert!(
        app.submit(&alice, 3, &old_delete, &csrf, fields.clone())
            .await
            .is_err(),
        "delete accepts no application fields"
    );
    let mut corrupt = token.clone().into_bytes();
    corrupt[0] = if corrupt[0] == b'A' { b'B' } else { b'A' };
    assert!(
        app.submit(
            &alice,
            2,
            &String::from_utf8(corrupt).unwrap(),
            &csrf,
            fields.clone()
        )
        .await
        .is_err()
    );
    assert_eq!(inspect.state().await, before);
    let (one, two) = tokio::join!(
        app.submit(&alice, 2, &token, &csrf, fields.clone()),
        app.submit(&alice, 2, &token, &csrf, fields.clone())
    );
    assert_eq!(one.unwrap().location, two.unwrap().location);
    let (receipts, stored, revision) = inspect.state().await;
    assert_eq!((receipts, revision), (1, 2));
    let stored: Fields = serde_json::from_str(&stored).unwrap();
    assert_eq!(stored["body"], "first edit");
    assert_eq!(stored["tag"], "private tag");
    assert!(
        app.submit(
            &alice,
            2,
            &token,
            &csrf,
            Fields::from([("body".into(), "different committed input".into())])
        )
        .await
        .is_err(),
        "a committed receipt does not authorize different input"
    );
    let unsaved = Fields::from([("body".into(), "\nunsaved <script>".into())]);
    let conflict = app
        .submit(&alice, 2, &stale, &csrf, unsaved.clone())
        .await
        .unwrap();
    assert_eq!(conflict.status, 409);
    let html = String::from_utf8(conflict.body).unwrap();
    assert!(html.contains("first edit") && html.contains("unsaved &lt;script&gt;"));
    let next = support::hidden(&html, "_submission");
    assert_ne!(next, stale);
    assert_eq!(
        app.submit(&alice, 3, &old_delete, &csrf, Fields::new())
            .await
            .unwrap()
            .status,
        409
    );
    assert_eq!(inspect.state().await.2, 2);
    assert_eq!(
        app.submit(&alice, 2, &next, &csrf, unsaved.clone())
            .await
            .unwrap()
            .status,
        303
    );
    inspect
        .execute("DELETE FROM nx_roles WHERE principal='alice'")
        .await;
    assert_eq!(
        app.submit(&alice, 2, &next, &csrf, unsaved)
            .await
            .unwrap()
            .status,
        303
    );
    let denied = app
        .submit(&alice, 2, &stale, &csrf, fields.clone())
        .await
        .unwrap();
    assert_eq!(denied.status, 404);
    assert!(
        !String::from_utf8(denied.body)
            .unwrap()
            .contains("first edit")
    );
    inspect
        .execute("INSERT INTO nx_roles(principal,name,tenant) VALUES('alice','writer','')")
        .await;
    // Two independent forms share a revision, but have different receipt IDs.
    let (left, csrf) = form(&app, &alice, 2).await;
    let (right, _) = form(&app, &alice, 2).await;
    assert_ne!(left, right);
    let before = inspect.state().await;
    let (left, right) = tokio::join!(
        app.submit(
            &alice,
            2,
            &left,
            &csrf,
            Fields::from([("body".into(), "left contender".into())])
        ),
        app.submit(
            &alice,
            2,
            &right,
            &csrf,
            Fields::from([("body".into(), "right contender".into())])
        )
    );
    let mut statuses = [left.unwrap().status, right.unwrap().status];
    statuses.sort();
    assert_eq!(statuses, [303, 409]);
    let after = inspect.state().await;
    assert_eq!((after.0, after.2), (before.0 + 1, before.2 + 1));
    let stored: Fields = serde_json::from_str(&after.1).unwrap();
    assert!(matches!(
        stored["body"].as_str(),
        "left contender" | "right contender"
    ));
    assert_eq!(stored["tag"], "private tag");

    // A stale submission must not even enter guest code, including a guest
    // which would trap after its effect if it were allowed to execute.
    let trapping = application(&db, &keys, "trap").await;
    let (stale_edit, csrf) = form(&trapping, &alice, 2).await;
    let (stale_delete, _) = form(&trapping, &alice, 3).await;
    inspect
        .execute("UPDATE nx_records SET revision=revision+1 WHERE id=42")
        .await;
    let before = inspect.state().await;
    for (action, token, input) in [
        (2, stale_edit, fields.clone()),
        (3, stale_delete, Fields::new()),
    ] {
        assert_eq!(
            trapping
                .submit(&alice, action, &token, &csrf, input)
                .await
                .unwrap()
                .status,
            409
        );
        assert_eq!(inspect.state().await, before);
    }
    for mode in [
        "trap",
        "invalid",
        "loop",
        "twice",
        "target",
        "read",
        "bad_reject",
        "reject",
    ] {
        let app = application(&db, &keys, mode).await;
        for (action, input) in [(2, fields.clone()), (3, Fields::new())] {
            let (token, csrf) = form(&app, &alice, action).await;
            let before = inspect.state().await;
            let result = app.submit(&alice, action, &token, &csrf, input).await;
            if mode == "reject" {
                let response = result.unwrap();
                assert_eq!(response.status, 422);
                let html = String::from_utf8(response.body).unwrap();
                assert!(html.contains("Application rule &lt;script&gt;"));
                assert_eq!(support::hidden(&html, "_submission"), token);
            } else {
                assert!(result.is_err(), "{mode} action {action}");
            }
            assert_eq!(
                inspect.state().await,
                before,
                "{mode} action {action} changed state"
            );
        }
    }
    snapshots(&db, &keys, &alice, &mut inspect).await;
    corrected_rejection(&db, &keys, &alice, &mut inspect).await;
    inspection_revocation(&db, &keys, &alice, &mut inspect).await;
    let app = application(&db, &keys, "ok").await;
    let (deleted, csrf) = form(&app, &alice, 3).await;
    let (other_delete, _) = form(&app, &alice, 3).await;
    let result = app
        .submit(&alice, 3, &deleted, &csrf, Fields::new())
        .await
        .unwrap();
    assert_eq!(result.location.as_deref(), Some("/"));
    inspect
        .execute("DELETE FROM nx_roles WHERE principal='alice' AND name='writer'")
        .await;
    assert_eq!(
        app.submit(&alice, 3, &deleted, &csrf, Fields::new())
            .await
            .unwrap()
            .status,
        303
    );
    inspect
        .execute("INSERT INTO nx_roles(principal,name,tenant) VALUES('alice','writer','')")
        .await;
    assert_eq!(
        app.submit(&alice, 3, &other_delete, &csrf, Fields::new())
            .await
            .unwrap()
            .status,
        404
    );
    inspect.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision) VALUES(1,42,'alice','one','{\"body\":\"replacement secret\",\"tag\":\"replacement\"}','second-incarnation',3)").await;
    let result = app
        .submit(&alice, 3, &other_delete, &csrf, Fields::new())
        .await
        .unwrap();
    assert_eq!(result.status, 404);
    assert!(
        !String::from_utf8(result.body)
            .unwrap()
            .contains("replacement secret")
    );
    assert!(inspect.state().await.1.contains("replacement secret"));
}

fn echoed_request(body: Vec<u8>) -> RequestView {
    let html = String::from_utf8(body).unwrap();
    let text = html
        .split_once("<p class=\"application-error\">")
        .unwrap()
        .1
        .split_once("</p>")
        .unwrap()
        .0;
    let json = text
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    serde_json::from_str(&json).unwrap()
}

async fn snapshots(db: &Database, keys: &[u8], alice: &str, inspect: &mut InspectDb) {
    for mode in ["snapshot", "snapshot_after"] {
        for projection in [false, true] {
            let mut m = declarations();
            if !projection {
                m.actions[0].inspect = None;
            }
            let app = application_with(db, keys, mode, m).await;
            for action in [2, 3] {
                let (token, csrf) = form(&app, alice, action).await;
                let before = inspect.state().await;
                let stored: Fields = serde_json::from_str(&before.1).unwrap();
                let input = if action == 2 {
                    Fields::from([("body".into(), "staged replacement".into())])
                } else {
                    Fields::new()
                };
                let response = app
                    .submit(alice, action, &token, &csrf, input.clone())
                    .await
                    .unwrap();
                assert_eq!(response.status, 422);
                let seen = echoed_request(response.body);
                assert_eq!(seen.kind, RequestKind::Action(action));
                assert_eq!(seen.target, Some(42));
                assert_eq!(seen.input, input);
                assert_eq!(
                    seen.inspection,
                    (projection && action == 2)
                        .then(|| Fields::from([("body".into(), stored["body"].clone())])),
                    "{mode}: only the original body projection may enter the guest"
                );
                assert_eq!(inspect.state().await, before);
            }
        }
    }
}

async fn corrected_rejection(db: &Database, keys: &[u8], alice: &str, inspect: &mut InspectDb) {
    let app = application(db, keys, "correctable").await;
    let (token, csrf) = form(&app, alice, 2).await;
    let (other, _) = form(&app, alice, 2).await;
    let before = inspect.state().await;
    let input = Fields::from([("body".into(), "needs correction".into())]);
    for token in [&token, &other] {
        let rejected = app
            .submit(alice, 2, token, &csrf, input.clone())
            .await
            .unwrap();
        assert_eq!(rejected.status, 422);
        let html = String::from_utf8(rejected.body).unwrap();
        assert!(html.contains("Correct this body &lt;script&gt;"));
        assert!(html.contains("aria-invalid=\"true\""));
        assert!(html.contains("needs correction</textarea>"));
        assert!(!html.contains(" readonly"));
        assert_eq!(support::hidden(&html, "_submission"), *token);
        assert_eq!(inspect.state().await, before);
    }
    let corrected = Fields::from([("body".into(), "corrected content".into())]);
    assert_eq!(
        app.submit(alice, 2, &token, &csrf, corrected.clone())
            .await
            .unwrap()
            .status,
        303,
        "a rejected submission leaves its token available for corrected input"
    );
    let after = inspect.state().await;
    assert_eq!((after.0, after.2), (before.0 + 1, before.2 + 1));
    let stored: Fields = serde_json::from_str(&after.1).unwrap();
    assert_eq!(stored["body"], "corrected content");
    assert_eq!(stored["tag"], "private tag");
    assert_eq!(
        app.submit(alice, 2, &other, &csrf, corrected)
            .await
            .unwrap()
            .status,
        409,
        "rejection must not upgrade the other form's original revision"
    );
    assert_eq!(inspect.state().await, after);
}

async fn inspection_revocation(db: &Database, keys: &[u8], alice: &str, inspect: &mut InspectDb) {
    let mut m = declarations();
    m.operations[0].policy.any[0].push(noxide_protocol::Predicate::Role {
        name: "reader".into(),
        tenant_scoped: false,
    });
    inspect
        .execute("INSERT INTO nx_roles(principal,name,tenant) VALUES('alice','reader','')")
        .await;
    let app = application_with(db, keys, "ok", m).await;
    let (completed, csrf) = form(&app, alice, 2).await;
    let (stale, _) = form(&app, alice, 2).await;
    let input = Fields::from([("body".into(), "read permission before revocation".into())]);
    let outcome = app
        .submit(alice, 2, &completed, &csrf, input.clone())
        .await
        .unwrap();
    let (pending, _) = form(&app, alice, 2).await;
    inspect
        .execute("DELETE FROM nx_roles WHERE principal='alice' AND name='reader'")
        .await;
    let before = inspect.state().await;
    let replay = app
        .submit(alice, 2, &completed, &csrf, input.clone())
        .await
        .unwrap();
    assert_eq!(replay.status, 303);
    assert_eq!(replay.location, outcome.location);
    for token in [stale, pending] {
        let denied = app
            .submit(alice, 2, &token, &csrf, input.clone())
            .await
            .unwrap();
        assert_eq!(denied.status, 404);
        let html = String::from_utf8(denied.body).unwrap();
        assert!(!html.contains("read permission before revocation"));
        assert!(!html.contains("_submission"));
    }
    assert_eq!(inspect.state().await, before);
}

#[test]
fn declares_field_scoped_record_actions() {
    manifest::validate(&declarations()).unwrap();
}

#[test]
fn rejects_ambiguous_or_expanded_record_action_contracts() {
    let mut wrong_route = declarations();
    let mut other_resource = wrong_route.resources[0].clone();
    other_resource.id = 9;
    other_resource.name = "other_notes".into();
    wrong_route.resources.push(other_resource);
    wrong_route.routes[1].resource = Some(9);
    assert!(manifest::validate(&wrong_route).is_err());

    for fields in [vec!["owner"], vec!["body", "body"], Vec::new()] {
        let mut m = declarations();
        m.actions[0].inspect.as_mut().unwrap().fields =
            fields.into_iter().map(str::to_owned).collect();
        assert!(
            manifest::validate(&m).is_err(),
            "invalid inspection projection"
        );
    }
    let mut non_read = declarations();
    non_read.actions[0].inspect.as_mut().unwrap().operation = 5;
    assert!(manifest::validate(&non_read).is_err());

    let mut wrong_resource = declarations();
    let mut other_resource = wrong_resource.resources[0].clone();
    other_resource.id = 9;
    other_resource.name = "other_notes".into();
    wrong_resource.resources.push(other_resource);
    let mut other_read = wrong_resource.operations[0].clone();
    other_read.id = 9;
    other_read.resource = 9;
    wrong_resource.operations.push(other_read);
    wrong_resource.actions[0]
        .inspect
        .as_mut()
        .unwrap()
        .operation = 9;
    assert!(manifest::validate(&wrong_resource).is_err());

    for fields in [vec!["owner"], vec!["body", "body"], Vec::new()] {
        let mut m = declarations();
        m.actions[0].fields = fields.into_iter().map(str::to_owned).collect();
        assert!(
            manifest::validate(&m).is_err(),
            "invalid writable projection"
        );
    }
    let mut delete_fields = declarations();
    delete_fields.actions[1].fields.push("body".into());
    assert!(manifest::validate(&delete_fields).is_err());
}

#[tokio::test]
async fn sqlite_record_actions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.db");
    let db = Database::sqlite(&path);
    // initialize creates a private file before the independent inspection connection.
    db.initialize().await.unwrap();
    let connection = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
    )
    .await
    .unwrap();
    conformance(db, InspectDb::Sqlite(connection)).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable test cluster"]
async fn postgres_record_actions() {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "noxide_mutations_{}",
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
    let connection = sqlx::PgConnection::connect(case.as_str()).await.unwrap();
    conformance(
        Database::postgres(case.as_str()).unwrap(),
        InspectDb::Postgres(connection),
    )
    .await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
