//! Test-only fault points wrap actual provider effects and COMMITs. They are
//! absent from production artifacts and cannot be selected by an application.
use crate::{
    Application, Database, HostKeys, RequestError, database::Transaction, manifest,
    runtime::Limits, test_support as fixture,
};
use noxide_protocol::Fields;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use crate::test_support::record_actions;

#[derive(Debug)]
pub(crate) struct Aborted;
impl std::fmt::Display for Aborted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("injected known-aborted conflict")
    }
}
impl std::error::Error for Aborted {}

#[derive(Clone, Copy, PartialEq)]
enum Point {
    Effect,
    Commit,
}
#[derive(Clone, Copy)]
enum Mode {
    Abort,
    LoseAck,
    Pause,
    Wait,
}
struct Plan {
    point: Point,
    mode: Mode,
    remaining: AtomicUsize,
    hits: AtomicUsize,
    marker: Option<std::path::PathBuf>,
    resume: tokio::sync::Notify,
}
tokio::task_local! {static FAULT:Arc<Plan>;}
fn plan(point: Point, mode: Mode, remaining: usize) -> Arc<Plan> {
    Arc::new(Plan {
        point,
        mode,
        remaining: AtomicUsize::new(remaining),
        hits: AtomicUsize::new(0),
        marker: None,
        resume: tokio::sync::Notify::new(),
    })
}
fn hit(point: Point) -> Option<Arc<Plan>> {
    FAULT
        .try_with(|plan| {
            if plan.point != point {
                return None;
            }
            plan.hits.fetch_add(1, Ordering::SeqCst);
            plan.remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .ok()
                .map(|_| plan.clone())
        })
        .ok()
        .flatten()
}
async fn pause(plan: &Plan) {
    if let Some(path) = &plan.marker {
        std::fs::write(path, b"at fault boundary").unwrap();
    }
    std::future::pending::<()>().await;
}
pub(crate) async fn after_effect(tx: &mut Transaction) -> anyhow::Result<()> {
    if let Some(plan) = hit(Point::Effect) {
        match plan.mode {
            Mode::Abort => {
                tx.rollback().await?;
                return Err(Aborted.into());
            }
            Mode::Pause => pause(&plan).await,
            Mode::Wait => plan.resume.notified().await,
            Mode::LoseAck => unreachable!(),
        }
    }
    Ok(())
}
pub(crate) async fn lose_commit_ack<T>(future: impl std::future::Future<Output = T>) -> T {
    FAULT
        .scope(plan(Point::Commit, Mode::LoseAck, 1), future)
        .await
}

pub(crate) async fn after_commit() -> anyhow::Result<()> {
    if let Some(plan) = hit(Point::Commit) {
        match plan.mode {
            Mode::LoseAck => anyhow::bail!("commit acknowledgement lost"),
            Mode::Pause => pause(&plan).await,
            Mode::Wait => plan.resume.notified().await,
            Mode::Abort => unreachable!(),
        }
    }
    Ok(())
}

async fn application(db: Database, keys: HostKeys) -> Application {
    let m = fixture::manifest();
    let app = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&m).unwrap(),
        manifest::digest(&m).unwrap(),
        db,
        keys,
        Limits::default(),
    )
    .unwrap();
    app.activate().await.unwrap();
    app
}
async fn account(app: &Application) -> String {
    let c = app.login_challenge().await.unwrap();
    app.login(&c.cookie, &c.csrf, "alice", "private test password")
        .await
        .unwrap()
}
async fn form(app: &Application, session: &str) -> (String, String) {
    let page = String::from_utf8(app.view(session, 1, None).await.unwrap().body).unwrap();
    (
        fixture::hidden(&page, "_submission"),
        fixture::hidden(&page, "_csrf"),
    )
}
async fn counts(db: &Database) -> (u64, u64) {
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let rows=tx.fetch::<2>("SELECT CAST((SELECT COUNT(*) FROM nx_records) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts) AS TEXT)",&[]).await.unwrap();
    (rows[0][0].parse().unwrap(), rows[0][1].parse().unwrap())
}

async fn stored_bounds(db: &Database) {
    use crate::{auth::Principal, repository::Effects};
    use noxide_protocol::{Record, RequestKind, RequestView, TextField, VERSION};
    let mut m = fixture::manifest();
    m.resources[0].fields.push(TextField {
        kind: noxide_protocol::FieldKind::Text,
        optional: false,
        initial: None,
        name: "extra".into(),
        label: "Extra".into(),
        max_bytes: 4096,
    });
    m.actions[0].fields.push("extra".into());
    let fields = Fields::from([
        ("body".into(), "\\".repeat(4096)),
        ("extra".into(), "\"".repeat(4096)),
    ]);
    manifest::validate_fields(&m.resources[0], &fields).unwrap();
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.bind_schema(&m).await.unwrap();
    for id in [2_i64, 9, 10, 99, 100, 101] {
        tx.allocate_creation().await.unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES(1,$1,(SELECT id FROM nx_accounts WHERE login_name='alice'),'',$2,'fixture-incarnation',1,(SELECT value FROM nx_creation_counter WHERE singleton=1))",
            &[id.into(), serde_json::to_string(&fields).unwrap().into()],
        )
        .await
        .unwrap();
    }
    let mut effects = Effects {
        provenance: Default::default(),
        follow_sources: Vec::new(),
        invoked: Default::default(),
        list_bytes: 0,
        list_calls: crate::repository::MAX_LIST_DATABASE_CALLS,
        result_limit: noxide_protocol::MAX_RESULT_BYTES,
        truncated: false,
        see_all: Vec::new(),
        tx,
        plans: crate::query_plan::compile_all(&m).unwrap(),
        manifest: Arc::new(m),
        principal: Principal::User(crate::auth::User {
            id: crate::test_account(db, "alice").await,
            tenant: String::new(),
            roles: vec![],
        }),
        request: RequestView {
            params: Default::default(),
            available_forms: Vec::new(),
            version: VERSION,
            kind: RequestKind::Route(1),
            target: None,
            input: Fields::new(),
            inspection: None,
        },
        outcome: None,
        grant: None,
        capability_grant: None,
        record: None,
        calls: 50,
        cursor: None,
        more: None,
    };
    // Maximum escaped fields must fit the actual cross-boundary result budget.
    let bytes = effects.invoke(1, 0).await.unwrap();
    assert!(bytes.len() <= noxide_protocol::MAX_RESULT_BYTES);
    let records: Vec<Record> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        records.iter().map(|r| r.id).collect::<Vec<_>>(),
        [2, 9, 10],
        "records follow creation order independently of ID width"
    );
    assert!(records.iter().all(|r| r.fields == fields));
    assert_eq!(effects.more, Some(3));
    effects.cursor = effects.more.take();
    effects.next_request();
    let records: Vec<Record> =
        serde_json::from_slice(&effects.invoke(1, 0).await.unwrap()).unwrap();
    assert_eq!(
        records.iter().map(|r| r.id).collect::<Vec<_>>(),
        [99, 100, 101],
        "cursor continuation must neither skip nor repeat records"
    );
    assert!(
        effects.more.is_none(),
        "full last page must not link to an empty page"
    );
    effects.cursor = None;
    effects.request.kind = RequestKind::Action(1);
    assert!(
        effects.invoke(1, 0).await.is_err(),
        "an action cannot borrow unrelated read authority"
    );
    effects.request.kind = RequestKind::Route(2);
    effects.request.target = Some(101);
    assert!(
        effects.invoke(2, 3).await.is_err(),
        "a route grant cannot change target"
    );
    assert!(effects.invoke(3, 0).await.is_err(), "GET cannot mutate");
    effects.request.kind = RequestKind::Route(1);
    effects.request.target = None;
    for bad in [
        r#"{"body":"valid-looking","extra":"x","unknown":"secret"}"#.to_owned(),
        "x".repeat(20_001),
    ] {
        effects
            .tx
            .execute("UPDATE nx_records SET fields=$1 WHERE id=2", &[bad.into()])
            .await
            .unwrap();
        assert!(
            effects.invoke(1, 0).await.is_err(),
            "stored values must be validated before disclosure"
        );
        effects.request.kind = RequestKind::Route(2);
        effects.request.target = Some(2);
        assert!(effects.invoke(2, 2).await.is_err());
        effects.request.kind = RequestKind::Route(1);
        effects.request.target = None;
    }
    effects.tx.rollback().await.unwrap();
    assert_eq!(counts(db).await, (0, 0));
    // SQL work has its own deadline even when no guest computation is running.
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_millis(150))
        .await
        .unwrap();
    let query = match db {
        Database::Sqlite(_) => {
            "WITH RECURSIVE slow(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM slow WHERE n<100000000) SELECT CAST(SUM(n) AS TEXT) FROM slow"
        }
        Database::Postgres(_) => "SELECT CAST(pg_sleep(10) AS TEXT)",
    };
    let began = std::time::Instant::now();
    assert!(tx.fetch::<1>(query, &[]).await.is_err());
    let _ = tx.rollback().await;
    drop(tx);
    assert!(began.elapsed() < Duration::from_secs(2));
    assert_eq!(counts(db).await, (0, 0));
}

async fn revocation(db: &Database) {
    use noxide_protocol::{Policy, Predicate};
    let mut m = fixture::manifest();
    m.operations[2].policy = Policy {
        any: vec![vec![Predicate::Role {
            name: "writer".into(),
            tenant_scoped: false,
        }]],
    };
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "INSERT INTO nx_roles(principal,name,tenant) VALUES((SELECT id FROM nx_accounts WHERE login_name='alice'),'writer','')",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let app = Arc::new(
        Application::new(
            &fixture::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db.clone(),
            HostKeys::generate().unwrap(),
            Limits::default(),
        )
        .unwrap(),
    );
    app.activate().await.unwrap();
    let session = account(&app).await;
    let (submission, csrf) = form(&app, &session).await;
    let (later, _) = form(&app, &session).await;
    let input = Fields::from([("body".into(), "authorized before revocation".into())]);
    let gate = plan(Point::Effect, Mode::Wait, 1);
    let action = {
        let (app, session, submission, csrf, input, gate) = (
            app.clone(),
            session.clone(),
            submission.clone(),
            csrf.clone(),
            input.clone(),
            gate.clone(),
        );
        tokio::spawn(async move {
            FAULT
                .scope(gate, app.submit(&session, 1, &submission, &csrf, input))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while gate.hits.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let revoke = {
        let db = db.clone();
        tokio::spawn(async move {
            let mut tx = db
                .begin(std::time::Instant::now() + Duration::from_secs(2))
                .await
                .unwrap();
            tx.execute(
                "DELETE FROM nx_roles WHERE principal=(SELECT id FROM nx_accounts WHERE login_name='alice') AND name='writer'",
                &[],
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    gate.resume.notify_one();
    // An overlapping request can serialize before revocation on either provider.
    let first = action.await.unwrap().unwrap();
    revoke.await.unwrap();
    assert_eq!(counts(db).await, (1, 1));
    let read_only = app.view(&session, 1, None).await.unwrap();
    assert_eq!(read_only.status, 200);
    assert!(
        !String::from_utf8(read_only.body)
            .unwrap()
            .contains("_submission")
    );
    assert!(
        app.submit(&session, 1, &later, &csrf, input.clone())
            .await
            .is_err()
    );
    assert_eq!(
        app.submit(&session, 1, &submission, &csrf, input.clone())
            .await
            .unwrap()
            .location,
        first.location,
        "receipt recovery does not require the old mutation role"
    );
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute("UPDATE nx_accounts SET epoch=epoch+1 WHERE id=(SELECT id FROM nx_accounts WHERE login_name='alice')", &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        app.submit(&session, 1, &submission, &csrf, input).await,
        Err(RequestError::Authentication)
    ));
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    for table in ["nx_records", "nx_receipts", "nx_sessions"] {
        tx.execute(&format!("DELETE FROM {table}"), &[])
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
}

async fn faults(db: Database) {
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "")
        .await
        .unwrap();
    stored_bounds(&db).await;
    revocation(&db).await;
    let keys = HostKeys::generate().unwrap();
    let saved = serde_json::to_vec(&keys).unwrap();
    let app = application(db.clone(), keys).await;
    let session = account(&app).await;
    let input = Fields::from([("body".into(), "private content".into())]);
    let (submission, csrf) = form(&app, &session).await;
    let retry = plan(Point::Effect, Mode::Abort, 1);
    let response = FAULT
        .scope(
            retry.clone(),
            app.submit(&session, 1, &submission, &csrf, input.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        retry.hits.load(Ordering::SeqCst),
        2,
        "retry must re-execute with a fresh guest global"
    );
    assert_eq!(counts(&db).await, (1, 1));
    let (submission, csrf) = form(&app, &session).await;
    let repeated = plan(Point::Effect, Mode::Abort, 10);
    assert!(
        FAULT
            .scope(
                repeated.clone(),
                app.submit(&session, 1, &submission, &csrf, input.clone())
            )
            .await
            .is_err()
    );
    assert_eq!(repeated.hits.load(Ordering::SeqCst), 3);
    assert_eq!(counts(&db).await, (1, 1));
    let cancelled = plan(Point::Effect, Mode::Pause, 1);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            FAULT.scope(
                cancelled.clone(),
                app.submit(&session, 1, &submission, &csrf, input.clone())
            )
        )
        .await
        .is_err()
    );
    assert_eq!(cancelled.hits.load(Ordering::SeqCst), 1);
    assert_eq!(counts(&db).await, (1, 1));
    let lost = plan(Point::Commit, Mode::LoseAck, 1);
    assert!(matches!(
        FAULT
            .scope(
                lost,
                app.submit(&session, 1, &submission, &csrf, input.clone())
            )
            .await,
        Err(RequestError::OutcomeUnknown)
    ));
    assert_eq!(counts(&db).await, (2, 2));
    let restarted = application(db.clone(), serde_json::from_slice(&saved).unwrap()).await;
    let recovered = restarted
        .submit(&session, 1, &submission, &csrf, input.clone())
        .await
        .unwrap();
    assert_ne!(recovered.location, response.location);
    assert_eq!(counts(&db).await, (2, 2));
    // Deleting a receipt's target does not cause recovery to re-run the action.
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute("DELETE FROM nx_records", &[]).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        restarted
            .submit(&session, 1, &submission, &csrf, input)
            .await
            .unwrap()
            .location,
        recovered.location
    );
    assert_eq!(counts(&db).await, (0, 2));
    let old = restarted
        .keys
        .verify(&submission, crate::security::now().unwrap())
        .unwrap();
    let (expired, signed) = restarted
        .keys
        .issue(
            old.kind,
            &old.subject,
            crate::security::now().unwrap() - 1000,
            900,
        )
        .unwrap();
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES($1,$2,'expired',1,'old','old',$3)",&[expired.nonce.into(),expired.subject.into(),expired.expires.into()]).await.unwrap();
    tx.commit().await.unwrap();
    db.maintain().await.unwrap();
    assert_eq!(counts(&db).await, (0, 2));
    assert!(
        restarted
            .submit(
                &session,
                1,
                &signed,
                &csrf,
                Fields::from([("body".into(), "expired".into())])
            )
            .await
            .is_err()
    );
    // Persisted time fences protect expired receipts after collection/restart.
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let future = crate::security::now().unwrap() + 7200;
    crate::security::observe_clock(&mut tx, future)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(db.maintain().await.is_err());
    assert!(restarted.view(&session, 1, None).await.is_err());
}

#[tokio::test]
async fn sqlite_failure_protocol() {
    let temp = tempfile::tempdir().unwrap();
    faults(Database::sqlite(temp.path().join("failure.db"))).await;
}

async fn record_application(db: &Database, keys: &[u8]) -> Arc<Application> {
    let m = record_actions::declarations();
    let app = Arc::new(
        Application::new(
            &record_actions::component("ok"),
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

async fn record_mutation_state(db: &Database) -> (Vec<[String; 5]>, Vec<[String; 2]>) {
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let record = tx
        .fetch::<5>(
            "SELECT owner,tenant,fields,incarnation,CAST(revision AS TEXT) FROM nx_records WHERE resource=1 AND id=42",
            &[],
        )
        .await
        .unwrap();
    let receipts = tx
        .fetch::<2>("SELECT input,outcome FROM nx_receipts ORDER BY nonce", &[])
        .await
        .unwrap();
    (record, receipts)
}

async fn record_mutation_failures(db: Database) {
    use noxide_protocol::{ResponseIntent, RouteRef};
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "")
        .await
        .unwrap();
    let mut tx = db
        .begin(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "INSERT INTO nx_roles(principal,name,tenant) VALUES((SELECT id FROM nx_accounts WHERE login_name='alice'),'writer','')",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let keys = serde_json::to_vec(&HostKeys::generate().unwrap()).unwrap();
    let app = record_application(&db, &keys).await;
    let session = account(&app).await;
    for action in [2, 3] {
        for case in ["retry", "cancel", "lost", "unconfirmed"] {
            let mut tx = db
                .begin(std::time::Instant::now() + Duration::from_secs(2))
                .await
                .unwrap();
            tx.execute("DELETE FROM nx_records", &[]).await.unwrap();
            tx.execute("DELETE FROM nx_receipts", &[]).await.unwrap();
            let incarnation = format!("fault-{action}-{case}");
            tx.allocate_creation().await.unwrap();
            tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES(1,42,(SELECT id FROM nx_accounts WHERE login_name='alice'),'','{\"body\":\"original\",\"tag\":\"protected tag\"}',$1,1,(SELECT value FROM nx_creation_counter WHERE singleton=1))",
                &[incarnation.clone().into()],
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            let page =
                String::from_utf8(app.view(&session, 2, Some(42)).await.unwrap().body).unwrap();
            let form = page
                .split_once(&format!("action=\"/actions/{action}\""))
                .unwrap()
                .1;
            let submission = fixture::hidden(form, "_submission");
            let csrf = fixture::hidden(form, "_csrf");
            let input = if action == 2 {
                Fields::from([("body".into(), "committed edit".into())])
            } else {
                Fields::new()
            };
            match case {
                "unconfirmed" => {
                    let mut tx = db
                        .begin(std::time::Instant::now() + Duration::from_secs(2))
                        .await
                        .unwrap();
                    tx.execute(
                        "UPDATE nx_records SET fields='{\"body\":\"newer private text\",\"tag\":\"protected tag\"}',revision=2 WHERE resource=1 AND id=42",
                        &[],
                    )
                    .await
                    .unwrap();
                    tx.commit().await.unwrap();
                    let before = record_mutation_state(&db).await;
                    let recovery = app
                        .recover_form(&session, action, &submission, &csrf, &input, true)
                        .await
                        .unwrap();
                    assert_eq!(recovery.status, 503);
                    let html = String::from_utf8(recovery.body).unwrap();
                    assert_eq!(fixture::hidden(&html, "_submission"), submission);
                    assert!(!html.contains("newer private text"));
                    if action == 2 {
                        assert!(html.contains("readonly") && html.contains("committed edit"));
                    }
                    let conflict = app
                        .recover_form(&session, action, &submission, &csrf, &input, false)
                        .await
                        .unwrap();
                    assert_eq!(conflict.status, 409);
                    let html = String::from_utf8(conflict.body).unwrap();
                    assert_ne!(fixture::hidden(&html, "_submission"), submission);
                    assert!(html.contains("newer private text"));
                    assert_eq!(record_mutation_state(&db).await, before);
                    continue;
                }
                "retry" => {
                    let retry = plan(Point::Effect, Mode::Abort, 1);
                    let response = FAULT
                        .scope(
                            retry.clone(),
                            app.submit(&session, action, &submission, &csrf, input.clone()),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status, 303);
                    assert_eq!(retry.hits.load(Ordering::SeqCst), 2);
                }
                "cancel" => {
                    let before = record_mutation_state(&db).await;
                    let cancelled = plan(Point::Effect, Mode::Pause, 1);
                    let request = {
                        let (app, session, submission, csrf, input, cancelled) = (
                            app.clone(),
                            session.clone(),
                            submission.clone(),
                            csrf.clone(),
                            input.clone(),
                            cancelled.clone(),
                        );
                        tokio::spawn(async move {
                            FAULT
                                .scope(
                                    cancelled,
                                    app.submit(&session, action, &submission, &csrf, input),
                                )
                                .await
                        })
                    };
                    tokio::time::timeout(Duration::from_secs(1), async {
                        while cancelled.hits.load(Ordering::SeqCst) == 0 {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    })
                    .await
                    .unwrap();
                    request.abort();
                    assert!(request.await.unwrap_err().is_cancelled());
                    assert_eq!(record_mutation_state(&db).await, before);
                    assert_eq!(
                        app.submit(&session, action, &submission, &csrf, input.clone())
                            .await
                            .unwrap()
                            .status,
                        303,
                        "cancellation must release the receipt claim and restore the target"
                    );
                }
                "lost" => {
                    let lost = plan(Point::Commit, Mode::LoseAck, 1);
                    assert!(matches!(
                        FAULT
                            .scope(
                                lost.clone(),
                                app.submit(&session, action, &submission, &csrf, input.clone())
                            )
                            .await,
                        Err(RequestError::OutcomeUnknown)
                    ));
                    assert_eq!(lost.hits.load(Ordering::SeqCst), 1);
                }
                _ => unreachable!(),
            }
            let committed = record_mutation_state(&db).await;
            assert_eq!(committed.1.len(), 1, "{case} action {action}");
            let expected = if action == 2 {
                assert_eq!(committed.0.len(), 1);
                let [owner, tenant, fields, stored_incarnation, revision] = &committed.0[0];
                assert_eq!(
                    (owner.as_str(), tenant.as_str()),
                    (crate::test_account(&db, "alice").await.as_str(), "")
                );
                assert_eq!(stored_incarnation, &incarnation);
                assert_eq!(revision, "2", "a retry must advance the revision only once");
                assert_eq!(
                    serde_json::from_str::<Fields>(fields).unwrap(),
                    Fields::from([
                        ("body".into(), "committed edit".into()),
                        ("tag".into(), "protected tag".into())
                    ])
                );
                ResponseIntent::Updated {
                    resource: 1,
                    id: 42,
                    destination: RouteRef {
                        params: Default::default(),
                        route: 2,
                        target: Some(42),
                    },
                }
            } else {
                assert!(
                    committed.0.is_empty(),
                    "hard deletion must remove the target"
                );
                ResponseIntent::Deleted {
                    resource: 1,
                    id: 42,
                    destination: RouteRef {
                        params: Default::default(),
                        route: 1,
                        target: None,
                    },
                }
            };
            assert_eq!(
                serde_json::from_str::<ResponseIntent>(&committed.1[0][1]).unwrap(),
                expected
            );
            let restarted = record_application(&db, &keys).await;
            let recovery = restarted
                .recover_form(&session, action, &submission, &csrf, &input, true)
                .await
                .unwrap();
            assert_eq!(recovery.status, 303);
            let must_not_execute = plan(Point::Effect, Mode::Abort, 10);
            let recovered = FAULT
                .scope(
                    must_not_execute.clone(),
                    restarted.submit(&session, action, &submission, &csrf, input),
                )
                .await
                .unwrap();
            assert_eq!(recovered.status, 303);
            assert_eq!(
                recovered.location.as_deref(),
                Some(if action == 2 { "/notes/42" } else { "/" })
            );
            assert_eq!(must_not_execute.hits.load(Ordering::SeqCst), 0);
            assert_eq!(record_mutation_state(&db).await, committed);
        }
    }
}

#[tokio::test]
async fn sqlite_record_mutation_failures() {
    let temp = tempfile::tempdir().unwrap();
    record_mutation_failures(Database::sqlite(temp.path().join("record-faults.db"))).await;
}

async fn crashes(db: Database, descriptor: serde_json::Value) {
    db.initialize().await.unwrap();
    db.create_account("alice", "private test password", "")
        .await
        .unwrap();
    let keys = HostKeys::generate().unwrap();
    let saved = serde_json::to_value(&keys).unwrap();
    let app = application(db.clone(), keys).await;
    let session = account(&app).await;
    let input = Fields::from([("body".into(), "crash boundary".into())]);
    for (point, expected) in [("effect", (0, 0)), ("commit", (1, 1))] {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("ready");
        let (submission, csrf) = form(&app, &session).await;
        let file = temp.path().join("case.json");
        std::fs::write(&file,serde_json::to_vec(&serde_json::json!({"database":descriptor,"keys":saved,"session":session,"submission":submission,"csrf":csrf,"point":point,"marker":marker})).unwrap()).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "failure_tests::crash_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("NOXIDE_CRASH_CASE", &file)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !marker.exists() && tokio::time::Instant::now() < deadline {
            assert!(
                child.try_wait().unwrap().is_none(),
                "worker exited before its fault boundary"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let reached = marker.exists();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(reached, "child did not reach the selected boundary");
        assert_eq!(
            counts(&db).await,
            expected,
            "host process crash must not split receipt and mutation"
        );
        if point == "commit" {
            let restarted =
                application(db.clone(), serde_json::from_value(saved.clone()).unwrap()).await;
            assert!(
                restarted
                    .submit(&session, 1, &submission, &csrf, input.clone())
                    .await
                    .is_ok()
            );
            assert_eq!(counts(&db).await, (1, 1));
        }
    }
}

#[test]
#[ignore = "internal subprocess fixture; invoked by crash tests"]
fn crash_worker() {
    let Ok(path) = std::env::var("NOXIDE_CRASH_CASE") else {
        return;
    };
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let database = if let Some(path) = data["database"]["sqlite"].as_str() {
            Database::sqlite(path)
        } else {
            Database::postgres(data["database"]["postgres"].as_str().unwrap()).unwrap()
        };
        let app = application(
            database,
            serde_json::from_value(data["keys"].clone()).unwrap(),
        )
        .await;
        let plan = Arc::new(Plan {
            point: if data["point"] == "effect" {
                Point::Effect
            } else {
                Point::Commit
            },
            mode: Mode::Pause,
            remaining: AtomicUsize::new(1),
            hits: AtomicUsize::new(0),
            marker: Some(data["marker"].as_str().unwrap().into()),
            resume: tokio::sync::Notify::new(),
        });
        FAULT
            .scope(
                plan,
                app.submit(
                    data["session"].as_str().unwrap(),
                    1,
                    data["submission"].as_str().unwrap(),
                    data["csrf"].as_str().unwrap(),
                    Fields::from([("body".into(), "crash boundary".into())]),
                ),
            )
            .await
            .unwrap();
        panic!("worker escaped its fault boundary");
    });
}

#[tokio::test]
async fn sqlite_process_crashes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("crash.db");
    crashes(Database::sqlite(&path), serde_json::json!({"sqlite":path})).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_failure_protocol() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_fault_{}",
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
    faults(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
    let name = format!(
        "nx_crash_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    case.set_path(&format!("/{name}"));
    crashes(
        Database::postgres(case.as_str()).unwrap(),
        serde_json::json!({"postgres":case.as_str()}),
    )
    .await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
    let name = format!(
        "nx_record_fault_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    case.set_path(&format!("/{name}"));
    record_mutation_failures(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
