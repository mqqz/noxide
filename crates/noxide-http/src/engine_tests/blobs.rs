use super::prelude::*;
use crate::auth::AccountAdmin as _;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use noxide_authority::authority;
use noxide_blobs::metadata::MetadataContext;
use noxide_blobs::runtime::ReconcileHost;
use noxide_blobs::store::{IoGuard, ObjectKey};
use noxide_blobs::upload::Barrier;
use noxide_host::PreparedUpload;
use noxide_protocol::time::Timestamp;
use noxide_store::database::Transaction;
use tokio::time::Instant;
use tower::ServiceExt;
fn declarations() -> Manifest {
    let mut m = crate::test_support::manifest();
    m.resources[0].fields.push(TextField {
        immutable: false,
        name: "attachment".into(),
        label: "Attachment".into(),
        kind: FieldKind::Blob { max_bytes: 1024 },
        optional: false,
        initial: None,
        max_bytes: 67,
    });
    m.resources[0].fields.push(TextField {
        immutable: false,
        name: "extra".into(),
        label: "Extra attachment".into(),
        kind: FieldKind::Blob { max_bytes: 1024 },
        optional: true,
        initial: None,
        max_bytes: 67,
    });
    m.actions[0].inputs.push(Input {
        name: "attachment".into(),
        label: "Attachment".into(),
        kind: FieldKind::UploadHandle { max_bytes: 1024 },
        optional: false,
        max_bytes: 67,
    });
    m.actions[0].steps[0].assign.push(Assignment {
        field: "attachment".into(),
        change: Change::Set(Value::Input("attachment".into())),
    });
    let mut delete = m.operations[1].clone();
    delete.id = 4;
    delete.kind = OperationKind::Delete;
    m.operations.push(delete);
    m.actions.push(Action {
        id: 2,
        version: 1,
        name: "Delete file".into(),
        inputs: vec![],
        targets: vec![ActionTarget {
            name: "target".into(),
            resource: 1,
            source: TargetSource::Page { reads: vec![2] },
            revision: Revision::Exact,
            projection: None,
            inspect: None,
        }],
        steps: vec![Step {
            operation: 4,
            target: Target::Named("target".into()),
            assign: vec![],
            guards: vec![],
        }],
    });
    m.web_bindings.push(WebBinding {
        id: 2,
        version: 1,
        action: 2,
        layout: vec![],
        redirect: Redirect {
            route: 1,
            source: RedirectSource::Target("target".into()),
        },
    });
    m.routes[1].forms.push(2);
    m.blobs = Some(BlobPolicy {
        limits: BlobLimits::default(),
        anonymous: None,
        uploads: vec![noxide_protocol::blobs::UploadBinding {
            id: 1,
            name: "attachment".into(),
            web_binding: 1,
            input: "attachment".into(),
            anonymous: None,
        }],
    });
    m
}
fn emit(bytes: &[u8]) -> String {
    bytes
        .chunks(8)
        .map(|part| {
            let mut word = [0; 8];
            word[..part.len()].copy_from_slice(part);
            format!(
                "i64.const {} i32.const {} call $emit\n",
                i64::from_le_bytes(word),
                part.len()
            )
        })
        .collect()
}
fn component() -> Vec<u8> {
    component_with_read(true)
}
fn component_with_read(read: bool) -> Vec<u8> {
    let read_call = if read {
        "i32.const 2 local.get $id call $invoke drop"
    } else {
        ""
    };
    let root = emit(
        &serde_json::to_vec(&ResponseIntent::Page(Document::new(
            "Upload",
            vec![Instruction::Form { action: 1 }],
        )))
        .unwrap(),
    );
    let kind = format!(r#"{{"version":{VERSION},"kind":{{"#).len() + 1;
    let target = format!(r#"{{"version":{VERSION},"kind":{{"route":2}},"target":"#).len();
    let prefix = emit(br#"{"page":{"title":"File","nodes":[{"download":{"read":2,"target":"#);
    let suffix =
        emit(br#", "field":"attachment","text":"Download file"}},{"form":{"action":2}}]}}"#);
    let execute = emit(br#""execute""#);
    wat::parse_str(format!(r#"(component
      (import "noxide:application/host@0.1.0" (instance $h
       (export "emit" (func (param "word" u64) (param "length" u32)))
       (export "request-chunk" (func (param "offset" u32) (result u64)))
       (export "invoke" (func (param "operation" u32) (param "target" u64) (result u32)))))
      (alias export $h "emit" (func $emit)) (core func $emit (canon lower (func $emit)))
      (alias export $h "request-chunk" (func $request)) (core func $request (canon lower (func $request)))
      (alias export $h "invoke" (func $invoke)) (core func $invoke (canon lower (func $invoke)))
      (core module $m
       (import "h" "emit" (func $emit (param i64 i32)))
       (import "h" "request" (func $request (param i32) (result i64)))
       (import "h" "invoke" (func $invoke (param i32 i64) (result i32)))
       (func (export "handle") (local $i i32) (local $c i32) (local $id i64)
        i32.const {kind} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 97 i32.eq
        if {execute} else
         i32.const {target} call $request i32.wrap_i64 i32.const 255 i32.and local.set $c
         local.get $c i32.const 48 i32.ge_u local.get $c i32.const 57 i32.le_u i32.and
         if
          i32.const {target} local.set $i
          block $done loop $digits
           local.get $i call $request i32.wrap_i64 i32.const 255 i32.and local.set $c
           local.get $c i32.const 48 i32.lt_u local.get $c i32.const 57 i32.gt_u i32.or br_if $done
           local.get $id i64.const 10 i64.mul local.get $c i32.const 48 i32.sub i64.extend_i32_u i64.add local.set $id
           local.get $i i32.const 1 i32.add local.set $i br $digits
          end end
          {read_call}
          {prefix}
          i32.const {target} local.set $i
          block $out_done loop $out
           local.get $i call $request i32.wrap_i64 i32.const 255 i32.and local.set $c
           local.get $c i32.const 48 i32.lt_u local.get $c i32.const 57 i32.gt_u i32.or br_if $out_done
           local.get $c i64.extend_i32_u i32.const 1 call $emit
           local.get $i i32.const 1 i32.add local.set $i br $out
          end end {suffix}
         else {root} end end))
      (core instance $i (instantiate $m (with "h" (instance (export "emit" (func $emit)) (export "request" (func $request)) (export "invoke" (func $invoke))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#)).unwrap()
}
async fn login(app: &Application, name: &str) -> String {
    let challenge = app.login_challenge().await.unwrap();
    app.login(
        &challenge.cookie,
        &challenge.csrf,
        name,
        "blob test password",
    )
    .await
    .unwrap()
}
fn post(session: &str, page: &str, text: &str, filename: &str, bytes: &[u8]) -> Request<Body> {
    let mut body = Vec::new();
    for (name, value) in [
        ("_csrf", crate::test_support::hidden(page, "_csrf")),
        (
            "_submission",
            crate::test_support::hidden(page, "_submission"),
        ),
        ("_upload", crate::test_support::hidden(page, "_upload")),
        ("body", text.into()),
    ] {
        body.extend_from_slice(format!("--test-boundary\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes());
    }
    body.extend_from_slice(format!("--test-boundary\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"{filename}\"\r\nContent-Type: text/html\r\n\r\n").as_bytes());
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n--test-boundary--\r\n");
    Request::builder()
        .method("POST")
        .uri("/actions/1")
        .header("Host", "localhost:8080")
        .header("Origin", "http://localhost:8080")
        .header("Cookie", format!("session={session}"))
        .header(
            "Content-Type",
            "multipart/form-data; boundary=test-boundary",
        )
        .body(Body::from(body))
        .unwrap()
}
async fn flow(db: Database) {
    let temporary = tempfile::tempdir().unwrap();
    db.initialize().await.unwrap();
    db.create_account("alice", "blob test password", "")
        .await
        .unwrap();
    db.create_account("bob", "blob test password", "")
        .await
        .unwrap();
    let m = declarations();
    let ceilings = BlobCeilings::default();
    let app = Arc::new(
        Application::new(
            &component(),
            &serde_json::to_vec(&m).unwrap(),
            crate::deployment::approval_digest(&m, Some(&ceilings), None, None).unwrap(),
            db.clone(),
            HostKeys::generate().unwrap(),
            Limits::default(),
            crate::DeploymentResources {
                effects: None,
                jobs: None,
                assets: Default::default(),
                blobs: Some(crate::BlobDeployment {
                    directory: temporary.path().join("objects"),
                    ceilings,
                }),
            },
        )
        .unwrap(),
    );
    app.activate().await.unwrap();
    let session = login(&app, "alice").await;
    let page = String::from_utf8(app.view(&session, 1, None).await.unwrap().body).unwrap();
    assert!(page.contains("enctype=\"multipart/form-data\""));
    assert!(page.find("name=\"body\"").unwrap() < page.find("type=\"file\"").unwrap());
    let router = crate::router(
        app.clone(),
        crate::Origin::parse("http://localhost:8080").unwrap(),
    );
    let content = b"<script>hostile bytes</script>";
    let response = router
        .clone()
        .oneshot(post(&session, &page, "note", "../../evil.html", content))
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let location = location.unwrap();
    let request = |path: &str, session: &str| {
        Request::builder()
            .uri(path)
            .header("Host", "localhost:8080")
            .header("Cookie", format!("session={session}"))
            .body(Body::empty())
            .unwrap()
    };
    let response = router
        .clone()
        .oneshot(request(&location, &session))
        .await
        .unwrap();
    let status = response.status();
    let page = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(status, StatusCode::OK, "{page}");
    let href = page
        .split_once("href=\"/_noxide/download?")
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap();
    let download = format!("/_noxide/download?{href}");
    let response = router
        .clone()
        .oneshot(request(&download, &session))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/octet-stream"
    );
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"evil.html\""
    );
    assert_eq!(
        response.headers()["content-security-policy"],
        noxide_blobs::transport::CSP
    );
    assert_eq!(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .as_ref(),
        content
    );
    let bob = login(&app, "bob").await;
    assert_eq!(
        router
            .clone()
            .oneshot(request(&download, &bob))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    app.request_lifecycle().drain().await.unwrap();
    let mut tx = db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>(
            "SELECT CAST(COUNT(*) AS TEXT) FROM nx_blobs WHERE state='attached'",
            &[]
        )
        .await
        .unwrap()[0][0],
        "1"
    );
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_receipts", &[])
            .await
            .unwrap()[0][0],
        "1"
    );
    tx.commit().await.unwrap();
    // The descriptor captured at stream start survives later revocation; fresh
    // streams must independently authorize the current record owner.
    let captured = router
        .clone()
        .oneshot(request(&download, &session))
        .await
        .unwrap();
    assert_eq!(captured.status(), StatusCode::OK);
    let bob_id = db.account_id("bob").await.unwrap();
    let mut tx = db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute("UPDATE nx_records SET owner=$1", &[bob_id.as_str().into()])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        to_bytes(captured.into_body(), 65536)
            .await
            .unwrap()
            .as_ref(),
        content
    );
    assert_eq!(
        router
            .clone()
            .oneshot(request(&download, &session))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let alice_id = db.account_id("alice").await.unwrap();
    let mut tx = db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_records SET owner=$1",
        &[alice_id.as_str().into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let blobs = app.blobs().unwrap();
    let key = ObjectKey::parse(
        blobs
            .workers()
            .lock()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone(),
    )
    .unwrap();
    blobs
        .store()
        .remove(
            &key,
            &IoGuard::new(
                std::time::Instant::now() + std::time::Duration::from_secs(2),
                Arc::new(AtomicBool::new(false)),
            ),
        )
        .unwrap();
    assert_eq!(
        router
            .oneshot(request(&download, &session))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(
        blobs.quarantined().load(Ordering::Acquire),
        "a missing object blocks new uploads"
    );
}
#[tokio::test]
async fn sqlite_nojs_upload_and_authorized_download() {
    let temp = tempfile::tempdir().unwrap();
    flow(Database::sqlite(temp.path().join("blob.db"))).await;
}

struct Case {
    app: Arc<Application>,
    db: Database,
    _temp: tempfile::TempDir,
    session: String,
    router: axum::Router,
}
impl Case {
    async fn new(db: Option<Database>, manifest: Manifest) -> Self {
        Self::with_component(db, manifest, component()).await
    }
    async fn with_component(db: Option<Database>, manifest: Manifest, bytes: Vec<u8>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let db = db.unwrap_or_else(|| Database::sqlite(temp.path().join("blobs.db")));
        db.initialize().await.unwrap();
        db.create_account("alice", "blob test password", "")
            .await
            .unwrap();
        let ceilings = BlobCeilings::default();
        let app = Arc::new(
            Application::new(
                &bytes,
                &serde_json::to_vec(&manifest).unwrap(),
                crate::deployment::approval_digest(&manifest, Some(&ceilings), None, None).unwrap(),
                db.clone(),
                HostKeys::generate().unwrap(),
                Limits::default(),
                crate::DeploymentResources {
                    effects: None,
                    jobs: None,
                    assets: Default::default(),
                    blobs: Some(crate::BlobDeployment {
                        directory: temp.path().join("store"),
                        ceilings,
                    }),
                },
            )
            .unwrap(),
        );
        app.activate().await.unwrap();
        let session = login(&app, "alice").await;
        let router = crate::router(
            app.clone(),
            crate::Origin::parse("http://localhost:8080").unwrap(),
        );
        Self {
            app,
            db,
            _temp: temp,
            session,
            router,
        }
    }
    async fn page(&self) -> String {
        String::from_utf8(self.app.view(&self.session, 1, None).await.unwrap().body).unwrap()
    }
    async fn state(&self) -> (String, String, String, String, String) {
        self.app.request_lifecycle().drain().await.unwrap();
        let mut tx = self
            .db
            .begin((Instant::now() + std::time::Duration::from_secs(2)).into_std())
            .await
            .unwrap();
        let blobs = tx
            .fetch::<2>(
                "SELECT state,upload_handle FROM nx_blobs ORDER BY slot",
                &[],
            )
            .await
            .unwrap();
        let counters=tx.fetch::<2>("SELECT CAST(reserved_bytes AS TEXT),CAST(used_bytes AS TEXT) FROM nx_blob_store WHERE singleton=1",&[]).await.unwrap();
        let receipts = tx
            .fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_receipts", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (
            blobs.first().map(|r| r[0].clone()).unwrap_or_default(),
            blobs.first().map(|r| r[1].clone()).unwrap_or_default(),
            counters[0][0].clone(),
            counters[0][1].clone(),
            receipts[0][0].clone(),
        )
    }
    async fn maintenance(&self) {
        self.app.request_lifecycle().drain().await.unwrap();
        self.app
            .test_reconcile_blobs(Instant::now() + std::time::Duration::from_secs(2))
            .await
            .unwrap();
    }
}
async fn retry_and_delete(db: Option<Database>) {
    let mut m = declarations();
    m.actions[0].steps[0].guards.push(Guard {
        condition: GuardCondition::Compare {
            left: Value::Input("body".into()),
            comparison: Comparison::Equal,
            right: Value::Literal(Literal::Text("corrected".into())),
        },
        rejection: GuardRejection {
            input: Some("body".into()),
            message: "Correct this note".into(),
        },
    });
    let case = Case::new(db, m).await;
    let original = case.page().await;
    let response = case
        .router
        .clone()
        .oneshot(post(&case.session, &original, "bad", "file.bin", b"abc"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let recovery = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(
        crate::test_support::hidden(&original, "_submission"),
        crate::test_support::hidden(&recovery, "_submission")
    );
    let state = case.state().await;
    assert_eq!(
        (
            state.0.as_str(),
            state.2.as_str(),
            state.3.as_str(),
            state.4.as_str()
        ),
        ("staged", "0", "3", "0")
    );
    let foreign = case.page().await;
    let result = case
        .app
        .submit(
            &case.session,
            1,
            &crate::test_support::hidden(&foreign, "_submission"),
            &crate::test_support::hidden(&foreign, "_csrf"),
            Fields::from([
                ("body".into(), "corrected".into()),
                ("attachment".into(), state.1.clone()),
            ]),
        )
        .await;
    assert!(
        result.is_err(),
        "a fresh nonce must not claim another form's file"
    );
    assert_eq!(case.state().await.0, "staged");
    let replacement = case
        .router
        .clone()
        .oneshot(post(
            &case.session,
            &recovery,
            "corrected",
            "replacement.bin",
            b"new",
        ))
        .await
        .unwrap();
    assert_eq!(replacement.status(), StatusCode::BAD_REQUEST);
    assert_eq!(case.state().await.0, "staged");
    let response = case
        .router
        .clone()
        .oneshot(post(&case.session, &recovery, "corrected", "", b""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    let state = case.state().await;
    assert_eq!(
        (
            state.0.as_str(),
            state.2.as_str(),
            state.3.as_str(),
            state.4.as_str()
        ),
        ("attached", "0", "3", "1")
    );
    let replay = case
        .router
        .clone()
        .oneshot(post(
            &case.session,
            &recovery,
            "corrected",
            "ignored.bin",
            b"never staged",
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::SEE_OTHER);
    assert_eq!(case.state().await, state);
    let id = location.rsplit('/').next().unwrap().parse().unwrap();
    let detail = String::from_utf8(
        case.app
            .view(&case.session, 2, Some(id))
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    let submission = crate::test_support::hidden(&detail, "_submission");
    let csrf = crate::test_support::hidden(&detail, "_csrf");
    // An extra/mismatched association must roll back the sole delete and receipt.
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_blobs SET owner_field='unexpected' WHERE state='attached'",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(
        case.app
            .submit(&case.session, 2, &submission, &csrf, Fields::new())
            .await
            .is_err()
    );
    assert_eq!(case.state().await.4, "1");
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_blobs SET owner_field='attachment' WHERE state='attached'",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    case.app
        .submit(&case.session, 2, &submission, &csrf, Fields::new())
        .await
        .unwrap();
    assert_eq!(case.state().await.0, "unreferenced");
    case.maintenance().await;
    let state = case.state().await;
    assert_eq!(
        (
            state.0.as_str(),
            state.2.as_str(),
            state.3.as_str(),
            state.4.as_str()
        ),
        ("deleted", "0", "0", "2")
    );
    case.maintenance().await;
    assert_eq!(case.state().await, state, "quota releases exactly once");
}
#[tokio::test]
async fn sqlite_rejected_scalar_correction_reuses_file_and_delete_gc_is_atomic() {
    retry_and_delete(None).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable server"]
async fn postgres_nojs_upload_download_retry_and_gc() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for index in 0..9 {
        let name = format!("nx_blob_flow_{}_{}", std::process::id(), index);
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut case = url::Url::parse(&url).unwrap();
        case.set_path(&format!("/{name}"));
        let db = Database::postgres(case.as_str()).unwrap();
        match index {
            0 => flow(db).await,
            1 => retry_and_delete(Some(db)).await,
            2 => restart_after_finalize(Some(db), false).await,
            3 => restart_after_finalize(Some(db), true).await,
            4 => {
                #[cfg(unix)]
                native_http(Some(db)).await;
            }
            5 => attachment_wins_gc(Some(db)).await,
            6 => absence_and_prefix_are_serialized(Some(db)).await,
            7 => empty_cannot_discard_stage(Some(db)).await,
            _ => lifecycle_clock_safety(Some(db)).await,
        }
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}

fn prefix(page: &str, body: &str) -> Fields {
    Fields::from([
        ("_csrf".into(), crate::test_support::hidden(page, "_csrf")),
        (
            "_submission".into(),
            crate::test_support::hidden(page, "_submission"),
        ),
        (
            "_upload".into(),
            crate::test_support::hidden(page, "_upload"),
        ),
        ("body".into(), body.into()),
    ])
}
#[tokio::test]
async fn sqlite_quota_race_reserves_before_bytes_and_reclaims_unstarted_upload() {
    let mut m = declarations();
    m.blobs.as_mut().unwrap().limits.app_bytes = 1024;
    m.blobs.as_mut().unwrap().limits.file_bytes = 1024;
    let case = Case::new(None, m).await;
    let a = prefix(&case.page().await, "one");
    let b = prefix(&case.page().await, "two");
    let filename = noxide_blobs::transport::AttachmentName::normalize("file.bin").unwrap();
    let (one, two) = tokio::join!(
        case.app
            .prepare_upload(&case.session, 1, &a, Some(filename.clone())),
        case.app
            .prepare_upload(&case.session, 1, &b, Some(filename))
    );
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    assert_eq!(case.state().await.2, "1024");
    let store = &case.app.blobs().unwrap().store();
    let guard = IoGuard::new(
        std::time::Instant::now() + std::time::Duration::from_secs(2),
        Arc::new(AtomicBool::new(false)),
    );
    assert!(
        store
            .scan(noxide_blobs::store::ObjectLocation::Partial)
            .unwrap()
            .next_batch(&guard)
            .unwrap()
            .is_empty(),
        "reservation must precede all file bytes"
    );
    drop(one);
    drop(two);
    case.maintenance().await;
    let state = case.state().await;
    assert_eq!(
        (state.0.as_str(), state.2.as_str(), state.3.as_str()),
        ("deleted", "0", "0")
    );
}
#[tokio::test]
async fn sqlite_unknown_file_is_charged_retained_and_blocks_new_uploads() {
    let case = Case::new(None, declarations()).await;
    let blobs = case.app.blobs().unwrap();
    let key = ObjectKey::random().unwrap();
    let guard = IoGuard::new(
        std::time::Instant::now() + std::time::Duration::from_secs(2),
        Arc::new(AtomicBool::new(false)),
    );
    let mut pending = blobs
        .store()
        .begin(key.clone(), 1024, guard.clone())
        .unwrap();
    pending.write_chunk(b"orphan").unwrap();
    pending.finalize().unwrap();
    case.maintenance().await;
    assert!(blobs.quarantined().load(Ordering::Acquire));
    assert_eq!(
        blobs
            .store()
            .open_object(&key, 6, guard)
            .unwrap()
            .read_chunk(&mut [0; 64])
            .unwrap(),
        6
    );
    let page = case.page().await;
    assert!(
        case.app
            .prepare_upload(
                &case.session,
                1,
                &prefix(&page, "note"),
                Some(noxide_blobs::transport::AttachmentName::normalize("new.bin").unwrap())
            )
            .await
            .is_err()
    );
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<2>(
            "SELECT CAST(charged_bytes AS TEXT),CAST(charged_objects AS TEXT) FROM nx_blob_orphans",
            &[]
        )
        .await
        .unwrap(),
        vec![["6".to_owned(), "1".to_owned()]]
    );
    assert_eq!(
        tx.fetch::<2>(
            "SELECT CAST(used_bytes AS TEXT),CAST(objects AS TEXT) FROM nx_blob_store",
            &[]
        )
        .await
        .unwrap(),
        vec![["6".to_owned(), "1".to_owned()]]
    );
    tx.commit().await.unwrap();
    case.maintenance().await;
    assert!(
        blobs
            .store()
            .snapshot(
                &key,
                &IoGuard::new(
                    std::time::Instant::now() + std::time::Duration::from_secs(2),
                    Arc::new(AtomicBool::new(false))
                )
            )
            .unwrap()
            .is_some()
    );
}
#[test]
fn host_rejects_forged_blob_declarations() {
    let good = declarations();
    manifest::validate(&good).unwrap();
    let mut bad = Vec::new();
    let mut m = good.clone();
    m.blobs = None;
    bad.push(m);
    let mut m = good.clone();
    m.resources[0].fields[1].initial = Some(format!("b1_{}", "a".repeat(64)));
    bad.push(m);
    let mut m = good.clone();
    m.actions[0].inputs[1].optional = true;
    bad.push(m);
    let mut m = good.clone();
    m.actions[0].steps[0].assign[1].change = Change::Set(Value::Literal(Literal::Text(format!(
        "b1_{}",
        "a".repeat(64)
    ))));
    bad.push(m);
    let mut m = good.clone();
    m.blobs.as_mut().unwrap().uploads[0].web_binding = 2;
    bad.push(m);
    let mut m = good.clone();
    m.blobs.as_mut().unwrap().uploads[0].anonymous = Some(AnonymousCapabilityQuota {
        stages: 1,
        bytes: 1024,
    });
    bad.push(m);
    let mut m = good.clone();
    m.actions[0].steps[0].guards.push(Guard {
        condition: GuardCondition::Compare {
            left: Value::Input("attachment".into()),
            comparison: Comparison::Equal,
            right: Value::Input("attachment".into()),
        },
        rejection: GuardRejection {
            input: None,
            message: "No opaque scalar comparisons".into(),
        },
    });
    bad.push(m);
    for m in bad {
        assert!(manifest::validate(&m).is_err());
    }
}

#[tokio::test]
async fn sqlite_truncated_file_waits_for_physical_stop_before_gc() {
    let case = Case::new(None, declarations()).await;
    let page = case.page().await;
    let (parts, body) =
        post(&case.session, &page, "note", "file.bin", b"partial bytes").into_parts();
    let bytes = to_bytes(body, 65536).await.unwrap();
    let truncated = bytes.slice(..bytes.len() - b"\r\n--test-boundary--\r\n".len());
    let response = case
        .router
        .clone()
        .oneshot(Request::from_parts(parts, Body::from(truncated)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let workers: Vec<_> = case
        .app
        .blobs()
        .unwrap()
        .workers()
        .lock()
        .unwrap()
        .values()
        .cloned()
        .collect();
    assert_eq!(workers.len(), 1);
    for worker in &workers {
        tokio::time::timeout(std::time::Duration::from_secs(2), worker.wait_stopped())
            .await
            .unwrap();
    }
    assert_eq!(case.state().await.0, "uploading");
    case.maintenance().await;
    let state = case.state().await;
    assert_eq!(
        (
            state.0.as_str(),
            state.2.as_str(),
            state.3.as_str(),
            state.4.as_str()
        ),
        ("deleted", "0", "0", "0")
    );
}
async fn restart_after_finalize(db: Option<Database>, finalized: bool) {
    let m = declarations();
    let case = Case::new(db, m.clone()).await;
    let fields = prefix(&case.page().await, "note");
    let prepared = case
        .app
        .prepare_upload(
            &case.session,
            1,
            &fields,
            Some(noxide_blobs::transport::AttachmentName::normalize("file.bin").unwrap()),
        )
        .await
        .unwrap();
    let PreparedUpload::Created(row, lease) = prepared else {
        panic!("fresh reservation")
    };
    let blobs = case.app.blobs().unwrap();
    let key = row.metadata.key.clone();
    let guard = IoGuard::new(
        std::time::Instant::now() + std::time::Duration::from_secs(2),
        Arc::new(AtomicBool::new(false)),
    );
    let mut pending = blobs.store().begin(key.clone(), 1024, guard).unwrap();
    pending.write_chunk(b"known reservation").unwrap();
    if finalized {
        pending.finalize().unwrap();
    } else {
        drop(pending);
    }
    drop(lease);
    case.app.request_lifecycle().drain().await.unwrap();
    let keys = serde_json::from_slice(&serde_json::to_vec(case.app.test_keys()).unwrap()).unwrap();
    let Case {
        app,
        db,
        _temp,
        session: _,
        router,
    } = case;
    drop(router);
    drop(app);
    let ceilings = BlobCeilings::default();
    let app = Application::new(
        &component(),
        &serde_json::to_vec(&m).unwrap(),
        crate::deployment::approval_digest(&m, Some(&ceilings), None, None).unwrap(),
        db.clone(),
        keys,
        Limits::default(),
        crate::DeploymentResources {
            effects: None,
            jobs: None,
            assets: Default::default(),
            blobs: Some(crate::BlobDeployment {
                directory: _temp.path().join("store"),
                ceilings,
            }),
        },
    )
    .unwrap();
    app.activate().await.unwrap();
    let blobs = app.blobs().unwrap();
    assert!(!blobs.quarantined().load(Ordering::Acquire));
    assert!(
        blobs
            .store()
            .snapshot(
                &key,
                &IoGuard::new(
                    std::time::Instant::now() + std::time::Duration::from_secs(2),
                    Arc::new(AtomicBool::new(false))
                )
            )
            .unwrap()
            .is_none()
    );
    let mut tx = db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT state FROM nx_blobs", &[])
            .await
            .unwrap()[0][0],
        "deleted"
    );
    assert_eq!(tx.fetch::<3>("SELECT CAST(reserved_bytes AS TEXT),CAST(used_bytes AS TEXT),CAST(objects AS TEXT) FROM nx_blob_store",&[]).await.unwrap()[0],["0".to_owned(),"0".to_owned(),"0".to_owned()]);
    tx.commit().await.unwrap();
}
#[tokio::test]
async fn sqlite_restart_recovers_known_partial_and_finalized_unpublished_reservations() {
    restart_after_finalize(None, false).await;
    restart_after_finalize(None, true).await;
}
#[tokio::test]
async fn sqlite_forged_prefix_is_denied_before_any_quota_or_file() {
    let case = Case::new(None, declarations()).await;
    let page = case.page().await;
    let mut request = post(&case.session, &page, "note", "file.bin", b"must not stage");
    request.headers_mut().insert(
        "origin",
        axum::http::HeaderValue::from_static("http://elsewhere.onion"),
    );
    assert_eq!(
        case.router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let invalid = page.replace(&crate::test_support::hidden(&page, "_csrf"), "forged");
    assert!(
        case.router
            .clone()
            .oneshot(post(
                &case.session,
                &invalid,
                "note",
                "file.bin",
                b"must not stage"
            ))
            .await
            .unwrap()
            .status()
            .is_client_error()
    );
    let invalid = page.replace(&crate::test_support::hidden(&page, "_upload"), "forged");
    assert!(
        case.router
            .clone()
            .oneshot(post(
                &case.session,
                &invalid,
                "note",
                "file.bin",
                b"must not stage"
            ))
            .await
            .unwrap()
            .status()
            .is_client_error()
    );
    let state = case.state().await;
    assert_eq!(
        (
            state.0.as_str(),
            state.2.as_str(),
            state.3.as_str(),
            state.4.as_str()
        ),
        ("", "0", "0", "0")
    );
}
async fn anonymous_handover(absent: bool) {
    let mut m = declarations();
    if absent {
        m.resources[0].fields[1].optional = true;
        m.actions[0].inputs[1].optional = true;
    }
    m.routes[0].access = Access::PublicOptional;
    m.routes[0].operations.clear();
    m.routes[1].access = Access::PublicOptional;
    m.resources[0].fields.push(TextField {
        immutable: false,
        name: "published".into(),
        label: "Published".into(),
        kind: FieldKind::Boolean,
        optional: false,
        initial: Some("true".into()),
        max_bytes: 5,
    });
    m.operations[1].visibility = Some(Visibility {
        field: "published".into(),
        equals: "true".into(),
    });
    m.operations[1].policy = Policy {
        any: vec![vec![Predicate::Public]],
    };
    m.operations[1].fields = Some(vec!["body".into(), "attachment".into()]);
    m.operations[2].policy = Policy {
        any: vec![vec![Predicate::Public]],
    };
    m.operations[3].policy = Policy {
        any: vec![vec![Predicate::Capability]],
    };
    let deployment = AnonymousDeploymentQuota {
        stages: 4,
        bytes: 4096,
    };
    let capability = AnonymousCapabilityQuota {
        stages: 2,
        bytes: 2048,
    };
    m.blobs.as_mut().unwrap().anonymous = Some(deployment);
    m.blobs.as_mut().unwrap().uploads[0].anonymous = Some(capability);
    assert!(crate::deployment::approval(&m, Some(&BlobCeilings::default()), None, None).is_err());
    let ceilings = BlobCeilings {
        limits: BlobLimits::default(),
        anonymous: Some(AnonymousCeilings {
            deployment,
            capability,
        }),
    };
    let temp = tempfile::tempdir().unwrap();
    let db = Database::sqlite(temp.path().join("anonymous.db"));
    db.initialize().await.unwrap();
    let app = Arc::new(
        Application::new(
            &component(),
            &serde_json::to_vec(&m).unwrap(),
            crate::deployment::approval_digest(&m, Some(&ceilings), None, None).unwrap(),
            db.clone(),
            HostKeys::generate().unwrap(),
            Limits::default(),
            crate::DeploymentResources {
                effects: None,
                jobs: None,
                assets: Default::default(),
                blobs: Some(crate::BlobDeployment {
                    directory: temp.path().join("store"),
                    ceilings,
                }),
            },
        )
        .unwrap(),
    );
    app.activate().await.unwrap();
    let page = app
        .view_page_anonymous(None, None, 1, None, None)
        .await
        .unwrap();
    let anonymous = page.anonymous_cookie.unwrap();
    let page = String::from_utf8(page.body).unwrap();
    let router = crate::router(
        app.clone(),
        crate::Origin::parse("http://localhost:8080").unwrap(),
    );
    let mut request = post(
        "",
        &page,
        "anonymous",
        if absent { "" } else { "file.bin" },
        if absent { b"" } else { b"abc" },
    );
    request.headers_mut().insert(
        "cookie",
        format!("noxide_anon={anonymous}").parse().unwrap(),
    );
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let handover = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        handover.contains("edit secret") || handover.contains("Edit secret"),
        "{handover}"
    );
    let mut request = post(
        "",
        &page,
        "anonymous",
        if absent { "" } else { "ignored.bin" },
        if absent { b"" } else { b"never stage again" },
    );
    request.headers_mut().insert(
        "cookie",
        format!("noxide_anon={anonymous}").parse().unwrap(),
    );
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 65536).await.unwrap(),
        handover.as_bytes()
    );
    app.request_lifecycle().drain().await.unwrap();
    let mut tx = db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let rows = tx
        .fetch::<2>("SELECT state,CAST(anonymous AS TEXT) FROM nx_blobs", &[])
        .await
        .unwrap();
    if absent {
        assert!(rows.is_empty());
    } else {
        assert_eq!(rows[0], ["attached".to_owned(), "1".to_owned()]);
    }
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_receipts", &[])
            .await
            .unwrap()[0][0],
        "1"
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn sqlite_anonymous_upload_requires_approval_and_retains_single_create_handover() {
    anonymous_handover(false).await;
    anonymous_handover(true).await;
}

#[cfg(unix)]
async fn native_http(db: Option<Database>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn exchange(path: &std::path::Path, request: Vec<u8>) -> Vec<u8> {
        let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
        stream.write_all(&request).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        response
    }
    fn split(response: &[u8]) -> (&str, &[u8]) {
        let offset = response.windows(4).position(|b| b == b"\r\n\r\n").unwrap();
        (
            std::str::from_utf8(&response[..offset]).unwrap(),
            &response[offset + 4..],
        )
    }
    let case = Case::new(db, declarations()).await;
    let socket = case._temp.path().join("http.sock");
    let listener = crate::Listener::unix(&socket).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(crate::serve(
        listener,
        case.app.clone(),
        crate::Origin::parse("http://localhost:8080").unwrap(),
        async {
            let _ = stopped.await;
        },
    ));
    let get = |path: &str| {
        format!("GET {path} HTTP/1.1\r\nHost: localhost:8080\r\nCookie: session={}\r\nConnection: close\r\n\r\n",case.session).into_bytes()
    };
    let response = exchange(&socket, get("/")).await;
    let (head, body) = split(&response);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = std::str::from_utf8(body).unwrap();
    let (_, body) = post(
        &case.session,
        page,
        "native HTTP",
        "file.bin",
        b"native streamed attachment",
    )
    .into_parts();
    let body = to_bytes(body, 65536).await.unwrap();
    let mut request=format!("POST /actions/1 HTTP/1.1\r\nHost: localhost:8080\r\nOrigin: http://localhost:8080\r\nCookie: session={}\r\nContent-Type: multipart/form-data; boundary=test-boundary\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",case.session,body.len()).into_bytes();
    request.extend_from_slice(&body);
    let response = exchange(&socket, request).await;
    let (head, body) = split(&response);
    assert!(
        head.starts_with("HTTP/1.1 303"),
        "{head}: {}",
        String::from_utf8_lossy(body)
    );
    let location = head
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .unwrap();
    let response = exchange(&socket, get(location)).await;
    let (head, body) = split(&response);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = std::str::from_utf8(body).unwrap();
    let href = page
        .split_once("href=\"/_noxide/download?")
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap();
    let response = exchange(&socket, get(&format!("/_noxide/download?{href}"))).await;
    let (head, body) = split(&response);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.contains("content-type: application/octet-stream"));
    assert!(head.contains("content-disposition: attachment; filename=\"file.bin\""));
    assert_eq!(body, b"native streamed attachment");
    stop.send(()).unwrap();
    serving.await.unwrap().unwrap();
}
#[cfg(unix)]
#[tokio::test]
async fn sqlite_native_nojs_http_upload_and_download() {
    native_http(None).await;
}

#[tokio::test]
async fn sqlite_download_slot_and_no_poll_watchdog_hold_until_actual_native_stop() {
    let mut m = declarations();
    m.blobs.as_mut().unwrap().limits.downloads = 1;
    let case = Case::new(None, m).await;
    let page = case.page().await;
    let response = case
        .router
        .clone()
        .oneshot(post(&case.session, &page, "note", "file.bin", b"abc"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let id = response.headers()["location"]
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let detail = String::from_utf8(
        case.app
            .view(&case.session, 2, Some(id))
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    let path = format!(
        "/_noxide/download?{}",
        detail
            .split_once("href=\"/_noxide/download?")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap()
    );
    let request = || {
        let mut request = Request::builder()
            .uri(&path)
            .header("Host", "localhost:8080")
            .header("Cookie", format!("session={}", case.session))
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(crate::TransportDeadline(
            Instant::now() + std::time::Duration::from_secs(60),
        ));
        request
    };
    let response = case.router.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        case.router
            .clone()
            .oneshot(request())
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
        "a completed native read still occupies the unconsumed stream slot"
    );
    case.app.request_lifecycle().drain().await.unwrap();
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(16)).await;
    tokio::time::resume();
    let permit = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        case.app.blobs().unwrap().streams().clone().acquire_owned(),
    )
    .await
    .unwrap()
    .unwrap();
    drop(permit);
    assert!(
        to_bytes(response.into_body(), 65536).await.is_err(),
        "a timed-out unpolled body cannot later return buffered bytes"
    );
    let response = case.router.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .as_ref(),
        b"abc"
    );
}

#[tokio::test]
async fn sqlite_live_stage_quota_is_per_account_across_sessions() {
    let case = Case::new(None, declarations()).await;
    let other = login(&case.app, "alice").await;
    let mut leases = Vec::new();
    for index in 0..5 {
        let session = if index % 2 == 0 {
            &case.session
        } else {
            &other
        };
        let page = String::from_utf8(case.app.view(session, 1, None).await.unwrap().body).unwrap();
        let result = case
            .app
            .prepare_upload(
                session,
                1,
                &prefix(&page, "note"),
                Some(noxide_blobs::transport::AttachmentName::normalize("file.bin").unwrap()),
            )
            .await;
        if index < 4 {
            leases.push(result.unwrap());
        } else {
            assert!(
                result.is_err(),
                "another login must not create four additional stages"
            );
        }
    }
    drop(leases);
    case.maintenance().await;
    assert_eq!(case.state().await.2, "0");
}
#[tokio::test]
async fn sqlite_canceled_committed_gc_claim_recovers_without_restart() {
    let case = Case::new(None, declarations()).await;
    let prepared = case
        .app
        .prepare_upload(
            &case.session,
            1,
            &prefix(&case.page().await, "note"),
            Some(noxide_blobs::transport::AttachmentName::normalize("file.bin").unwrap()),
        )
        .await
        .unwrap();
    let PreparedUpload::Created(row, lease) = prepared else {
        panic!("reservation")
    };
    drop(lease);
    let barrier = Arc::new(Barrier::default());
    *case.app.blobs().unwrap().gc_after_commit().lock().unwrap() = Some(barrier.clone());
    let app = case.app.clone();
    let task = tokio::spawn(async move {
        app.test_reconcile_blobs(Instant::now() + std::time::Duration::from_secs(2))
            .await
    });
    barrier.entered.notified().await;
    assert_eq!(case.state().await.0, "deleting");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    *case.app.blobs().unwrap().gc_after_commit().lock().unwrap() = None;
    case.maintenance().await;
    let state = case.state().await;
    assert_eq!(
        (state.0.as_str(), state.2.as_str(), state.3.as_str()),
        ("deleted", "0", "0")
    );
    assert!(
        case.app
            .blobs()
            .unwrap()
            .undispatched()
            .lock()
            .unwrap()
            .get(row.metadata.key.as_str())
            .is_none()
    );
}
async fn attachment_wins_gc(db: Option<Database>) {
    use std::{future::Future, task::Poll};
    let mut m = declarations();
    m.actions[0].steps[0].guards.push(Guard {
        condition: GuardCondition::Compare {
            left: Value::Input("body".into()),
            comparison: Comparison::Equal,
            right: Value::Literal(Literal::Text("corrected".into())),
        },
        rejection: GuardRejection {
            input: None,
            message: "Correct this note".into(),
        },
    });
    let case = Case::new(db, m).await;
    let response = case
        .router
        .clone()
        .oneshot(post(
            &case.session,
            &case.page().await,
            "bad",
            "file.bin",
            b"abc",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let recovery = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let state = case.state().await;
    let key = ObjectKey::parse(
        case.app
            .blobs()
            .unwrap()
            .workers()
            .lock()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone(),
    )
    .unwrap();
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let row = MetadataContext { tx: &mut tx }
        .object(&key)
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    let barrier = Arc::new(Barrier::default());
    *case.app.blobs().unwrap().verification().lock().unwrap() = Some(barrier.clone());
    let app = case.app.clone();
    let session = case.session.clone();
    let token = crate::test_support::hidden(&recovery, "_submission");
    let csrf = crate::test_support::hidden(&recovery, "_csrf");
    let action = tokio::spawn(async move {
        app.submit(
            &session,
            1,
            &token,
            &csrf,
            Fields::from([
                ("body".into(), "corrected".into()),
                ("attachment".into(), state.1),
            ]),
        )
        .await
    });
    barrier.entered.notified().await;
    // Poll the competing provider attempt while attachment owns the stage lock.
    // Its stale expired-stage claim must fail after the attachment commits.
    let scope = case.app.blob_phase(std::time::Duration::from_secs(2));
    let app = case.app.clone();
    let gc = scope.run(async {
        let owner = app.test_admission_owner().await?;
        owner
            .run(async {
                let mut tx = app
                    .test_database()
                    .begin(owner.work_deadline().into_std())
                    .await?;
                let result = MetadataContext { tx: &mut tx }
                    .claim_collectable(&row, app.blobs().unwrap().process(), row.metadata.expires)
                    .await;
                tx.rollback().await?;
                result.map(|_| ())
            })
            .await
    });
    tokio::pin!(gc);
    std::future::poll_fn(|cx| {
        assert!(gc.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    barrier.release.notify_one();
    let (action, gc) = tokio::join!(action, gc);
    action.unwrap().unwrap();
    assert!(gc.is_err());
    let state = case.state().await;
    assert_eq!(
        (state.0.as_str(), state.3.as_str(), state.4.as_str()),
        ("attached", "3", "1")
    );
}
#[tokio::test]
async fn sqlite_attachment_row_lock_excludes_competing_gc() {
    attachment_wins_gc(None).await;
}

struct WaitingBody {
    first: Option<axum::body::Bytes>,
    waiting: Option<tokio::sync::oneshot::Sender<()>>,
}
impl hyper::body::Body for WaitingBody {
    type Data = axum::body::Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        if let Some(bytes) = self.first.take() {
            return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))));
        }
        if let Some(waiting) = self.waiting.take() {
            let _ = waiting.send(());
        }
        std::task::Poll::Pending
    }
}
#[tokio::test]
async fn sqlite_slow_prefix_and_file_enforce_original_root_and_idle_deadlines() {
    for file in [false, true] {
        let case = Case::new(None, declarations()).await;
        let (mut parts, body) = post(
            &case.session,
            &case.page().await,
            "note",
            "file.bin",
            b"partial",
        )
        .into_parts();
        let bytes = to_bytes(body, 65536).await.unwrap();
        let first = if file {
            bytes.slice(..bytes.len() - b"\r\n--test-boundary--\r\n".len())
        } else {
            axum::body::Bytes::from_static(b"--test-boundary\r\n")
        };
        parts.extensions.insert(crate::TransportDeadline(
            Instant::now() + std::time::Duration::from_secs(60),
        ));
        let (waiting, entered) = tokio::sync::oneshot::channel();
        let request = Request::from_parts(
            parts,
            Body::new(WaitingBody {
                first: Some(first),
                waiting: Some(waiting),
            }),
        );
        let router = case.router.clone();
        let task = tokio::spawn(async move { router.oneshot(request).await.unwrap() });
        entered.await.unwrap();
        case.app.request_lifecycle().drain().await.unwrap();
        tokio::time::pause();
        tokio::time::advance(std::time::Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        if file {
            assert!(
                !task.is_finished(),
                "the approved transfer phase retains the original outer deadline"
            );
            tokio::time::advance(std::time::Duration::from_secs(13)).await;
        }
        tokio::time::resume();
        let response = task.await.unwrap();
        assert!(response.status().is_client_error());
        let workers: Vec<_> = case
            .app
            .blobs()
            .unwrap()
            .workers()
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for worker in workers {
            tokio::time::timeout(std::time::Duration::from_secs(2), worker.wait_stopped())
                .await
                .unwrap();
        }
        if file {
            case.maintenance().await;
        }
        let state = case.state().await;
        assert_eq!(
            (state.2.as_str(), state.3.as_str(), state.4.as_str()),
            ("0", "0", "0")
        );
        if file {
            assert_eq!(state.0, "deleted");
        } else {
            assert!(state.0.is_empty());
        }
    }
}
#[tokio::test]
async fn sqlite_optional_absence_is_host_canonical_and_no_blob_id_mints_a_download() {
    let mut m = declarations();
    m.resources[0].fields[1].optional = true;
    m.actions[0].inputs[1].optional = true;
    let case = Case::new(None, m).await;
    let page = case.page().await;
    let response = case
        .router
        .clone()
        .oneshot(post(&case.session, &page, "note", "", b""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let original = response.headers()["location"].clone();
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let rows = tx
        .fetch::<1>("SELECT fields FROM nx_records", &[])
        .await
        .unwrap();
    let fields: Fields = serde_json::from_str(&rows[0][0]).unwrap();
    assert_eq!(fields.get("attachment").unwrap(), "");
    assert_eq!(fields.get("extra").unwrap(), "");
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_blobs", &[])
            .await
            .unwrap()[0][0],
        "0"
    );
    tx.commit().await.unwrap();
    let replay = case
        .router
        .clone()
        .oneshot(post(&case.session, &page, "note", "", b""))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::SEE_OTHER);
    assert_eq!(replay.headers()["location"], original);
    let changed = case
        .router
        .clone()
        .oneshot(post(&case.session, &page, "changed", "", b""))
        .await
        .unwrap();
    assert!(changed.status().is_client_error());
    let replacement = case
        .router
        .clone()
        .oneshot(post(
            &case.session,
            &page,
            "note",
            "new.bin",
            b"never staged",
        ))
        .await
        .unwrap();
    assert!(replacement.status().is_client_error());
    assert_eq!(case.state().await.4, "1");
    for path in [
        format!("/_noxide/download?ticket=b1_{}", "a".repeat(64)),
        "/_noxide/download?read=2&target=1&field=attachment".into(),
    ] {
        let response = case
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("Host", "localhost:8080")
                    .header("Cookie", format!("session={}", case.session))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
#[tokio::test]
async fn sqlite_download_instruction_requires_successful_read_and_exact_projection() {
    for read in [false, true] {
        let mut m = declarations();
        if read {
            m.resources[0].fields.push(TextField {
                immutable: false,
                name: "published".into(),
                label: "Published".into(),
                kind: FieldKind::Boolean,
                optional: false,
                initial: Some("true".into()),
                max_bytes: 5,
            });
            m.operations[1].policy = Policy {
                any: vec![vec![Predicate::Public]],
            };
            m.operations[1].visibility = Some(Visibility {
                field: "published".into(),
                equals: "true".into(),
            });
            m.operations[1].fields = Some(vec!["body".into()]);
            m.routes[1].access = Access::PublicOptional;
        }
        let case = Case::with_component(None, m, component_with_read(read)).await;
        let response = case
            .router
            .clone()
            .oneshot(post(
                &case.session,
                &case.page().await,
                "note",
                "file.bin",
                b"abc",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let id = response.headers()["location"]
            .to_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            case.app.view(&case.session, 2, Some(id)).await.is_err(),
            "an instruction alone cannot synthesize Read provenance or widen its projection"
        );
        assert_eq!(case.state().await.0, "attached");
    }
}

async fn lifecycle_clock_safety(db: Option<Database>) {
    let case = Case::new(db, declarations()).await;
    assert!(authority::uses_time(case.app.manifest()));
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let clock=tx.fetch::<2>("SELECT CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock WHERE singleton=1",&[]).await.unwrap();
    let future = (clock[0][0].parse::<i64>().unwrap() / 1000 + 7200) * 1000 + 123;
    tx.execute("UPDATE nx_clock SET lifecycle_ms=$1,lifecycle_version=lifecycle_version+1 WHERE singleton=1",&[future.into()]).await.unwrap();
    tx.commit().await.unwrap();
    // The existing startup tick sees a lower wall sample and preserves the
    // durable watermark, including its subsecond precision.
    case.app.request_lifecycle().drain().await.unwrap();
    case.app.activate().await.unwrap();
    let original = case.page().await;
    let response = case
        .router
        .clone()
        .oneshot(post(&case.session, &original, "note", "file.bin", b"abc"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let id = response.headers()["location"]
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let row = tx
        .fetch::<2>(
            "SELECT CAST(created_ms AS TEXT),CAST(expires_ms AS TEXT) FROM nx_blobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        row[0],
        [
            future.to_string(),
            (future + STAGE_LIFETIME_MILLIS).to_string()
        ]
    );
    let before=tx.fetch::<3>("SELECT CAST(observed AS TEXT),CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock",&[]).await.unwrap();
    tx.commit().await.unwrap();
    let detail = String::from_utf8(
        case.app
            .view(&case.session, 2, Some(id))
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    let path = format!(
        "/_noxide/download?{}",
        detail
            .split_once("href=\"/_noxide/download?")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap()
    );
    let get = || {
        Request::builder()
            .uri(&path)
            .header("Host", "localhost:8080")
            .header("Cookie", format!("session={}", case.session))
            .body(Body::empty())
            .unwrap()
    };
    let response = case.router.clone().oneshot(get()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .as_ref(),
        b"abc"
    );
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(tx.fetch::<3>("SELECT CAST(observed AS TEXT),CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock",&[]).await.unwrap(),before,"GET and download must not write clock state");
    tx.commit().await.unwrap();
    let fresh = case.page().await;
    case.app.request_lifecycle().drain().await.unwrap();
    // This expires the existing freshness lease; it does not order a race.
    tokio::time::sleep(
        crate::lifecycle_clock::FRESHNESS_LIMIT + std::time::Duration::from_millis(50),
    )
    .await;
    let error = case
        .app
        .prepare_upload(
            &case.session,
            1,
            &prefix(&fresh, "new"),
            Some(noxide_blobs::transport::AttachmentName::normalize("new.bin").unwrap()),
        )
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error.downcast_ref::<RequestError>(),
        Some(RequestError::Busy)
    ));
    assert_eq!(
        case.router.clone().oneshot(get()).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    assert!(
        case.app
            .test_reconcile_blobs(Instant::now() + std::time::Duration::from_secs(2))
            .await
            .is_err()
    );
    let replay = case
        .router
        .clone()
        .oneshot(post(
            &case.session,
            &original,
            "note",
            "ignored.bin",
            b"never staged",
        ))
        .await
        .unwrap();
    assert!(
        replay.status() == StatusCode::OK || replay.status() == StatusCode::SEE_OTHER,
        "known receipts recover before stale lifecycle checks"
    );
    assert_eq!(case.state().await.4, "1");
}

async fn absence_and_prefix_are_serialized(db: Option<Database>) {
    use std::{future::Future, task::Poll};
    let mut m = declarations();
    m.resources[0].fields[1].optional = true;
    m.actions[0].inputs[1].optional = true;
    let case = Case::new(db, m).await;
    let page = case.page().await;
    let fields = prefix(&page, "note");
    let barrier = Arc::new(Barrier::default());
    *case.app.blobs().unwrap().verification().lock().unwrap() = Some(barrier.clone());
    let app = case.app.clone();
    let session = case.session.clone();
    let token = crate::test_support::hidden(&page, "_submission");
    let csrf = crate::test_support::hidden(&page, "_csrf");
    let absence = tokio::spawn(async move {
        app.submit(
            &session,
            1,
            &token,
            &csrf,
            Fields::from([
                ("body".into(), "note".into()),
                ("attachment".into(), String::new()),
            ]),
        )
        .await
    });
    barrier.entered.notified().await;
    let filename = noxide_blobs::transport::AttachmentName::normalize("new.bin").unwrap();
    let competing = case
        .app
        .prepare_upload(&case.session, 1, &fields, Some(filename));
    tokio::pin!(competing);
    std::future::poll_fn(|cx| {
        assert!(competing.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    barrier.release.notify_one();
    let (absence, competing) = tokio::join!(absence, competing);
    absence.unwrap().unwrap();
    assert!(matches!(
        competing.err().unwrap().downcast_ref::<RequestError>(),
        Some(RequestError::InvalidRequest)
    ));
    let state = case.state().await;
    assert_eq!(
        (
            state.0.as_str(),
            state.2.as_str(),
            state.3.as_str(),
            state.4.as_str()
        ),
        ("", "0", "0", "1")
    );
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let records = tx
        .fetch::<1>("SELECT fields FROM nx_records", &[])
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    let fields: Fields = serde_json::from_str(&records[0][0]).unwrap();
    assert_eq!(fields["attachment"], "");
    tx.commit().await.unwrap();
}
async fn empty_cannot_discard_stage(db: Option<Database>) {
    let mut m = declarations();
    m.resources[0].fields[1].optional = true;
    m.actions[0].inputs[1].optional = true;
    m.actions[0].steps[0].guards.push(Guard {
        condition: GuardCondition::Compare {
            left: Value::Input("body".into()),
            comparison: Comparison::Equal,
            right: Value::Literal(Literal::Text("corrected".into())),
        },
        rejection: GuardRejection {
            input: None,
            message: "Correct this note".into(),
        },
    });
    let case = Case::new(db, m).await;
    let response = case
        .router
        .clone()
        .oneshot(post(
            &case.session,
            &case.page().await,
            "bad",
            "file.bin",
            b"abc",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let recovery = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("_csrf", &crate::test_support::hidden(&recovery, "_csrf"))
        .append_pair(
            "_submission",
            &crate::test_support::hidden(&recovery, "_submission"),
        )
        .append_pair("body", "corrected")
        .append_pair("attachment", "")
        .finish();
    let request = Request::builder()
        .method("POST")
        .uri("/actions/1")
        .header("Host", "localhost:8080")
        .header("Origin", "http://localhost:8080")
        .header("Cookie", format!("session={}", case.session))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    assert!(
        case.router
            .clone()
            .oneshot(request)
            .await
            .unwrap()
            .status()
            .is_client_error()
    );
    let state = case.state().await;
    assert_eq!(
        (state.0.as_str(), state.3.as_str(), state.4.as_str()),
        ("staged", "3", "0")
    );
    let response = case
        .router
        .clone()
        .oneshot(post(&case.session, &recovery, "corrected", "", b""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let state = case.state().await;
    assert_eq!(
        (state.0.as_str(), state.3.as_str(), state.4.as_str()),
        ("attached", "3", "1")
    );
}
#[tokio::test]
async fn sqlite_inflight_optional_absence_blocks_file_prefix_and_empty_submit_cannot_drop_stage() {
    absence_and_prefix_are_serialized(None).await;
    empty_cannot_discard_stage(None).await;
}

#[tokio::test]
async fn sqlite_blob_lifecycle_uses_durable_milliseconds_and_stale_reads_fail_closed() {
    lifecycle_clock_safety(None).await;
}

/// Delegates to the real host and counts fence calls, so a transaction that skips
/// the deployment fence after this logic moved into `noxide-blobs` fails here.
struct CountingFence<'a> {
    app: &'a Application,
    fences: std::sync::atomic::AtomicUsize,
}
impl ReconcileHost for CountingFence<'_> {
    fn database(&self) -> &Database {
        ReconcileHost::database(self.app)
    }
    async fn fence<'a>(&'a self, tx: &'a mut Transaction) -> anyhow::Result<()> {
        self.fences.fetch_add(1, Ordering::SeqCst);
        ReconcileHost::fence(self.app, tx).await
    }
    async fn observed_now<'a>(&'a self, tx: &'a mut Transaction) -> anyhow::Result<Timestamp> {
        ReconcileHost::observed_now(self.app, tx).await
    }
}

#[tokio::test]
async fn sqlite_every_reconcile_transaction_passes_the_deployment_fence() {
    let case = Case::new(None, declarations()).await;
    let prepared = case
        .app
        .prepare_upload(
            &case.session,
            1,
            &prefix(&case.page().await, "note"),
            Some(noxide_blobs::transport::AttachmentName::normalize("file.bin").unwrap()),
        )
        .await
        .unwrap();
    let PreparedUpload::Created(_, lease) = prepared else {
        panic!("reservation")
    };
    drop(lease);
    let app = &case.app;
    let counting = CountingFence {
        app,
        fences: Default::default(),
    };
    app.test_reconcile_blobs_through(
        &counting,
        Instant::now() + std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(case.state().await.0, "deleted");
    // The inventory page, the deletion claim and the deletion's completion.
    assert_eq!(counting.fences.load(Ordering::SeqCst), 3);
}
