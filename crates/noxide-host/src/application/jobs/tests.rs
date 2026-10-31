//! Real component/core/queue proofs. Every database is a fresh retained fixture.
use super::*;
use crate::{
    HostKeys,
    job_deployment::{JobDeployment, JobGrant, JobLimits},
    test_support as fixture,
};
use noxide_protocol::{computation::Literal, jobs::*, time::Duration};
use std::{collections::BTreeSet, path::PathBuf};

pub(in crate::application) fn declarations(expiry: bool) -> Manifest {
    let mut m = fixture::manifest();
    let service = Policy {
        any: vec![vec![
            Predicate::Service {
                worker: "repair".into(),
            },
            Predicate::SameTenant,
        ]],
    };
    let mut read = m.operations[1].clone();
    read.id = 4;
    read.policy = service.clone();
    let mut update = read.clone();
    update.id = 5;
    update.kind = OperationKind::Update;
    m.operations.extend([read, update]);
    m.actions.push(Action {
        id: 2,
        version: 1,
        name: "Finish note".into(),
        targets: vec![ActionTarget {
            name: "record".into(),
            resource: 1,
            source: TargetSource::Service { eligible: 4 },
            revision: Revision::Identity,
            projection: Some(Inspection {
                operation: 4,
                fields: vec!["body".into()],
            }),
            inspect: None,
        }],
        inputs: vec![],
        steps: vec![Step {
            operation: 5,
            target: Target::Named("record".into()),
            guards: vec![Guard {
                condition: GuardCondition::Compare {
                    left: Value::SnapshotField {
                        target: "record".into(),
                        field: "body".into(),
                        reviewed: false,
                    },
                    comparison: Comparison::Equal,
                    right: Value::Literal(Literal::Text("ready".into())),
                },
                rejection: GuardRejection {
                    input: None,
                    message: "Already completed".into(),
                },
            }],
            assign: vec![Assignment {
                field: "body".into(),
                change: Change::Set(Value::Literal(Literal::Text("finished".into()))),
            }],
        }],
    });
    m.jobs = Some(JobContract {
        workers: vec![Worker {
            name: "repair".into(),
            actions: vec![WorkerAction {
                action: 2,
                targets: BTreeMap::from([(
                    "record".into(),
                    WorkerTarget {
                        resource: 1,
                        eligible: 4,
                    },
                )]),
            }],
        }],
        schedules: vec![Schedule {
            source_action: 1,
            ordinal: 0,
            worker: "repair".into(),
            action: 2,
            targets: BTreeMap::from([("record".into(), ScheduledTarget::Created(0))]),
            inputs: BTreeMap::new(),
            due_at: Value::TransactionTime,
        }],
        recurring: vec![],
    });
    if expiry {
        m.resources[0].fields.push(TextField {
            immutable: true,
            kind: FieldKind::Timestamp,
            optional: false,
            initial: None,
            name: "expires_at".into(),
            label: "Expires".into(),
            max_bytes: 64,
        });
        m.resources[0].expiry = Some(noxide_protocol::expiry::ResourceExpiry {
            field: "expires_at".into(),
            max_after: Duration::from_millis(60_000).unwrap(),
        });
        m.actions[0].steps[0].assign.push(Assignment {
            field: "expires_at".into(),
            change: Change::Set(Value::Add {
                left: Box::new(Value::TransactionTime),
                right: Box::new(Value::Literal(Literal::Duration(
                    Duration::from_millis(60_000).unwrap(),
                ))),
            }),
        });
    }
    m
}

pub(in crate::application) struct Case {
    pub(in crate::application) path: PathBuf,
    pub(in crate::application) db: Database,
    pub(in crate::application) app: Arc<Application>,
    pub(in crate::application) cookie: String,
    clock: Option<super::super::clock::ClockService>,
}
impl Case {
    pub(in crate::application) async fn new(database: Option<Database>, expiry: bool) -> Self {
        Self::new_manifest(database, declarations(expiry)).await
    }
    pub(in crate::application) async fn new_manifest(
        database: Option<Database>,
        m: Manifest,
    ) -> Self {
        Self::new_component(database, m, fixture::component(None)).await
    }
    async fn new_component(database: Option<Database>, m: Manifest, component: Vec<u8>) -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/capability-evidence/p10-action-fixtures");
        std::fs::create_dir_all(&directory).unwrap();
        let path = tempfile::Builder::new()
            .prefix("real-action-")
            .tempdir_in(directory)
            .unwrap()
            .keep();
        let db = database.unwrap_or_else(|| Database::sqlite(path.join("runtime.db")));
        db.initialize().await.unwrap();
        db.create_account("alice", "service fixture password", "team")
            .await
            .unwrap();
        let job_deployment = JobDeployment {
            grants: vec![JobGrant {
                worker: "repair".into(),
                tenant: "team".into(),
                actions: m.jobs.as_ref().unwrap().workers[0]
                    .actions
                    .iter()
                    .map(|rule| rule.action)
                    .collect::<BTreeSet<_>>(),
            }],
            limits: JobLimits::default(),
        };
        let approved = crate::deployment::approval_digest(&m, None, Some(&job_deployment)).unwrap();
        let app = Arc::new(
            Application::new(
                &component,
                &serde_json::to_vec(&m).unwrap(),
                approved,
                db.clone(),
                HostKeys::generate().unwrap(),
                Limits::default(),
                crate::DeploymentResources {
                    assets: crate::assets::AssetBundle::default(),
                    blobs: None,
                    jobs: Some(job_deployment),
                },
            )
            .unwrap(),
        );
        app.activate().await.unwrap();
        let clock = Some(app.start_clock_service().unwrap());
        let login = app.login_challenge().await.unwrap();
        let cookie = app
            .login(
                &login.cookie,
                &login.csrf,
                "alice",
                "service fixture password",
            )
            .await
            .unwrap();
        eprintln!("retained P10 real action fixture: {}", path.display());
        Self {
            path,
            db,
            app,
            cookie,
            clock,
        }
    }
    pub(in crate::application) async fn close(mut self) {
        if let Some(clock) = self.clock.take() {
            clock.shutdown().await.unwrap();
        }
        if let Some(jobs) = &self.app.jobs {
            jobs.lifecycle.wait_idle_for_test().await.unwrap();
        }
        self.app
            .request_lifecycle
            .wait_idle_for_test()
            .await
            .unwrap();
        assert!(self.path.is_dir());
    }
    pub(in crate::application) async fn form(&self) -> (String, String) {
        let route = self
            .app
            .manifest
            .routes
            .iter()
            .find(|route| route.forms.contains(&1))
            .unwrap();
        let page = self
            .app
            .view(&self.cookie, route.id, route.resource.map(|_| 1))
            .await
            .unwrap();
        let html = String::from_utf8(page.body).unwrap();
        (
            fixture::hidden(&html, "_submission"),
            fixture::hidden(&html, "_csrf"),
        )
    }
    pub(in crate::application) async fn create(&self, value: &str) -> CapturedJob {
        let (submission, csrf) = self.form().await;
        self.app
            .submit(
                &self.cookie,
                1,
                &submission,
                &csrf,
                Fields::from([("body".into(), value.into())]),
            )
            .await
            .unwrap();
        let mut tx = self
            .db
            .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .unwrap();
        let rows = tx
            .fetch::<1>("SELECT payload FROM nx_jobs ORDER BY id", &[])
            .await
            .unwrap();
        let job = serde_json::from_str(&rows.last().unwrap()[0]).unwrap();
        tx.commit().await.unwrap();
        job
    }
    pub(in crate::application) async fn claim(&self, offset: i64) -> Option<Claim> {
        let scope = self.app.request_scope(self.app.runtime.limits().wall_time);
        scope
            .run(async {
                let admission = self.app.admit_job_invocation_work().await.unwrap();
                let owner = admission.owner;
                owner
                    .run(async {
                        let mut tx = self
                            .db
                            .begin(owner.work_deadline().into_std())
                            .await
                            .unwrap();
                        self.app.admission(&mut tx, false).await.unwrap();
                        let now = self
                            .app
                            .temporal_after_admission(&mut tx)
                            .await
                            .unwrap()
                            .timestamp()
                            .checked_add(Duration::from_millis(offset).unwrap())
                            .unwrap();
                        let mut calls = 16;
                        let claim = QueueContext {
                            tx: &mut tx,
                            calls: &mut calls,
                        }
                        .claim(self.app.generation.get().unwrap(), now)
                        .await
                        .unwrap();
                        tx.commit().await.unwrap();
                        claim
                    })
                    .await
            })
            .await
    }
    pub(in crate::application) async fn stored(
        &self,
        job: &CapturedJob,
    ) -> (String, String, usize) {
        let mut tx = self
            .db
            .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .unwrap();
        let queue = tx
            .fetch::<2>(
                "SELECT state,reason FROM nx_jobs WHERE id=$1",
                &[job.id().unwrap().into()],
            )
            .await
            .unwrap();
        let target = &job.targets()["record"];
        let stored = repository::load(&mut tx, &self.app.manifest, target.resource, target.id)
            .await
            .unwrap()
            .unwrap();
        let receipts = tx
            .fetch::<1>(
                "SELECT CAST(COUNT(*) AS TEXT) FROM nx_receipts WHERE nonce=$1",
                &[job.id().unwrap().into()],
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (
            queue[0][0].clone(),
            stored.record.fields["body"].clone(),
            receipts[0][0].parse().unwrap(),
        )
    }
    pub(in crate::application) async fn revoke(&self) {
        let mut tx = self
            .db
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .unwrap();
        tx.execute(
            "UPDATE nx_job_grants SET state='revoked' WHERE worker='repair'",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    pub(in crate::application) async fn change_record(&self, job: &CapturedJob, expiry: bool) {
        let mut tx = self
            .db
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .unwrap();
        let target = &job.targets()["record"];
        let storage = tx
            .storage_resource(&self.app.manifest, target.resource)
            .await
            .unwrap();
        if expiry {
            let mut fields =
                repository::load(&mut tx, &self.app.manifest, target.resource, target.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .record
                    .fields;
            fields.insert("expires_at".into(), "0".into());
            tx.execute(
                "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2 AND id=$3",
                &[
                    serde_json::to_string(&fields).unwrap().into(),
                    storage.into(),
                    (target.id as i64).into(),
                ],
            )
            .await
            .unwrap();
        } else {
            tx.execute("UPDATE nx_records SET tenant='other',revision=revision+1 WHERE resource=$1 AND id=$2", &[storage.into(), (target.id as i64).into()]).await.unwrap();
        }
        tx.commit().await.unwrap();
    }
}

async fn success(database: Option<Database>) {
    let case = Case::new(database, false).await;
    let job = case.create("ready").await;
    assert!(job.input().is_empty());
    assert_eq!(job.targets()["record"].revision, 0);
    let claim = case.claim(0).await.unwrap();
    assert!(
        case.claim(0).await.is_none(),
        "a live claim cannot be duplicated"
    );
    let (result, roots) =
        crate::database::lifecycle::observe_roots(case.app.invoke_job(&claim)).await;
    assert!(
        matches!(result.unwrap(), JobRunOutcome::Completed { recovered: false, ref outcomes } if outcomes.len() == 1)
    );
    assert_eq!(
        roots.len(),
        1,
        "one root covers complete service invocation"
    );
    eprintln!(
        "service invocation statement meter: {:?}",
        roots[0].statement_snapshot()
    );
    assert_eq!(
        case.stored(&job).await,
        ("succeeded".into(), "finished".into(), 1)
    );
    case.revoke().await;
    case.app.lifecycle_clock.quarantine();
    assert!(
        matches!(
            case.app.invoke_job(&claim).await.unwrap(),
            JobRunOutcome::Completed {
                recovered: true,
                ..
            }
        ),
        "receipt recovery precedes revocation and stale lifecycle checks"
    );
    assert_eq!(
        case.stored(&job).await,
        ("succeeded".into(), "finished".into(), 1)
    );
    case.close().await;
}
async fn rejection(database: Option<Database>) {
    let case = Case::new(database, false).await;
    let job = case.create("blocked").await;
    let claim = case.claim(0).await.unwrap();
    let result = case.app.invoke_job(&claim).await.unwrap();
    let JobRunOutcome::BusinessRejected(rejection) = result else {
        panic!("expected structured terminal guard rejection")
    };
    assert!(
        matches!(rejection.as_rejection(), ActionRejection::GuardRejected { input: None, message } if message == "Already completed")
    );
    assert_eq!(
        case.stored(&job).await,
        ("rejected".into(), "blocked".into(), 0)
    );
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let rows = tx
        .fetch::<1>(
            "SELECT reason FROM nx_jobs WHERE id=$1",
            &[job.id().unwrap().into()],
        )
        .await
        .unwrap();
    assert!(matches!(
        ValidatedActionRejection::from_stored(&case.app.manifest.actions[1], &rows[0][0])
            .unwrap()
            .as_rejection(),
        ActionRejection::GuardRejected { input: None, .. }
    ));
    tx.commit().await.unwrap();
    case.close().await;
}
async fn denied(database: Option<Database>, expiry: bool) {
    let case = Case::new(database, expiry).await;
    let job = case.create("ready").await;
    let claim = case.claim(0).await.unwrap();
    case.change_record(&job, expiry).await;
    assert!(matches!(
        case.app.invoke_job(&claim).await.unwrap(),
        JobRunOutcome::Unavailable
    ));
    assert_eq!(
        case.stored(&job).await,
        ("rejected".into(), "ready".into(), 0)
    );
    case.close().await;
}
async fn approved_maintenance(database: Option<Database>) {
    let mut m = declarations(true);
    for op in &mut m.operations {
        if matches!(op.id, 4 | 5) {
            op.maintenance = true;
        }
    }
    let case = Case::new_manifest(database, m).await;
    let job = case.create("ready").await;
    let claim = case.claim(0).await.unwrap();
    case.change_record(&job, true).await;
    assert!(matches!(
        case.app.invoke_job(&claim).await.unwrap(),
        JobRunOutcome::Completed {
            recovered: false,
            ..
        }
    ));
    assert_eq!(
        case.stored(&job).await,
        ("succeeded".into(), "finished".into(), 1)
    );
    case.close().await;
}
#[tokio::test]
async fn sqlite_service_explicit_maintenance_can_update_expired_row() {
    approved_maintenance(None).await;
}

async fn revoked(database: Option<Database>) {
    let case = Case::new(database, false).await;
    let job = case.create("ready").await;
    let claim = case.claim(0).await.unwrap();
    case.revoke().await;
    assert!(matches!(
        case.app.invoke_job(&claim).await.unwrap(),
        JobRunOutcome::Paused
    ));
    assert_eq!(
        case.stored(&job).await,
        ("paused".into(), "ready".into(), 0)
    );
    case.close().await;
}
async fn stale_fence(database: Option<Database>) {
    let case = Case::new(database, false).await;
    let job = case.create("ready").await;
    let stale = case.claim(0).await.unwrap();
    let current = case.claim(JOB_LEASE_MILLIS).await.unwrap();
    assert!(current.fence() > stale.fence());
    assert!(case.app.invoke_job(&stale).await.is_err());
    assert_eq!(
        case.stored(&job).await,
        ("running".into(), "ready".into(), 0)
    );
    assert!(matches!(
        case.app.invoke_job(&current).await.unwrap(),
        JobRunOutcome::Completed {
            recovered: false,
            ..
        }
    ));
    assert_eq!(
        case.stored(&job).await,
        ("succeeded".into(), "finished".into(), 1)
    );
    case.close().await;
}
async fn lost_ack(database: Option<Database>) {
    let case = Case::new(database, false).await;
    let job = case.create("ready").await;
    let claim = case.claim(0).await.unwrap();
    let result = crate::failure_tests::lose_commit_ack(case.app.invoke_job(&claim)).await;
    assert!(matches!(result, Err(RequestError::OutcomeUnknown)));
    case.app
        .request_lifecycle
        .wait_idle_for_test()
        .await
        .unwrap();
    assert_eq!(
        case.stored(&job).await,
        ("succeeded".into(), "finished".into(), 1)
    );
    assert!(matches!(
        case.app.invoke_job(&claim).await.unwrap(),
        JobRunOutcome::Completed {
            recovered: true,
            ..
        }
    ));
    assert_eq!(
        case.stored(&job).await,
        ("succeeded".into(), "finished".into(), 1)
    );
    case.close().await;
}
async fn enqueue_rollback(database: Option<Database>) {
    let case = Case::new(database, false).await;
    let (submission, csrf) = case.form().await;
    case.revoke().await;
    assert!(
        case.app
            .submit(
                &case.cookie,
                1,
                &submission,
                &csrf,
                Fields::from([("body".into(), "ready".into())])
            )
            .await
            .is_err()
    );
    case.app
        .request_lifecycle
        .wait_idle_for_test()
        .await
        .unwrap();
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    for table in ["nx_records", "nx_receipts", "nx_jobs"] {
        let rows = tx
            .fetch::<1>(&format!("SELECT CAST(COUNT(*) AS TEXT) FROM {table}"), &[])
            .await
            .unwrap();
        assert_eq!(rows[0][0], "0", "enqueue failure rolls back {table}");
    }
    tx.commit().await.unwrap();
    case.close().await;
}

fn worker_trap_component() -> Vec<u8> {
    fn emit(bytes: &[u8]) -> String {
        bytes
            .chunks(8)
            .map(|chunk| {
                let mut word = [0; 8];
                word[..chunk.len()].copy_from_slice(chunk);
                format!(
                    "i64.const {} i32.const {} call $emit\n",
                    i64::from_le_bytes(word),
                    chunk.len()
                )
            })
            .collect()
    }
    let page = emit(
        &serde_json::to_vec(&ResponseIntent::Page(Document::new(
            "Worker fixture",
            vec![Instruction::Form { action: 1 }],
        )))
        .unwrap(),
    );
    let execute = emit(&serde_json::to_vec(&ResponseIntent::Execute).unwrap());
    let kind = format!(r#"{{"version":{VERSION},"kind":{{"#).len() + 1;
    let action = format!(r#"{{"version":{VERSION},"kind":{{"action":"#).len();
    wat::parse_str(format!(r#"(component
      (import "noxide:application/host@0.1.0" (instance $h
        (export "emit" (func (param "word" u64) (param "length" u32)))
        (export "request-chunk" (func (param "offset" u32) (result u64)))))
      (alias export $h "emit" (func $emit)) (core func $emit (canon lower (func $emit)))
      (alias export $h "request-chunk" (func $request)) (core func $request (canon lower (func $request)))
      (core module $m (import "h" "emit" (func $emit (param i64 i32)))
        (import "h" "request" (func $request (param i32) (result i64)))
        (func (export "handle")
          i32.const {kind} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 97 i32.eq
          if i32.const {action} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 50 i32.eq
            if unreachable else {execute} end
          else {page} end))
      (core instance $i (instantiate $m (with "h" (instance (export "emit" (func $emit)) (export "request" (func $request))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#)).unwrap()
}
async fn lifecycle_millis(database: &Database) -> i64 {
    let mut tx = database
        .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let rows = tx
        .fetch::<1>(
            "SELECT CAST(lifecycle_ms AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    rows[0][0].parse().unwrap()
}
async fn acknowledged_trap_backoff(database: Option<Database>) {
    let case = Case::new_component(database, declarations(false), worker_trap_component()).await;
    let job = case.create("ready").await;
    let claim = case.claim(0).await.unwrap();
    let before = lifecycle_millis(&case.db).await;
    let JobRunOutcome::Retrying(next) = case.app.invoke_job(&claim).await.unwrap() else {
        panic!("acknowledged trap rollback must enter durable backoff")
    };
    let after = lifecycle_millis(&case.db).await;
    assert!((before + 60_000..=after + 66_000).contains(&next.unix_millis()));
    assert_eq!(
        case.stored(&job).await,
        ("pending".into(), "ready".into(), 0)
    );
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let rows = tx.fetch::<4>("SELECT reason,CAST(eligible_ms AS TEXT),CAST(lease_until_ms AS TEXT),CAST(attempts AS TEXT) FROM nx_jobs WHERE id=$1", &[job.id().unwrap().into()]).await.unwrap();
    assert_eq!(
        rows[0],
        [
            "transient".to_owned(),
            next.unix_millis().to_string(),
            "0".into(),
            "1".into()
        ]
    );
    tx.commit().await.unwrap();
    assert!(
        case.claim(0).await.is_none(),
        "transient abort cannot be immediately reclaimed"
    );
    case.close().await;
}
async fn exhausted_abort_budget(database: Option<Database>) {
    let case = Case::new(database, false).await;
    let job = case.create("ready").await;
    let claim = case.claim(0).await.unwrap();
    let (result, roots) = crate::database::lifecycle::observe_roots(
        crate::failure_tests::known_conflicts(3, case.app.invoke_job(&claim)),
    )
    .await;
    assert!(
        matches!(result.unwrap(), JobRunOutcome::Retrying(_)),
        "three acknowledged aborts must use durable backoff within the original16"
    );
    assert_eq!(roots.len(), 1);
    case.app
        .request_lifecycle
        .wait_idle_for_test()
        .await
        .unwrap();
    assert_eq!(
        case.stored(&job).await,
        ("pending".into(), "ready".into(), 0),
        "acknowledged aborts cannot commit effects or skip declared backoff"
    );
    case.close().await;
}
#[tokio::test]
async fn sqlite_service_acknowledged_trap_uses_retry_backoff() {
    acknowledged_trap_backoff(None).await;
}
#[tokio::test]
async fn sqlite_service_three_acknowledged_aborts_use_backoff() {
    exhausted_abort_budget(None).await;
}

async fn known_retry(database: Option<Database>) {
    let case = Case::new(database, false).await;
    let job = case.create("ready").await;
    let claim = case.claim(0).await.unwrap();
    let (result, roots) = crate::database::lifecycle::observe_roots(
        crate::failure_tests::known_conflict_once(case.app.invoke_job(&claim)),
    )
    .await;
    assert!(matches!(
        result.unwrap(),
        JobRunOutcome::Completed {
            recovered: false,
            ..
        }
    ));
    assert_eq!(roots.len(), 1);
    assert_eq!(
        case.stored(&job).await,
        ("succeeded".into(), "finished".into(), 1)
    );
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let row = repository::load(&mut tx, &case.app.manifest, 1, job.targets()["record"].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.revision, 2,
        "known aborted guest rerun commits only once"
    );
    tx.commit().await.unwrap();
    case.close().await;
}

async fn authoritative_limits(database: Option<Database>) {
    let case = Case::new(database, false).await;
    let first = case.create("ready").await;
    case.create("ready").await;
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_job_runtime SET pending_limit=2,tenant_limit=2,concurrency=1 WHERE singleton=1",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (submission, csrf) = case.form().await;
    assert!(
        case.app
            .submit(
                &case.cookie,
                1,
                &submission,
                &csrf,
                Fields::from([("body".into(), "ready".into())])
            )
            .await
            .is_err()
    );
    case.app
        .request_lifecycle
        .wait_idle_for_test()
        .await
        .unwrap();
    let claim = case.claim(0).await.unwrap();
    assert!(
        case.claim(0).await.is_none(),
        "authoritative downward concurrency limit applies"
    );
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    for table in ["nx_records", "nx_receipts", "nx_jobs"] {
        assert_eq!(
            tx.fetch::<1>(&format!("SELECT CAST(COUNT(*) AS TEXT) FROM {table}"), &[])
                .await
                .unwrap()[0][0],
            "2",
            "quota refusal rolls back {table}"
        );
    }
    tx.commit().await.unwrap();
    assert!(matches!(
        case.app.invoke_job(&claim).await.unwrap(),
        JobRunOutcome::Completed { .. }
    ));
    assert_eq!(
        case.stored(&first).await.2,
        usize::from(claim.id() == first.id().unwrap())
    );
    case.close().await;
}

fn derived_declarations() -> Manifest {
    let mut m = declarations(false);
    let mut folder = m.resources[0].clone();
    folder.id = 2;
    folder.name = "folders".into();
    folder.fields[0].name = "label".into();
    folder.fields[0].label = "Label".into();
    m.resources.push(folder);
    m.resources[0].fields.push(TextField {
        immutable: true,
        kind: FieldKind::Reference {
            resource: "folders".into(),
        },
        optional: false,
        initial: None,
        name: "parent".into(),
        label: "Folder".into(),
        max_bytes: 64,
    });
    let mut service_read = m.operations.iter().find(|op| op.id == 4).unwrap().clone();
    service_read.id = 6;
    service_read.resource = 2;
    let mut owner_read = m.operations.iter().find(|op| op.id == 2).unwrap().clone();
    owner_read.id = 8;
    owner_read.resource = 2;
    m.operations.extend([service_read, owner_read]);
    m.operations
        .iter_mut()
        .find(|op| op.id == 3)
        .unwrap()
        .bind
        .insert("parent".into(), 8);
    m.actions[0].targets.push(ActionTarget {
        name: "folder".into(),
        resource: 2,
        source: TargetSource::Page { reads: vec![8] },
        revision: Revision::Identity,
        projection: None,
        inspect: None,
    });
    m.actions[0].steps[0].assign.push(Assignment {
        field: "parent".into(),
        change: Change::Set(Value::Target("folder".into())),
    });
    m.routes[0].forms.clear();
    m.routes.push(Route {
        params: vec![],
        access: Access::Authenticated,
        id: 3,
        path: "/folders/{folder}".into(),
        resource: Some(2),
        operations: vec![8],
        forms: vec![1],
    });
    m.actions[1].targets[0]
        .projection
        .as_mut()
        .unwrap()
        .fields
        .push("parent".into());
    m.actions[1].targets.push(ActionTarget {
        name: "parent".into(),
        resource: 2,
        source: TargetSource::Reference {
            target: "record".into(),
            field: "parent".into(),
            eligible: 6,
        },
        revision: Revision::Identity,
        projection: Some(Inspection {
            operation: 6,
            fields: vec![],
        }),
        inspect: None,
    });
    let jobs = m.jobs.as_mut().unwrap();
    jobs.workers[0].actions[0].targets.insert(
        "parent".into(),
        WorkerTarget {
            resource: 2,
            eligible: 6,
        },
    );
    jobs.schedules[0]
        .targets
        .insert("parent".into(), ScheduledTarget::Target("folder".into()));
    m
}
async fn derived_targets(database: Option<Database>, failure: Option<&str>) {
    let case = Case::new_manifest(database, derived_declarations()).await;
    let owner = case.app.account_identity(&case.cookie).await.unwrap();
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let storage = tx.storage_resource(&case.app.manifest, 2).await.unwrap();
    for id in 1..=2i64 {
        let sequence = tx.allocate_creation().await.unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,'team',$4,$5,1,$6)", &[storage.into(), id.into(), owner.as_str().into(), serde_json::to_string(&Fields::from([("label".into(), "Folder".into())])).unwrap().into(), format!("folder_{id}").into(), sequence.into()]).await.unwrap();
    }
    tx.commit().await.unwrap();
    let job = case.create("ready").await;
    assert_eq!(job.targets().len(), 2);
    assert_eq!(job.targets()["parent"].id, 1);
    if let Some(failure) = failure {
        let mut tx = case
            .db
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
            .await
            .unwrap();
        if failure == "relation" {
            let mut forged = serde_json::to_value(&job).unwrap();
            forged["targets"]["parent"]["id"] = 2.into();
            forged["targets"]["parent"]["incarnation"] = "folder_2".into();
            let forged: CapturedJob = serde_json::from_value(forged).unwrap();
            tx.execute(
                "UPDATE nx_jobs SET payload=$1,payload_digest=$2 WHERE id=$3",
                &[
                    serde_json::to_string(&forged).unwrap().into(),
                    forged.invocation_digest().unwrap().into(),
                    job.id().unwrap().into(),
                ],
            )
            .await
            .unwrap();
        } else {
            tx.execute(
                "UPDATE nx_records SET tenant='other' WHERE resource=$1 AND id=1",
                &[storage.into()],
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }
    let claim = case.claim(0).await.unwrap();
    let result = case.app.invoke_job(&claim).await.unwrap();
    if failure.is_some() {
        assert!(matches!(result, JobRunOutcome::Unavailable));
        assert_eq!(
            case.stored(&job).await,
            ("rejected".into(), "ready".into(), 0)
        );
    } else {
        assert!(matches!(result, JobRunOutcome::Completed { .. }));
        assert_eq!(
            case.stored(&job).await,
            ("succeeded".into(), "finished".into(), 1)
        );
    }
    case.close().await;
}
#[tokio::test]
async fn sqlite_service_created_and_derived_targets() {
    derived_targets(None, None).await;
}
#[tokio::test]
async fn sqlite_service_derived_parent_read_is_independent() {
    derived_targets(None, Some("authority")).await;
}
#[tokio::test]
async fn sqlite_service_forged_derived_relation_is_unavailable() {
    derived_targets(None, Some("relation")).await;
}

async fn exact_revision(database: Option<Database>) {
    let mut m = declarations(false);
    m.actions[1].targets[0].revision = Revision::Exact;
    let case = Case::new_manifest(database, m).await;
    let job = case.create("ready").await;
    assert_eq!(job.targets()["record"].revision, 1);
    let mut forged = serde_json::to_value(&job).unwrap();
    forged["targets"]["record"]["revision"] = 0.into();
    let forged: CapturedJob = serde_json::from_value(forged).unwrap();
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_jobs SET payload=$1,payload_digest=$2 WHERE id=$3",
        &[
            serde_json::to_string(&forged).unwrap().into(),
            forged.invocation_digest().unwrap().into(),
            job.id().unwrap().into(),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let claim = case.claim(0).await.unwrap();
    assert!(
        matches!(
            case.app.invoke_job(&claim).await.unwrap(),
            JobRunOutcome::Unavailable
        ),
        "Exact never accepts the Identity-only zero revision"
    );
    assert_eq!(
        case.stored(&job).await,
        ("rejected".into(), "ready".into(), 0)
    );
    case.close().await;
}

async fn malformed_receipt(database: Option<Database>) {
    let case = Case::new(database, false).await;
    let job = case.create("ready").await;
    let claim = case.claim(0).await.unwrap();
    assert!(matches!(
        case.app.invoke_job(&claim).await.unwrap(),
        JobRunOutcome::Completed { .. }
    ));
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_receipts SET outcome=$1 WHERE nonce=$2",
        &[
            r#"{"version":3,"outcomes":[],"source":null,"destination":null,"handover":null}"#
                .into(),
            job.id().unwrap().into(),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(
        case.app.invoke_job(&claim).await.is_err(),
        "incomplete semantic receipt is never abort evidence"
    );
    assert_eq!(
        case.stored(&job).await,
        ("succeeded".into(), "finished".into(), 1)
    );
    case.close().await;
}

#[tokio::test]
async fn sqlite_service_exact_rejects_zero_revision() {
    exact_revision(None).await;
}
#[tokio::test]
async fn sqlite_service_malformed_receipt_never_reexecutes() {
    malformed_receipt(None).await;
}

async fn maximum_effects(database: Option<Database>) {
    maximum_effects_mode(database, false).await;
}
async fn maximum_effects_worker(database: Option<Database>) {
    maximum_effects_mode(database, true).await;
}
async fn maximum_effects_mode(database: Option<Database>, via_worker: bool) {
    let mut m = declarations(false);
    let mut followup = m.actions[1].clone();
    followup.id = 3;
    followup.name = "Observe completion".into();
    followup.inputs.push(Input {
        name: "original".into(),
        label: "Original state".into(),
        kind: FieldKind::Text,
        optional: false,
        max_bytes: 4096,
    });
    followup.steps[0].guards = vec![Guard {
        condition: GuardCondition::Compare {
            left: Value::Input("original".into()),
            comparison: Comparison::Equal,
            right: Value::Literal(Literal::Text("ready".into())),
        },
        rejection: GuardRejection {
            input: Some("original".into()),
            message: "Original state differs".into(),
        },
    }];
    m.actions[1].steps = vec![m.actions[1].steps[0].clone(); 4];
    m.actions.push(followup);
    let jobs = m.jobs.as_mut().unwrap();
    let mut rule = jobs.workers[0].actions[0].clone();
    rule.action = 3;
    jobs.workers[0].actions.push(rule);
    for ordinal in 0..2 {
        jobs.schedules.push(Schedule {
            source_action: 2,
            ordinal,
            worker: "repair".into(),
            action: 3,
            targets: BTreeMap::from([("record".into(), ScheduledTarget::Target("record".into()))]),
            inputs: BTreeMap::from([(
                "original".into(),
                Value::SnapshotField {
                    target: "record".into(),
                    field: "body".into(),
                    reviewed: false,
                },
            )]),
            due_at: Value::TransactionTime,
        });
    }
    let case = Case::new_manifest(database, m).await;
    let job = case.create("ready").await;
    let claim = if via_worker {
        None
    } else {
        Some(case.claim(0).await.unwrap())
    };
    let (result, roots) = crate::database::lifecycle::observe_roots(async {
        if let Some(claim) = &claim {
            case.app.invoke_job(claim).await
        } else {
            case.app
                .run_job_once()
                .await
                .map(|result| result.expect("scheduled job must be claimed"))
        }
    })
    .await;
    eprintln!(
        "four mutations/two enqueues via_worker={via_worker}: statement meter={:?}, error={:?}",
        roots[0].statement_snapshot(),
        result.as_ref().err()
    );
    assert!(
        matches!(result.unwrap(), JobRunOutcome::Completed { ref outcomes, .. } if outcomes.len() == 4)
    );
    assert_eq!(roots.len(), 1);
    eprintln!(
        "four mutations/two enqueues statement meter: {:?}",
        roots[0].statement_snapshot()
    );
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_jobs", &[])
            .await
            .unwrap()[0][0],
        "3"
    );
    let captures = tx
        .fetch::<1>(
            "SELECT payload FROM nx_jobs WHERE action=3 ORDER BY ordinal",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(captures.len(), 2);
    for [payload] in captures {
        let followup: CapturedJob = serde_json::from_str(&payload).unwrap();
        assert_eq!(
            followup.input()["original"],
            "ready",
            "schedule expressions use initial snapshots, not final mutated row data"
        );
        assert_eq!(followup.targets()["record"].revision, 0);
    }
    let stored = repository::load(&mut tx, &case.app.manifest, 1, job.targets()["record"].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.revision, 5);
    tx.commit().await.unwrap();
    if let Some(claim) = &claim {
        assert!(matches!(
            case.app.invoke_job(claim).await.unwrap(),
            JobRunOutcome::Completed {
                recovered: true,
                ..
            }
        ));
    } else {
        assert_eq!(
            case.stored(&job).await,
            ("succeeded".into(), "finished".into(), 1)
        );
    }
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_jobs", &[])
            .await
            .unwrap()[0][0],
        "3",
        "recovery must not duplicate schedules"
    );
    tx.commit().await.unwrap();
    case.close().await;
}

#[tokio::test]
async fn sqlite_service_known_abort_reruns_complete_invocation() {
    known_retry(None).await;
}
#[tokio::test]
async fn sqlite_service_authoritative_downward_limits() {
    authoritative_limits(None).await;
}
#[tokio::test]
async fn sqlite_service_four_mutations_two_enqueues_original_budget() {
    maximum_effects(None).await;
}

#[tokio::test]
async fn sqlite_worker_four_mutations_two_enqueues_original_budget() {
    maximum_effects_worker(None).await;
}

#[tokio::test]
async fn sqlite_service_success_receipt_first_replay() {
    success(None).await;
}
#[tokio::test]
async fn sqlite_service_guard_rejection() {
    rejection(None).await;
}
#[tokio::test]
async fn sqlite_service_current_authorization_denial() {
    denied(None, false).await;
}
#[tokio::test]
async fn sqlite_service_current_expiry_denial() {
    denied(None, true).await;
}
#[tokio::test]
async fn sqlite_service_revoked_grant_pauses() {
    revoked(None).await;
}
#[tokio::test]
async fn sqlite_service_stale_fence() {
    stale_fence(None).await;
}
#[tokio::test]
async fn sqlite_service_lost_commit_ack() {
    lost_ack(None).await;
}
#[tokio::test]
async fn sqlite_service_atomic_enqueue_rollback() {
    enqueue_rollback(None).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_service_action_integration() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for case in [
        "success",
        "rejection",
        "denied",
        "expiry",
        "revoked",
        "fence",
        "ack",
        "rollback",
        "retry",
        "limits",
        "maximum",
        "exact",
        "malformed",
        "maintenance",
        "derived",
        "derived_authority",
        "derived_relation",
        "trap_backoff",
        "abort_budget",
        "worker_maximum",
    ] {
        let name = format!(
            "nx_p10_action_{case}_{}",
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
        eprintln!("retained P10 PostgreSQL fixture: {name}");
        let db = Some(Database::postgres(case_url.as_str()).unwrap());
        match case {
            "success" => success(db).await,
            "rejection" => rejection(db).await,
            "denied" => denied(db, false).await,
            "expiry" => denied(db, true).await,
            "revoked" => revoked(db).await,
            "fence" => stale_fence(db).await,
            "ack" => lost_ack(db).await,
            "rollback" => enqueue_rollback(db).await,
            "retry" => known_retry(db).await,
            "limits" => authoritative_limits(db).await,
            "maximum" => maximum_effects(db).await,
            "exact" => exact_revision(db).await,
            "malformed" => malformed_receipt(db).await,
            "maintenance" => approved_maintenance(db).await,
            "derived" => derived_targets(db, None).await,
            "derived_authority" => derived_targets(db, Some("authority")).await,
            "derived_relation" => derived_targets(db, Some("relation")).await,
            "trap_backoff" => acknowledged_trap_backoff(db).await,
            "abort_budget" => exhausted_abort_budget(db).await,
            "worker_maximum" => maximum_effects_worker(db).await,
            _ => unreachable!(),
        }
    }
}
