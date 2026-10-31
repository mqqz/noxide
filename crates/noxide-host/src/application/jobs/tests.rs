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
                    jobs: Some(JobDeployment {
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
                    }),
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
        self.app
            .request_lifecycle
            .wait_idle_for_test()
            .await
            .unwrap();
        assert!(self.path.is_dir());
    }
    pub(in crate::application) async fn form(&self) -> (String, String) {
        let page = self.app.view(&self.cookie, 1, None).await.unwrap();
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

async fn maximum_effects(database: Option<Database>) {
    let mut m = declarations(false);
    let mut followup = m.actions[1].clone();
    followup.id = 3;
    followup.name = "Observe completion".into();
    followup.steps[0].guards.clear();
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
            inputs: BTreeMap::new(),
            due_at: Value::TransactionTime,
        });
    }
    let case = Case::new_manifest(database, m).await;
    let job = case.create("ready").await;
    let claim = case.claim(0).await.unwrap();
    let (result, roots) =
        crate::database::lifecycle::observe_roots(case.app.invoke_job(&claim)).await;
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
    let stored = repository::load(&mut tx, &case.app.manifest, 1, job.targets()["record"].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.revision, 5);
    tx.commit().await.unwrap();
    assert!(matches!(
        case.app.invoke_job(&claim).await.unwrap(),
        JobRunOutcome::Completed {
            recovered: true,
            ..
        }
    ));
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
            _ => unreachable!(),
        }
    }
}
