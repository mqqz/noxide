use super::*;
use noxide_protocol::{
    effects::PayloadField,
    time::{Duration, Timestamp},
};
use repository::ScheduleScalar as Scalar;
fn schema(kind: FieldKind) -> Input {
    Input {
        name: "value".into(),
        label: "Value".into(),
        kind,
        optional: false,
        max_bytes: 4096,
    }
}
#[test]
fn typed_json_has_no_string_numeric_or_identity_coercion() {
    let integer = schema(FieldKind::Integer {
        min: Some(0),
        max: Some(9),
    });
    assert_eq!(
        scalar_json(Scalar::Integer(7), &integer).unwrap(),
        serde_json::json!(7)
    );
    assert!(scalar_json(Scalar::Text("7".into()), &integer).is_err());
    assert!(scalar_json(Scalar::Integer(10), &integer).is_err());
    let reference = schema(FieldKind::Reference {
        resource: "notes".into(),
    });
    assert_eq!(
        scalar_json(
            Scalar::Reference {
                resource: "notes".into(),
                id: 7
            },
            &reference
        )
        .unwrap(),
        serde_json::json!(7)
    );
    assert!(
        scalar_json(
            Scalar::Reference {
                resource: "other".into(),
                id: 7
            },
            &reference
        )
        .is_err()
    );
    assert!(
        scalar_json(
            Scalar::Reference {
                resource: "notes".into(),
                id: 0
            },
            &reference
        )
        .is_err()
    );
    let account = schema(FieldKind::Account {
        scope: AccountScope::SameTenant,
    });
    assert!(scalar_json(Scalar::Account("x".into()), &account).is_err());
    assert_eq!(
        scalar_json(Scalar::Account("A".repeat(43)), &account).unwrap(),
        serde_json::json!("A".repeat(43))
    );
    assert_eq!(
        scalar_json(
            Scalar::Timestamp(Timestamp::from_unix_millis(1234).unwrap()),
            &schema(FieldKind::Timestamp)
        )
        .unwrap(),
        serde_json::json!(1234)
    );
    assert_eq!(
        scalar_json(
            Scalar::Duration(Duration::from_millis(1200).unwrap()),
            &schema(FieldKind::Duration { max_millis: 1200 })
        )
        .unwrap(),
        serde_json::json!(1200)
    );
}
#[test]
fn missing_is_null_but_empty_or_noncanonical_text_never_becomes_missing() {
    let mut optional = schema(FieldKind::Text);
    optional.optional = true;
    assert_eq!(
        scalar_json(Scalar::Missing(FieldKind::Text), &optional).unwrap(),
        serde_json::Value::Null
    );
    assert!(scalar_json(Scalar::Text(String::new()), &optional).is_err());
    assert!(scalar_json(Scalar::Missing(FieldKind::Boolean), &optional).is_err());
    assert!(scalar_json(Scalar::Text("a\r\nb".into()), &optional).is_err());
    optional.optional = false;
    assert!(scalar_json(Scalar::Missing(FieldKind::Text), &optional).is_err());
    let mut opaque = schema(FieldKind::Blob { max_bytes: 10 });
    opaque.optional = true;
    assert!(scalar_json(Scalar::Missing(opaque.kind.clone()), &opaque).is_err());
}
fn mapped(name: &str, kind: FieldKind, value: Value) -> PayloadField {
    PayloadField {
        schema: Input {
            name: name.into(),
            ..schema(kind)
        },
        value,
    }
}
#[test]
fn payload_is_one_sorted_canonical_object_with_initial_snapshot_values() {
    let m = crate::test_support::manifest();
    let input = Fields::from([("body".into(), "caller".into())]);
    let principal = auth::Principal::Anonymous;
    let grants = BTreeMap::from([(
        "record".into(),
        RecordTarget {
            resource: 1,
            id: 7,
            incarnation: "record".into(),
            revision: 1,
            route: None,
        },
    )]);
    let snapshots = BTreeMap::from([(
        (1, 7),
        StoredRecord {
            record: Record {
                resource: 1,
                id: 7,
                fields: Fields::from([("body".into(), "initial".into())]),
            },
            owner: "owner".into(),
            tenant: "team".into(),
            incarnation: "record".into(),
            revision: 1,
            cap_version: None,
        },
    )]);
    let outcomes = vec![MutationOutcome {
        kind: MutationKind::Created,
        resource: 1,
        id: 9,
        incarnation: "created".into(),
    }];
    let values = repository::ScheduleValues {
        manifest: &m,
        input: &input,
        principal: &principal,
        grants: &grants,
        snapshots: &snapshots,
        outcomes: &outcomes,
        time: None,
        current: None,
    };
    let mut emission = EmitEffect {
        source_action: 1,
        ordinal: 0,
        endpoint: "events".into(),
        fields: vec![
            mapped("z", FieldKind::Text, Value::Input("body".into())),
            mapped(
                "a",
                FieldKind::Text,
                Value::SnapshotField {
                    target: "record".into(),
                    field: "body".into(),
                    reviewed: false,
                },
            ),
            mapped(
                "record",
                FieldKind::Reference {
                    resource: "notes".into(),
                },
                Value::Created(0),
            ),
        ],
    };
    let expected = br#"{"a":"initial","record":9,"z":"caller"}"#;
    assert_eq!(
        payload(&values, ActionCore::of(&m.actions[0]).unwrap(), &emission).unwrap(),
        expected
    );
    emission.fields.reverse();
    assert_eq!(
        payload(&values, ActionCore::of(&m.actions[0]).unwrap(), &emission).unwrap(),
        expected
    );
    emission.fields[0].value = Value::CurrentField {
        target: "record".into(),
        field: "body".into(),
    };
    assert!(payload(&values, ActionCore::of(&m.actions[0]).unwrap(), &emission).is_err());
}
#[test]
fn encoded_body_limit_includes_escaping_and_never_truncates() {
    let m = crate::test_support::manifest();
    let input = Fields::from([("body".into(), "\"".repeat(4096))]);
    let values = repository::ScheduleValues {
        manifest: &m,
        input: &input,
        principal: &auth::Principal::Anonymous,
        grants: &BTreeMap::new(),
        snapshots: &BTreeMap::new(),
        outcomes: &[],
        time: None,
        current: None,
    };
    let mut emission = EmitEffect {
        source_action: 1,
        ordinal: 0,
        endpoint: "events".into(),
        fields: (0..7)
            .map(|i| {
                mapped(
                    &format!("field_{i}"),
                    FieldKind::Text,
                    Value::Input("body".into()),
                )
            })
            .collect(),
    };
    let body = payload(&values, ActionCore::of(&m.actions[0]).unwrap(), &emission).unwrap();
    assert!(body.len() < MAX_EFFECT_BODY_BYTES);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["field_0"],
        "\"".repeat(4096)
    );
    emission.fields.push(mapped(
        "field_7",
        FieldKind::Text,
        Value::Input("body".into()),
    ));
    assert!(payload(&values, ActionCore::of(&m.actions[0]).unwrap(), &emission).is_err());
}

// Real provider integration fixtures. No delivery service, listener or transport
// call is started; endpoint/proxy values are approved metadata only.
use crate::effect_deployment::{EffectDeployment, EffectGrant, EffectLimits};
use crate::{
    Database, HostKeys, JobDeployment, JobGrant, JobLimits, runtime::Limits,
    test_support as fixture,
};
use noxide_protocol::effects::{EffectContract, EffectEndpoint};
use std::{collections::BTreeSet, path::PathBuf};

pub(in crate::application) struct Case {
    pub(in crate::application) path: PathBuf,
    pub(in crate::application) app: Arc<Application>,
    pub(in crate::application) db: Database,
    pub(in crate::application) cookie: String,
    pub(in crate::application) actor: String,
    clock: Option<super::super::clock::ClockService>,
}
pub(in crate::application) fn declarations(job: bool) -> Manifest {
    let mut m = if job {
        super::super::jobs::tests::declarations(false)
    } else {
        fixture::manifest()
    };
    let fields = if job {
        vec![
            mapped(
                "message",
                FieldKind::Text,
                Value::SnapshotField {
                    target: "record".into(),
                    field: "body".into(),
                    reviewed: false,
                },
            ),
            mapped(
                "record",
                FieldKind::Reference {
                    resource: "notes".into(),
                },
                Value::Target("record".into()),
            ),
        ]
    } else {
        m.actions[0].inputs.push(Input {
            name: "caption".into(),
            label: "Caption".into(),
            kind: FieldKind::Text,
            optional: true,
            max_bytes: 64,
        });
        let mut caption = mapped("caption", FieldKind::Text, Value::Input("caption".into()));
        caption.schema.optional = true;
        caption.schema.max_bytes = 64;
        vec![
            mapped("message", FieldKind::Text, Value::Input("body".into())),
            mapped(
                "record",
                FieldKind::Reference {
                    resource: "notes".into(),
                },
                Value::Created(0),
            ),
            mapped(
                "actor",
                FieldKind::Account {
                    scope: AccountScope::SameTenant,
                },
                Value::Principal,
            ),
            caption,
        ]
    };
    let count = if job { 1 } else { 2 };
    m.effects = Some(EffectContract {
        endpoints: vec![EffectEndpoint {
            name: "events".into(),
            secret_slot: None,
        }],
        emissions: (0..count)
            .map(|ordinal| EmitEffect {
                source_action: if job { 2 } else { 1 },
                ordinal,
                endpoint: "events".into(),
                fields: fields.clone(),
            })
            .collect(),
    });
    m
}
impl Case {
    async fn new(database: Option<Database>, limit: u16, job: bool) -> Self {
        Self::new_manifest(database, limit, job, declarations(job)).await
    }
    async fn new_manifest(database: Option<Database>, limit: u16, job: bool, m: Manifest) -> Self {
        Self::new_internal(database, limit, job, m, None).await
    }
    pub(in crate::application) async fn configured(
        database: Option<Database>,
        manifest: Manifest,
        effects: EffectDeployment,
    ) -> Self {
        let job = manifest.jobs.is_some();
        let limit = effects.limits.pending_per_app;
        Self::new_internal(database, limit, job, manifest, Some(effects)).await
    }
    async fn new_internal(
        database: Option<Database>,
        limit: u16,
        job: bool,
        m: Manifest,
        configured: Option<EffectDeployment>,
    ) -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/capability-evidence/p11-action-fixtures");
        std::fs::create_dir_all(&base).unwrap();
        let path = tempfile::Builder::new()
            .prefix("effects-")
            .tempdir_in(base)
            .unwrap()
            .keep()
            .canonicalize()
            .unwrap();
        let db = database.unwrap_or_else(|| Database::sqlite(path.join("runtime.db")));
        db.initialize().await.unwrap();
        let actor = db
            .create_account("alice", "effect fixture password", "team")
            .await
            .unwrap();
        let jobs = job.then(|| JobDeployment {
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
        });
        let mut effects = configured.unwrap_or_else(|| EffectDeployment {
            grants: vec![EffectGrant {
                endpoint: "events".into(),
                tenant: "team".into(),
                host: "receiver.org".into(),
                port: 443,
                path: "/events".into(),
            }],
            secrets: vec![],
            tor_proxy: "127.0.0.1:9050".parse().unwrap(),
            limits: EffectLimits {
                pending_per_app: limit,
                pending_per_tenant: limit,
                worker_concurrency: 2,
            },
            runtime_directory: Some(path.clone()),
        });
        if effects.runtime_directory.is_none() {
            effects.runtime_directory = Some(path.clone());
        }
        let approved =
            crate::deployment::approval_digest(&m, None, jobs.as_ref(), Some(&effects)).unwrap();
        let app = Arc::new(
            Application::new(
                &fixture::component(None),
                &serde_json::to_vec(&m).unwrap(),
                approved,
                db.clone(),
                HostKeys::generate().unwrap(),
                Limits::default(),
                crate::DeploymentResources {
                    assets: Default::default(),
                    blobs: None,
                    jobs,
                    effects: Some(effects),
                },
            )
            .unwrap(),
        );
        app.activate().await.unwrap();
        let clock = Some(app.start_clock_service().unwrap());
        let challenge = app.login_challenge().await.unwrap();
        let cookie = app
            .login(
                &challenge.cookie,
                &challenge.csrf,
                "alice",
                "effect fixture password",
            )
            .await
            .unwrap();
        eprintln!("retained P11 action/outbox fixture: {}", path.display());
        Self {
            path,
            app,
            db,
            cookie,
            actor,
            clock,
        }
    }
    async fn form(&self) -> (String, String) {
        let page = self.app.view(&self.cookie, 1, None).await.unwrap();
        let html = String::from_utf8(page.body).unwrap();
        (
            fixture::hidden(&html, "_submission"),
            fixture::hidden(&html, "_csrf"),
        )
    }
    fn input(job: bool) -> Fields {
        let mut input = Fields::from([("body".into(), "ready".into())]);
        if !job {
            input.insert("caption".into(), String::new());
        }
        input
    }
    pub(in crate::application) async fn create(&self, body: &str) {
        let (submission, csrf) = self.form().await;
        let mut input = Fields::from([("body".into(), body.into())]);
        if self
            .app
            .manifest
            .actions
            .iter()
            .find(|action| action.id == 1)
            .unwrap()
            .inputs
            .iter()
            .any(|input| input.name == "caption")
        {
            input.insert("caption".into(), String::new());
        }
        self.app
            .submit(&self.cookie, 1, &submission, &csrf, input)
            .await
            .unwrap();
    }
    pub(in crate::application) async fn state(
        &self,
    ) -> (
        usize,
        usize,
        Vec<(String, serde_json::Value)>,
        Vec<StoredRecord>,
    ) {
        let mut tx = self
            .db
            .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(3))
            .await
            .unwrap();
        let records: usize = tx
            .fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
            .await
            .unwrap()[0][0]
            .parse()
            .unwrap();
        let receipts: usize = tx
            .fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_receipts", &[])
            .await
            .unwrap()[0][0]
            .parse()
            .unwrap();
        let captures = tx
            .fetch::<2>("SELECT id,payload FROM nx_outbox ORDER BY id", &[])
            .await
            .unwrap();
        let mut outbox = Vec::new();
        for [id, payload] in captures {
            let capture: serde_json::Value = serde_json::from_str(&payload).unwrap();
            let body = serde_json::from_str(capture["body"].as_str().unwrap()).unwrap();
            outbox.push((id, body));
        }
        let ids = tx
            .fetch::<1>("SELECT CAST(id AS TEXT) FROM nx_records ORDER BY id", &[])
            .await
            .unwrap();
        let mut rows = Vec::new();
        for [id] in ids {
            rows.push(
                repository::load(&mut tx, &self.app.manifest, 1, id.parse().unwrap())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        tx.commit().await.unwrap();
        (records, receipts, outbox, rows)
    }
    pub(in crate::application) async fn stop_clock(&mut self) {
        self.clock
            .take()
            .expect("fixture clock already stopped")
            .shutdown()
            .await
            .unwrap();
    }
    pub(in crate::application) async fn close(mut self) {
        if self.clock.is_some() {
            self.stop_clock().await;
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
}
async fn real_success(database: Option<Database>, lost_ack: bool) {
    let case = Case::new(database, 1000, false).await;
    let (submission, csrf) = case.form().await;
    let input = Case::input(false);
    if lost_ack {
        let result = crate::failure_tests::lose_commit_ack(case.app.submit(
            &case.cookie,
            1,
            &submission,
            &csrf,
            input.clone(),
        ))
        .await;
        assert!(matches!(result, Err(RequestError::OutcomeUnknown)));
        case.app
            .request_lifecycle
            .wait_idle_for_test()
            .await
            .unwrap();
    } else {
        case.app
            .submit(&case.cookie, 1, &submission, &csrf, input.clone())
            .await
            .unwrap();
    }
    let (records, receipts, first, rows) = case.state().await;
    assert_eq!((records, receipts, first.len()), (1, 1, 2));
    assert_ne!(first[0].0, first[1].0);
    for (_, body) in &first {
        assert_eq!(body["message"], "ready");
        assert_eq!(body["record"], rows[0].record.id);
        assert_eq!(body["actor"], case.actor);
        assert!(body["caption"].is_null());
    }
    case.app
        .submit(&case.cookie, 1, &submission, &csrf, input)
        .await
        .unwrap();
    let (records, receipts, replayed, _) = case.state().await;
    assert_eq!((records, receipts), (1, 1));
    assert_eq!(
        first, replayed,
        "receipt replay must not evaluate or enqueue another effect"
    );
    assert!(
        case.app
            .submit(
                &case.cookie,
                1,
                &submission,
                &csrf,
                Fields::from([
                    ("body".into(), "different".into()),
                    ("caption".into(), String::new())
                ])
            )
            .await
            .is_err()
    );
    assert_eq!(case.state().await.2, first);
    case.close().await;
}
async fn real_rollback(database: Option<Database>) {
    let case = Case::new(database, 1, false).await;
    let (submission, csrf) = case.form().await;
    assert!(
        case.app
            .submit(&case.cookie, 1, &submission, &csrf, Case::input(false))
            .await
            .is_err()
    );
    case.app
        .request_lifecycle
        .wait_idle_for_test()
        .await
        .unwrap();
    let (records, receipts, outbox, _) = case.state().await;
    assert_eq!(
        (records, receipts, outbox.len()),
        (0, 0, 0),
        "second effect quota failure must roll back first effect, mutation and receipt"
    );
    case.close().await;
}
async fn real_job_source(database: Option<Database>) {
    let case = Case::new(database, 1000, true).await;
    let (submission, csrf) = case.form().await;
    case.app
        .submit(&case.cookie, 1, &submission, &csrf, Case::input(true))
        .await
        .unwrap();
    assert!(case.state().await.2.is_empty());
    let (result, roots) = crate::database::lifecycle::observe_roots(case.app.run_job_once()).await;
    assert!(matches!(
        result.unwrap(),
        Some(super::super::JobRunOutcome::Completed { .. })
    ));
    assert_eq!(roots.len(), 1);
    eprintln!(
        "P11 real job/effect original-budget meter: {:?}",
        roots[0].statement_snapshot()
    );
    let (records, receipts, outbox, rows) = case.state().await;
    assert_eq!((records, receipts, outbox.len()), (1, 2, 1));
    assert_eq!(rows[0].record.fields["body"], "finished");
    assert_eq!(
        outbox[0].1["message"], "ready",
        "payload must read initial authorized snapshot after mutation"
    );
    assert_eq!(outbox[0].1["record"], rows[0].record.id);
    assert!(case.app.run_job_once().await.unwrap().is_none());
    assert_eq!(case.state().await.2, outbox);
    case.close().await;
}
async fn real_combined_budget(database: Option<Database>) {
    use noxide_protocol::jobs::{Schedule, ScheduledTarget};
    let mut m = declarations(true);
    let mut followup = m.actions[1].clone();
    followup.id = 3;
    followup.name = "Follow up".into();
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
    let mut second = m.effects.as_ref().unwrap().emissions[0].clone();
    second.ordinal = 1;
    m.effects.as_mut().unwrap().emissions.push(second);
    let case = Case::new_manifest(database, 1000, true, m).await;
    let (submission, csrf) = case.form().await;
    case.app
        .submit(&case.cookie, 1, &submission, &csrf, Case::input(true))
        .await
        .unwrap();
    let (result, roots) = crate::database::lifecycle::observe_roots(case.app.run_job_once()).await;
    assert!(
        result.is_err(),
        "all maximum dimensions cannot replenish the original sixteen calls"
    );
    assert_eq!(roots.len(), 1);
    eprintln!(
        "P11 combined 4 mutations/2 jobs/2 emits budget refusal meter: {:?}",
        roots[0].statement_snapshot()
    );
    if let Some(jobs) = &case.app.jobs {
        jobs.lifecycle.wait_idle_for_test().await.unwrap();
    }
    let (records, receipts, outbox, rows) = case.state().await;
    assert_eq!((records, receipts, outbox.len()), (1, 1, 0));
    assert_eq!(rows[0].record.fields["body"], "ready");
    assert_eq!(rows[0].revision, 1);
    let mut tx = case
        .db
        .begin_read(std::time::Instant::now() + std::time::Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_jobs", &[])
            .await
            .unwrap()[0][0],
        "1",
        "scheduled jobs must roll back with effects and mutations"
    );
    tx.commit().await.unwrap();
    case.close().await;
}
#[tokio::test]
async fn sqlite_combined_effects_never_replenish_original_request_budget() {
    real_combined_budget(None).await;
}

#[tokio::test]
async fn sqlite_real_action_outbox_receipt_and_replay() {
    real_success(None, false).await;
}
#[tokio::test]
async fn sqlite_real_action_effect_lost_ack_replays_once() {
    real_success(None, true).await;
}
#[tokio::test]
async fn sqlite_real_action_second_effect_failure_is_atomic() {
    real_rollback(None).await;
}
#[tokio::test]
async fn sqlite_real_job_effect_uses_existing_core_and_snapshots() {
    real_job_source(None).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
async fn postgres_real_action_effects_atomicity_and_replay() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for mode in ["success", "ack", "rollback", "job", "combined"] {
        let name = format!(
            "nx_p11_action_{mode}_{}",
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
        eprintln!("retained P11 PostgreSQL action fixture: {name}");
        let db = Some(Database::postgres(case.as_str()).unwrap());
        match mode {
            "success" => real_success(db, false).await,
            "ack" => real_success(db, true).await,
            "rollback" => real_rollback(db).await,
            "job" => real_job_source(db).await,
            "combined" => real_combined_budget(db).await,
            _ => unreachable!(),
        }
    }
}
