//! Provider-paired durable state and forged-storage tests. The fake semantic
//! result is deliberately restricted to this queue fixture; production supplies
//! the existing action receipt decoder and executor.
use super::*;
use crate::{
    Database,
    database::lifecycle::{AdmissionOwner, Registry, RequestScope},
};
use anyhow::{Result, ensure};
use noxide_protocol::{
    Fields,
    jobs::*,
    time::{Duration, Timestamp},
};
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use tokio::sync::Semaphore;

fn at(ms: i64) -> Timestamp {
    Timestamp::from_unix_millis(ms).unwrap()
}
fn grant(tenant: &str) -> Grant {
    Grant {
        scope: JobScope {
            deployment: "deployment".into(),
            tenant: tenant.into(),
        },
        worker: Worker {
            name: "expiry".into(),
            actions: vec![WorkerAction {
                action: 2,
                targets: BTreeMap::from([(
                    "order".into(),
                    WorkerTarget {
                        resource: 1,
                        eligible: 8,
                    },
                )]),
            }],
        },
        version: 1,
        contract: "contract".into(),
        epoch: "epoch".into(),
    }
}
fn declaration(ordinal: u8) -> Schedule {
    Schedule {
        source_action: 1,
        ordinal,
        worker: "expiry".into(),
        action: 2,
        targets: BTreeMap::from([("order".into(), ScheduledTarget::Created(0))]),
        inputs: BTreeMap::new(),
        due_at: noxide_protocol::Value::TransactionTime,
    }
}
fn targets(id: u64) -> BTreeMap<String, SealedTarget> {
    BTreeMap::from([(
        "order".into(),
        SealedTarget {
            resource: 1,
            id,
            incarnation: format!("record_{id}"),
            revision: 0,
        },
    )])
}
fn captured(grant: &Grant, origin: &str, ordinal: u8, id: u64) -> CapturedJob {
    CapturedJob::capture(
        &declaration(ordinal),
        origin.into(),
        grant,
        1,
        at(1_000),
        at(1_000),
        Fields::new(),
        targets(id),
    )
    .unwrap()
}
fn admission() -> (AdmissionOwner, Arc<Registry>) {
    let registry = Arc::new(Registry::default());
    let cap = std::time::Duration::from_secs(5);
    let scope = RequestScope::new(
        registry.clone(),
        tokio::time::Instant::now() + cap,
        cap,
        256,
    );
    let request = Arc::new(Semaphore::new(1));
    let database = Arc::new(Semaphore::new(1));
    (
        AdmissionOwner::new(
            scope,
            Arc::new(request.try_acquire_owned().unwrap()),
            Arc::new(database.try_acquire_owned().unwrap()),
            None,
        ),
        registry,
    )
}
fn receipt(value: &str) -> Result<()> {
    ensure!(
        value == r#"{"version":3,"fixture":"committed"}"#,
        "malformed queue fixture receipt"
    );
    Ok(())
}
async fn setup(database: &Database) {
    database.initialize().await.unwrap();
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(5))
        .await
        .unwrap();
    // Leaves stay unregistered on the dependency SHA. Once storage14 is
    // integrated these statements preserve the actual centrally audited tables.
    for line in include_str!("schema.sql")
        .lines()
        .filter(|line| line.starts_with("CREATE "))
    {
        let sql = line
            .replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
            .replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ");
        tx.execute(&sql, &[]).await.unwrap();
    }
    tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'contract','incarnation','deployment') ON CONFLICT(singleton) DO UPDATE SET contract='contract',incarnation='incarnation',generation='deployment'", &[]).await.unwrap();
    tx.execute("INSERT INTO nx_job_runtime(singleton,deployment,contract,epoch,state) VALUES(1,'deployment','contract','epoch','active') ON CONFLICT(singleton) DO UPDATE SET deployment='deployment',contract='contract',epoch='epoch',state='active'", &[]).await.unwrap();
    tx.execute("INSERT INTO nx_job_queue(singleton,claim_seq) VALUES(1,0) ON CONFLICT(singleton) DO NOTHING", &[]).await.unwrap();
    for tenant in ["alpha", "beta"] {
        let grant = grant(tenant);
        tx.execute("INSERT INTO nx_job_grants(deployment,tenant,worker,version,contract,epoch,state,declaration) VALUES('deployment',$1,'expiry',1,'contract','epoch','active',$2)", &[tenant.into(), serde_json::to_string(&grant).unwrap().into()]).await.unwrap();
    }
    tx.execute(
        "CREATE TABLE nx_job_test_mutations(id BIGINT PRIMARY KEY,value BIGINT NOT NULL)",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}
async fn insert_receipt(tx: &mut crate::database::Transaction, job: &CapturedJob, outcome: &str) {
    tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES($1,$2,$3,$4,$5,$6,2147483647)", &[job.id().unwrap().into(), job.receipt_subject().unwrap().into(), job.contract().into(), i64::from(job.action().0).into(), job.invocation_digest().unwrap().into(), outcome.into()]).await.unwrap();
}
async fn enqueue(database: &Database, job: &CapturedJob) {
    let (owner, registry) = admission();
    owner
        .run(async {
            let mut tx = database
                .begin(owner.work_deadline().into_std())
                .await
                .unwrap();
            let mut calls = 16;
            assert!(
                QueueContext {
                    tx: &mut tx,
                    calls: &mut calls
                }
                .enqueue(job, at(1_000), 1_000)
                .await
                .unwrap()
            );
            assert_eq!(calls, 15);
            tx.commit().await.unwrap();
        })
        .await;
    registry.shutdown().await.unwrap();
}
async fn claim(database: &Database, now: Timestamp) -> Option<Claim> {
    let (owner, registry) = admission();
    let claim = owner
        .run(async {
            let mut tx = database
                .begin(owner.work_deadline().into_std())
                .await
                .unwrap();
            let mut calls = 16;
            let claim = QueueContext {
                tx: &mut tx,
                calls: &mut calls,
            }
            .claim("deployment", now)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            claim
        })
        .await;
    registry.shutdown().await.unwrap();
    claim
}
async fn state(database: &Database, job: &CapturedJob) -> (String, i64, i64) {
    let mut tx = database
        .begin_read(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let rows = tx
        .fetch::<3>(
            "SELECT state,CAST(attempts AS TEXT),CAST(fence AS TEXT) FROM nx_jobs WHERE id=$1",
            &[job.id().unwrap().into()],
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (
        rows[0][0].clone(),
        rows[0][1].parse().unwrap(),
        rows[0][2].parse().unwrap(),
    )
}

#[test]
fn capture_horizons_binding_seals_payload_and_stable_identity() {
    let grant = grant("alpha");
    let job = captured(&grant, "origin", 0, 1);
    assert_eq!(job.id().unwrap(), job.clone().id().unwrap());
    assert_eq!(
        job.input_digest().unwrap(),
        job.clone().input_digest().unwrap()
    );
    let mut changed = job.clone();
    changed.targets.get_mut("order").unwrap().incarnation = "replacement".into();
    assert_eq!(job.id().unwrap(), changed.id().unwrap());
    assert_ne!(
        job.invocation_digest().unwrap(),
        changed.invocation_digest().unwrap()
    );
    changed = job.clone();
    changed.grant_version += 1;
    assert_ne!(
        job.invocation_digest().unwrap(),
        changed.invocation_digest().unwrap()
    );
    assert!(
        CapturedJob::capture(
            &declaration(2),
            "origin".into(),
            &grant,
            1,
            at(1000),
            at(1000),
            Fields::new(),
            targets(1)
        )
        .is_err()
    );
    assert!(
        CapturedJob::capture(
            &declaration(0),
            "origin".into(),
            &grant,
            1,
            at(1001 + MAX_SCHEDULE_HORIZON_MILLIS),
            at(1000),
            Fields::new(),
            targets(1)
        )
        .is_err()
    );
    let mut bad = targets(1);
    bad.get_mut("order").unwrap().id = u64::MAX;
    assert!(
        CapturedJob::capture(
            &declaration(0),
            "origin".into(),
            &grant,
            1,
            at(1000),
            at(1000),
            Fields::new(),
            bad
        )
        .is_err()
    );
    let mut large = job;
    large.input.insert("text".into(), "x".repeat(MAX_JOB_BYTES));
    assert!(large.validate().is_err());
    for invalid in ["-1", "01", "+1", "1.0", "9223372036854775808"] {
        assert!(super::types::integer(invalid).is_err());
    }
}

async fn durable_contract(database: Database) {
    setup(&database).await;
    let first = captured(&grant("alpha"), "origin_a", 0, 1);
    let second = captured(&grant("beta"), "origin_b", 0, 2);
    enqueue(&database, &first).await;
    enqueue(&database, &second).await;
    // Retry of an effect ordinal reuses the immutable capture, even at quota.
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let mut calls = 16;
    assert!(
        !QueueContext {
            tx: &mut tx,
            calls: &mut calls
        }
        .enqueue(&first, at(1000), 1)
        .await
        .unwrap()
    );
    let mut forged = first.clone();
    forged.targets.get_mut("order").unwrap().incarnation = "forged".into();
    assert!(
        QueueContext {
            tx: &mut tx,
            calls: &mut calls
        }
        .enqueue(&forged, at(1000), 1000)
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    let first_claim = claim(&database, at(1000)).await.unwrap();
    let second_claim = claim(&database, at(1000)).await.unwrap();
    assert_ne!(first_claim.scope.tenant, second_claim.scope.tenant);
    assert!(claim(&database, at(1000)).await.is_none());
    let (first_claim, second_claim) = if first_claim.id() == first.id().unwrap() {
        (first_claim, second_claim)
    } else {
        (second_claim, first_claim)
    };
    let stable_identity = first.invocation_digest().unwrap();
    // Mutation, complete receipt and queue success are one transaction. Lost
    // acknowledgment must recover that receipt, preserving exactly one mutation.
    let (owner, registry) = admission();
    owner
        .run(async {
            let mut tx = database
                .begin(owner.work_deadline().into_std())
                .await
                .unwrap();
            let mut calls = 16;
            let Execution::Ready(verified) = (QueueContext {
                tx: &mut tx,
                calls: &mut calls,
            })
            .lock_execution(&first_claim, at(1000), receipt)
            .await
            .unwrap() else {
                panic!("expected ready")
            };
            assert_eq!(verified.invocation_digest().unwrap(), stable_identity);
            assert_eq!(verified.fence(), first_claim.fence());
            tx.execute(
                "INSERT INTO nx_job_test_mutations(id,value) VALUES(1,1)",
                &[],
            )
            .await
            .unwrap();
            insert_receipt(&mut tx, &first, r#"{"version":3,"fixture":"committed"}"#).await;
            QueueContext {
                tx: &mut tx,
                calls: &mut calls,
            }
            .succeed(&verified, receipt)
            .await
            .unwrap();
            assert_eq!(calls, 14);
            assert!(
                crate::failure_tests::lose_commit_ack(tx.commit())
                    .await
                    .is_err()
            );
            assert!(tx.commit_may_have_succeeded());
            assert!(tx.rollback().await.is_err());
        })
        .await;
    registry.shutdown().await.unwrap();
    assert_eq!(state(&database, &first).await, ("succeeded".into(), 1, 1));
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let mut calls = 16;
    assert!(matches!(
        QueueContext {
            tx: &mut tx,
            calls: &mut calls
        }
        .fail(&first_claim, at(2000), Failure::Transient, receipt)
        .await
        .unwrap(),
        FailureResult::Recovered(_)
    ));
    assert_eq!(
        tx.fetch::<1>(
            "SELECT CAST(value AS TEXT) FROM nx_job_test_mutations WHERE id=1",
            &[]
        )
        .await
        .unwrap(),
        [["1".into()]]
    );
    tx.commit().await.unwrap();
    // Expired lease is recoverable only via a higher fence and the locked receipt
    // probe. The stale worker cannot finalize, and invocation digest is stable.
    if !database.is_sqlite() {
        // PostgreSQL claims skip an execution-held row instead of retaining the
        // queue lock while waiting on an action that could itself enqueue.
        let mut held = database
            .begin(Instant::now() + std::time::Duration::from_secs(5))
            .await
            .unwrap();
        held.execute(
            "UPDATE nx_jobs SET fence=fence WHERE id=$1",
            &[second.id().unwrap().into()],
        )
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                claim(&database, at(31_000))
            )
            .await
            .unwrap()
            .is_none()
        );
        held.rollback().await.unwrap();
    }
    let newer = claim(&database, at(31_000)).await.unwrap();
    assert_eq!(newer.id(), second_claim.id());
    assert!(newer.fence() > second_claim.fence());
    let (owner, registry) = admission();
    owner
        .run(async {
            let mut tx = database
                .begin(owner.work_deadline().into_std())
                .await
                .unwrap();
            let mut calls = 16;
            assert!(
                QueueContext {
                    tx: &mut tx,
                    calls: &mut calls
                }
                .lock_execution(&second_claim, at(31_000), receipt)
                .await
                .is_err()
            );
            tx.rollback().await.unwrap();
        })
        .await;
    registry.shutdown().await.unwrap();
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let mut calls = 16;
    let FailureResult::Retrying(next) = (QueueContext {
        tx: &mut tx,
        calls: &mut calls,
    })
    .fail(&newer, at(31_000), Failure::Transient, receipt)
    .await
    .unwrap() else {
        panic!("expected retry")
    };
    assert!((331_000..=361_000).contains(&next.unix_millis()));
    tx.commit().await.unwrap();
    assert!(claim(&database, at(next.unix_millis() - 1)).await.is_none());
    let claim = claim(&database, next).await.unwrap();
    assert_eq!(state(&database, &second).await.1, 3);
    // A forged/incomplete receipt is unavailable, never a known abort/retry.
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    insert_receipt(&mut tx, &second, "{}").await;
    let mut calls = 16;
    assert!(
        QueueContext {
            tx: &mut tx,
            calls: &mut calls
        }
        .fail(&claim, next, Failure::Rejected, receipt)
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    insert_receipt(&mut tx, &second, r#"{"version":3,"fixture":"committed"}"#).await;
    tx.execute(
        "UPDATE nx_receipts SET input='forged' WHERE nonce=$1",
        &[second.id().unwrap().into()],
    )
    .await
    .unwrap();
    let mut calls = 16;
    assert!(
        QueueContext {
            tx: &mut tx,
            calls: &mut calls
        }
        .fail(&claim, next, Failure::Transient, receipt)
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    // Authoritative revocation pauses without executing or retrying as a user.
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_job_grants SET state='revoked' WHERE deployment='deployment' AND tenant='beta'",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (owner, registry) = admission();
    owner
        .run(async {
            let mut tx = database
                .begin(owner.work_deadline().into_std())
                .await
                .unwrap();
            let mut calls = 16;
            assert!(matches!(
                QueueContext {
                    tx: &mut tx,
                    calls: &mut calls
                }
                .lock_execution(&claim, next, receipt)
                .await
                .unwrap(),
                Execution::Paused
            ));
            tx.commit().await.unwrap();
        })
        .await;
    registry.shutdown().await.unwrap();
    assert_eq!(state(&database, &second).await.0, "paused");
    terminal_rejection_contract(&database).await;
    recurrence_contract(&database).await;
}

#[tokio::test]
async fn sqlite_durable_claim_fence_lost_ack_retry_and_forged_receipts() {
    let directory = tempfile::tempdir().unwrap();
    durable_contract(Database::sqlite(directory.path().join("jobs.db"))).await;
}
#[tokio::test]
#[ignore = "requires authorized disposable NOXIDE_TEST_POSTGRES; fixture retained"]
async fn postgres_durable_claim_fence_lost_ack_retry_and_forged_receipts() {
    use sqlx::Connection;
    let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
    let name = format!(
        "nx_jobs_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    println!("retained_fixture={name}");
    admin.close().await.unwrap();
    let mut url = url::Url::parse(&root).unwrap();
    url.set_path(&name);
    durable_contract(Database::postgres(url.as_str()).unwrap()).await;
}

#[test]
fn recurrence_occurrences_are_stable_and_expiry_repair_deduplicates_ticks() {
    let grant = grant("alpha");
    let targets = targets(1);
    let first = occurrence_key(
        &grant.scope,
        "repair",
        at(1000),
        1,
        &targets,
        Some(at(900)),
        &grant.contract,
    )
    .unwrap();
    let second = occurrence_key(
        &grant.scope,
        "repair",
        at(9000),
        9,
        &targets,
        Some(at(900)),
        &grant.contract,
    )
    .unwrap();
    assert_eq!(first, second);
    assert_ne!(
        first,
        occurrence_key(
            &grant.scope,
            "repair",
            at(1000),
            1,
            &targets,
            Some(at(901)),
            &grant.contract
        )
        .unwrap()
    );
    assert_ne!(
        occurrence_key(
            &grant.scope,
            "regular",
            at(1000),
            1,
            &targets,
            None,
            &grant.contract
        )
        .unwrap(),
        occurrence_key(
            &grant.scope,
            "regular",
            at(2000),
            2,
            &targets,
            None,
            &grant.contract
        )
        .unwrap()
    );
    let next = at(1_000)
        .checked_add(Duration::from_millis(60_000).unwrap())
        .unwrap();
    assert_eq!(next.unix_millis(), 61_000);
}

async fn recurrence_contract(database: &Database) {
    let declaration = RecurringSchedule {
        name: "repair".into(),
        worker: "expiry".into(),
        action: 2,
        interval: Duration::from_millis(60_000).unwrap(),
        inputs: BTreeMap::new(),
        selection: Some(RecurringSelection {
            operation: 9,
            target: "order".into(),
            expiry_repair: true,
        }),
    };
    let scope = grant("alpha").scope;
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_creation_counter SET value=100 WHERE singleton=1",
        &[],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO nx_job_recurring(deployment,tenant,name,contract,epoch,grant_version,version,state,next_ms,cutoff_ms,cutoff_seq,cursor) VALUES('deployment','alpha','repair','contract','epoch',1,1,'active',1000,0,0,'')", &[]).await.unwrap();
    tx.commit().await.unwrap();
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let mut calls = 16;
    let mut queue = QueueContext {
        tx: &mut tx,
        calls: &mut calls,
    };
    let mut batch = queue
        .begin_recurrence(&scope, &declaration, at(1000))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch.cutoff(), at(1000));
    assert_eq!(batch.cutoff_seq(), 100);
    assert_eq!(batch.remaining(), 20);
    assert!(
        queue
            .emit_recurrence(
                &mut batch,
                1,
                Fields::new(),
                targets(3),
                Some(at(900)),
                1000
            )
            .await
            .unwrap()
    );
    assert!(
        !queue
            .emit_recurrence(
                &mut batch,
                1,
                Fields::new(),
                targets(3),
                Some(at(900)),
                1000
            )
            .await
            .unwrap()
    );
    assert_eq!(batch.remaining(), 18);
    queue
        .finish_recurrence(batch, Some("frontier_a"))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // A missed interval coalesces; resume the original scan/cutoff and do not
    // reemit a repaired target. A newly inserted record is beyond cutoff_seq.
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_creation_counter SET value=200 WHERE singleton=1",
        &[],
    )
    .await
    .unwrap();
    let mut calls = 16;
    let mut queue = QueueContext {
        tx: &mut tx,
        calls: &mut calls,
    };
    let mut batch = queue
        .begin_recurrence(&scope, &declaration, at(121000))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch.cutoff(), at(1000));
    assert_eq!(batch.cutoff_seq(), 100);
    assert_eq!(batch.cursor(), Some("frontier_a"));
    assert!(
        !queue
            .emit_recurrence(
                &mut batch,
                1,
                Fields::new(),
                targets(3),
                Some(at(900)),
                1000
            )
            .await
            .unwrap()
    );
    assert!(
        queue
            .emit_recurrence(
                &mut batch,
                1,
                Fields::new(),
                targets(4),
                Some(at(950)),
                1000
            )
            .await
            .unwrap()
    );
    queue.finish_recurrence(batch, None).await.unwrap();
    tx.commit().await.unwrap();
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let mut calls = 16;
    let mut queue = QueueContext {
        tx: &mut tx,
        calls: &mut calls,
    };
    let mut batch = queue
        .begin_recurrence(&scope, &declaration, at(181000))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch.cutoff(), at(181000));
    assert_eq!(batch.cutoff_seq(), 200);
    assert!(batch.cursor().is_none());
    assert!(
        !queue
            .emit_recurrence(
                &mut batch,
                1,
                Fields::new(),
                targets(3),
                Some(at(900)),
                1000
            )
            .await
            .unwrap()
    );
    batch.emitted = MAX_RECURRENCE_FANOUT;
    assert!(
        queue
            .emit_recurrence(
                &mut batch,
                1,
                Fields::new(),
                targets(5),
                Some(at(950)),
                1000
            )
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    // A forged continuation cutoff cannot select future rows or bypass expiry.
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    tx.execute("UPDATE nx_job_recurring SET cursor='forged',cutoff_ms=1000000,cutoff_seq=201 WHERE name='repair'", &[]).await.unwrap();
    let mut calls = 16;
    assert!(
        QueueContext {
            tx: &mut tx,
            calls: &mut calls
        }
        .begin_recurrence(&scope, &declaration, at(181000))
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
}

async fn terminal_rejection_contract(database: &Database) {
    use crate::application::{ActionRejection, ValidatedActionRejection};
    let job = captured(&grant("alpha"), "terminal_rejection", 0, 5);
    enqueue(database, &job).await;
    let claimed = claim(database, at(1000)).await.unwrap();
    let action = noxide_protocol::Action {
        id: 2,
        version: 1,
        name: "Expiry".into(),
        targets: Vec::new(),
        inputs: Vec::new(),
        steps: Vec::new(),
    };
    let rejection = ActionRejection::Rejected {
        field_errors: Fields::new(),
        message: "Reservation already closed.".into(),
    };
    let validated = ValidatedActionRejection::new(&action, rejection.clone()).unwrap();
    let expected = validated.stored_json().to_owned();
    let (owner, registry) = admission();
    owner
        .run(async {
            let mut tx = database
                .begin(owner.work_deadline().into_std())
                .await
                .unwrap();
            let mut calls = 16;
            assert!(matches!(
                QueueContext {
                    tx: &mut tx,
                    calls: &mut calls
                }
                .lock_execution(&claimed, at(1000), receipt)
                .await
                .unwrap(),
                Execution::Ready(_)
            ));
            // The existing core rolls back a business rejection before the queue's
            // separate fenced terminal transition. No receipt/mutation is committed.
            tx.rollback().await.unwrap();
        })
        .await;
    registry.shutdown().await.unwrap();
    let mut other_action = action.clone();
    other_action.id = 99;
    let wrong = ValidatedActionRejection::new(&other_action, rejection.clone()).unwrap();
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let mut calls = 16;
    assert!(
        QueueContext {
            tx: &mut tx,
            calls: &mut calls
        }
        .fail(
            &claimed,
            at(1000),
            Failure::BusinessRejected(wrong),
            receipt
        )
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = database
        .begin(Instant::now() + std::time::Duration::from_secs(2))
        .await
        .unwrap();
    let mut calls = 16;
    let result = QueueContext {
        tx: &mut tx,
        calls: &mut calls,
    }
    .fail(
        &claimed,
        at(1000),
        Failure::BusinessRejected(validated),
        receipt,
    )
    .await
    .unwrap();
    let FailureResult::BusinessRejected(result) = result else {
        panic!("expected structured terminal rejection")
    };
    assert!(result.as_rejection() == &rejection);
    let column = tx.bounded_text("reason", crate::application::MAX_ACTION_REJECTION_BYTES);
    let rows = tx
        .fetch::<1>(
            &format!("SELECT {column} FROM nx_jobs WHERE id=$1"),
            &[job.id().unwrap().into()],
        )
        .await
        .unwrap();
    assert_eq!(rows[0][0], expected);
    assert!(
        ValidatedActionRejection::from_stored(&action, &rows[0][0])
            .unwrap()
            .as_rejection()
            == &rejection
    );
    tx.commit().await.unwrap();
    assert_eq!(state(database, &job).await.0, "rejected");
    assert!(claim(database, at(1000)).await.is_none());
}
