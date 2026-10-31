//! Retained provider-paired store/operator fixtures. Actual action receipts and
//! Tor/TLS delivery are covered by the application adapter fixtures separately.
use super::*;
use crate::{
    database::{
        Database, Transaction,
        lifecycle::{AdmissionOwner, Registry, RequestScope},
    },
    effect_deployment::{EffectDeployment, EffectGrant, EffectLimits, EffectiveEffectDeployment},
};
use anyhow::Result;
use noxide_protocol::{effects::*, time::Timestamp};
use sqlx::Connection;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
fn at(ms: i64) -> Timestamp {
    Timestamp::from_unix_millis(ms).unwrap()
}
fn approval() -> EffectiveEffectDeployment {
    EffectDeployment {
        grants: ["alpha", "beta"]
            .map(|tenant| EffectGrant {
                endpoint: "events".into(),
                tenant: tenant.into(),
                host: "receiver.org".into(),
                port: 443,
                path: "/events".into(),
            })
            .into(),
        secrets: vec![],
        tor_proxy: "127.0.0.1:9050".parse().unwrap(),
        limits: EffectLimits::default(),
        runtime_directory: None,
    }
    .effective(&EffectContract {
        endpoints: vec![EffectEndpoint {
            name: "events".into(),
            secret_slot: None,
        }],
        emissions: vec![EmitEffect {
            source_action: 1,
            ordinal: 0,
            endpoint: "events".into(),
            fields: vec![],
        }],
    })
    .unwrap()
}
async fn phase<T>(
    db: &Database,
    operation: impl for<'a> std::ops::AsyncFnOnce(&'a mut Transaction) -> Result<T>,
) -> Result<T> {
    let registry = Arc::new(Registry::default());
    let cap = Duration::from_secs(5);
    let scope = RequestScope::new(
        registry.clone(),
        tokio::time::Instant::now() + cap,
        cap,
        256,
    );
    let request = Arc::new(Semaphore::new(1));
    let database = Arc::new(Semaphore::new(1));
    let owner = AdmissionOwner::new(
        scope,
        Arc::new(request.try_acquire_owned()?),
        Arc::new(database.try_acquire_owned()?),
        None,
    );
    let value = owner
        .run(async {
            let mut tx = db.begin(owner.work_deadline().into_std()).await?;
            match operation(&mut tx).await {
                Ok(value) => {
                    tx.commit().await?;
                    Ok(value)
                }
                Err(error) => {
                    tx.rollback().await?;
                    Err(error)
                }
            }
        })
        .await;
    registry.shutdown().await?;
    value
}
async fn setup(db: &Database, effective: &EffectiveEffectDeployment) {
    db.initialize().await.unwrap();
    phase(db,async |tx:&mut Transaction| {tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'contract','incarnation','deployment') ON CONFLICT(singleton) DO UPDATE SET contract='contract',incarnation='incarnation',generation='deployment'",&[]).await?;tx.execute("INSERT INTO nx_job_runtime(singleton,deployment,contract,epoch,state,pending_limit,tenant_limit,concurrency) VALUES(1,'deployment','contract','epoch','active',1000,1000,2)",&[]).await?;tx.execute("CREATE TABLE nx_effect_test_mutations(id BIGINT PRIMARY KEY,value BIGINT NOT NULL)",&[]).await?;Ok(())}).await.unwrap();
    let permits = Arc::new(Semaphore::new(1));
    let mut lease = crate::database::MaintenanceLease::new(
        permits.try_acquire_owned().unwrap(),
        Instant::now() + Duration::from_secs(5),
        crate::lifecycle_clock::Freshness::default(),
    );
    lease.begin(db).await.unwrap();
    lease
        .tx()
        .activate_effects(
            "deployment",
            "contract",
            Some(effective),
            Some("prepared-directory-fixture-proof"),
        )
        .await
        .unwrap();
    lease.tx().commit().await.unwrap();
    lease.finish().await.unwrap();
}
async fn enqueue(db: &Database, tenant: &str, origin: &str) -> CapturedEffect {
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        let mut outbox = OutboxContext {
            tx,
            calls: &mut calls,
        };
        let proof = outbox
            .endpoint_grant(
                &EffectScope {
                    deployment: "deployment".into(),
                    tenant: tenant.into(),
                },
                "events",
                "contract",
            )
            .await?;
        let captured = CapturedEffect::capture(
            &approval().contract.emissions[0],
            origin.into(),
            1,
            &proof,
            b"{}".to_vec(),
            at(1000),
        )?;
        outbox.enqueue(&captured, at(1000)).await?;
        assert_eq!(calls, 14);
        Ok(captured)
    })
    .await
    .unwrap()
}
async fn claim(db: &Database, now: i64) -> EffectClaim {
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        Ok(OutboxContext {
            tx,
            calls: &mut calls,
        }
        .claim("deployment", "contract", at(now), &[])
        .await?
        .unwrap())
    })
    .await
    .unwrap()
}
async fn state(db: &Database, id: &str) -> String {
    phase(db, async |tx: &mut Transaction| {
        Ok(tx
            .fetch::<1>("SELECT state FROM nx_outbox WHERE id=$1", &[id.into()])
            .await?[0][0]
            .clone())
    })
    .await
    .unwrap()
}
async fn observe(
    db: &Database,
    claim: &EffectClaim,
    now: i64,
    result: DeliveryResult,
) -> Finalized {
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        OutboxContext {
            tx,
            calls: &mut calls,
        }
        .finalize(claim, at(now), result)
        .await
    })
    .await
    .unwrap()
}

async fn known_success_contract(db: &Database) {
    let effective = approval();
    setup(db, &effective).await;
    for (index, mutation) in ["revoke", "cancel", "wall"].into_iter().enumerate() {
        if index > 0 {
            phase(db, async |tx: &mut Transaction| {
                tx.grant_effect_endpoint("deployment", "contract", &effective.grants[0])
                    .await
            })
            .await
            .unwrap();
        }
        let capture = enqueue(db, "alpha", mutation).await;
        let claim = claim(db, 1000).await;
        phase(db, async |tx: &mut Transaction| {
            let mut calls = 16;
            assert!(matches!(
                OutboxContext {
                    tx,
                    calls: &mut calls
                }
                .preflight(&claim, at(1000))
                .await?,
                Preflight::Send(_)
            ));
            Ok(())
        })
        .await
        .unwrap();
        match mutation {
            "revoke" => phase(db, async |tx: &mut Transaction| {
                tx.revoke_effect_endpoint("deployment", "alpha", "events")
                    .await
            })
            .await
            .unwrap(),
            "cancel" => phase(db, async |tx: &mut Transaction| {
                tx.cancel_effect("deployment", &capture.id()?).await
            })
            .await
            .unwrap(),
            _ => (),
        }
        assert_eq!(
            observe(
                db,
                &claim,
                if mutation == "wall" { 61_001 } else { 1001 },
                DeliveryResult::Delivered
            )
            .await,
            Finalized::Delivered
        );
        assert_eq!(state(db, &capture.id().unwrap()).await, "delivered");
    }
    let capture = enqueue(db, "alpha", "stale-epoch").await;
    let old = claim(db, 1000).await;
    phase(db, async |tx: &mut Transaction| {
        tx.pause_effects_for_epoch().await?;
        tx.execute(
            "UPDATE nx_job_runtime SET epoch='new-epoch',state='paused'",
            &[],
        )
        .await?;
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(
        observe(db, &old, 1001, DeliveryResult::Delivered).await,
        Finalized::Superseded
    );
    assert_eq!(state(db, &capture.id().unwrap()).await, "paused");
    // Explicit current grants/reconciliation keep the receiver identity, while
    // advancing the fence makes the original in-flight observation obsolete.
    phase(db, async |tx: &mut Transaction| {
        tx.grant_effect_endpoint("deployment", "contract", &effective.grants[0])
            .await?;
        tx.resume_effect(
            "deployment",
            "contract",
            &effective,
            &capture.id()?,
            1,
            at(1001),
            false,
        )
        .await
    })
    .await
    .unwrap();
    assert_eq!(
        observe(db, &old, 1002, DeliveryResult::Delivered).await,
        Finalized::Superseded
    );
    phase(db, async |tx: &mut Transaction| {
        let source = tx
            .effect_operator_source("deployment", &capture.id()?)
            .await?;
        assert_eq!(source.receiver_key()?, capture.receiver_key()?);
        assert_eq!(source.body(), capture.body());
        Ok(())
    })
    .await
    .unwrap();
}
async fn fill(db: &Database, tenant: &str, count: usize) {
    // Valid captures bootstrap a full queue in <=64 native queries/root;
    // setup deliberately bypasses enqueue only to avoid testing 1000 adapters.
    for first in (0..count).step_by(32) {
        let end = (first + 32).min(count);
        phase(db,async |tx:&mut Transaction| {let mut calls=16;let proof=OutboxContext {tx,calls:&mut calls}.endpoint_grant(&EffectScope {deployment:"deployment".into(),tenant:tenant.into()},"events","contract").await?;
        for n in first..end {let capture=CapturedEffect::capture(&approval().contract.emissions[0],format!("filler-{n}"),1,&proof,b"{}".to_vec(),at(1000))?;
            tx.execute("INSERT INTO nx_effect_tenants(deployment,tenant,claim_seq) VALUES('deployment',$1,0) ON CONFLICT(deployment,tenant) DO NOTHING",&[tenant.into()]).await?;
            tx.execute("INSERT INTO nx_outbox(id,deployment,tenant,origin,ordinal,endpoint,contract,epoch,grant_version,secret_version,payload,payload_digest,eligible_ms,first_eligible_ms,attempts,fence,lease_until_ms,round,state,reason) VALUES($1,'deployment',$2,$3,0,'events','contract','epoch',1,0,$4,$5,1000,1000,0,0,0,0,'pending','')",&[capture.id()?.into(),tenant.into(),capture.origin.as_str().into(),serde_json::to_string(&capture)?.into(),capture.capture_digest()?.into()]).await?;
        }Ok(())}).await.unwrap();
    }
}
async fn quota_contract(db: &Database, app_full: bool) {
    let effective = approval();
    setup(db, &effective).await;
    let dead = enqueue(db, "alpha", "dead").await;
    let claim = claim(db, 1000).await;
    assert_eq!(
        observe(db, &claim, 1001, DeliveryResult::Terminal).await,
        Finalized::Dead
    );
    fill(
        db,
        if app_full { "beta" } else { "alpha" },
        if app_full { 1000 } else { 1 },
    )
    .await;
    if !app_full {
        phase(db, async |tx: &mut Transaction| {
            tx.execute("UPDATE nx_effect_queue SET tenant_limit=1", &[])
                .await?;
            Ok(())
        })
        .await
        .unwrap();
    }
    assert!(
        phase(db, async |tx: &mut Transaction| tx
            .resume_effect(
                "deployment",
                "contract",
                &effective,
                &dead.id()?,
                1,
                at(1002),
                true
            )
            .await)
        .await
        .is_err()
    );
    assert_eq!(state(db, &dead.id().unwrap()).await, "dead");
    if !app_full {
        let rows = phase(db, async |tx: &mut Transaction| {
            Ok(tx
                .fetch::<1>("SELECT id FROM nx_outbox WHERE state='pending'", &[])
                .await?)
        })
        .await
        .unwrap();
        let id = &rows[0][0];
        phase(db, async |tx: &mut Transaction| {
            tx.execute(
                "UPDATE nx_outbox SET state='paused' WHERE id=$1",
                &[id.as_str().into()],
            )
            .await?;
            tx.resume_effect("deployment", "contract", &effective, id, 1, at(1002), false)
                .await
        })
        .await
        .unwrap();
        assert_eq!(state(db, id).await, "pending");
    }
}
async fn retry_and_atomicity_contract(db: &Database) {
    let effective = approval();
    setup(db, &effective).await;
    let failed: Result<()> = phase(db, async |tx: &mut Transaction| {
        tx.execute("INSERT INTO nx_effect_test_mutations VALUES(1,1)", &[])
            .await?;
        let mut calls = 16;
        let mut outbox = OutboxContext {
            tx,
            calls: &mut calls,
        };
        let proof = outbox
            .endpoint_grant(
                &EffectScope {
                    deployment: "deployment".into(),
                    tenant: "alpha".into(),
                },
                "events",
                "contract",
            )
            .await?;
        let capture = CapturedEffect::capture(
            &effective.contract.emissions[0],
            "rollback".into(),
            1,
            &proof,
            b"{}".to_vec(),
            at(1000),
        )?;
        outbox.enqueue(&capture, at(1000)).await?;
        anyhow::bail!("forced precommit rejection")
    })
    .await;
    assert!(failed.is_err());
    phase(db,async |tx:&mut Transaction| {assert_eq!(tx.fetch::<2>("SELECT CAST((SELECT COUNT(*) FROM nx_outbox) AS TEXT),CAST((SELECT COUNT(*) FROM nx_effect_test_mutations) AS TEXT)",&[]).await?,[[String::from("0"),String::from("0")]]);Ok(())}).await.unwrap();
    let capture = enqueue(db, "alpha", "five-attempts").await;
    let duplicate = enqueue(db, "alpha", "five-attempts").await;
    assert_eq!(capture.id().unwrap(), duplicate.id().unwrap());
    let mut now = 1000;
    for attempt in 1..=5 {
        let claim = claim(db, now).await;
        let result = observe(
            db,
            &claim,
            now,
            DeliveryResult::Retry {
                retry_after_seconds: None,
            },
        )
        .await;
        match result {
            Finalized::Retrying(next) => {
                assert!(attempt < 5);
                now = next.unix_millis();
            }
            Finalized::Dead => assert_eq!(attempt, 5),
            _ => panic!("unexpected attempt outcome"),
        }
    }
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        assert!(
            OutboxContext {
                tx,
                calls: &mut calls
            }
            .claim("deployment", "contract", at(now + 86400000), &[])
            .await?
            .is_none()
        );
        Ok(())
    })
    .await
    .unwrap();
    let exact = enqueue(db, "alpha", "exact-window").await;
    let exact_claim = claim(db, 1000 + EFFECT_RETRY_WINDOW_MILLIS).await;
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        assert!(matches!(
            OutboxContext {
                tx,
                calls: &mut calls
            }
            .preflight(&exact_claim, at(1000 + EFFECT_RETRY_WINDOW_MILLIS))
            .await?,
            Preflight::Settled(Finalized::Dead)
        ));
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(state(db, &exact.id().unwrap()).await, "dead");
    let lost = enqueue(db, "alpha", "lost-fifth-attempt").await;
    phase(db, async |tx: &mut Transaction| {
        tx.execute(
            "UPDATE nx_outbox SET attempts=4 WHERE id=$1",
            &[lost.id()?.into()],
        )
        .await?;
        Ok(())
    })
    .await
    .unwrap();
    let fifth = claim(db, 1000).await;
    // No finalization acknowledgment: the fifth send could already have left.
    // Reclaim may inspect state but cannot create a sixth network attempt.
    let recovered = claim(db, fifth.lease_until.unix_millis()).await;
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        assert!(matches!(
            OutboxContext {
                tx,
                calls: &mut calls
            }
            .preflight(&recovered, fifth.lease_until)
            .await?,
            Preflight::Settled(Finalized::Dead)
        ));
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(state(db, &lost.id().unwrap()).await, "dead");
}
async fn sqlite(label: &str) -> Database {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/capability-evidence/p11-store-fixtures");
    std::fs::create_dir_all(&root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(root)
        .unwrap()
        .keep();
    let db = Database::sqlite(directory.join("case.db"));
    eprintln!("retained P11 store fixture: {}", directory.display());
    db
}
async fn postgres(label: &str) -> Database {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_p11_{label}_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    assert!(name.len() <= 63);
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut url = url::Url::parse(&url).unwrap();
    url.set_path(&format!("/{name}"));
    Database::postgres(url.as_str()).unwrap()
}
#[tokio::test]
async fn sqlite_known_success_survives_revocation_cancel_and_wall_expiry() {
    known_success_contract(&sqlite("success-").await).await;
}
#[tokio::test]
async fn sqlite_dead_retry_respects_app_quota() {
    quota_contract(&sqlite("app-quota-").await, true).await;
}
#[tokio::test]
async fn sqlite_dead_retry_respects_lowered_tenant_quota_and_paused_resume() {
    quota_contract(&sqlite("tenant-quota-").await, false).await;
}
#[tokio::test]
async fn sqlite_atomicity_dedup_five_attempts_and_exact_window() {
    retry_and_atomicity_contract(&sqlite("retry-").await).await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_known_success_survives_revocation_cancel_and_wall_expiry() {
    known_success_contract(&postgres("success").await).await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_dead_retry_respects_app_quota() {
    quota_contract(&postgres("appquota").await, true).await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_dead_retry_respects_lowered_tenant_quota_and_paused_resume() {
    quota_contract(&postgres("tenantquota").await, false).await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_atomicity_dedup_five_attempts_and_exact_window() {
    retry_and_atomicity_contract(&postgres("retry").await).await;
}
