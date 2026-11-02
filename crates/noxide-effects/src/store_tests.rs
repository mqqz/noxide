//! Retained provider-paired store/operator fixtures. Actual action receipts and
//! Tor/TLS delivery are covered by the application adapter fixtures separately.

use crate::{
    EffectOperatorTransaction as _,
    effect_deployment::{EffectDeployment, EffectGrant, EffectLimits, EffectiveEffectDeployment},
    store::*,
    types::*,
};
use anyhow::Result;
use noxide_jobs::JobOperatorTransaction as _;
use noxide_protocol::{effects::*, time::Timestamp};
use noxide_store::database::{
    Database, Transaction,
    lifecycle::{AdmissionOwner, Registry, RequestScope},
};
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
    let mut lease = noxide_store::database::MaintenanceLease::new(
        permits.try_acquire_owned().unwrap(),
        Instant::now() + Duration::from_secs(5),
        noxide_store::lifecycle_clock::Freshness::default(),
    );
    lease.begin(db).await.unwrap();
    lease
        .tx()
        .activate_effects(
            "deployment",
            "contract",
            Some(effective),
            Some("prepared-directory-fixture-proof"),
            false,
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
        .claim(
            "deployment",
            "contract",
            "prepared-directory-fixture-proof",
            at(now),
            &[],
        )
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
            tx.execute("INSERT INTO nx_outbox(id,deployment,tenant,origin,ordinal,endpoint,contract,epoch,grant_version,secret_version,payload,payload_digest,eligible_ms,first_eligible_ms,attempts,fence,lease_until_ms,round,state,reason) VALUES($1,'deployment',$2,$3,0,'events','contract','epoch',1,0,$4,$5,1000,1000,0,0,0,0,'pending','')",&[capture.id()?.into(),tenant.into(),capture.origin().into(),serde_json::to_string(&capture)?.into(),capture.capture_digest()?.into()]).await?;
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
            tx.fetch::<1>("SELECT id FROM nx_outbox WHERE state='pending'", &[])
                .await
        })
        .await
        .unwrap();
        let id = &rows[0][0];
        phase(db, async |tx: &mut Transaction| {
            tx.grant_effect_endpoint("deployment", "contract", &effective.grants[0])
                .await?;
            assert_eq!(
                tx.fetch::<1>(
                    "SELECT state FROM nx_outbox WHERE id=$1",
                    &[id.as_str().into()]
                )
                .await?,
                [[String::from("paused")]]
            );
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
            .claim(
                "deployment",
                "contract",
                "prepared-directory-fixture-proof",
                at(now + 86400000),
                &[]
            )
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
    let recovered = claim(db, fifth.lease_until().unix_millis()).await;
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        assert!(matches!(
            OutboxContext {
                tx,
                calls: &mut calls
            }
            .preflight(&recovered, fifth.lease_until())
            .await?,
            Preflight::Settled(Finalized::Dead)
        ));
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(state(db, &lost.id().unwrap()).await, "dead");
    // A preflight failure before any send returns the claim and its attempt.
    let unsent = enqueue(db, "alpha", "preflight-unavailable").await;
    let first = claim(db, 1000).await;
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        OutboxContext {
            tx,
            calls: &mut calls,
        }
        .release_unsent(&first)
        .await
    })
    .await
    .unwrap();
    assert_eq!(state(db, &unsent.id().unwrap()).await, "pending");
    let second = claim(db, 1000).await;
    assert_eq!(second.id(), first.id());
    let attempts = phase(db, async |tx: &mut Transaction| {
        tx.fetch::<1>(
            "SELECT CAST(attempts AS TEXT) FROM nx_outbox WHERE id=$1",
            &[second.id().into()],
        )
        .await
    })
    .await
    .unwrap();
    assert_eq!(attempts[0][0], "1", "the released attempt was refunded");
    // A stale claim cannot release the newer one.
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        OutboxContext {
            tx,
            calls: &mut calls,
        }
        .release_unsent(&first)
        .await
    })
    .await
    .unwrap();
    assert_eq!(state(db, &unsent.id().unwrap()).await, "running");
    // A clock jump past the lease before any send requeues; it is not dead.
    let jumped = enqueue(db, "alpha", "lease-expired-before-send").await;
    let stale = claim(db, 1000).await;
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        assert!(matches!(
            OutboxContext {
                tx,
                calls: &mut calls
            }
            .preflight(&stale, stale.lease_until())
            .await?,
            Preflight::Settled(Finalized::Retrying(at)) if at == stale.lease_until()
        ));
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(state(db, &jumped.id().unwrap()).await, "pending");
}
async fn secret_grant_change_contract(db: &Database) {
    let mut effective = approval();
    effective
        .grants
        .iter_mut()
        .for_each(|g| g.endpoint.secret_slot = Some("token".into()));
    effective.contract.endpoints[0].secret_slot = Some("token".into());
    effective.secrets = vec![crate::effect_deployment::EffectSecret {
        slot: "token".into(),
        path: "/host/test-only-no-read".into(),
    }];
    setup(db, &effective).await;
    let capture = enqueue(db, "alpha", "slot-change").await;
    phase(db, async |tx: &mut Transaction| {
        tx.grant_effect_secret("deployment", "contract", "token", &effective)
            .await
    })
    .await
    .unwrap();
    assert_eq!(state(db, &capture.id().unwrap()).await, "paused");
    phase(db, async |tx: &mut Transaction| {
        tx.resume_effect(
            "deployment",
            "contract",
            &effective,
            &capture.id()?,
            1,
            at(1001),
            false,
        )
        .await?;
        let source = tx
            .effect_operator_source("deployment", &capture.id()?)
            .await?;
        assert_eq!(source.receiver_key()?, capture.receiver_key()?);
        assert_eq!(source.capture_digest()?, capture.capture_digest()?);
        Ok(())
    })
    .await
    .unwrap();
    let claim = claim(db, 1001).await;
    phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        assert!(matches!(
            OutboxContext {
                tx,
                calls: &mut calls
            }
            .preflight(&claim, at(1001))
            .await?,
            Preflight::Send(_)
        ));
        Ok(())
    })
    .await
    .unwrap();
}
async fn recovered_activation(
    db: &Database,
    generation: &str,
    effective: &EffectiveEffectDeployment,
) {
    let permits = Arc::new(Semaphore::new(1));
    let mut lease = noxide_store::database::MaintenanceLease::new(
        permits.try_acquire_owned().unwrap(),
        Instant::now() + Duration::from_secs(5),
        noxide_store::lifecycle_clock::Freshness::default(),
    );
    lease.begin(db).await.unwrap();
    lease
        .tx()
        .activate_jobs(generation, "contract", None, None, true)
        .await
        .unwrap();
    lease
        .tx()
        .activate_effects(
            generation,
            "contract",
            Some(effective),
            Some("prepared-directory-fixture-proof"),
            false,
        )
        .await
        .unwrap();
    let memory = std::sync::atomic::AtomicI64::new(0);
    let _tick = noxide_store::lifecycle_clock::tick(lease.tx(), &memory)
        .await
        .unwrap();
    lease.finish().await.unwrap();
}
async fn actual_clock_recovery_contract(db: &Database) {
    let effective = approval();
    setup(db, &effective).await;
    let initial = noxide_protocol::time::Timestamp::from_system_time(SystemTime::now()).unwrap();
    let (capture, pending) = phase(db, async |tx: &mut Transaction| {
        tx.execute(
            "UPDATE nx_clock SET lifecycle_ms=$1,lifecycle_version=7 WHERE singleton=1",
            &[initial.unix_millis().into()],
        )
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
        let captured = CapturedEffect::capture(
            &effective.contract.emissions[0],
            "actual-clock-recovery".into(),
            1,
            &proof,
            b"{}".to_vec(),
            initial,
        )?;
        outbox.enqueue(&captured, initial).await?;
        let proof = outbox
            .endpoint_grant(
                &EffectScope {
                    deployment: "deployment".into(),
                    tenant: "beta".into(),
                },
                "events",
                "contract",
            )
            .await?;
        let pending = CapturedEffect::capture(
            &effective.contract.emissions[0],
            "actual-clock-pending".into(),
            1,
            &proof,
            b"{}".to_vec(),
            initial,
        )?;
        outbox.enqueue(&pending, initial).await?;
        Ok((captured, pending))
    })
    .await
    .unwrap();
    let _old = claim(db, initial.unix_millis()).await;
    phase(db,async |tx:&mut Transaction| {assert_eq!(tx.fetch::<2>("SELECT CAST((SELECT COUNT(*) FROM nx_outbox WHERE state='pending') AS TEXT),CAST((SELECT COUNT(*) FROM nx_outbox WHERE state='running') AS TEXT)",&[]).await?,[[String::from("1"),String::from("1")]]);Ok(())}).await.unwrap();
    db.recover_clock("effect-store-test").await.unwrap();
    let recovered=phase(db,async |tx:&mut Transaction| {tx.fetch::<6>("SELECT generation,CAST((SELECT lifecycle_ms FROM nx_clock WHERE singleton=1) AS TEXT),(SELECT state FROM nx_outbox WHERE id=$1),(SELECT state FROM nx_job_runtime WHERE singleton=1),(SELECT state FROM nx_outbox WHERE id=$2),CAST((SELECT first_eligible_ms FROM nx_outbox WHERE id=$1) AS TEXT) FROM nx_deployment WHERE singleton=1",&[capture.id()?.into(),pending.id()?.into()]).await}).await.unwrap();
    assert_ne!(recovered[0][0], "deployment");
    assert_eq!(recovered[0][1], initial.unix_millis().to_string());
    assert_eq!(recovered[0][2], "paused");
    assert_eq!(recovered[0][3], "paused");
    assert_eq!(recovered[0][4], "paused");
    assert_eq!(recovered[0][5], initial.unix_millis().to_string());
    let generation = &recovered[0][0];
    recovered_activation(db, generation, &effective).await;
    let snapshot=phase(db,async |tx:&mut Transaction| {tx.fetch::<4>("SELECT epoch,state,(SELECT state FROM nx_effect_grants WHERE deployment=$1 AND tenant='alpha' AND endpoint='events'),(SELECT state FROM nx_outbox WHERE id=$2) FROM nx_job_runtime WHERE singleton=1",&[generation.as_str().into(),capture.id()?.into()]).await}).await.unwrap();
    assert_eq!(
        &snapshot[0][1..],
        &[
            String::from("paused"),
            String::from("revoked"),
            String::from("paused")
        ]
    );
    recovered_activation(db, generation, &effective).await;
    phase(db, async |tx: &mut Transaction| {
        let rows = tx
            .fetch::<2>(
                "SELECT epoch,state FROM nx_job_runtime WHERE singleton=1",
                &[],
            )
            .await?;
        assert_eq!(rows, [[snapshot[0][0].clone(), String::from("paused")]]);
        Ok(())
    })
    .await
    .unwrap();
    phase(db, async |tx: &mut Transaction| {
        let rows = tx
            .fetch::<1>(
                "SELECT CAST(lifecycle_ms AS TEXT) FROM nx_clock WHERE singleton=1",
                &[],
            )
            .await?;
        let now = at(rows[0][0].parse()?);
        tx.grant_effect_endpoint(generation, "contract", &effective.grants[0])
            .await?;
        tx.resume_effect(
            generation,
            "contract",
            &effective,
            &capture.id()?,
            1,
            now,
            false,
        )
        .await?;
        let source = tx
            .effect_operator_source(generation, &capture.id()?)
            .await?;
        assert_eq!(source.capture_digest()?, capture.capture_digest()?);
        assert_eq!(source.receiver_key()?, capture.receiver_key()?);
        assert_eq!(tx.fetch::<2>("SELECT CAST(first_eligible_ms AS TEXT),CAST(round AS TEXT) FROM nx_outbox WHERE id=$1",&[capture.id()?.into()]).await?,[[initial.unix_millis().to_string(),String::from("0")]]);
        let mut calls = 16;
        let claim = OutboxContext {
            tx,
            calls: &mut calls,
        }
        .claim(generation, "contract", "prepared-directory-fixture-proof", now, &[])
        .await?
        .unwrap();
        assert!(matches!(
            OutboxContext {
                tx,
                calls: &mut calls
            }
            .preflight(&claim, now)
            .await?,
            Preflight::Send(_)
        ));
        Ok(())
    })
    .await
    .unwrap();
}
async fn restore_owner_contract(db: &Database) {
    let effective = approval();
    setup(db, &effective).await;
    let capture = enqueue(db, "alpha", "restored-owner").await;
    let activate = async |restore_fork: bool| {
        let permits = Arc::new(Semaphore::new(1));
        let mut lease = noxide_store::database::MaintenanceLease::new(
            permits.try_acquire_owned().unwrap(),
            Instant::now() + Duration::from_secs(5),
            noxide_store::lifecycle_clock::Freshness::default(),
        );
        lease.begin(db).await.unwrap();
        let result = lease
            .tx()
            .activate_effects(
                "deployment",
                "contract",
                Some(&effective),
                Some("restored-directory-fixture-proof"),
                restore_fork,
            )
            .await;
        if result.is_ok() {
            lease.tx().commit().await.unwrap();
        } else {
            lease.tx().rollback().await.unwrap();
        }
        lease.finish().await.unwrap();
        result
    };
    // A copied queue under another owner directory fails closed by default.
    let refused = activate(false).await.unwrap_err();
    assert!(refused.to_string().contains("another owner directory"));
    assert_eq!(state(db, &capture.id().unwrap()).await, "pending");
    // Explicit restore fencing adopts it and pauses captures atomically.
    activate(true).await.unwrap();
    assert_eq!(state(db, &capture.id().unwrap()).await, "paused");
    let rows = phase(db, async |tx: &mut Transaction| {
        tx.fetch::<2>(
            "SELECT owner_directory,(SELECT CAST(COUNT(*) AS TEXT) FROM nx_effect_grants WHERE state='active') FROM nx_effect_queue",
            &[],
        )
        .await
    })
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![[
            "restored-directory-fixture-proof".to_owned(),
            "0".to_owned()
        ]]
    );
    // A host still bound to the original owner directory cannot claim.
    let stale = phase(db, async |tx: &mut Transaction| {
        let mut calls = 16;
        OutboxContext {
            tx,
            calls: &mut calls,
        }
        .claim(
            "deployment",
            "contract",
            "prepared-directory-fixture-proof",
            at(1000),
            &[],
        )
        .await
    })
    .await;
    assert!(
        stale
            .err()
            .unwrap()
            .to_string()
            .contains("another directory")
    );
    // Re-activating the adopted owner is an ordinary restart.
    activate(false).await.unwrap();
    assert_eq!(state(db, &capture.id().unwrap()).await, "paused");
}
async fn sqlite(label: &str) -> Database {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-fixtures/effect-store-fixtures");
    std::fs::create_dir_all(&root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(root)
        .unwrap()
        .keep();
    let db = Database::sqlite(directory.join("case.db"));
    eprintln!("retained store fixture: {}", directory.display());
    db
}
async fn postgres(label: &str) -> Database {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_effect_store_{label}_{}_{}",
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
async fn sqlite_secret_grant_rotation_pauses_before_explicit_resume() {
    secret_grant_change_contract(&sqlite("secret-change-").await).await;
}
#[tokio::test]
async fn sqlite_actual_clock_recovery_preserves_pause_until_current_reconciliation() {
    actual_clock_recovery_contract(&sqlite("clock-recovery-").await).await;
}
#[tokio::test]
async fn sqlite_restore_fork_alone_adopts_copied_effect_owner() {
    restore_owner_contract(&sqlite("restore-owner-").await).await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_restore_fork_alone_adopts_copied_effect_owner() {
    restore_owner_contract(&postgres("restoreowner").await).await;
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
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_secret_grant_rotation_pauses_before_explicit_resume() {
    secret_grant_change_contract(&postgres("secretchange").await).await;
}
#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_actual_clock_recovery_preserves_pause_until_current_reconciliation() {
    actual_clock_recovery_contract(&postgres("clockrecovery").await).await;
}
