use super::*;

async fn quota_case(database: &Database, limit: u16) -> (u16, bool) {
    let registry = Arc::new(Registry::default());
    let scope = RequestScope::new(
        registry.clone(),
        tokio::time::Instant::now() + Duration::from_secs(2),
        Duration::from_secs(2),
        limit,
    );
    let meter = scope.root.meter.clone();
    let requests = Arc::new(Semaphore::new(1));
    let slots = Arc::new(Semaphore::new(1));
    let owner = AdmissionOwner::new(
        scope,
        Arc::new(requests.clone().try_acquire_owned().unwrap()),
        Arc::new(slots.clone().try_acquire_owned().unwrap()),
        None,
    );
    let committed = owner
        .run(async {
            let mut tx = match database.begin(owner.work_deadline().into_std()).await {
                Ok(tx) => tx,
                Err(error) => {
                    assert!(error.is::<meter::StatementLimit>(), "{error:#}");
                    return false;
                }
            };
            let mutation = tx
                .execute("UPDATE nx_clock SET observed=42 WHERE singleton=1", &[])
                .await;
            if let Err(error) = mutation {
                assert!(error.is::<meter::StatementLimit>(), "{error:#}");
                tx.rollback().await.unwrap();
                return false;
            }
            match tx.commit().await {
                Ok(()) => {
                    assert!(tx.commit_acknowledged());
                    true
                }
                Err(error) => {
                    assert!(error.is::<meter::StatementLimit>(), "{error:#}");
                    assert!(
                        !tx.commit_may_have_succeeded(),
                        "quota refusal before COMMIT issue must remain known pre-send"
                    );
                    tx.rollback().await.unwrap();
                    false
                }
            }
        })
        .await;
    drop(owner);
    registry.shutdown().await.unwrap();
    assert_eq!(requests.available_permits(), 1);
    assert_eq!(slots.available_permits(), 1);
    let (free, reserved, spent) = meter.snapshot();
    assert_eq!(reserved, 0);
    assert_eq!(free + spent, limit);
    assert!(spent <= limit);
    let mut read = database
        .begin(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let value = read
        .fetch::<1>(
            "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(value[0][0], if committed { "42" } else { "0" });
    read.execute("UPDATE nx_clock SET observed=0 WHERE singleton=1", &[])
        .await
        .unwrap();
    read.commit().await.unwrap();
    println!(
        "provider={} limit={limit} charged={spent} remaining={free} committed={committed}",
        if database.is_sqlite() {
            "sqlite"
        } else {
            "postgres"
        }
    );
    (spent, committed)
}

#[tokio::test]
async fn sqlite_actual_setup_mutation_commit_exhaustion_keeps_capacity_and_state() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::sqlite(directory.path().join("quota.db"));
    database.initialize().await.unwrap();
    for limit in 1..=10 {
        let (spent, committed) = quota_case(&database, limit).await;
        assert_eq!(committed, limit >= 9);
        if committed {
            assert_eq!(spent, 9);
        }
    }
}

#[tokio::test]
#[ignore = "requires authorized disposable NOXIDE_TEST_POSTGRES"]
async fn postgres_actual_setup_mutation_commit_exhaustion_keeps_capacity_and_state() {
    let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
    let name = format!(
        "nx_actual_quota_{}_{}",
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
    let database = Database::postgres(url.as_str()).unwrap();
    database.initialize().await.unwrap();
    for limit in [1, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50] {
        let (_, committed) = quota_case(&database, limit).await;
        assert_eq!(committed, limit >= 49);
    }
}
