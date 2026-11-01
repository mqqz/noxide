use super::*;
use crate::database::lifecycle::Registry;
use std::{sync::Arc, time::Duration};
fn owner() -> RequestScope {
    RequestScope::new(
        Arc::new(Registry::default()),
        tokio::time::Instant::now() + Duration::from_secs(2),
        Duration::from_secs(2),
        256,
    )
}
#[tokio::test]
async fn internal_cursor_is_canonical_bound_and_has_no_browser_expiry() {
    let m = crate::test_support::manifest();
    let plan = crate::query_plan::compile(&m, &m.operations[0]).unwrap();
    owner()
        .run(async {
            let cursor = Frontier {
                version: 1,
                binding: "alpha-worker-declaration-cutoff".into(),
                after: Some(CursorKey::Created {
                    sequence: 4,
                    record: 42,
                }),
            };
            let raw = cursor.encode().unwrap();
            assert!(raw.len() <= 4096);
            assert_eq!(
                Frontier::decode(Some(&raw), cursor.binding.clone(), &plan, &m, 10)
                    .unwrap()
                    .encode()
                    .unwrap(),
                raw
            );
            assert!(
                Frontier::decode(
                    Some(&raw),
                    "beta-worker-declaration-cutoff".into(),
                    &plan,
                    &m,
                    10
                )
                .is_err()
            );
            assert!(Frontier::decode(Some(&raw), cursor.binding.clone(), &plan, &m, 3).is_err());
            assert!(
                Frontier::decode(
                    Some(&(raw.clone() + " ")),
                    cursor.binding.clone(),
                    &plan,
                    &m,
                    10
                )
                .is_err()
            );
            let forged = raw.replace("\"version\":1", "\"version\":1,\"cookie\":\"forged\"");
            assert!(
                Frontier::decode(Some(&forged), cursor.binding.clone(), &plan, &m, 10).is_err()
            );
            assert!(
                Frontier::decode(
                    Some(&"x".repeat(4097)),
                    cursor.binding.clone(),
                    &plan,
                    &m,
                    10
                )
                .is_err()
            );
            let zero = Frontier {
                version: 1,
                binding: cursor.binding.clone(),
                after: Some(CursorKey::Created {
                    sequence: 1,
                    record: 0,
                }),
            }
            .encode()
            .unwrap();
            assert!(Frontier::decode(Some(&zero), cursor.binding.clone(), &plan, &m, 10).is_err());
            let scalar = Frontier {
                version: 1,
                binding: cursor.binding.clone(),
                after: Some(CursorKey::Scalar {
                    value: noxide_protocol::query::CursorValue::Integer(1),
                    record: 1,
                }),
            }
            .encode()
            .unwrap();
            assert!(
                Frontier::decode(Some(&scalar), cursor.binding.clone(), &plan, &m, 10).is_err()
            );
            let start = Frontier::decode(None, "initial-scan".into(), &plan, &m, 0)
                .unwrap()
                .encode()
                .unwrap();
            assert!(
                Frontier::decode(Some(&start), "initial-scan".into(), &plan, &m, 0)
                    .unwrap()
                    .after
                    .is_none(),
                "budget yield never invents row progress"
            );
        })
        .await;
    assert!(
        Frontier {
            version: 1,
            binding: "scope".into(),
            after: None
        }
        .encode()
        .is_err(),
        "CPU work needs its existing host root"
    );
}
#[test]
fn candidate_work_reserves_emission_and_cursor_persistence() {
    assert_eq!(candidate_cap(20, 13, 200, 0), 2);
    assert_eq!(candidate_cap(20, 7, 200, 0), 1);
    assert_eq!(candidate_cap(20, 6, 200, 0), 0);
    assert_eq!(candidate_cap(20, 13, 13, 0), 0);
    assert_eq!(candidate_cap(20, 13, 14, 0), 1);
    assert_eq!(candidate_cap(20, 13, 200, 4), 1);
    assert_eq!(candidate_cap(1, 16, 256, 0), 1);
    assert_eq!(candidate_cap(20, 16, 256, 0), 3);
}
#[test]
fn recurrence_policy_has_one_explicit_worker_and_tenant_conjunction() {
    let mut m = crate::test_support::manifest();
    let op = &mut m.operations[0];
    op.policy.any = vec![vec![
        Predicate::SameTenant,
        Predicate::Service {
            worker: "expiry".into(),
        },
    ]];
    assert!(service_selection(op, "expiry"));
    assert!(!service_selection(op, "other"));
    op.policy.any.push(op.policy.any[0].clone());
    assert!(!service_selection(op, "expiry"));
    op.policy.any.truncate(1);
    op.policy.any[0].push(Predicate::Owner);
    assert!(!service_selection(op, "expiry"));
    op.policy.any = vec![vec![Predicate::Service {
        worker: "expiry".into(),
    }]];
    assert!(!service_selection(op, "expiry"));
}

fn declarations() -> Manifest {
    use noxide_protocol::{expiry::ResourceExpiry, jobs::*, time::Duration as JobDuration};
    let mut m = crate::test_support::manifest();
    let field = |name: &str, kind, max_bytes| TextField {
        immutable: false,
        name: name.into(),
        label: name.into(),
        kind,
        optional: false,
        initial: None,
        max_bytes,
    };
    m.resources[0].fields = vec![
        field("body", FieldKind::Text, 64),
        field("expires", FieldKind::Timestamp, 20),
        field("ready", FieldKind::Boolean, 5),
    ];
    m.resources[0].expiry = Some(ResourceExpiry {
        field: "expires".into(),
        max_after: JobDuration::from_millis(3_600_000).unwrap(),
    });
    let operation = |id, kind| Operation {
        maintenance: true,
        id,
        resource: 1,
        kind,
        policy: Policy {
            any: vec![vec![
                Predicate::Service {
                    worker: "expiry".into(),
                },
                Predicate::SameTenant,
            ]],
        },
        bind: BTreeMap::new(),
        scope: None,
        via: None,
        filter: vec![],
        disclose: vec![],
        list: None,
        visibility: None,
        fields: None,
        query: None,
    };
    let mut list = operation(9, OperationKind::List);
    list.list = Some(ListSettings {
        order: ListOrder::CreatedAsc,
        page_size: 20,
        preview: None,
    });
    list.filter = vec![Condition {
        field: "ready".into(),
        equals: Operand::Literal("true".into()),
    }];
    m.operations = vec![
        operation(8, OperationKind::Read),
        list,
        operation(10, OperationKind::Delete),
    ];
    m.actions = vec![Action {
        id: 2,
        version: 1,
        name: "Expiry repair".into(),
        targets: vec![ActionTarget {
            name: "order".into(),
            resource: 1,
            source: TargetSource::Service { eligible: 8 },
            revision: Revision::Exact,
            projection: Some(Inspection {
                operation: 8,
                fields: Vec::new(),
            }),
            inspect: None,
        }],
        inputs: vec![],
        steps: vec![Step {
            operation: 10,
            target: Target::Named("order".into()),
            assign: vec![],
            guards: vec![],
        }],
    }];
    m.routes.clear();
    m.web_bindings.clear();
    m.jobs = Some(JobContract {
        workers: vec![Worker {
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
        }],
        schedules: vec![],
        recurring: vec![RecurringSchedule {
            name: "repair".into(),
            worker: "expiry".into(),
            action: 2,
            interval: JobDuration::from_millis(60_000).unwrap(),
            inputs: BTreeMap::new(),
            selection: Some(RecurringSelection {
                operation: 9,
                target: "order".into(),
                expiry_repair: true,
            }),
        }],
    });
    m
}
async fn fixture_application(database: &Database, m: &Manifest) -> Application {
    manifest::validate(m).unwrap();
    let jobs = crate::JobDeployment {
        grants: ["alpha", "beta"]
            .into_iter()
            .map(|tenant| crate::JobGrant {
                worker: "expiry".into(),
                tenant: tenant.into(),
                actions: std::collections::BTreeSet::from([2]),
            })
            .collect(),
        limits: crate::JobLimits::default(),
    };
    let approved = crate::deployment::approval_digest(m, None, Some(&jobs), None).unwrap();
    database.initialize().await.unwrap();
    database.reconcile_query_indexes(m).await.unwrap();
    let app = Application::new(
        &crate::test_support::component(None),
        &serde_json::to_vec(m).unwrap(),
        approved,
        database.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
        crate::DeploymentResources {
            effects: None,
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
            jobs: Some(jobs),
        },
    )
    .unwrap();
    app.activate().await.unwrap();
    app
}
async fn app_fixture(database: &Database) -> Application {
    let m = declarations();
    let app = fixture_application(database, &m).await;
    let mut tx = database
        .begin(std::time::Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
    let storage = tx.storage_resource(&m, 1).await.unwrap();
    let now = tx
        .fetch::<1>(
            "SELECT CAST(lifecycle_ms AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await
        .unwrap()[0][0]
        .parse::<i64>()
        .unwrap();
    let alice = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let bob = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
    for (account, tenant) in [(alice, "alpha"), (bob, "beta")] {
        tx.execute(
            "INSERT INTO nx_accounts(id,tenant,state,epoch) VALUES($1,$2,'active',1)",
            &[account.into(), tenant.into()],
        )
        .await
        .unwrap();
    }
    let beta = serde_json::to_string(&Fields::from([
        ("body".into(), "synthetic".into()),
        ("expires".into(), (now - 1).to_string()),
        ("ready".into(), "true".into()),
    ]))
    .unwrap();
    let filtered_alpha = serde_json::to_string(&Fields::from([
        ("body".into(), "synthetic".into()),
        ("expires".into(), (now - 1).to_string()),
        ("ready".into(), "false".into()),
    ]))
    .unwrap();
    // Put unrelated rows before every matching row. Half differ by tenant,
    // half by the fixed filter, so either missing prefix causes a large scan.
    for batch in 0..10 {
        let first = batch * 10_000 + 1;
        let last = (batch + 1) * 10_000;
        tx.execute(&format!("WITH RECURSIVE numbers(n) AS (SELECT {first} UNION ALL SELECT n+1 FROM numbers WHERE n<{last}) INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) SELECT $1,1000000+n,CASE WHEN n<=50000 THEN $2 ELSE $4 END,CASE WHEN n<=50000 THEN 'beta' ELSE 'alpha' END,CASE WHEN n<=50000 THEN $3 ELSE $5 END,'unrelated_record',1,1000+n FROM numbers"),&[storage.into(),bob.into(),beta.as_str().into(),alice.into(),filtered_alpha.as_str().into()]).await.unwrap();
    }
    for (id, expires, ready) in [
        (1i64, now - 1, true),
        (2, now - 1, true),
        (3, now + 3_000_000, true),
        (4, now - 1, false),
    ] {
        let fields = Fields::from([
            ("body".into(), "synthetic".into()),
            ("expires".into(), expires.to_string()),
            ("ready".into(), ready.to_string()),
        ]);
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,'alpha',$4,$5,1,200000+$2)",&[storage.into(),id.into(),alice.into(),serde_json::to_string(&fields).unwrap().into(),format!("record_{id}").into()]).await.unwrap();
    }
    tx.execute(
        "UPDATE nx_creation_counter SET value=200004 WHERE singleton=1",
        &[],
    )
    .await
    .unwrap();
    tx.execute("ANALYZE nx_records", &[]).await.unwrap();
    tx.commit().await.unwrap();
    app.checkpoint_clock().await.unwrap();
    app
}
fn request(app: &Application) -> crate::database::lifecycle::AdmissionOwner {
    let request = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let database = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    app.owned_request(
        Arc::new(request),
        Arc::new(database),
        None,
        app.runtime.limits().wall_time,
    )
}
async fn provider(database: Database) {
    use crate::jobs::{JobScope, QueueContext};
    let app = Arc::new(app_fixture(&database).await);
    let schedule = app.manifest.jobs.as_ref().unwrap().recurring[0].clone();
    let scope = JobScope {
        deployment: app.generation.get().unwrap().clone(),
        tenant: "alpha".into(),
    };
    let (cutoff, cutoff_seq, cursor) = request(&app)
        .run(async {
            let mut tx = database
                .begin(std::time::Instant::now() + app.runtime.limits().wall_time)
                .await
                .unwrap();
            app.admission(&mut tx, false).await.unwrap();
            let mut calls = 16;
            calls -= 1;
            let time = app.temporal_after_admission(&mut tx).await.unwrap();
            let locked = QueueContext {
                tx: &mut tx,
                calls: &mut calls,
            }
            .schedule_grant(&scope, "expiry", &app.contract)
            .await
            .unwrap();
            let mut batch = QueueContext {
                tx: &mut tx,
                calls: &mut calls,
            }
            .begin_recurrence(&scope, &schedule, time.timestamp())
            .await
            .unwrap()
            .unwrap();
            let page = app
                .select_recurring(
                    &mut tx,
                    &locked,
                    &schedule,
                    time,
                    batch.cutoff(),
                    u64::try_from(batch.cutoff_seq()).unwrap(),
                    batch.cursor(),
                    batch.remaining(),
                    &mut calls,
                )
                .await
                .unwrap();
            assert_eq!(
                page.items
                    .iter()
                    .map(|item| item.targets["order"].id)
                    .collect::<Vec<_>>(),
                [1, 2]
            );
            assert!(!page.complete);
            let cursor = page.next_cursor.unwrap();
            assert!(cursor.len() <= 4096);
            for item in page.items {
                assert_eq!(item.targets["order"].revision, 1);
                assert!(item.expiry.unwrap() <= batch.cutoff());
                assert!(
                    QueueContext {
                        tx: &mut tx,
                        calls: &mut calls
                    }
                    .emit_recurrence(
                        &mut batch,
                        1,
                        Fields::new(),
                        item.targets,
                        item.expiry,
                        1000
                    )
                    .await
                    .unwrap()
                );
            }
            let cutoff = batch.cutoff();
            let cutoff_seq = batch.cutoff_seq();
            QueueContext {
                tx: &mut tx,
                calls: &mut calls,
            }
            .finish_recurrence(batch, Some(&cursor))
            .await
            .unwrap();
            assert!(calls <= 16);
            let result = (cutoff, u64::try_from(cutoff_seq).unwrap(), cursor);
            tx.commit().await.unwrap();
            result
        })
        .await;
    app.request_lifecycle().wait_idle_for_test().await.unwrap();
    #[cfg(feature = "query-metrics")]
    {
        let mut tx = database
            .begin(std::time::Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let storage = tx.storage_resource(&app.manifest, 1).await.unwrap();
        let ready = tx.field_expression("ready").unwrap();
        let sql = format!(
            "SELECT id FROM nx_records WHERE resource={storage} AND tenant='alpha' AND {ready}='true' AND created_seq<={cutoff_seq} ORDER BY created_seq ASC,id ASC LIMIT 2"
        );
        let visits = tx.examined_rows(&sql).await.unwrap();
        // A valid plan may inspect the tiny matching set before LIMIT. It
        // must never inspect the100k earlier tenant/filter-unrelated rows.
        assert!(
            (2..=4).contains(&visits),
            "protected tenant/filter frontier examined {visits} rows"
        );
        eprintln!("selector100k unrelated index visits={visits}");
        tx.rollback().await.unwrap();
    }
    // The barrier commits a new same-tenant expired row after the batch cutoff,
    // before opening the next selector transaction. No timing sleeps are used.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let other = barrier.clone();
    let insert_db = database.clone();
    let late_expiry = cutoff.unix_millis() - 1;
    let insertion = tokio::spawn(async move {
        other.wait().await;
        let mut tx = insert_db
            .begin(std::time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let fields = serde_json::to_string(&Fields::from([
            ("body".into(), "late".into()),
            ("expires".into(), late_expiry.to_string()),
            ("ready".into(), "true".into()),
        ]))
        .unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) SELECT storage_id,999999,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','alpha',$1,'late_record',1,1000000 FROM nx_resource_catalog WHERE resource_key='notes'",&[fields.into()]).await.unwrap();
        tx.execute(
            "UPDATE nx_creation_counter SET value=1000000 WHERE singleton=1",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        other.wait().await;
    });
    tokio::time::timeout(Duration::from_secs(5), barrier.wait())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), barrier.wait())
        .await
        .unwrap();
    insertion.await.unwrap();
    app.checkpoint_clock().await.unwrap();
    request(&app).run(async {
        let mut tx=database.begin(std::time::Instant::now()+app.runtime.limits().wall_time).await.unwrap();app.admission(&mut tx,false).await.unwrap();let mut calls=16;calls-=1;let time=app.temporal_after_admission(&mut tx).await.unwrap();let locked=QueueContext{tx:&mut tx,calls:&mut calls}.schedule_grant(&scope,"expiry",&app.contract).await.unwrap();
        calls-=1;
        let stored=tx.fetch::<3>("SELECT CAST(cutoff_ms AS TEXT),CAST(cutoff_seq AS TEXT),cursor FROM nx_job_recurring WHERE deployment=$1 AND tenant='alpha' AND name='repair'",&[scope.deployment.as_str().into()]).await.unwrap();assert_eq!(stored[0],[cutoff.unix_millis().to_string(),cutoff_seq.to_string(),cursor.clone()]);
        // Inspect the persisted selector continuation directly; the worker's
        // separate sixty-second due gate is not bypassed or changed here.
        let page=app.select_recurring(&mut tx,&locked,&schedule,time,cutoff,cutoff_seq,Some(&cursor),20,&mut calls).await.unwrap();assert!(page.items.is_empty());assert!(page.complete);assert!(page.next_cursor.is_none(),"future expiry and post-cutoff insertion are not selected");
        calls-=1;
        let jobs=tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_jobs",&[]).await.unwrap();assert_eq!(jobs[0][0],"2");tx.rollback().await.unwrap();eprintln!("recurring resume logical calls remaining={calls}");
    }).await;
    app.request_lifecycle().wait_idle_for_test().await.unwrap();
    request(&app)
        .run(async {
            let mut tx = database
                .begin(std::time::Instant::now() + app.runtime.limits().wall_time)
                .await
                .unwrap();
            app.admission(&mut tx, false).await.unwrap();
            let mut calls = 16;
            calls -= 1;
            let time = app.temporal_after_admission(&mut tx).await.unwrap();
            let beta = JobScope {
                deployment: scope.deployment.clone(),
                tenant: "beta".into(),
            };
            let locked = QueueContext {
                tx: &mut tx,
                calls: &mut calls,
            }
            .schedule_grant(&beta, "expiry", &app.contract)
            .await
            .unwrap();
            assert!(
                app.select_recurring(
                    &mut tx,
                    &locked,
                    &schedule,
                    time,
                    cutoff,
                    cutoff_seq,
                    Some(&cursor),
                    20,
                    &mut calls
                )
                .await
                .is_err(),
                "cross-tenant frontier cannot rebind"
            );
            tx.rollback().await.unwrap();
        })
        .await;
    app.request_lifecycle().wait_idle_for_test().await.unwrap();
    request(&app)
        .run(async {
            let mut tx = database
                .begin(std::time::Instant::now() + app.runtime.limits().wall_time)
                .await
                .unwrap();
            app.admission(&mut tx, false).await.unwrap();
            let mut calls = 16;
            calls -= 1;
            let time = app.temporal_after_admission(&mut tx).await.unwrap();
            let locked = QueueContext {
                tx: &mut tx,
                calls: &mut calls,
            }
            .schedule_grant(&scope, "expiry", &app.contract)
            .await
            .unwrap();
            // Three remaining logical calls cannot fund a candidate plus emit and
            // finish. Spend the existing counter down; never reset it upward.
            while calls > 3 {
                calls -= 1;
            }
            let before = RequestScope::statements_remaining().unwrap();
            let page = app
                .select_recurring(
                    &mut tx,
                    &locked,
                    &schedule,
                    time,
                    cutoff,
                    cutoff_seq,
                    Some(&cursor),
                    20,
                    &mut calls,
                )
                .await
                .unwrap();
            assert!(page.items.is_empty() && !page.complete);
            assert_eq!(page.next_cursor.as_deref(), Some(cursor.as_str()));
            assert_eq!(calls, 3);
            assert_eq!(RequestScope::statements_remaining().unwrap(), before);
            tx.rollback().await.unwrap();
        })
        .await;
    app.request_lifecycle().wait_idle_for_test().await.unwrap();

    // The other tenant is still due. Exercise the production worker adapter,
    // including its clock/due-row costs, over the same100k indexed corpus.
    app.checkpoint_clock().await.unwrap();
    let (result, roots) =
        crate::database::lifecycle::observe_roots(app.run_recurrence_once()).await;
    result.unwrap();
    assert_eq!(roots.len(), 1);
    app.jobs
        .as_ref()
        .unwrap()
        .lifecycle
        .wait_idle_for_test()
        .await
        .unwrap();
    let (_, reserved, spent) = roots[0].statement_snapshot();
    assert_eq!(reserved, 0);
    assert!(spent <= 256);
    let mut tx = database
        .begin_read(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    let counts = tx
        .fetch::<2>(
            "SELECT tenant,CAST(COUNT(*) AS TEXT) FROM nx_jobs GROUP BY tenant ORDER BY tenant",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        counts,
        [
            [String::from("alpha"), String::from("2")],
            [String::from("beta"), String::from("2")],
        ]
    );
    let frontier = tx
        .fetch::<2>(
            "SELECT CAST(cutoff_seq AS TEXT),cursor FROM nx_job_recurring WHERE tenant='beta'",
            &[],
        )
        .await
        .unwrap();
    assert!(frontier[0][0].parse::<u64>().unwrap() >= cutoff_seq);
    assert!(!frontier[0][1].is_empty());
    tx.commit().await.unwrap();
}
#[tokio::test]
async fn sqlite_recurring_selector_cutoffs_scope_budget_and_native_frontier() {
    let base = std::env::var_os("NOXIDE_TEST_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("noxide-job-selection"));
    std::fs::create_dir_all(&base).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("selector-")
        .tempdir_in(base)
        .unwrap()
        .keep();
    eprintln!("retained selector fixture {}", directory.display());
    provider(Database::sqlite(directory.join("selection.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES"]
async fn postgres_recurring_selector_cutoffs_scope_budget_and_native_frontier() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_job_select_{}", crate::security::record_id().unwrap());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    eprintln!("retained selector database {name}");
    provider(Database::postgres(case.as_str()).unwrap()).await;
}

fn derived_declarations() -> Manifest {
    use noxide_protocol::jobs::WorkerTarget;
    let mut m = declarations();
    let mut product = m.resources[0].clone();
    product.id = 2;
    product.name = "products".into();
    m.resources.push(product);
    m.resources[0].fields.push(TextField {
        name: "product".into(),
        label: "Product".into(),
        kind: FieldKind::Reference {
            resource: "products".into(),
        },
        immutable: true,
        optional: false,
        initial: None,
        max_bytes: 64,
    });
    let mut read = m.operations.iter().find(|op| op.id == 8).unwrap().clone();
    read.id = 11;
    read.resource = 2;
    read.maintenance = false;
    m.operations.push(read);
    // Derivation follows only a reference the source projection approves.
    m.actions[0].targets[0]
        .projection
        .as_mut()
        .unwrap()
        .fields
        .push("product".into());
    m.actions[0].targets.push(ActionTarget {
        name: "product".into(),
        resource: 2,
        source: TargetSource::Reference {
            target: "order".into(),
            field: "product".into(),
            eligible: 11,
        },
        revision: Revision::Identity,
        projection: Some(Inspection {
            operation: 11,
            fields: vec![],
        }),
        inspect: None,
    });
    m.jobs.as_mut().unwrap().workers[0].actions[0]
        .targets
        .insert(
            "product".into(),
            WorkerTarget {
                resource: 2,
                eligible: 11,
            },
        );
    m
}
#[test]
fn recurring_selection_accepts_only_one_service_root_and_its_independent_references() {
    let m = derived_declarations();
    manifest::validate(&m).unwrap();
    let jobs = m.jobs.as_ref().unwrap();
    let selection = jobs.recurring[0].selection.as_ref().unwrap();
    let rule = &jobs.workers[0].actions[0];
    crate::jobs::validate_recurring_targets(&m, rule, selection).unwrap();
    for forged in 0..5 {
        let mut invalid = m.clone();
        match forged {
            0 => {
                invalid.jobs.as_mut().unwrap().recurring[0]
                    .selection
                    .as_mut()
                    .unwrap()
                    .target = "product".into()
            }
            1 => invalid.actions[0].targets[1].source = TargetSource::Service { eligible: 11 },
            2 => {
                invalid.actions[0].targets[1].source = TargetSource::Reference {
                    target: "product".into(),
                    field: "product".into(),
                    eligible: 11,
                }
            }
            3 => {
                invalid.jobs.as_mut().unwrap().workers[0].actions[0]
                    .targets
                    .get_mut("product")
                    .unwrap()
                    .eligible = 8;
            }
            4 => {
                invalid.jobs.as_mut().unwrap().workers[0].actions[0]
                    .targets
                    .remove("product");
            }
            _ => unreachable!(),
        }
        assert!(
            manifest::validate(&invalid).is_err(),
            "forged recurrence {forged} admitted"
        );
    }
}
async fn derived_provider(database: Database) {
    use crate::jobs::CapturedJob;
    let m = derived_declarations();
    let app = Arc::new(fixture_application(&database, &m).await);
    let mut tx = database
        .begin(std::time::Instant::now() + Duration::from_secs(10))
        .await
        .unwrap();
    let order = tx.storage_resource(&m, 1).await.unwrap();
    let product = tx.storage_resource(&m, 2).await.unwrap();
    let now = tx
        .fetch::<1>(
            "SELECT CAST(lifecycle_ms AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await
        .unwrap()[0][0]
        .parse::<i64>()
        .unwrap();
    let alice = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let bob = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
    for (account, tenant) in [(alice, "alpha"), (bob, "beta")] {
        tx.execute(
            "INSERT INTO nx_accounts(id,tenant,state,epoch) VALUES($1,$2,'active',1)",
            &[account.into(), tenant.into()],
        )
        .await
        .unwrap();
    }
    // Product2 is expired; Product3 belongs to another tenant. Neither may be
    // sealed merely because its referring expired order was selected.
    for (id, tenant, expires) in [
        (1i64, "alpha", now + 1_000_000),
        (2, "alpha", now - 1),
        (3, "beta", now + 1_000_000),
    ] {
        let fields = Fields::from([
            ("body".into(), "product".into()),
            ("expires".into(), expires.to_string()),
            ("ready".into(), "true".into()),
        ]);
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,$4,$5,$6,1,$2)", &[product.into(),id.into(),if tenant=="alpha" {alice} else {bob}.into(),tenant.into(),serde_json::to_string(&fields).unwrap().into(),format!("product_{id}").into()]).await.unwrap();
        let fields = Fields::from([
            ("body".into(), "order".into()),
            ("expires".into(), (now - 1).to_string()),
            ("ready".into(), "true".into()),
            ("product".into(), id.to_string()),
        ]);
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,'alpha',$4,$5,1,3+$2)", &[order.into(),id.into(),alice.into(),serde_json::to_string(&fields).unwrap().into(),format!("order_{id}").into()]).await.unwrap();
    }
    tx.execute(
        "UPDATE nx_creation_counter SET value=6 WHERE singleton=1",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    app.checkpoint_clock().await.unwrap();
    // Each call has its normal worker request root, database meter and logical
    // budget. Short pages retain the frontier across denied related targets.
    for _ in 0..6 {
        app.run_recurrence_once().await.unwrap();
    }
    let mut tx = database
        .begin_read(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let payloads = tx
        .fetch::<1>("SELECT payload FROM nx_jobs ORDER BY id", &[])
        .await
        .unwrap();
    assert_eq!(payloads.len(), 1);
    let captured: CapturedJob = serde_json::from_str(&payloads[0][0]).unwrap();
    assert_eq!(captured.targets().len(), 2);
    assert_eq!(captured.targets()["order"].resource, 1);
    assert_eq!(captured.targets()["order"].id, 1);
    assert_eq!(captured.targets()["order"].incarnation, "order_1");
    assert_eq!(captured.targets()["product"].resource, 2);
    assert_eq!(captured.targets()["product"].id, 1);
    assert_eq!(captured.targets()["product"].incarnation, "product_1");
    tx.commit().await.unwrap();
    assert!(matches!(
        app.run_job_once().await.unwrap(),
        Some(crate::application::JobRunOutcome::Completed {
            recovered: false,
            ..
        })
    ));
    assert!(app.run_job_once().await.unwrap().is_none());
    let mut tx = database
        .begin_read(std::time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>(
            "SELECT CAST(id AS TEXT) FROM nx_records WHERE resource=$1 ORDER BY id",
            &[order.into()]
        )
        .await
        .unwrap(),
        [["2".to_string()], ["3".to_string()]]
    );
    assert_eq!(
        tx.fetch::<2>("SELECT state,CAST(attempts AS TEXT) FROM nx_jobs", &[])
            .await
            .unwrap(),
        [["succeeded".to_string(), "1".to_string()]]
    );
    assert_eq!(
        tx.fetch::<1>(
            "SELECT CAST(COUNT(*) AS TEXT) FROM nx_receipts WHERE action=2",
            &[]
        )
        .await
        .unwrap(),
        [["1".to_string()]]
    );
    tx.commit().await.unwrap();
}
#[tokio::test]
async fn sqlite_recurring_derived_targets_recheck_current_read_and_expiry() {
    let root = std::env::temp_dir().join("noxide-recurring-derived");
    std::fs::create_dir_all(&root).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("selector-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    eprintln!("retained derived recurrence fixture {}", dir.display());
    derived_provider(Database::sqlite(dir.join("runtime.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES"]
async fn postgres_recurring_derived_targets_recheck_current_read_and_expiry() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_derived_select_{}",
        crate::security::record_id().unwrap()
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    eprintln!("retained derived recurrence database {name}");
    derived_provider(Database::postgres(case.as_str()).unwrap()).await;
}
