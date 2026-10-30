use crate::{
    Database,
    auth::{Principal, User},
    database::{Param, Transaction},
    manifest,
    repository::{self, Effects},
};
use noxide_protocol::*;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
fn declarations() -> Manifest {
    let mut m = crate::test_support::manifest();
    m.resources[0].fields.push(TextField {
        name: "recipient".into(),
        label: "Recipient".into(),
        kind: FieldKind::Account {
            scope: AccountScope::SameTenant,
        },
        optional: false,
        initial: None,
        max_bytes: 43,
    });
    m.actions[0].fields.push("recipient".into());
    let mut reviewer = m.resources[0].fields[1].clone();
    reviewer.name = "recipient_tenant".into();
    m.resources[0].fields.push(reviewer);
    m.actions[0].fields.push("recipient_tenant".into());
    for op in &mut m.operations[..2] {
        op.policy.any.push(vec![Predicate::PrincipalIs {
            field: "recipient".into(),
        }]);
    }
    m.operations[0].list = Some(ListSettings {
        preview: None,
        order: ListOrder::CreatedAsc,
        page_size: 20,
    });
    m
}
fn effects(tx: Transaction, m: &Manifest, id: &str, action: bool, recipient: &str) -> Effects {
    Effects {
        invoked: Default::default(),
        list_bytes: 0,
        list_calls: crate::repository::MAX_LIST_DATABASE_CALLS,
        result_limit: noxide_protocol::MAX_RESULT_BYTES,
        truncated: false,
        see_all: Vec::new(),
        tx,
        manifest: Arc::new(m.clone()),
        plans: crate::query_plan::compile_all(m).unwrap(),
        principal: Principal::User(User {
            id: id.into(),
            tenant: "team".into(),
            roles: vec![],
        }),
        request: RequestView {
            params: Default::default(),
            version: VERSION,
            kind: if action {
                RequestKind::Action(1)
            } else {
                RequestKind::Route(1)
            },
            target: None,
            input: if action {
                Fields::from([
                    ("body".into(), "private".into()),
                    ("recipient".into(), recipient.into()),
                    ("recipient_tenant".into(), id.into()),
                ])
            } else {
                Fields::new()
            },
            inspection: None,
            available_forms: vec![],
        },
        outcome: None,
        grant: None,
        capability_grant: None,
        record: None,
        calls: 64,
        cursor: None,
        more: None,
    }
}
async fn contract(db: Database, descending: bool) {
    db.initialize().await.unwrap();
    let alice = db
        .create_account("alice", "inbox test password", "team")
        .await
        .unwrap();
    let bob = db
        .create_account("bob", "inbox test password", "team")
        .await
        .unwrap();
    let eve = db
        .create_account("eve", "inbox test password", "other")
        .await
        .unwrap();
    let mut m = declarations();
    if descending {
        m.operations[0].list.as_mut().unwrap().order = ListOrder::CreatedDesc;
    }
    manifest::validate(&m).unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
    tx.bind_schema(&m).await.unwrap();
    tx.commit().await.unwrap();
    for target in [&eve, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
        let tx = db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let mut e = effects(tx, &m, &alice, true, target);
        assert!(e.invoke(3, 0).await.is_err());
        e.tx.rollback().await.unwrap();
    }
    for principal in [
        Principal::Anonymous,
        Principal::User(User {
            id: eve.clone(),
            tenant: "team".into(),
            roles: vec![],
        }),
    ] {
        let tx = db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let mut e = effects(tx, &m, &alice, true, &bob);
        e.principal = principal;
        assert!(e.invoke(3, 0).await.is_err());
        e.tx.rollback().await.unwrap();
    }
    let tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let mut e = effects(tx, &m, &alice, true, &bob);
    e.request
        .input
        .insert("recipient_tenant".into(), eve.clone());
    assert!(e.invoke(3, 0).await.is_err());
    assert_eq!(
        e.tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
            .await
            .unwrap()[0][0],
        "0"
    );
    e.tx.rollback().await.unwrap();
    let mut ids = Vec::new();
    for i in 0..45 {
        let tx = db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let mut e = effects(tx, &m, &alice, true, if i == 0 { &alice } else { &bob });
        let record: Record = serde_json::from_slice(&e.invoke(3, 0).await.unwrap()).unwrap();
        ids.push(record.id);
        e.tx.commit().await.unwrap();
    }
    let outsider = db
        .create_account("outsider", "inbox test password", "elsewhere")
        .await
        .unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(60))
        .await
        .unwrap();
    tx.execute("UPDATE nx_records SET created_seq=created_seq*2000", &[])
        .await
        .unwrap();
    let fields = serde_json::to_string(&Fields::from([
        ("body".into(), "unrelated".into()),
        ("recipient".into(), outsider.clone()),
        ("recipient_tenant".into(), outsider.clone()),
    ]))
    .unwrap();
    for batch in 0..10 {
        let owner = if batch == 0 {
            outsider.clone()
        } else {
            let owner = crate::security::random_id().unwrap();
            tx.execute("INSERT INTO nx_accounts(id,login_name,password,tenant,state,epoch) VALUES($1,$2,'unused','elsewhere','active',1)", &[owner.as_str().into(), format!("fixture{batch}").into()]).await.unwrap();
            owner
        };
        tx.execute(&format!("WITH RECURSIVE numbers(n) AS (SELECT {} UNION ALL SELECT n+1 FROM numbers WHERE n<{}) INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) SELECT 1,1000000+n,$1,'elsewhere',$2,'unrelated',1,n*2+1 FROM numbers", batch * 10000 + 1, (batch + 1) * 10000), &[owner.as_str().into(), fields.as_str().into()]).await.unwrap();
    }
    tx.execute("UPDATE nx_creation_counter SET value=200002", &[])
        .await
        .unwrap();
    tx.execute("ANALYZE nx_records", &[]).await.unwrap();
    let direction = if descending { "DESC" } else { "ASC" };
    for (column, id, index) in [
        ("owner".to_owned(), &alice, "nx_records_owner"),
        (
            tx.field_expression("recipient").unwrap(),
            &bob,
            "nx_a_1_recipient_i",
        ),
    ] {
        let sql = format!(
            "SELECT CAST(created_seq AS TEXT),CAST(id AS TEXT) FROM nx_records WHERE resource=1 AND {column}='{id}' AND created_seq>0 ORDER BY nx_records.created_seq {direction} LIMIT 21"
        );
        let plan = tx.explain(&sql).await.unwrap().join("\n");
        assert!(plan.contains(index), "{plan}");
        assert!(
            !plan.contains("Seq Scan") && !plan.contains("TEMP B-TREE"),
            "{plan}"
        );
        eprintln!("inbox branch plan: {plan}");
        #[cfg(feature = "query-metrics")]
        {
            let examined = tx.examined_rows(&sql).await.unwrap();
            assert_eq!(
                examined, 21,
                "indexed page must examine only its 21 candidates"
            );
            eprintln!("inbox branch examined rows: {examined}");
        }
    }
    tx.commit().await.unwrap();
    for (id, expected) in [(&alice, 45), (&bob, 44), (&eve, 0)] {
        let tx = db
            .begin_read(Instant::now() + Duration::from_secs(30))
            .await
            .unwrap();
        let mut e = effects(tx, &m, id, false, "");
        let mut seen = std::collections::BTreeSet::new();
        let mut previous = None;
        loop {
            let records: Vec<Record> =
                serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            if seen.len() < 40 && expected > 0 {
                assert_eq!(records.len(), 20);
            }
            for record in records {
                if let Some(previous) = previous {
                    let index = ids.iter().position(|id| *id == record.id).unwrap();
                    assert!(if descending {
                        index < previous
                    } else {
                        index > previous
                    });
                }
                previous = ids.iter().position(|id| *id == record.id);
                assert!(seen.insert(record.id));
            }
            if e.more.is_none() {
                break;
            }
            e.cursor = e.more;
            e.next_request();
        }
        assert_eq!(seen.len(), expected);
        assert_eq!(
            repository::read_resource(&mut e.tx, &m, &e.principal, &m.operations[1], ids[44])
                .await
                .unwrap()
                .is_some(),
            expected > 0
        );
        e.tx.commit().await.unwrap();
    }
    let mut residual = m.clone();
    residual.operations[0].policy.any = vec![vec![
        Predicate::Owner,
        Predicate::PrincipalIs {
            field: "recipient".into(),
        },
        Predicate::SameTenant,
    ]];
    let tx = db
        .begin_read(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let mut e = effects(tx, &residual, &outsider, false, "");
    let page: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
    assert!(page.is_empty());
    let first = e
        .more
        .expect("bounded residual scan must allow continuation");
    e.cursor = Some(first);
    e.next_request();
    let page: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
    assert!(page.is_empty());
    assert!(if descending {
        e.more.unwrap() < first
    } else {
        e.more.unwrap() > first
    });
    e.tx.commit().await.unwrap();
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let moved = Principal::User(User {
        id: bob.clone(),
        tenant: "different".into(),
        roles: vec![],
    });
    assert!(
        repository::read_resource(&mut tx, &m, &moved, &m.operations[1], ids[44])
            .await
            .unwrap()
            .is_some()
    );
    let mut confined = m.operations[1].clone();
    confined.policy.any = vec![vec![
        Predicate::PrincipalIs {
            field: "recipient".into(),
        },
        Predicate::SameTenant,
    ]];
    assert!(
        repository::read_resource(&mut tx, &m, &moved, &confined, ids[44])
            .await
            .unwrap()
            .is_none()
    );
    tx.commit().await.unwrap();
    // A binding already in flight and a lifecycle write have a serial outcome.
    let racing = db
        .create_account("racing", "inbox test password", "team")
        .await
        .unwrap();
    let tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let mut e = effects(tx, &m, &alice, true, &racing);
    e.invoke(3, 0).await.unwrap();
    let (created, disabled) = tokio::join!(e.tx.commit(), db.disable_account(&racing));
    created.unwrap();
    disabled.unwrap();
    let tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let mut e = effects(tx, &m, &alice, true, &racing);
    assert!(e.invoke(3, 0).await.is_err());
    e.tx.rollback().await.unwrap();
    db.disable_account(&bob).await.unwrap();
    let tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let mut e = effects(tx, &m, &alice, true, &bob);
    assert!(e.invoke(3, 0).await.is_err());
    e.tx.rollback().await.unwrap();
    db.delete_account(&bob).await.unwrap();
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
            .await
            .unwrap()[0][0],
        "100046"
    );
    assert_eq!(
        tx.fetch::<1>(
            "SELECT state FROM nx_accounts WHERE id=$1",
            &[Param::from(bob.as_str())]
        )
        .await
        .unwrap()[0][0],
        "deleted"
    );
    tx.commit().await.unwrap();
}
#[test]
fn admission_rejects_forged_account_authority() {
    let m = declarations();
    for kind in [
        OperationKind::Create,
        OperationKind::Update,
        OperationKind::Delete,
    ] {
        let mut bad = m.clone();
        bad.operations[1].kind = kind;
        assert!(manifest::validate(&bad).is_err());
    }
    let mut bad = m.clone();
    bad.resources[0].fields[1].optional = true;
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.operations[1].policy.any[1] = vec![Predicate::PrincipalIs {
        field: "body".into(),
    }];
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m;
    bad.operations[2].kind = OperationKind::Update;
    assert!(manifest::validate(&bad).is_err());
}
#[tokio::test]
async fn sqlite_account_bindings_and_full_pages() {
    let tmp = tempfile::tempdir().unwrap();
    contract(Database::sqlite(tmp.path().join("accounts.db")), false).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES"]
async fn postgres_account_bindings_and_full_pages() {
    postgres_case(false).await;
}
#[tokio::test]
async fn sqlite_descending_account_pages() {
    let tmp = tempfile::tempdir().unwrap();
    contract(Database::sqlite(tmp.path().join("descending.db")), true).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES"]
async fn postgres_descending_account_pages() {
    postgres_case(true).await;
}
async fn postgres_case(descending: bool) {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_accounts_{}",
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
    case.set_path(&name);
    contract(Database::postgres(case.as_str()).unwrap(), descending).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}

async fn filtered_lists(db: Database) {
    db.initialize().await.unwrap();
    let alice = db
        .create_account("filteralice", "filter test password", "team")
        .await
        .unwrap();
    let bob = db
        .create_account("filterbob", "filter test password", "team")
        .await
        .unwrap();
    let eve = db
        .create_account("filtereve", "filter test password", "team")
        .await
        .unwrap();
    let mut m = declarations();
    m.resources[0].fields.push(TextField {
        name: "archived".into(),
        label: "Archived".into(),
        kind: FieldKind::Boolean,
        optional: false,
        initial: None,
        max_bytes: 5,
    });
    m.actions[0].fields.push("archived".into());
    m.operations[0].filter.push(Condition {
        field: "archived".into(),
        equals: Operand::Literal("false".into()),
    });
    manifest::validate(&m).unwrap();
    let mut base = m.clone();
    base.operations[0].filter.clear();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    tx.bind_schema(&base).await.unwrap();
    tx.commit().await.unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let error = tx.bind_schema(&m).await.unwrap_err().to_string();
    assert!(
        error.contains("missing derived index") && error.contains("schema indexes"),
        "{error}"
    );
    tx.rollback().await.unwrap();
    db.reconcile_query_indexes(&m).await.unwrap();
    db.reconcile_query_indexes(&m).await.unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
    tx.bind_schema(&m).await.unwrap();
    for i in 1..=1001i64 {
        let owner = if i == 1001 { &eve } else { &alice };
        let recipient = if i == 1001 { &eve } else { &bob };
        let fields = Fields::from([
            ("body".into(), format!("message {i}")),
            ("recipient".into(), recipient.clone()),
            ("recipient_tenant".into(), recipient.clone()),
            ("archived".into(), (i % 10 != 0 && i != 1001).to_string()),
        ]);
        let seq = tx.allocate_creation().await.unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES(1,$1,$2,'team',$3,'filtered',1,$4)", &[i.into(), owner.as_str().into(), serde_json::to_string(&fields).unwrap().into(), seq.into()]).await.unwrap();
    }
    tx.execute("UPDATE nx_records SET created_seq=created_seq*2000", &[])
        .await
        .unwrap();
    let unrelated = serde_json::to_string(&Fields::from([
        ("body".into(), "unrelated".into()),
        ("recipient".into(), eve.clone()),
        ("recipient_tenant".into(), eve.clone()),
        ("archived".into(), "false".into()),
    ]))
    .unwrap();
    for batch in 0..10 {
        tx.execute(&format!("WITH RECURSIVE numbers(n) AS (SELECT {} UNION ALL SELECT n+1 FROM numbers WHERE n<{}) INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) SELECT 1,1000000+n,$1,'team',$2,'unrelated',1,n*2+1 FROM numbers", batch * 10000 + 1, (batch + 1) * 10000), &[eve.as_str().into(), unrelated.as_str().into()]).await.unwrap();
    }
    tx.execute("UPDATE nx_creation_counter SET value=2002000", &[])
        .await
        .unwrap();
    tx.execute("ANALYZE nx_records", &[]).await.unwrap();
    #[cfg(feature = "query-metrics")]
    {
        let expression = tx.field_expression("archived").unwrap();
        let sql = format!(
            "SELECT id FROM nx_records WHERE resource=1 AND owner='{alice}' AND {expression}='false' ORDER BY created_seq ASC LIMIT 21"
        );
        eprintln!(
            "filtered inbox indexed (1000 caller records, one in ten matches, 100000 unrelated): {} visits",
            {
                let visits = tx.examined_rows(&sql).await.unwrap();
                assert_eq!(visits, 21);
                visits
            }
        );
    }
    tx.commit().await.unwrap();
    #[cfg(feature = "query-metrics")]
    {
        let mut multi = m.clone();
        multi.operations[0].policy.any = vec![
            vec![Predicate::Owner],
            vec![Predicate::Role {
                name: "moderator".into(),
                tenant_scoped: false,
            }],
        ];
        db.reconcile_query_indexes(&multi).await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        for granted in [false, true] {
            let principal = Principal::User(User {
                id: alice.clone(),
                tenant: "team".into(),
                roles: if granted {
                    vec![("moderator".into(), "".into())]
                } else {
                    vec![]
                },
            });
            let mut params = vec![Param::Number(1)];
            let policy =
                crate::policy::sql(&tx, &multi.operations[0].policy, &principal, &mut params)
                    .join(" OR ");
            let mut sql = format!(
                "SELECT id FROM nx_records WHERE resource=$1 AND resource=1 AND ({policy}) AND {}='false' ORDER BY nx_records.created_seq ASC LIMIT 21",
                tx.field_expression("archived").unwrap()
            );
            for (i, value) in params.iter().enumerate().rev() {
                let value = match value {
                    Param::Text(value) => format!("'{value}'"),
                    Param::Number(value) => value.to_string(),
                };
                sql = sql.replace(&format!("${}", i + 1), &value);
            }
            eprintln!(
                "single multi-rule filtered moderator={granted} visits={} plan={:?}",
                tx.examined_rows(&sql).await.unwrap(),
                tx.explain(&sql).await.unwrap()
            );
        }
        tx.rollback().await.unwrap();
    }
    for parameterized in [false, true] {
        m.operations[0].filter[0].equals = if parameterized {
            Operand::Param("flag".into())
        } else {
            Operand::Literal("false".into())
        };
        m.routes[0].params = if parameterized {
            vec!["flag".into()]
        } else {
            vec![]
        };
        for descending in [false, true] {
            m.operations[0].list.as_mut().unwrap().order = if descending {
                ListOrder::CreatedDesc
            } else {
                ListOrder::CreatedAsc
            };
            for tenant in [false, true] {
                m.operations[0].policy.any[1] = vec![Predicate::PrincipalIs {
                    field: "recipient".into(),
                }];
                if tenant {
                    m.operations[0].policy.any[1].push(Predicate::SameTenant);
                }
                m.operations[1].policy = m.operations[0].policy.clone();
                for (id, single) in [(&bob, false), (&alice, true)] {
                    let mut selected = m.clone();
                    if single {
                        selected.operations[0].policy.any = vec![vec![Predicate::Owner]];
                        selected.operations[1].policy = selected.operations[0].policy.clone();
                    }
                    db.reconcile_query_indexes(&selected).await.unwrap();
                    let tx = db
                        .begin(Instant::now() + Duration::from_secs(10))
                        .await
                        .unwrap();
                    let mut tx = tx;
                    for requirement in crate::query_plan::required_indexes(&selected).unwrap() {
                        let mut predicates = vec!["resource=$1 AND resource=1".to_owned()];
                        let mut values = vec!["1".to_owned()];
                        let mut types = vec!["bigint"];
                        for column in &requirement.columns {
                            let (expression, value) = match column {
                                crate::policy::IndexColumn::Owner => {
                                    ("owner".into(), alice.as_str())
                                }
                                crate::policy::IndexColumn::Tenant => ("tenant".into(), "team"),
                                crate::policy::IndexColumn::Field(field) => (
                                    tx.field_expression(field).unwrap(),
                                    if field == "archived" {
                                        "false"
                                    } else {
                                        bob.as_str()
                                    },
                                ),
                            };
                            values.push(format!("'{value}'"));
                            types.push("text");
                            predicates.push(format!("{expression}=${}", values.len()));
                        }
                        values.push(if descending {
                            i64::MAX.to_string()
                        } else {
                            "0".into()
                        });
                        types.push("bigint");
                        let direction = if descending { "DESC" } else { "ASC" };
                        let comparison = if descending { "<" } else { ">" };
                        let sql = format!(
                            "SELECT id FROM nx_records WHERE {} AND created_seq{comparison}${} ORDER BY nx_records.created_seq {direction} LIMIT 21",
                            predicates.join(" AND "),
                            values.len()
                        );
                        let plan = match &db {
                            Database::Sqlite(_) => {
                                let mut literal = sql.clone();
                                for (i, value) in values.iter().enumerate().rev() {
                                    literal = literal.replace(&format!("${}", i + 1), value);
                                }
                                tx.explain(&literal).await.unwrap().join("\n")
                            }
                            Database::Postgres(_) => {
                                tx.execute("SET LOCAL plan_cache_mode=force_generic_plan", &[])
                                    .await
                                    .unwrap();
                                tx.execute(
                                    &format!("PREPARE filtered_plan({}) AS {sql}", types.join(",")),
                                    &[],
                                )
                                .await
                                .unwrap();
                                let plan = tx
                                    .fetch::<1>(
                                        &format!(
                                            "EXPLAIN EXECUTE filtered_plan({})",
                                            values.join(",")
                                        ),
                                        &[],
                                    )
                                    .await
                                    .unwrap()
                                    .into_iter()
                                    .map(|[line]| line)
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                tx.execute("DEALLOCATE filtered_plan", &[]).await.unwrap();
                                plan
                            }
                        };
                        assert!(plan.contains(&requirement.name(1)), "{plan}");
                        assert!(
                            !plan.contains("Sort") && !plan.contains("TEMP B-TREE"),
                            "{plan}"
                        );
                    }
                    let mut e = effects(tx, &selected, id, false, "");
                    if parameterized {
                        e.request.params.insert("flag".into(), "false".into());
                    }
                    let mut ids = Vec::new();
                    loop {
                        let rows: Vec<Record> =
                            serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
                        assert_eq!(rows.len(), (100 - ids.len()).min(20));
                        for row in rows {
                            assert_eq!(row.fields["archived"], "false");
                            assert!(
                                repository::read_resource(
                                    &mut e.tx,
                                    &selected,
                                    &e.principal,
                                    &selected.operations[1],
                                    row.id
                                )
                                .await
                                .unwrap()
                                .is_some()
                            );
                            ids.push(row.id);
                        }
                        if e.more.is_none() {
                            break;
                        }
                        e.cursor = e.more;
                        e.next_request();
                    }
                    let expected: Vec<_> = if descending {
                        (1..=100).rev().map(|i| i * 10).collect()
                    } else {
                        (1..=100).map(|i| i * 10).collect()
                    };
                    assert_eq!(ids, expected);
                    assert!(
                        repository::read_resource(
                            &mut e.tx,
                            &selected,
                            &e.principal,
                            &selected.operations[1],
                            1
                        )
                        .await
                        .unwrap()
                        .is_some()
                    );
                    assert!(
                        repository::read_resource(
                            &mut e.tx,
                            &selected,
                            &e.principal,
                            &selected.operations[1],
                            1001
                        )
                        .await
                        .unwrap()
                        .is_none()
                    );
                    e.tx.rollback().await.unwrap();
                }
            }
            let mut residual = m.clone();
            residual.operations[0].policy.any = vec![vec![
                Predicate::Owner,
                Predicate::PrincipalIs {
                    field: "recipient".into(),
                },
            ]];
            let tx = db
                .begin(Instant::now() + Duration::from_secs(10))
                .await
                .unwrap();
            let mut e = effects(tx, &residual, &alice, false, "");
            if parameterized {
                e.request.params.insert("flag".into(), "false".into());
            }
            let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            assert!(rows.is_empty());
            assert!(
                e.more.is_some(),
                "residual bound must not report a false end"
            );
            e.cursor = e.more;
            e.next_request();
            let rows: Vec<Record> = serde_json::from_slice(&e.invoke(1, 0).await.unwrap()).unwrap();
            assert!(rows.is_empty());
            assert!(e.more.is_none());
            e.tx.rollback().await.unwrap();
        }
    }
    db.reconcile_query_indexes(&base).await.unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert!(tx.bind_schema(&m).await.is_err());
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn sqlite_filtered_account_and_single_lists() {
    let tmp = tempfile::tempdir().unwrap();
    filtered_lists(Database::sqlite(tmp.path().join("filters.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES"]
async fn postgres_filtered_account_and_single_lists() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_filter_{}", crate::security::record_id().unwrap());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    filtered_lists(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}

fn preview_declarations() -> Manifest {
    let mut m = declarations();
    m.resources[0].fields.push(TextField {
        name: "extra".into(),
        label: "Extra".into(),
        kind: FieldKind::Text,
        optional: false,
        initial: None,
        max_bytes: 3900,
    });
    m.actions[0].fields.push("extra".into());
    m.operations[0].list.as_mut().unwrap().page_size = 10;
    for id in 4..=6 {
        let mut preview = m.operations[0].clone();
        preview.id = id;
        preview.list.as_mut().unwrap().preview = Some(noxide_protocol::Preview {
            see_all: (id == 4).then_some(1),
        });
        if id == 5 {
            preview.policy.any = vec![vec![Predicate::Owner]];
        }
        if id == 6 {
            preview.policy.any = vec![vec![
                Predicate::Owner,
                Predicate::PrincipalIs {
                    field: "recipient".into(),
                },
            ]];
        }
        m.operations.push(preview);
        m.routes[0].operations.push(id);
    }
    m
}
#[test]
fn host_rejects_forged_preview_shapes_and_destinations() {
    let m = preview_declarations();
    manifest::validate(&m).unwrap();
    let mut bad = m.clone();
    bad.operations[3].list.as_mut().unwrap().preview = None;
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.operations[0].list.as_mut().unwrap().page_size = 9;
    let mut fifth = bad.operations[4].clone();
    fifth.id = 7;
    fifth.list.as_mut().unwrap().page_size = 1;
    bad.operations.push(fifth);
    bad.routes[0].operations.push(7);
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.operations[0].list.as_mut().unwrap().page_size = 11;
    assert!(manifest::validate(&bad).is_err());
    for route in [2, 99] {
        let mut bad = m.clone();
        bad.operations[3]
            .list
            .as_mut()
            .unwrap()
            .preview
            .as_mut()
            .unwrap()
            .see_all = Some(route);
        assert!(manifest::validate(&bad).is_err());
    }
    let mut bad = m.clone();
    bad.operations[3].policy.any = vec![vec![Predicate::Owner]];
    assert!(manifest::validate(&bad).is_err());
    let mut selection = m.clone();
    selection.resources[0].fields.push(TextField {
        name: "archived".into(),
        label: "Archived".into(),
        kind: FieldKind::Boolean,
        optional: false,
        initial: Some("false".into()),
        max_bytes: 5,
    });
    selection.operations[3].filter.push(Condition {
        field: "archived".into(),
        equals: Operand::Literal("false".into()),
    });
    assert!(
        manifest::validate(&selection)
            .unwrap_err()
            .to_string()
            .contains("preview destination")
    );
    let mut visibility = selection.clone();
    visibility.operations[3].filter.clear();
    for index in [0, 3] {
        visibility.operations[index].policy.any = vec![vec![Predicate::Public]];
        visibility.operations[index].visibility = Some(Visibility {
            field: "archived".into(),
            equals: "false".into(),
        });
        visibility.operations[index].fields = Some(vec!["body".into()]);
    }
    manifest::validate(&visibility).unwrap();
    visibility.operations[3].visibility.as_mut().unwrap().equals = "true".into();
    assert!(
        manifest::validate(&visibility)
            .unwrap_err()
            .to_string()
            .contains("preview destination")
    );
    let mut subset = selection.clone();
    subset.operations[3].filter.clear();
    let mut extra = subset.operations[4].clone();
    extra.id = 7;
    extra.filter.push(Condition {
        field: "archived".into(),
        equals: Operand::Param("flag".into()),
    });
    subset.operations.push(extra);
    subset.routes.push(Route {
        id: 3,
        path: "/all".into(),
        resource: None,
        operations: vec![1, 7],
        forms: vec![],
        access: Access::Authenticated,
        params: vec!["flag".into()],
    });
    subset.operations[3]
        .list
        .as_mut()
        .unwrap()
        .preview
        .as_mut()
        .unwrap()
        .see_all = Some(3);
    assert!(
        manifest::validate(&subset)
            .unwrap_err()
            .to_string()
            .contains("preview destination parameters")
    );

    let mut bad = m;
    bad.operations[3]
        .list
        .as_mut()
        .unwrap()
        .preview
        .as_mut()
        .unwrap()
        .see_all = Some(2);
    assert!(manifest::validate(&bad).is_err());
}
async fn previews_case(db: Database) {
    db.initialize().await.unwrap();
    let alice = db
        .create_account("previewalice", "preview test password", "team")
        .await
        .unwrap();
    let bob = db
        .create_account("previewbob", "preview test password", "team")
        .await
        .unwrap();
    let mut m = preview_declarations();
    manifest::validate(&m).unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(10))
        .await
        .unwrap();
    tx.bind_schema(&m).await.unwrap();
    for i in 1..=300i64 {
        let fields = Fields::from([
            ("body".into(), format!("message {i}")),
            ("extra".into(), "small".into()),
            ("recipient".into(), bob.clone()),
            ("recipient_tenant".into(), bob.clone()),
        ]);
        let seq = tx.allocate_creation().await.unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES(1,$1,$2,'team',$3,'preview',1,$4)", &[i.into(),alice.as_str().into(),serde_json::to_string(&fields).unwrap().into(),seq.into()]).await.unwrap();
    }
    tx.commit().await.unwrap();
    for descending in [false, true] {
        for op in m
            .operations
            .iter_mut()
            .filter(|op| op.kind == OperationKind::List)
        {
            op.list.as_mut().unwrap().order = if descending {
                ListOrder::CreatedDesc
            } else {
                ListOrder::CreatedAsc
            };
        }
        for order in [[1, 4, 5, 6], [4, 6, 5, 1]] {
            let started = Instant::now();
            let tx = db
                .begin_read(started + Duration::from_secs(2))
                .await
                .unwrap();
            let mut e = effects(tx, &m, &alice, false, "");
            e.calls = 16;
            e.cursor = Some(150);
            for id in order {
                let bytes = e.invoke(id, 0).await.unwrap();
                assert!(bytes.len() <= MAX_RESULT_BYTES);
                if id == 1 {
                    let items: Vec<Record> = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(items.len(), 10);
                    assert_eq!(items[0].id, if descending { 149 } else { 151 });
                } else {
                    let preview: PreviewResult = serde_json::from_slice(&bytes).unwrap();
                    assert!(preview.truncated);
                    if id == 6 {
                        assert!(
                            preview.items.is_empty(),
                            "residual empty preview must disclose truncation"
                        );
                    } else {
                        assert_eq!(preview.items.len(), 10);
                        assert_eq!(preview.items[0].id, if descending { 300 } else { 1 });
                    }
                }
            }
            assert!(started.elapsed() < Duration::from_secs(2));
            assert_eq!(e.more, Some(if descending { 140 } else { 160 }));
            assert_eq!(e.see_all.len(), 1);
            assert_eq!(crate::routing::resolve(&m, &e.see_all[0]).unwrap(), "/");
            assert!(e.list_bytes <= MAX_LIST_RESULT_BYTES);
            assert!(e.list_calls < crate::repository::MAX_LIST_DATABASE_CALLS - 100);
            assert!(
                e.invoke(4, 0)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("already invoked")
            );
            e.tx.rollback().await.unwrap();
        }
    }
    // Maximum declared field sizes force strict per-list and aggregate prefixes.
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    let fields = Fields::from([
        ("body".into(), "\\".repeat(4096)),
        ("extra".into(), "\"".repeat(3900)),
        ("recipient".into(), bob.clone()),
        ("recipient_tenant".into(), bob),
    ]);
    tx.execute(
        "UPDATE nx_records SET fields=$1",
        &[serde_json::to_string(&fields).unwrap().into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    for order in [[1, 4, 5, 6], [4, 5, 6, 1]] {
        let tx = db
            .begin_read(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let mut e = effects(tx, &m, &alice, false, "");
        let mut nodes = Vec::new();
        for id in order {
            let bytes = e.invoke(id, 0).await.unwrap();
            assert!(bytes.len() <= MAX_RESULT_BYTES);
            let items = if id == 1 {
                serde_json::from_slice::<Vec<Record>>(&bytes).unwrap()
            } else {
                let preview: PreviewResult = serde_json::from_slice(&bytes).unwrap();
                assert!(preview.truncated);
                preview.items
            };
            assert!(items.len() < 10);
            for record in items {
                nodes.extend(record.fields.into_values().map(Instruction::Text));
            }
        }
        assert!(e.list_bytes <= MAX_LIST_RESULT_BYTES);
        let response = ResponseIntent::Page(Document::new("Too much", nodes));
        assert!(
            crate::render::render(&response, &crate::render::RenderContext::empty()).is_err(),
            "all maximum-sized fields cannot bypass Document IR budget"
        );
        e.tx.rollback().await.unwrap();
    }
    let tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let mut e = effects(tx, &m, &alice, false, "");
    e.list_calls = 0;
    assert!(
        e.invoke(4, 0)
            .await
            .unwrap_err()
            .to_string()
            .contains("database call budget")
    );
    e.tx.rollback().await.unwrap();
    let mut target = m.clone();
    target.resources[0].fields.push(TextField {
        name: "archived".into(),
        label: "Archived".into(),
        kind: FieldKind::Boolean,
        optional: false,
        initial: Some("false".into()),
        max_bytes: 5,
    });
    for op in target
        .operations
        .iter_mut()
        .filter(|op| op.kind == OperationKind::List)
    {
        op.filter.push(Condition {
            field: "archived".into(),
            equals: Operand::Literal("false".into()),
        });
    }
    let migration = crate::schema::Migration {
        version: 1,
        from: crate::schema::digest(&m.resources).unwrap(),
        to: crate::schema::digest(&target.resources).unwrap(),
        operations: vec![crate::schema::MigrationOp::AddField {
            resource: "notes".into(),
            field: "archived".into(),
            value: "false".into(),
        }],
    };
    db.schema_apply(&target, &migration).await.unwrap();
    let old_indexes: Vec<_> = crate::query_plan::required_indexes(&target)
        .unwrap()
        .into_iter()
        .map(|r| r.name(1))
        .collect();
    let mut renamed = target.clone();
    renamed.resources[0].fields.last_mut().unwrap().name = "saved".into();
    for op in renamed
        .operations
        .iter_mut()
        .filter(|op| op.kind == OperationKind::List)
    {
        op.filter[0].field = "saved".into();
    }
    let migration = crate::schema::Migration {
        version: 1,
        from: crate::schema::digest(&target.resources).unwrap(),
        to: crate::schema::digest(&renamed.resources).unwrap(),
        operations: vec![crate::schema::MigrationOp::RenameField {
            resource: "notes".into(),
            from: "archived".into(),
            to: "saved".into(),
        }],
    };
    db.schema_apply(&renamed, &migration).await.unwrap();
    let mut tx = db
        .begin_read(Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    tx.bind_schema(&renamed).await.unwrap();
    let catalog = match db {
        Database::Sqlite(_) => {
            "SELECT name FROM sqlite_schema WHERE type='index' AND name GLOB 'nx_q_*'"
        }
        Database::Postgres(_) => {
            "SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() AND left(indexname,5)='nx_q_'"
        }
    };
    let names: Vec<_> = tx
        .fetch::<1>(catalog, &[])
        .await
        .unwrap()
        .into_iter()
        .map(|[name]| name)
        .collect();
    assert_eq!(names.len(), old_indexes.len());
    assert!(names.iter().all(|name| !old_indexes.contains(name)));
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn sqlite_bounded_page_previews() {
    let tmp = tempfile::tempdir().unwrap();
    previews_case(Database::sqlite(tmp.path().join("previews.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES"]
async fn postgres_bounded_page_previews() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_preview_{}", crate::security::record_id().unwrap());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    previews_case(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
