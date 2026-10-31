//! Real repository route read/list/follow consumers of the shared context.
use super::*;
use crate::repository::{self, Effects};
use noxide_protocol::{ListOrder, ListSettings, Record, RequestKind, RequestView, VERSION, Via};
use std::sync::Arc;

fn declarations() -> Manifest {
    let mut m = manifest();
    for resource in &mut m.resources {
        if matches!(resource.id, 1 | 3) {
            resource.fields.push(field("published", FieldKind::Boolean));
        }
    }
    m.resources.iter_mut().find(|r| r.id == 3).unwrap().gate = Some(noxide_protocol::Gate {
        field: "workspace".into(),
        visible: noxide_protocol::Visibility {
            field: "published".into(),
            equals: "true".into(),
        },
        create_when: noxide_protocol::Visibility {
            field: "published".into(),
            equals: "true".into(),
        },
    });
    let mut public = m.operations[1].clone();
    public.id = 10;
    public.policy = Policy {
        any: vec![vec![Predicate::Public]],
    };
    public.visibility = Some(noxide_protocol::Visibility {
        field: "published".into(),
        equals: "true".into(),
    });
    public.fields = Some(vec!["body".into()]);
    let mut independent = m.operations[1].clone();
    independent.id = 11;
    independent.policy.any.push(vec![Predicate::Owner]);
    m.operations.extend([public, independent]);

    let mut list = m.operations[1].clone();
    list.id = 7;
    list.kind = OperationKind::List;
    list.scope = Some("workspace".into());
    list.list = Some(ListSettings {
        order: ListOrder::CreatedAsc,
        page_size: 20,
        preview: None,
    });
    let mut own = list.clone();
    own.id = 8;
    own.policy = Policy {
        any: vec![vec![Predicate::Owner]],
    };
    let mut follow = m.operations[0].clone();
    follow.id = 9;
    follow.via = Some(Via {
        source: 8,
        field: "workspace".into(),
    });
    m.operations.extend([list, own, follow]);
    m.routes[0].operations = vec![1, 7];
    m.routes[0].resource = Some(1);
    m.routes[0].path = "/workspaces/{workspace}".into();
    let mut followed = m.routes[0].clone();
    followed.id = 2;
    followed.path = "/follow/{workspace}".into();
    followed.operations = vec![1, 8, 9];
    m.routes.push(followed);
    let mut index = m.routes[0].clone();
    index.id = 3;
    index.path = "/".into();
    index.resource = None;
    index.operations.clear();
    m.routes.push(index);
    crate::manifest::validate(&m).unwrap();
    m
}
fn visible_workspace(expires: i64) -> Fields {
    let mut fields = workspace(expires);
    fields.insert("published".into(), "true".into());
    fields
}
fn effects(tx: Transaction, m: &Manifest, time: AttemptTime) -> Effects {
    Effects {
        authority: Authority::new(Some(time), scope()),
        upload: None,
        blob_reads: Default::default(),
        provenance: Default::default(),
        follow_sources: Vec::new(),
        invoked: Default::default(),
        list_bytes: 0,
        list_calls: repository::MAX_LIST_DATABASE_CALLS,
        result_limit: noxide_protocol::MAX_RESULT_BYTES,
        truncated: false,
        see_all: Vec::new(),
        tx,
        manifest: Arc::new(m.clone()),
        plans: crate::query_plan::compile_all(m).unwrap(),
        principal: user(),
        request: RequestView {
            version: VERSION,
            kind: RequestKind::Route(1),
            target: Some(1),
            input: Fields::new(),
            inspection: Default::default(),
            available_forms: Vec::new(),
            params: Default::default(),
        },
        grants: Default::default(),
        target_rows: Default::default(),
        written_rows: Default::default(),
        capability_grant: None,
        calls: 64,
        cursor: None,
        more: None,
    }
}
async fn paths(database: Database) {
    database.initialize().await.unwrap();
    let m = declarations();
    database.reconcile_query_indexes(&m).await.unwrap();
    let time = attempt(&database).await;
    let now = time.timestamp().unix_millis();
    let future = now + 3_600_000;
    let mut tx = transaction(&database).await;
    tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'authority','key','active')",&[]).await.unwrap();
    tx.execute(
        "INSERT INTO nx_accounts(id,tenant,state,epoch) VALUES($1,'team','active',1)",
        &[ALICE.into()],
    )
    .await
    .unwrap();
    let workspaces = tx.storage_resource(&m, 1).await.unwrap();
    let members = tx.storage_resource(&m, 2).await.unwrap();
    let documents = tx.storage_resource(&m, 3).await.unwrap();
    for id in 1..=2 {
        insert(
            &mut tx,
            workspaces,
            id,
            ALICE,
            "team",
            &visible_workspace(future),
        )
        .await;
    }
    insert(
        &mut tx,
        members,
        1,
        ALICE,
        "team",
        &member(1, ALICE, "admin", true, "current", future),
    )
    .await;
    for (id, workspace, expiry) in [(1, 1, future), (2, 1, now), (3, 2, future)] {
        insert(
            &mut tx,
            documents,
            id,
            ALICE,
            "team",
            &Fields::from([
                ("workspace".into(), workspace.to_string()),
                ("body".into(), format!("secret{id}")),
                ("published".into(), "true".into()),
                ("expires".into(), expiry.to_string()),
            ]),
        )
        .await;
    }
    tx.commit().await.unwrap();
    let tx = transaction(&database).await;
    let mut e = effects(tx, &m, time);
    let listed: Vec<Record> = serde_json::from_slice(&e.invoke(7, 0).await.unwrap()).unwrap();
    assert_eq!(
        listed.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![1],
        "list applies protected expiry and membership policy"
    );
    assert!(
        !e.provenance.keys().any(|(_, _, id)| *id == 2 || *id == 3),
        "denied list rows create no follow provenance"
    );
    let mut authority = Authority::new(Some(time), scope());
    let mut calls = 16;
    let principal = user();
    let mut ctx = repository::ReadContext {
        tx: &mut e.tx,
        manifest: &m,
        principal: &principal,
        authority: &mut authority,
        budget: repository::ReadBudget::Query(&mut calls),
    };
    assert!(
        repository::read_resource(&mut ctx, &m.operations[1], 1)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repository::read_resource(&mut ctx, &m.operations[1], 2)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repository::read_resource(&mut ctx, &m.operations[1], 3)
            .await
            .unwrap()
            .is_none()
    );
    e.tx.rollback().await.unwrap();
    let tx = transaction(&database).await;
    let mut e = effects(tx, &m, time);
    e.request.kind = RequestKind::Route(2);
    let owned: Vec<Record> = serde_json::from_slice(&e.invoke(8, 0).await.unwrap()).unwrap();
    assert_eq!(
        owned.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![1],
        "independent owner source grant remains usable"
    );
    for row in &owned {
        e.follow_source(3, row.id).unwrap();
    }
    let followed: Vec<Option<Record>> =
        serde_json::from_slice(&e.follow(9).await.unwrap()).unwrap();
    assert_eq!(
        followed
            .iter()
            .map(|row| row.as_ref().map(|r| r.id))
            .collect::<Vec<_>>(),
        vec![Some(1)],
        "follow target requires its own current membership grant"
    );
    e.tx.rollback().await.unwrap();
    let tx = transaction(&database).await;
    let mut e = effects(tx, &m, time);
    e.request.kind = RequestKind::Route(2);
    e.request.target = Some(2);
    let owned: Vec<Record> = serde_json::from_slice(&e.invoke(8, 0).await.unwrap()).unwrap();
    assert_eq!(owned.iter().map(|r| r.id).collect::<Vec<_>>(), vec![3]);
    e.follow_source(3, 3).unwrap();
    let denied: Vec<Option<Record>> = serde_json::from_slice(&e.follow(9).await.unwrap()).unwrap();
    assert!(
        denied[0].is_none(),
        "child source ownership is not a parent read grant"
    );
    e.tx.rollback().await.unwrap();
    // A new target read must reject an expired target even if its source had
    // an independent grant. This uses the same fixed attempt time throughout.
    let mut tx = transaction(&database).await;
    let expired = serde_json::to_string(&visible_workspace(now)).unwrap();
    tx.execute(
        "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2 AND id=1",
        &[expired.into(), workspaces.into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let tx = transaction(&database).await;
    let mut e = effects(tx, &m, time);
    e.request.kind = RequestKind::Route(2);
    let owned: Vec<Record> = serde_json::from_slice(&e.invoke(8, 0).await.unwrap()).unwrap();
    for row in &owned {
        e.follow_source(3, row.id).unwrap();
    }
    let followed: Vec<Option<Record>> =
        serde_json::from_slice(&e.follow(9).await.unwrap()).unwrap();
    assert!(
        followed.into_iter().all(|row| row.is_none()),
        "expired target cannot be disclosed by follow"
    );
    let mut authority = Authority::new(Some(time), scope());
    let mut calls = 32;
    let principal = user();
    let mut ctx = repository::ReadContext {
        tx: &mut e.tx,
        manifest: &m,
        principal: &principal,
        authority: &mut authority,
        budget: repository::ReadBudget::Query(&mut calls),
    };
    let public = m.operations.iter().find(|op| op.id == 10).unwrap();
    let private = m.operations.iter().find(|op| op.id == 11).unwrap();
    assert!(
        repository::read_resource(&mut ctx, public, 1)
            .await
            .unwrap()
            .is_none(),
        "expired gated parent denies the public child grant"
    );
    assert!(
        repository::read_resource(&mut ctx, &m.operations[1], 1)
            .await
            .unwrap()
            .is_some(),
        "independent Member child grant survives gated parent expiry"
    );
    assert!(
        repository::read_resource(&mut ctx, private, 1)
            .await
            .unwrap()
            .is_some(),
        "independent Owner OR Member child grant survives gated parent expiry"
    );
    e.tx.rollback().await.unwrap();
    let mut tx = transaction(&database).await;
    tx.execute(
        "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2 AND id=1",
        &[
            serde_json::to_string(&member(1, ALICE, "admin", false, "current", now))
                .unwrap()
                .into(),
            members.into(),
        ],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut tx = transaction(&database).await;
    let mut authority = Authority::new(Some(time), scope());
    let mut calls = 16;
    let principal = user();
    let mut ctx = repository::ReadContext {
        tx: &mut tx,
        manifest: &m,
        principal: &principal,
        authority: &mut authority,
        budget: repository::ReadBudget::Query(&mut calls),
    };
    assert!(
        repository::read_resource(&mut ctx, &m.operations[1], 1)
            .await
            .unwrap()
            .is_none(),
        "revoked/expired member grants no private read"
    );
    assert!(
        repository::read_resource(&mut ctx, private, 1)
            .await
            .unwrap()
            .is_some(),
        "explicit Owner OR Member grant remains owner-readable after revocation/expiry"
    );
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn sqlite_read_list_follow_share_membership_and_expiry_authority() {
    let temp = tempfile::tempdir().unwrap();
    paths(Database::sqlite(temp.path().join("paths.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable server"]
async fn postgres_read_list_follow_share_membership_and_expiry_authority() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let prior = sqlx::query_scalar::<_, String>(
        "SELECT datname FROM pg_database WHERE datname LIKE 'nx_p07_paths_%' ORDER BY datname",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    eprintln!("P07 retained read-path fixtures before run: {prior:?}");
    let name = format!("nx_p07_paths_{}", std::process::id());
    eprintln!("P07 new read-path fixture: {name}");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut parsed = url::Url::parse(&url).unwrap();
    parsed.set_path(&format!("/{name}"));
    paths(Database::postgres(parsed.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}

mod query_runtime;
