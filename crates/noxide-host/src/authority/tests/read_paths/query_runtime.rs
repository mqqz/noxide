//! Actual aggregate consumers of the same policy/expiry/witness owner.
use super::*;
use crate::database::lifecycle::{AdmissionOwner, Registry, RequestScope};
use noxide_protocol::query::{
    Aggregate, AggregateFunction, AggregateResult, AggregateValue, Query,
};
fn aggregate(source: &noxide_protocol::Operation, id: u32) -> noxide_protocol::Operation {
    let mut op = source.clone();
    op.id = id;
    op.kind = OperationKind::Aggregate;
    op.list = None;
    op.query = Some(Query {
        aggregate: Some(Aggregate {
            source: source.id,
            function: AggregateFunction::Count,
        }),
        ..Default::default()
    });
    op
}
async fn count(e: &mut Effects, id: u32) -> AggregateResult {
    serde_json::from_slice(&e.invoke(id, 0).await.unwrap()).unwrap()
}
async fn provider(database: Database) {
    let mut m = declarations();
    let source = m.operations.iter().find(|op| op.id == 7).unwrap().clone();
    m.operations
        .extend([aggregate(&source, 12), aggregate(&source, 13)]);
    m.routes[0].operations.extend([12, 13]);
    crate::manifest::validate(&m).unwrap();
    database.initialize().await.unwrap();
    database.reconcile_query_indexes(&m).await.unwrap();
    let time = attempt(&database).await;
    let now = time.timestamp().unix_millis();
    let future = now + 3600000;
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
    insert(
        &mut tx,
        workspaces,
        1,
        ALICE,
        "team",
        &visible_workspace(future),
    )
    .await;
    insert(
        &mut tx,
        members,
        1,
        ALICE,
        "team",
        &member(1, ALICE, "admin", true, "current", future),
    )
    .await;
    for (id, workspace, expires) in [(1, 1, future), (2, 1, now), (3, 2, future)] {
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
                ("expires".into(), expires.to_string()),
            ]),
        )
        .await;
    }
    tx.commit().await.unwrap();
    let root = RequestScope::new(
        Arc::new(Registry::default()),
        tokio::time::Instant::now() + StdDuration::from_secs(10),
        StdDuration::from_secs(10),
        256,
    );
    let request = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();
    let database_slot = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();
    let owner = AdmissionOwner::new(root, request.into(), database_slot.into(), None);
    owner
        .run(async {
            let mut e = effects(transaction(&database).await, &m, time);
            assert_eq!(
                count(&mut e, 12).await,
                Ok(AggregateValue::Count(1)),
                "expiry and current membership apply before count"
            );
            // A canonical mutation invalidates this same owner after every step.
            // Change the witness here to isolate the aggregate consumer's reuse rule.
            let revoked =
                serde_json::to_string(&member(1, ALICE, "admin", false, "current", future))
                    .unwrap();
            e.tx.execute(
                "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2 AND id=1",
                &[revoked.into(), members.into()],
            )
            .await
            .unwrap();
            e.authority.invalidate();
            assert_eq!(
                count(&mut e, 13).await,
                Ok(AggregateValue::Count(0)),
                "mutation clears witness and facts epoch"
            );
            assert!(
                e.provenance.is_empty(),
                "count never issues a Read/follow grant"
            );
            e.tx.rollback().await.unwrap();
        })
        .await;
}
#[tokio::test]
async fn sqlite_p09_aggregate_current_membership_expiry_and_invalidation() {
    let dir = tempfile::tempdir().unwrap().keep();
    eprintln!("retained aggregate authority fixture {}", dir.display());
    provider(Database::sqlite(dir.join("p09-authority.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES"]
async fn postgres_p09_aggregate_current_membership_expiry_and_invalidation() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_p09_authority_{}", crate::security::record_id().unwrap());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    eprintln!("retained P09 authority database {name}");
    provider(Database::postgres(case.as_str()).unwrap()).await;
}
