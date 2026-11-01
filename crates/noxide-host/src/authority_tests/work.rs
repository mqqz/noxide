//! Provider scan instrumentation for the exact specialized batch lookup SQL.
use super::*;
use crate::authority::witnesses::Witnesses;
use crate::membership::{LookupScope, ProtectedRow};

async fn work(database: Database) {
    database.initialize().await.unwrap();
    let m = manifest();
    assert!(
        m.resources[1].unique.is_empty(),
        "historical duplicates remain legal"
    );
    database.reconcile_query_indexes(&m).await.unwrap();
    let time = attempt(&database).await;
    let future = time.timestamp().unix_millis() + 3_600_000;
    let mut tx = database
        .begin(Instant::now() + StdDuration::from_secs(120))
        .await
        .unwrap();
    tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'authority','key','active')",&[]).await.unwrap();
    for account in [ALICE, BOB] {
        tx.execute(
            "INSERT INTO nx_accounts(id,tenant,state,epoch) VALUES($1,'team','active',1)",
            &[account.into()],
        )
        .await
        .unwrap();
    }
    let storage = tx.storage_resource(&m, 2).await.unwrap();
    // Three independent adversarial populations: unrelated identity, wrong role
    // at the requested identity, and expired otherwise matching duplicates.
    for (population, fields) in [
        member(999, BOB, "admin", true, "current", future),
        member(1, ALICE, "member", true, "current", future),
        member(2, ALICE, "admin", true, "current", 0),
    ]
    .into_iter()
    .enumerate()
    {
        let fields = serde_json::to_string(&fields).unwrap();
        for batch in 0..10i64 {
            let start = population as i64 * 100_000 + batch * 10_000 + 1;
            let end = start + 9_999;
            tx.execute(&format!("WITH RECURSIVE numbers(n) AS (SELECT {start} UNION ALL SELECT n+1 FROM numbers WHERE n<{end}) INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) SELECT $1,n,$2,'team',$3,'scan-proof',1,n FROM numbers"),&[storage.into(),ALICE.into(),fields.as_str().into()]).await.unwrap();
        }
    }
    tx.execute("UPDATE nx_creation_counter SET value=300000", &[])
        .await
        .unwrap();
    insert(
        &mut tx,
        storage,
        300_001,
        ALICE,
        "team",
        &member(1, ALICE, "admin", true, "current", future),
    )
    .await;
    tx.execute("ANALYZE nx_records", &[]).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = database
        .begin_read(Instant::now() + StdDuration::from_secs(30))
        .await
        .unwrap();
    let plan = crate::membership::plans(&m, &m.operations[0])
        .unwrap()
        .remove(0);
    let scope = scope();
    let deployment = scope.borrowed();
    let lookup = LookupScope {
        account: ALICE,
        tenant: "team",
        deployment,
        time,
    };
    let fields = Fields::new();
    let rows: Vec<_> = (1..=64)
        .map(|id| ProtectedRow {
            id,
            tenant: "team",
            fields: &fields,
        })
        .collect();
    let mut witnesses = Witnesses::new(&user(), time).unwrap();
    let mut calls = 1;
    let result = witnesses
        .lookup(&mut tx, &deployment, &plan, storage, &rows, &mut calls)
        .await
        .unwrap();
    assert_eq!(result, (1..=64).map(|id| id == 1).collect::<Vec<_>>());
    assert_eq!(calls, 0, "one roundtrip covers all 64 references");

    let mut params: Vec<Param> = (1..=64).map(|id| Param::Text(id.to_string())).collect();
    let requested = (1..=64)
        .map(|i| format!("SELECT ${i} AS reference_id"))
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let predicate = plan
        .exists_sql(
            tx.query_provider().unwrap(),
            storage,
            &lookup,
            false,
            &mut params,
        )
        .unwrap();
    let mut query = format!(
        "WITH requested AS ({requested}) SELECT reference_id,CASE WHEN {predicate} THEN '1' ELSE '0' END FROM requested LIMIT 64"
    );
    // Instrumentation takes a literal statement. Substitute only finite fixture
    // values, in descending placeholder order, preserving the production SQL.
    for (index, param) in params.iter().enumerate().rev() {
        let literal = match param {
            Param::Text(text) => format!("'{}'", text.replace('\'', "''")),
            Param::Number(number) => number.to_string(),
        };
        query = query.replace(&format!("${}", index + 1), &literal);
    }
    let visits = tx.examined_rows(&query).await.unwrap();
    eprintln!(
        "membership batch64: {visits} scanned rows; 100000 unrelated + 100000 wrong-role duplicates + 100000 expired matching duplicates; native planner, exact production EXISTS/LIMIT1 SQL"
    );
    assert!(
        (1..=256).contains(&visits),
        "membership physical work ceiling exceeded: {visits}"
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn sqlite_membership_batch64_bounds_adversarial_300k_work() {
    let temp = tempfile::tempdir().unwrap();
    work(Database::sqlite(temp.path().join("membership-work.db"))).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable server"]
async fn postgres_membership_batch64_bounds_adversarial_300k_work() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!("nx_work_{}", std::process::id());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut parsed = url::Url::parse(&url).unwrap();
    parsed.set_path(&format!("/{name}"));
    work(Database::postgres(parsed.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
