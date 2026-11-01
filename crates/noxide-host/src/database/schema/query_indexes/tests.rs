use super::*;
use crate::{
    database::Database,
    query_plan::{IndexOrder, IndexTable, ScalarRepresentation},
};
use sqlx::Connection;
use std::time::{Duration, Instant};

async fn contract(db: Database) {
    db.initialize().await.unwrap();
    let mut tx = db
        .begin(Instant::now() + Duration::from_secs(10))
        .await
        .unwrap();
    let requirement = IndexRequirement {
        resource: "documents".into(),
        table: IndexTable::Records,
        columns: vec![],
        order: IndexOrder::Scalar {
            field: "title".into(),
            representation: ScalarRepresentation::Binary,
        },
        queries: vec![1],
    };
    let storage = 1;
    let name = requirement.name(storage);
    let expected = requirement
        .native_sql(tx.query_provider().unwrap(), storage)
        .unwrap()
        .to_string();
    tx.execute(&expected, &[]).await.unwrap();
    let definitions = tx.query_definitions().await.unwrap();
    tx.verify_query_definition(&requirement, storage, definitions.get(&name).unwrap())
        .unwrap();
    tx.rollback().await.unwrap();

    for order in [
        IndexOrder::Created,
        IndexOrder::Scalar {
            field: "quantity".into(),
            representation: ScalarRepresentation::Numeric,
        },
    ] {
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let requirement = IndexRequirement {
            resource: "documents".into(),
            table: IndexTable::Records,
            columns: vec![
                crate::policy::IndexColumn::Owner,
                crate::policy::IndexColumn::Timestamp("expiry".into()),
            ],
            order,
            queries: vec![1],
        };
        let name = requirement.name(storage);
        tx.execute(
            &requirement
                .native_sql(tx.query_provider().unwrap(), storage)
                .unwrap()
                .to_string(),
            &[],
        )
        .await
        .unwrap();
        let definitions = tx.query_definitions().await.unwrap();
        tx.verify_query_definition(&requirement, storage, definitions.get(&name).unwrap())
            .unwrap();
        tx.rollback().await.unwrap();
    }

    for defect in [
        "table",
        "predicate",
        "order",
        "collation",
        "expression",
        "unique",
    ] {
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let mut sql = requirement
            .native_sql(tx.query_provider().unwrap(), storage)
            .unwrap()
            .to_string();
        match defect {
            "table" => {
                tx.execute(
                    "CREATE TABLE shadow_queries(resource BIGINT,fields TEXT,id BIGINT)",
                    &[],
                )
                .await
                .unwrap();
                sql = sql.replace(" ON nx_records(", " ON shadow_queries(");
            }
            "predicate" => sql = sql.replace("WHERE resource=1", "WHERE resource=2"),
            "order" => sql = sql.replace(",id)", ",id DESC)"),
            "collation" => {
                sql = match tx.query_provider().unwrap() {
                    NativeProvider::Sqlite => sql.replace("COLLATE BINARY", "COLLATE NOCASE"),
                    NativeProvider::Postgres => sql.replace("COLLATE \"C\"", "COLLATE \"POSIX\""),
                }
            }
            "expression" => sql = sql.replace("title", "other"),
            "unique" => sql = sql.replacen("CREATE INDEX", "CREATE UNIQUE INDEX", 1),
            _ => unreachable!(),
        }
        tx.execute(&sql, &[]).await.unwrap();
        let definitions = tx.query_definitions().await.unwrap();
        assert!(
            tx.verify_query_definition(&requirement, storage, definitions.get(&name).unwrap())
                .is_err(),
            "accepted {defect}"
        );
        assert_eq!(
            tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
                .await
                .unwrap(),
            [["0".to_owned()]]
        );
        tx.rollback().await.unwrap();
    }
}

#[tokio::test]
async fn sqlite_query_indexes_pin_native_shape() {
    let dir = tempfile::tempdir().unwrap();
    contract(Database::sqlite(dir.path().join("indexes.db"))).await;
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_query_indexes_pin_native_shape() {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let name = format!(
        "nx_query_indexes_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    eprintln!("retained index fixture: {name}");
    let fixture = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    contract(Database::postgres(&fixture).unwrap()).await;
}

#[test]
fn native_formatting_preserves_literal_contents() {
    assert_ne!(
        ddl_key("SELECT 'public.title'", 1),
        ddl_key("SELECT 'title'", 1)
    );
    assert_ne!(
        ddl_key("SELECT 'title''::text'", 1),
        ddl_key("SELECT 'title'", 1)
    );
    assert_eq!(
        ddl_key("WHERE resource='2147483648'::bigint", 2147483648),
        ddl_key("WHERE resource=2147483648", 2147483648)
    );
}
