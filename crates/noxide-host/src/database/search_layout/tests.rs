use super::*;
use crate::database::{Database, Param};
use sqlx::Connection;
use std::time::{Duration, Instant};

async fn posting(tx: &mut Transaction, token: &str, field: i64) -> Result<u64> {
    tx.execute("INSERT INTO nx_search_postings(resource,record_id,field,token,incarnation,revision,created_seq) VALUES(1,1,$1,$2,'original',1,1)", &[field.into(), token.into()]).await
}

async fn state(tx: &mut Transaction) -> Result<u64> {
    tx.execute("INSERT INTO nx_search_state(resource,tokenizer,declaration,version,state) VALUES(1,'tokenizer','{}',1,'ready')", &[]).await
}

async fn contract(db: Database) {
    db.initialize().await.unwrap();
    db.initialize().await.unwrap();
    let begin = || db.begin(Instant::now() + Duration::from_secs(10));
    let mut tx = begin().await.unwrap();
    tx.check_search_layout().await.unwrap();
    tx.execute(
        "INSERT INTO nx_resource_catalog(storage_id,resource_key) VALUES(1,'documents')",
        &[],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES(1,1,NULL,'','{}','original',1,NULL,1)", &[]).await.unwrap();
    state(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    // Native bounds reject invalid metadata independently of the token writer.
    for (token, field) in [
        (String::new(), 0),
        ("a".repeat(65), 0),
        ("valid".into(), 4),
        ("valid".into(), -1),
    ] {
        let mut tx = begin().await.unwrap();
        assert!(posting(&mut tx, &token, field).await.is_err());
        tx.rollback().await.unwrap();
    }
    for sql in [
        "UPDATE nx_search_state SET state='unreviewed'",
        "UPDATE nx_search_state SET version=2",
        "UPDATE nx_search_state SET tokenizer=''",
        "UPDATE nx_search_state SET declaration='[]'",
    ] {
        let mut tx = begin().await.unwrap();
        assert!(tx.execute(sql, &[]).await.is_err(), "{sql}");
        tx.rollback().await.unwrap();
    }
    let mut tx = begin().await.unwrap();
    assert!(
        tx.execute(
            "UPDATE nx_search_state SET declaration=$1",
            &[format!("{{\"key\":\"{}\"}}", "a".repeat(4096)).into()]
        )
        .await
        .is_err()
    );
    tx.rollback().await.unwrap();

    let mut tx = begin().await.unwrap();
    posting(&mut tx, &"😀".repeat(64), 3).await.unwrap();
    tx.commit().await.unwrap();
    let mut tx = begin().await.unwrap();
    assert!(posting(&mut tx, &"😀".repeat(64), 3).await.is_err());
    tx.rollback().await.unwrap();
    for (column, value) in [
        ("record_id", Param::Number(2)),
        ("incarnation", "x".repeat(65).into()),
        ("revision", Param::Number(0)),
        ("created_seq", Param::Number(0)),
    ] {
        let mut tx = begin().await.unwrap();
        assert!(
            tx.execute(
                &format!("UPDATE nx_search_postings SET {column}=$1"),
                &[value]
            )
            .await
            .is_err(),
            "{column}"
        );
        tx.rollback().await.unwrap();
    }

    // The record FK deletes every posting atomically with the record; rollback
    // restores both. State deletion is restricted while postings remain.
    let mut tx = begin().await.unwrap();
    assert!(
        tx.execute("DELETE FROM nx_search_state WHERE resource=1", &[])
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = begin().await.unwrap();
    tx.execute("DELETE FROM nx_records WHERE resource=1 AND id=1", &[])
        .await
        .unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_search_postings", &[])
            .await
            .unwrap(),
        [["0".to_owned()]]
    );
    tx.rollback().await.unwrap();
    let mut tx = begin().await.unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_search_postings", &[])
            .await
            .unwrap(),
        [["1".to_owned()]]
    );
    tx.rollback().await.unwrap();

    for replacement in [
        None,
        Some(
            "CREATE INDEX nx_search_tokens ON nx_search_postings(resource,token,field,created_seq,record_id)",
        ),
        Some(
            "CREATE UNIQUE INDEX nx_search_tokens ON nx_search_postings(resource,field,token,created_seq,record_id)",
        ),
        Some(
            "CREATE INDEX nx_search_tokens ON nx_search_postings(resource,field,token,created_seq,record_id) WHERE field=0",
        ),
    ] {
        let mut tx = begin().await.unwrap();
        tx.execute("DROP INDEX nx_search_tokens", &[])
            .await
            .unwrap();
        if let Some(sql) = replacement {
            tx.execute(sql, &[]).await.unwrap();
        }
        assert!(tx.check_search_layout().await.is_err(), "{replacement:?}");
        tx.rollback().await.unwrap();
    }
    let mut tx = begin().await.unwrap();
    tx.execute("CREATE TABLE shadow_search_postings (resource BIGINT,field BIGINT,token TEXT,created_seq BIGINT,record_id BIGINT)", &[]).await.unwrap();
    tx.execute("DROP INDEX nx_search_tokens", &[])
        .await
        .unwrap();
    tx.execute("CREATE INDEX nx_search_tokens ON shadow_search_postings(resource,field,token,created_seq,record_id)", &[]).await.unwrap();
    assert!(
        tx.check_search_layout().await.is_err(),
        "same-named index on wrong table"
    );
    tx.rollback().await.unwrap();

    // A usable index and matching column types cannot hide weakened keys,
    // foreign-key integrity, value constraints or token collation.
    let mut tx = begin().await.unwrap();
    let original = table_sql(&tx).unwrap()[1];
    let collation = if matches!(tx.backend, Backend::Postgres(_)) {
        ("COLLATE \"C\"", "COLLATE \"POSIX\"")
    } else {
        ("COLLATE BINARY", "COLLATE NOCASE")
    };
    tx.rollback().await.unwrap();
    for (from, to) in [
        (
            ", FOREIGN KEY(resource,record_id) REFERENCES nx_records(resource,id) ON DELETE CASCADE",
            "",
        ),
        ("CHECK(revision>=1)", "CHECK(revision>=0)"),
        (
            "PRIMARY KEY(resource,record_id,field,token)",
            "PRIMARY KEY(resource,record_id,token)",
        ),
        collation,
    ] {
        assert_eq!(original.matches(from).count(), 1);
        let mut tx = begin().await.unwrap();
        tx.execute("DROP TABLE nx_search_postings", &[])
            .await
            .unwrap();
        tx.execute(&original.replace(from, to), &[]).await.unwrap();
        tx.execute(INDEXES[0].1, &[]).await.unwrap();
        assert!(
            tx.check_search_layout().await.is_err(),
            "weakened metadata: {from}"
        );
        tx.rollback().await.unwrap();
        let mut tx = begin().await.unwrap();
        assert_eq!(
            tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_search_postings", &[])
                .await
                .unwrap(),
            [["1".to_owned()]]
        );
        tx.rollback().await.unwrap();
    }

    // A framework12 database remains untouched and explicitly rejected. No
    // initializer silently adds tables, updates its version or deletes data.
    let mut tx = begin().await.unwrap();
    tx.execute("UPDATE nx_storage SET version=12", &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        db.initialize()
            .await
            .unwrap_err()
            .to_string()
            .contains("storage 13 requires")
    );
    let mut tx = begin().await.unwrap();
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(version AS TEXT) FROM nx_storage", &[])
            .await
            .unwrap(),
        [["12".to_owned()]]
    );
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_search_postings", &[])
            .await
            .unwrap(),
        [["1".to_owned()]]
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn sqlite_search_layout_and_native_constraints() {
    let temp = tempfile::tempdir().unwrap();
    contract(Database::sqlite(temp.path().join("search.db"))).await;
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_search_layout_and_native_constraints() {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_p09_layout_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    eprintln!("P09 retained layout fixture: {name}");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    contract(Database::postgres(case.as_str()).unwrap()).await;
    // Intentionally retained; operator cleanup is a separate authorized action.
}
