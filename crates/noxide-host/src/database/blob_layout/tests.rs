use super::*;
use crate::database::{Database, Param};
use sqlx::Connection;
use std::time::{Duration, Instant};

async fn insert(
    tx: &mut Transaction,
    suffix: &str,
    duplicate: Option<&str>,
    attached: bool,
) -> Result<u64> {
    let choose = |column| {
        if duplicate == Some(column) {
            "a"
        } else {
            suffix
        }
    };
    let key = |column| choose(column).repeat(64);
    let values: Vec<Param> = vec![
        suffix.repeat(64).into(),
        format!("b1_{}", key("blob_ref")).into(),
        format!("u1_{}", key("upload_handle")).into(),
        key("object_key").into(),
        "b".repeat(64).into(),
        "c".repeat(64).into(),
        "d".repeat(64).into(),
        if attached { "attached" } else { "uploading" }.into(),
        if attached {
            "e".repeat(64)
        } else {
            String::new()
        }
        .into(),
        "f".repeat(64).into(),
    ];
    tx.execute("INSERT INTO nx_blobs(slot,blob_ref,upload_handle,object_key,subject,context,input,anonymous,state,generation,reserved_bytes,actual_bytes,sha256,filename,created_ms,expires_ms,owner_resource,owner_id,owner_incarnation,owner_field,claimed_ms,owner_process) VALUES($1,$2,$3,$4,$5,$6,$7,0,$8,1,0,0,$9,'file.bin',1,900001,1,1,'record','file',0,$10)", &values).await
}

async fn contract(db: Database) {
    db.initialize().await.unwrap();
    db.initialize().await.unwrap();
    let begin = || db.begin(Instant::now() + Duration::from_secs(5));
    // Independent adversarial review: named indexes must belong to their fixed
    // framework table, even when an unrelated table has compatible columns.
    let mut tx = begin().await.unwrap();
    if matches!(tx.backend, Backend::Postgres(_)) {
        tx.execute(
            "CREATE TABLE shadow_blob_handles (upload_handle TEXT NOT NULL)",
            &[],
        )
        .await
        .unwrap();
        tx.execute("DROP INDEX nx_blobs_handle", &[]).await.unwrap();
        tx.execute(
            "CREATE UNIQUE INDEX nx_blobs_handle ON shadow_blob_handles(upload_handle)",
            &[],
        )
        .await
        .unwrap();
        let accepted = tx.check_blob_layout().await.is_ok();
        let state = tx.fetch::<3>("SELECT t.relname,pg_catalog.pg_get_indexdef(i.indexrelid),CAST((SELECT count(*) FROM nx_blobs) AS TEXT) FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_class x ON x.oid=i.indexrelid WHERE x.relname='nx_blobs_handle'", &[]).await.unwrap();
        eprintln!(
            "P08 wrong-table probe: verifier_accepted={accepted}; table/index/blob_rows={state:?}"
        );
        assert!(!accepted, "index on wrong table accepted");
    }
    tx.rollback().await.unwrap();
    for (index, replacement) in [
        ("nx_blobs_handle", None),
        (
            "nx_blobs_handle",
            Some("CREATE INDEX nx_blobs_handle ON nx_blobs(upload_handle)"),
        ),
        (
            "nx_blobs_handle",
            Some("CREATE UNIQUE INDEX nx_blobs_handle ON nx_blobs(blob_ref)"),
        ),
        (
            "nx_blobs_attached_field",
            Some(
                "CREATE UNIQUE INDEX nx_blobs_attached_field ON nx_blobs(owner_resource,owner_id,owner_incarnation,owner_field) WHERE state='staged'",
            ),
        ),
        (
            "nx_blobs_expiry",
            Some("CREATE INDEX nx_blobs_expiry ON nx_blobs(state,slot,expires_ms)"),
        ),
        (
            "nx_blobs_subject_live",
            Some(
                "CREATE INDEX nx_blobs_subject_live ON nx_blobs(subject,slot) WHERE state='uploading' AND state='staged'",
            ),
        ),
    ] {
        let mut tx = begin().await.unwrap();
        tx.execute(&format!("DROP INDEX {index}"), &[])
            .await
            .unwrap();
        if let Some(sql) = replacement {
            tx.execute(sql, &[]).await.unwrap();
        }
        assert!(
            tx.check_blob_layout().await.is_err(),
            "{index}: {replacement:?}"
        );
        tx.rollback().await.unwrap();
    }
    let mut tx = begin().await.unwrap();
    tx.execute("DROP TABLE nx_blob_subjects", &[])
        .await
        .unwrap();
    let create = TABLE_SQL
        .iter()
        .find(|s| s.starts_with("CREATE TABLE nx_blob_subjects "))
        .unwrap();
    tx.execute(
        &create.replace("subject TEXT PRIMARY KEY NOT NULL", "subject TEXT NOT NULL"),
        &[],
    )
    .await
    .unwrap();
    assert!(tx.check_blob_layout().await.is_err());
    tx.rollback().await.unwrap();
    db.initialize().await.unwrap();

    for state in ["pending", "paired", "unreviewed"] {
        let mut tx = begin().await.unwrap();
        let result = tx.execute("INSERT INTO nx_blob_store(singleton,identity,pair_id,pair_state,serial,reserved_bytes,used_bytes,objects,anonymous_reserved_bytes,anonymous_used_bytes) VALUES(1,$1,$2,$3,1,0,0,0,0,0)", &["a".repeat(64).into(),"b".repeat(64).into(),state.into()]).await;
        assert_eq!(result.is_ok(), state != "unreviewed");
        tx.rollback().await.unwrap();
    }
    let mut tx = begin().await.unwrap();
    assert!(tx.execute("INSERT INTO nx_blob_store(singleton,identity,pair_state,serial,reserved_bytes,used_bytes,objects,anonymous_reserved_bytes,anonymous_used_bytes) VALUES(1,$1,'pending',1,0,0,0,0,0)", &["a".repeat(64).into()]).await.is_err());
    tx.rollback().await.unwrap();

    // Native constraints, independently of metadata loader/canonicalization.
    let mut tx = begin().await.unwrap();
    insert(&mut tx, "a", None, true).await.unwrap();
    tx.commit().await.unwrap();
    for duplicate in ["blob_ref", "upload_handle", "object_key", "attachment"] {
        let mut tx = begin().await.unwrap();
        assert!(
            insert(&mut tx, "b", Some(duplicate), duplicate == "attachment")
                .await
                .is_err(),
            "{duplicate}"
        );
        tx.rollback().await.unwrap();
        let mut tx = begin().await.unwrap();
        assert_eq!(
            tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_blobs", &[])
                .await
                .unwrap(),
            [["1".to_owned()]]
        );
        tx.rollback().await.unwrap();
    }
    // An explicit old version is never silently upgraded or erased.
    let mut tx = begin().await.unwrap();
    tx.execute("UPDATE nx_storage SET version=11", &[])
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
        [["11".to_owned()]]
    );
    assert_eq!(
        tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_blobs", &[])
            .await
            .unwrap(),
        [["1".to_owned()]]
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn sqlite_blob_layout_and_native_constraints() {
    let temp = tempfile::tempdir().unwrap();
    contract(Database::sqlite(temp.path().join("blobs.db"))).await;
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_blob_layout_and_native_constraints() {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_p08_layout_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    eprintln!("P08 owned layout fixture: {name}");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    contract(Database::postgres(case.as_str()).unwrap()).await;
    sqlx::query(&format!("DROP DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
}
