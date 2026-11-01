//! Independent negative probes; never part of the author implementation.
use crate::database::Database;
use sqlx::Connection;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[tokio::test]
#[ignore = "requires disposable NOXIDE_TEST_POSTGRES with CREATE DATABASE"]
async fn postgres_rejects_schema_prefix_inside_state_literals() {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_search_layout_literal_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    eprintln!("retained forged-CHECK fixture: {name}");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    let mut case = url::Url::parse(&url).unwrap();
    case.set_path(&name);
    let db = Database::postgres(case.as_str()).unwrap();
    db.initialize().await.unwrap();
    let mut tx = db.begin(deadline()).await.unwrap();
    let schema = tx
        .fetch::<1>("SELECT pg_catalog.quote_ident(current_schema())", &[])
        .await
        .unwrap()[0][0]
        .clone();
    tx.execute(
        "INSERT INTO nx_resource_catalog(storage_id,resource_key) VALUES(1,'documents')",
        &[],
    )
    .await
    .unwrap();
    tx.execute(
        "ALTER TABLE nx_search_state DROP CONSTRAINT nx_search_state_state_check",
        &[],
    )
    .await
    .unwrap();
    tx.execute(&format!("ALTER TABLE nx_search_state ADD CONSTRAINT nx_search_state_state_check CHECK(state IN ('{schema}.building','{schema}.ready'))"), &[])
        .await.unwrap();
    tx.execute(&format!("INSERT INTO nx_search_state(resource,tokenizer,declaration,version,state) VALUES(1,'tokenizer','{{}}',1,'{schema}.ready')"), &[])
        .await.unwrap();
    tx.commit().await.unwrap();
    let result = db.initialize().await;
    let mut tx = db.begin(deadline()).await.unwrap();
    let constraints = tx.fetch::<1>("SELECT pg_catalog.pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint WHERE conname='nx_search_state_state_check'", &[]).await.unwrap();
    let state = tx
        .fetch::<1>("SELECT state FROM nx_search_state", &[])
        .await
        .unwrap();
    let counts = tx.fetch::<3>("SELECT CAST((SELECT COUNT(*) FROM nx_records) AS TEXT),CAST((SELECT COUNT(*) FROM nx_search_postings) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts) AS TEXT)", &[]).await.unwrap();
    eprintln!(
        "forged-CHECK verifier_accepted={}; constraints={constraints:?}; state={state:?}; record/posting/receipt counts={counts:?}",
        result.is_ok()
    );
    tx.rollback().await.unwrap();
    assert!(
        result.is_err(),
        "initializer accepted changed CHECK literals"
    );
}

#[tokio::test]
async fn sqlite_rejects_token_over_scalar_limit_after_nul() {
    let path = std::env::temp_dir().join(format!(
        "retained-nul-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    eprintln!("retained NUL-token fixture: {}", path.display());
    let db = Database::sqlite(path);
    db.initialize().await.unwrap();
    let mut tx = db.begin(deadline()).await.unwrap();
    tx.execute(
        "INSERT INTO nx_resource_catalog(storage_id,resource_key) VALUES(1,'documents')",
        &[],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES(1,1,NULL,'','{}','original',1,NULL,1)", &[]).await.unwrap();
    tx.execute("INSERT INTO nx_search_state(resource,tokenizer,declaration,version,state) VALUES(1,'tokenizer','{}',1,'ready')", &[]).await.unwrap();
    let token = format!("a\0{}", "b".repeat(64));
    assert_eq!(token.chars().count(), 66);
    let result = tx.execute("INSERT INTO nx_search_postings(resource,record_id,field,token,incarnation,revision,created_seq) VALUES(1,1,0,$1,'original',1,1)", &[token.as_str().into()]).await;
    let accepted = result.is_ok();
    if accepted {
        tx.commit().await.unwrap();
    } else {
        tx.rollback().await.unwrap();
    }
    let initialize = db.initialize().await;
    let mut tx = db.begin(deadline()).await.unwrap();
    let native_lengths = tx.fetch::<2>("SELECT CAST(length(token) AS TEXT),CAST(length(CAST(token AS BLOB)) AS TEXT) FROM nx_search_postings", &[]).await.unwrap();
    let counts = tx.fetch::<3>("SELECT CAST((SELECT COUNT(*) FROM nx_records) AS TEXT),CAST((SELECT COUNT(*) FROM nx_search_postings) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts) AS TEXT)", &[]).await.unwrap();
    eprintln!(
        "NUL-token native_accepted={accepted}; initializer_accepted={}; rust_scalar_count={}; native_text/byte_lengths={native_lengths:?}; record/posting/receipt counts={counts:?}",
        initialize.is_ok(),
        token.chars().count()
    );
    tx.rollback().await.unwrap();
    assert!(
        !accepted,
        "native CHECK accepted token with66 Unicode scalars"
    );
}
