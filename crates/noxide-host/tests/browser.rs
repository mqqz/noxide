//! Uses a separately VM-built component; never invokes application Cargo here.
use sqlx::{Connection, Row};

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES, NOXIDE_TEST_COMPONENT, and NOXIDE_GECKODRIVER"]
async fn postgres_nojs_browser_flow() {
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let component = std::env::var("NOXIDE_TEST_COMPONENT").unwrap();
    let driver = std::env::var("NOXIDE_GECKODRIVER").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    let name = format!(
        "nx_browser_{}",
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
    case.set_path(&format!("/{name}"));
    let output = tempfile::tempdir().unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = tokio::process::Command::new("python3")
        .arg(root.join("tools/test_browser.py"))
        .args([
            "--component",
            &component,
            "--geckodriver",
            &driver,
            "--database",
            case.as_str(),
            "--onion",
            "--output",
        ])
        .arg(output.path().join("browser"))
        .status()
        .await
        .unwrap();
    if !status.success() {
        eprintln!("browser evidence retained at {}", output.keep().display());
        panic!("browser acceptance failed");
    }
    let mut connection = sqlx::PgConnection::connect(case.as_str()).await.unwrap();
    let row=sqlx::query("SELECT (SELECT count(*) FROM nx_records) AS records,(SELECT count(*) FROM nx_receipts) AS receipts").fetch_one(&mut connection).await.unwrap();
    assert_eq!(
        (row.get::<i64, _>("records"), row.get::<i64, _>("receipts")),
        (1, 1)
    );
    connection.close().await.unwrap();
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&mut admin)
        .await
        .unwrap();
}
