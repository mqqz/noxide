//! Original receipt evidence survives a separate aborted delivery transaction.
use super::*;
use crate::{
    Application, HostKeys, RequestError, manifest, runtime::Limits, test_support as fixture,
};
use noxide_protocol::{Access, Fields, Predicate};

async fn state(database: &Database, offline: bool) -> (String, String, String) {
    let mut tx = database
        .begin_read(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let table = if offline {
        "nx_records_offline"
    } else {
        "nx_records"
    };
    let rows=tx.fetch::<3>(&format!("SELECT CAST((SELECT COUNT(*) FROM {table}) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts WHERE outcome<>'') AS TEXT)"),&[]).await.unwrap();
    tx.commit().await.unwrap();
    (rows[0][0].clone(), rows[0][1].clone(), rows[0][2].clone())
}
async fn table(database: &Database, offline: bool) {
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    tx.execute(
        if offline {
            "ALTER TABLE nx_records RENAME TO nx_records_offline"
        } else {
            "ALTER TABLE nx_records_offline RENAME TO nx_records"
        },
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}
async fn app(database: &Database) -> Application {
    database.initialize().await.unwrap();
    let mut declarations = fixture::manifest();
    declarations.operations[2].policy.any = vec![vec![Predicate::Public]];
    declarations.routes[0].access = Access::PublicOptional;
    let app = Application::new(
        &fixture::component(None),
        &serde_json::to_vec(&declarations).unwrap(),
        manifest::digest(&declarations).unwrap(),
        database.clone(),
        HostKeys::generate().unwrap(),
        Limits::default(),
        crate::DeploymentResources {
            jobs: None,
            assets: crate::assets::AssetBundle::default(),
            blobs: None,
        },
    )
    .unwrap();
    app.activate().await.unwrap();
    app
}
async fn original_receipt_case(database: Database) {
    let app = app(&database).await;
    let form = app.view_page(None, 1, None, None).await.unwrap();
    let cookie = form.anonymous_cookie.unwrap();
    let html = String::from_utf8(form.body).unwrap();
    let token = fixture::hidden(&html, "_submission");
    let csrf = fixture::hidden(&html, "_csrf");
    let input = Fields::from([("body".into(), "original canonical input".into())]);
    let saved = app
        .submit(&cookie, 1, &token, &csrf, input.clone())
        .await
        .unwrap();
    let saved = String::from_utf8(saved.body).unwrap();
    let secret = saved
        .split("<pre>")
        .nth(1)
        .unwrap()
        .split("</pre>")
        .next()
        .unwrap();
    assert_eq!(
        state(&database, false).await,
        ("1".into(), "1".into(), "1".into())
    );
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let original_payload = tx
        .fetch::<1>("SELECT outcome FROM nx_receipts", &[])
        .await
        .unwrap()[0][0]
        .clone();
    tx.commit().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&original_payload).unwrap();
    let mut wrong_version = parsed.clone();
    wrong_version["version"] = 0.into();
    let mut wrong_identity = parsed.clone();
    wrong_identity["handover"]["incarnation"] = "different-incarnation".into();
    for payload in [
        "{}".to_owned(),
        serde_json::to_string(&wrong_version).unwrap(),
        serde_json::to_string(&wrong_identity).unwrap(),
    ] {
        let mut tx = database
            .begin(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        tx.execute("UPDATE nx_receipts SET outcome=$1", &[payload.into()])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(matches!(
            app.submit(&cookie, 1, &token, &csrf, input.clone()).await,
            Err(RequestError::Rejected)
        ));
        assert!(
            app.recover_form(&cookie, 1, &token, &csrf, &input, true)
                .await
                .is_err()
        );
    }
    let mut tx = database
        .begin(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_receipts SET outcome=$1",
        &[original_payload.into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    table(&database, true).await;
    let changed = Fields::from([("body".into(), "changed canonical input".into())]);
    assert!(matches!(
        app.submit(&cookie, 1, &token, &csrf, changed.clone()).await,
        Err(RequestError::InvalidRequest)
    ));
    let used = app
        .recover_form(&cookie, 1, &token, &csrf, &changed, true)
        .await
        .unwrap();
    let used = String::from_utf8(used.body).unwrap();
    assert!(!used.contains(secret));
    assert!(!used.contains("Recover edit secret"));
    for recover in [false, true] {
        let response = if recover {
            app.recover_form(&cookie, 1, &token, &csrf, &input, true)
                .await
                .unwrap()
        } else {
            app.submit(&cookie, 1, &token, &csrf, input.clone())
                .await
                .unwrap()
        };
        assert_eq!(response.status, 200);
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("Recover edit secret"));
        assert!(!html.contains(secret));
        assert_eq!(fixture::hidden(&html, "_submission"), token);
        assert_eq!(fixture::hidden(&html, "_csrf"), csrf);
    }
    assert_eq!(
        state(&database, true).await,
        ("1".into(), "1".into(), "1".into())
    );
    table(&database, false).await;
    let replay = app.submit(&cookie, 1, &token, &csrf, input).await.unwrap();
    assert!(String::from_utf8_lossy(&replay.body).contains(secret));
    assert_eq!(
        state(&database, false).await,
        ("1".into(), "1".into(), "1".into())
    );

    let mut tx = database
        .begin_read(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let id = tx
        .fetch::<1>("SELECT CAST(id AS TEXT) FROM nx_records", &[])
        .await
        .unwrap()[0][0]
        .parse()
        .unwrap();
    tx.commit().await.unwrap();
    let page = app.capability_page(1, id, Some(&cookie)).await.unwrap();
    let page = String::from_utf8(page.body).unwrap();
    let rotation = fixture::hidden(&page, "_submission");
    let rotation_csrf = fixture::hidden(&page, "_csrf");
    let rotated = app
        .rotate_capability(1, id, &cookie, &rotation_csrf, &rotation, secret)
        .await
        .unwrap();
    let rotated = String::from_utf8(rotated.body).unwrap();
    let new_secret = rotated
        .split("<pre>")
        .nth(1)
        .unwrap()
        .split("</pre>")
        .next()
        .unwrap();
    table(&database, true).await;
    assert!(matches!(
        app.rotate_capability(1, id, &cookie, &rotation_csrf, &rotation, "changed-secret")
            .await,
        Err(RequestError::InvalidRequest)
    ));
    let replay = app
        .rotate_capability(1, id, &cookie, &rotation_csrf, &rotation, secret)
        .await
        .unwrap();
    assert_eq!(replay.status, 200);
    let replay = String::from_utf8(replay.body).unwrap();
    assert!(!replay.contains(secret));
    assert!(!replay.contains(new_secret));
    assert_eq!(
        state(&database, true).await,
        ("1".into(), "2".into(), "2".into())
    );
    table(&database, false).await;
    let replay = app
        .rotate_capability(1, id, &cookie, &rotation_csrf, &rotation, secret)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&replay.body).contains(new_secret));
    assert_eq!(
        state(&database, false).await,
        ("1".into(), "2".into(), "2".into())
    );
}
#[tokio::test]
async fn sqlite_prior_receipt_delivery_failure_preserves_commit_not_grants() {
    let directory = tempfile::tempdir().unwrap();
    original_receipt_case(Database::sqlite(directory.path().join("prior-receipt.db"))).await;
}
#[tokio::test]
#[ignore = "requires authorized disposable NOXIDE_TEST_POSTGRES"]
async fn postgres_prior_receipt_delivery_failure_preserves_commit_not_grants() {
    let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
    let name = format!(
        "nx_prior_receipt_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .unwrap();
    println!("retained_fixture={name}");
    admin.close().await.unwrap();
    let mut url = url::Url::parse(&root).unwrap();
    url.set_path(&name);
    original_receipt_case(Database::postgres(url.as_str()).unwrap()).await;
}
