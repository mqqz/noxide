use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn auth_http_committed_lost_ack_is_unknown_and_preserves_durable_state() {
    use crate::{
        Application, HostKeys, Registration, manifest, runtime::Limits, test_support as fixture,
    };
    for register in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::sqlite(directory.path().join("auth-frontier.db"));
        database.initialize().await.unwrap();
        if !register {
            database
                .create_account("alice", "synthetic auth password", "")
                .await
                .unwrap();
        }
        let manifest = fixture::manifest();
        let app = Arc::new(
            Application::new(
                &fixture::component(None),
                &serde_json::to_vec(&manifest).unwrap(),
                manifest::digest(&manifest).unwrap(),
                database.clone(),
                HostKeys::generate().unwrap(),
                Limits::default(),
                crate::assets::AssetBundle::default(),
            )
            .unwrap()
            .with_registration(Registration::Open),
        );
        app.activate().await.unwrap();
        let challenge = app.login_challenge().await.unwrap();
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair(&app.presentation.csrf_field, &challenge.csrf)
            .append_pair("username", "alice")
            .append_pair("password", "synthetic auth password")
            .finish();
        let path = if register {
            &app.presentation.registration_path
        } else {
            &app.presentation.login_path
        };
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("Host", "localhost:8080")
            .header("Origin", "http://localhost:8080")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header(
                "Cookie",
                format!("{}={}", app.presentation.login_cookie, challenge.cookie),
            )
            .body(Body::from(body))
            .unwrap();
        let router = crate::http::router(
            app.clone(),
            crate::http::Origin::parse("http://localhost:8080").unwrap(),
        );
        let response = crate::failure_tests::lose_commit_ack(router.oneshot(request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key("set-cookie"));
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"The operation result is not yet confirmed.");
        let mut read = database
            .begin_read(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let counts=read.fetch::<3>("SELECT CAST((SELECT COUNT(*) FROM nx_accounts) AS TEXT),CAST((SELECT COUNT(*) FROM nx_sessions) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts) AS TEXT)",&[]).await.unwrap();
        assert_eq!(
            counts,
            [[
                "1".to_owned(),
                if register { "0" } else { "1" }.to_owned(),
                "0".to_owned()
            ]]
        );
        read.commit().await.unwrap();
        // Auth has no semantic action receipt. A fresh authenticated login proves
        // the account committed, without replaying registration or inventing one.
        let challenge = app.login_challenge().await.unwrap();
        app.login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "synthetic auth password",
        )
        .await
        .unwrap();
        app.request_lifecycle().shutdown().await.unwrap();
    }
}
