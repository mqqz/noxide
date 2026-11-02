use super::*;
#[tokio::test]
async fn invalid_cursor_has_safe_restart_link() {
    let response = cursor_error("/threads/10");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("href=\"/threads/10\">Restart pagination</a>"));
    assert!(!html.contains("?cursor="));
    let response = cursor_error("/x?value=\"<&");
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("&quot;&lt;&amp;")
    );
}
