use super::*;
#[tokio::test]
async fn elapsed_database_work_is_busy_but_schema_rejection_is_not() {
    let elapsed = tokio::time::timeout(
        std::time::Duration::from_millis(1),
        std::future::pending::<()>(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        RequestError::database(elapsed.into()),
        RequestError::Busy
    ));
    for busy in [
        noxide_guest::GuestBusy::Deadline,
        noxide_guest::GuestBusy::Capacity,
    ] {
        assert!(matches!(
            RequestError::database(guest_error(busy.into())),
            RequestError::Busy
        ));
    }
    assert!(matches!(
        RequestError::database(guest_error(anyhow::anyhow!("guest trap"))),
        RequestError::Rejected
    ));
    assert!(matches!(
        RequestError::database(anyhow::anyhow!("stored schema differs from manifest")),
        RequestError::Rejected
    ));
}
