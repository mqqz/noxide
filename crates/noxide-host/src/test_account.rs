use crate::{Database, auth::AccountAdmin as _};

pub async fn test_account(db: &Database, login: &str) -> String {
    db.account_id(login)
        .await
        .unwrap_or_else(|_| "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into())
}
