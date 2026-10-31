//! A cleanup acknowledgement cannot retrospectively prove COMMIT was refused.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CommitState {
    NotAttempted,
    Refused,
    Sent,
    Acknowledged,
}
impl CommitState {
    pub(super) fn may_have_committed(self) -> bool {
        matches!(self, Self::Sent | Self::Acknowledged)
    }
}

#[derive(Debug)]
pub(crate) enum CommitFailure {
    Uncertain(anyhow::Error),
    Committed(anyhow::Error),
}
impl std::fmt::Display for CommitFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Uncertain(_) => "commit outcome requires authoritative receipt recovery",
            Self::Committed(_) => "commit acknowledged; subsequent operation failed",
        })
    }
}
impl std::error::Error for CommitFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Uncertain(error) | Self::Committed(error) => error.as_ref(),
        })
    }
}
impl CommitFailure {
    pub(super) fn uncertain(error: anyhow::Error) -> anyhow::Error {
        Self::Uncertain(error).into()
    }
    pub(super) fn cleanup(error: anyhow::Error) -> anyhow::Error {
        Self::Committed(error).into()
    }
}

/// Only an actual provider refusal may restore known-abort/retry eligibility.
/// Host timeout, cancellation, IO, protocol errors and cleanup errors are absent.
pub(super) fn refused(backend: &Backend, error: &anyhow::Error) -> bool {
    let Some(sqlx::Error::Database(error)) = error.downcast_ref::<sqlx::Error>() else {
        return false;
    };
    match backend {
        Backend::Postgres(_) => matches!(error.code().as_deref(), Some("40001" | "40P01")),
        Backend::Sqlite(_) => matches!(error.code().as_deref(), Some("5" | "517")),
        Backend::Closed => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn acknowledged_cleanup_never_becomes_retryable_abort() {
        let elapsed = tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err();
        let error = CommitFailure::cleanup(elapsed.into()).context("cleanup caller");
        assert!(!retryable(&error));
        assert!(CommitState::Acknowledged.may_have_committed());
    }

    #[tokio::test]
    async fn sqlite_lost_commit_ack_survives_successful_rollback_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let database = Database::sqlite(tmp.path().join("commit-frontier.db"));
        database.initialize().await.unwrap();
        let mut tx = database
            .begin(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        tx.execute("UPDATE nx_clock SET observed=1 WHERE singleton=1", &[])
            .await
            .unwrap();
        let error = crate::failure_tests::lose_commit_ack(tx.commit())
            .await
            .unwrap_err();
        assert!(!retryable(&error));
        assert!(tx.commit_may_have_succeeded());
        assert!(!tx.commit_acknowledged());
        let error = tx.rollback().await.unwrap_err();
        assert!(!retryable(&error));
        assert!(tx.commit_may_have_succeeded());
        drop(tx);
        let mut read = database
            .begin_read(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            read.fetch::<1>(
                "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
                &[]
            )
            .await
            .unwrap(),
            [["1".to_owned()]]
        );
        read.commit().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires authorized disposable NOXIDE_TEST_POSTGRES"]
    async fn postgres_acknowledged_commit_refusal_is_known_aborted() {
        let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
        let name = format!(
            "nx_commit_refused_{}_{}",
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
        let mut url = url::Url::parse(&root).unwrap();
        url.set_path(&name);
        let database = Database::postgres(url.as_str()).unwrap();
        database.initialize().await.unwrap();
        let mut operator = sqlx::PgConnection::connect(url.as_str()).await.unwrap();
        sqlx::query("CREATE FUNCTION nx_commit_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic serialization refusal' USING ERRCODE='40001'; END $$").execute(&mut operator).await.unwrap();
        sqlx::query("CREATE CONSTRAINT TRIGGER nx_commit_refuse AFTER INSERT ON nx_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION nx_commit_refuse()").execute(&mut operator).await.unwrap();
        let mut tx = database
            .begin(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES('synthetic','subject','contract',1,'input','outcome',1)", &[]).await.unwrap();
        let error = tx.commit().await.unwrap_err();
        assert!(retryable(&error));
        assert!(!tx.commit_may_have_succeeded());
        assert!(!tx.commit_acknowledged());
        tx.rollback().await.unwrap();
        drop(tx);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nx_receipts")
            .fetch_one(&mut operator)
            .await
            .unwrap();
        assert_eq!(count, 0);
        operator.close().await.unwrap();
        admin.close().await.unwrap();
    }
}
