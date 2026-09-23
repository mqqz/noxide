use anyhow::{Result, ensure};
use sqlx::{
    Connection, Row,
    postgres::PgConnectOptions,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous},
};
use std::{
    path::Path,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
pub enum Database {
    Sqlite(SqliteConnectOptions),
    Postgres(PgConnectOptions),
}

pub(crate) enum Backend {
    Sqlite(sqlx::SqliteConnection),
    Postgres(sqlx::PgConnection),
}
pub(crate) struct Transaction {
    backend: Backend,
    active: bool,
    cancelled: Arc<AtomicBool>,
    deadline: tokio::time::Instant,
}

#[derive(Clone)]
pub(crate) enum Param {
    Text(String),
    Number(i64),
}
impl From<&str> for Param {
    fn from(s: &str) -> Self {
        Self::Text(s.into())
    }
}
impl From<String> for Param {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}
impl From<i64> for Param {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

macro_rules! bound_query {
    ($sql:expr,$params:expr) => {{
        let mut q = sqlx::query($sql);
        for p in $params {
            q = match p {
                Param::Text(s) => q.bind(s),
                Param::Number(n) => q.bind(*n),
            };
        }
        q
    }};
}

impl Database {
    pub fn sqlite(path: impl AsRef<Path>) -> Self {
        Self::Sqlite(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Full)
                .foreign_keys(true)
                .busy_timeout(Duration::from_millis(250))
                .pragma("trusted_schema", "OFF"),
        )
    }
    /// PostgreSQL is reached through a local socket or loopback. Remote database
    /// transport requires a separately configured trusted deployment extension.
    pub fn postgres(url: &str) -> Result<Self> {
        let options = PgConnectOptions::from_str(url)?;
        let host = options.get_host();
        ensure!(
            host.starts_with('/')
                || host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|a| a.is_loopback()),
            "database must be local"
        );
        Ok(Self::Postgres(options))
    }
    pub(crate) async fn begin(&self, deadline: Instant) -> Result<Transaction> {
        tokio::time::timeout_at(deadline.into(), self.connect(deadline)).await?
    }
    async fn connect(&self, deadline: Instant) -> Result<Transaction> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let backend = match self {
            Self::Sqlite(options) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                    let path = options.get_filename();
                    match std::fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        .open(path)
                    {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e.into()),
                    }
                    ensure!(
                        std::fs::metadata(path)?.permissions().mode() & 0o077 == 0,
                        "SQLite database must be private (mode 0600)"
                    );
                }
                let mut cx = sqlx::SqliteConnection::connect_with(options).await?;
                let flag = cancelled.clone();
                cx.lock_handle().await?.set_progress_handler(1000, move || {
                    !flag.load(Ordering::Relaxed) && Instant::now() < deadline
                });
                let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
                    .fetch_one(&mut cx)
                    .await?;
                let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
                    .fetch_one(&mut cx)
                    .await?;
                ensure!(
                    synchronous == 2 && mode == "wal",
                    "unsafe SQLite durability"
                );
                sqlx::query("BEGIN IMMEDIATE").execute(&mut cx).await?;
                Backend::Sqlite(cx)
            }
            Self::Postgres(options) => {
                let mut cx = sqlx::PgConnection::connect_with(options).await?;
                for setting in ["SHOW fsync", "SHOW full_page_writes"] {
                    let value: String = sqlx::query_scalar(setting).fetch_one(&mut cx).await?;
                    ensure!(value == "on", "unsafe PostgreSQL durability");
                }
                sqlx::query("SET synchronous_commit = on")
                    .execute(&mut cx)
                    .await?;
                sqlx::query("SET statement_timeout = '1500ms'")
                    .execute(&mut cx)
                    .await?;
                sqlx::query("SET lock_timeout = '250ms'")
                    .execute(&mut cx)
                    .await?;
                sqlx::query("SET idle_in_transaction_session_timeout = '3000ms'")
                    .execute(&mut cx)
                    .await?;
                sqlx::query("BEGIN ISOLATION LEVEL SERIALIZABLE")
                    .execute(&mut cx)
                    .await?;
                Backend::Postgres(cx)
            }
        };
        Ok(Transaction {
            backend,
            active: true,
            cancelled,
            deadline: deadline.into(),
        })
    }

    pub async fn initialize(&self) -> Result<()> {
        let mut tx = self.begin(Instant::now() + Duration::from_secs(10)).await?;
        for sql in SCHEMA {
            tx.execute(sql, &[]).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Bounded operator maintenance. Authenticated expiry remains enforceable
    /// after receipts disappear, including when a persisted clock moves back.
    pub async fn maintain(&self) -> Result<()> {
        let mut tx = self.begin(Instant::now() + Duration::from_secs(2)).await?;
        let now = crate::security::now()?;
        crate::security::observe_clock(&mut tx, now).await?;
        tx.execute("DELETE FROM nx_receipts WHERE nonce IN (SELECT nonce FROM nx_receipts WHERE expires<$1 ORDER BY expires LIMIT 256)",&[(now-60).into()]).await?;
        tx.execute("DELETE FROM nx_sessions WHERE id IN (SELECT id FROM nx_sessions WHERE expires<$1 ORDER BY expires LIMIT 256)",&[(now-60).into()]).await?;
        tx.commit().await
    }
}

impl Transaction {
    pub(crate) async fn deployment(
        &mut self,
        contract: &str,
        incarnation: &str,
        activate: bool,
    ) -> Result<String> {
        let candidate = crate::security::random_id()?;
        if activate {
            self.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,$1,$2,$3) ON CONFLICT(singleton) DO NOTHING",&[contract.into(),incarnation.into(),candidate.as_str().into()]).await?;
        }
        let rows = self
            .fetch::<3>(
                "SELECT contract,incarnation,generation FROM nx_deployment WHERE singleton=1",
                &[],
            )
            .await?;
        let [stored, key, generation] = rows
            .first()
            .ok_or_else(|| anyhow::anyhow!("deployment missing"))?;
        if stored == contract && key == incarnation {
            return Ok(generation.clone());
        }
        ensure!(activate, "deployment was superseded");
        self.execute(
            "UPDATE nx_deployment SET contract=$1,incarnation=$2,generation=$3 WHERE singleton=1",
            &[
                contract.into(),
                incarnation.into(),
                candidate.as_str().into(),
            ],
        )
        .await?;
        Ok(candidate)
    }
    pub(crate) fn bounded_text(&self, column: &str, maximum: usize) -> String {
        // Names and limits come only from trusted code. NULL rejects oversized
        // stored values before their contents cross the SQL driver.
        let size = match self.backend {
            Backend::Sqlite(_) => format!("length(CAST({column} AS BLOB))"),
            Backend::Postgres(_) => format!("octet_length({column})"),
        };
        format!("CASE WHEN {size}<={maximum} THEN {column} ELSE NULL END")
    }
    pub(crate) async fn bind_schema(&mut self, manifest: &noxide_protocol::Manifest) -> Result<()> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(serde_json::to_vec(&manifest.resources)?);
        let hash = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
        self.execute("INSERT INTO nx_schema(singleton,digest) VALUES(1,$1) ON CONFLICT(singleton) DO NOTHING",&[hash.as_str().into()]).await?;
        let rows = self
            .fetch::<1>("SELECT digest FROM nx_schema WHERE singleton=1", &[])
            .await?;
        ensure!(
            rows.first().is_some_and(|r| r[0] == hash),
            "stored schema differs from approved resource contract; an explicit migration is required"
        );
        Ok(())
    }
    pub(crate) async fn execute(&mut self, sql: &str, params: &[Param]) -> Result<u64> {
        let deadline = if sql == "ROLLBACK" {
            tokio::time::Instant::now() + Duration::from_millis(500)
        } else {
            self.deadline
        };
        tokio::time::timeout_at(deadline, async {
            Ok(match &mut self.backend {
                Backend::Sqlite(cx) => bound_query!(sql, params).execute(cx).await?.rows_affected(),
                Backend::Postgres(cx) => {
                    bound_query!(sql, params).execute(cx).await?.rows_affected()
                }
            })
        })
        .await?
    }
    // Trusted queries cast selected columns to TEXT, keeping backend conversion
    // rules out of the semantic repository and receipt contracts.
    pub(crate) async fn fetch<const N: usize>(
        &mut self,
        sql: &str,
        params: &[Param],
    ) -> Result<Vec<[String; N]>> {
        macro_rules! rows {
            ($cx:expr) => {{
                let rows = bound_query!(sql, params).fetch_all($cx).await?;
                ensure!(rows.len() <= 64, "database row limit");
                let mut output = Vec::with_capacity(rows.len());
                let mut bytes = 0usize;
                for row in rows {
                    let mut fields = Vec::with_capacity(N);
                    for i in 0..N {
                        let value: String = row.try_get(i)?;
                        bytes = bytes.saturating_add(value.len());
                        ensure!(bytes <= 65_536, "database result limit");
                        fields.push(value);
                    }
                    output.push(
                        fields
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("database shape"))?,
                    );
                }
                output
            }};
        }
        tokio::time::timeout_at(self.deadline, async {
            Ok(match &mut self.backend {
                Backend::Sqlite(cx) => rows!(cx),
                Backend::Postgres(cx) => rows!(cx),
            })
        })
        .await?
    }
    pub(crate) async fn commit(&mut self) -> Result<()> {
        self.execute("COMMIT", &[]).await?;
        self.active = false;
        #[cfg(test)]
        crate::failure_tests::after_commit().await?;
        Ok(())
    }
    pub(crate) async fn rollback(&mut self) -> Result<()> {
        tokio::time::timeout(Duration::from_millis(500), async {
            if self.active {
                if let Backend::Sqlite(cx) = &mut self.backend {
                    cx.lock_handle().await?.remove_progress_handler();
                }
                self.execute("ROLLBACK", &[]).await?;
                self.active = false;
            }
            Ok(())
        })
        .await?
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        // Connections are never returned to a pool with unresolved state.
        // SQLite's worker closes its connection; PostgreSQL disconnect rolls back.
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

pub(crate) fn retryable(error: &anyhow::Error) -> bool {
    #[cfg(test)]
    if error.is::<crate::failure_tests::Aborted>() {
        return true;
    }
    let Some(sqlx::Error::Database(db)) = error.downcast_ref::<sqlx::Error>() else {
        return false;
    };
    matches!(
        db.code().as_deref(),
        Some("40001" | "40P01" | "55P03" | "5" | "517")
    )
}

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS nx_accounts (id TEXT PRIMARY KEY, password TEXT NOT NULL, tenant TEXT NOT NULL, epoch BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_roles (principal TEXT NOT NULL REFERENCES nx_accounts(id), name TEXT NOT NULL, tenant TEXT NOT NULL, PRIMARY KEY(principal,name,tenant))",
    "CREATE TABLE IF NOT EXISTS nx_sessions (id TEXT PRIMARY KEY, principal TEXT NOT NULL REFERENCES nx_accounts(id), epoch BIGINT NOT NULL, expires BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_records (resource BIGINT NOT NULL, id BIGINT NOT NULL, owner TEXT NOT NULL REFERENCES nx_accounts(id), tenant TEXT NOT NULL, fields TEXT NOT NULL, PRIMARY KEY(resource,id))",
    "CREATE INDEX IF NOT EXISTS nx_records_owner ON nx_records(resource,owner,id)",
    "CREATE INDEX IF NOT EXISTS nx_records_tenant ON nx_records(resource,tenant,id)",
    "CREATE TABLE IF NOT EXISTS nx_receipts (nonce TEXT PRIMARY KEY, subject TEXT NOT NULL, contract TEXT NOT NULL, action BIGINT NOT NULL, input TEXT NOT NULL, outcome TEXT NOT NULL, expires BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_clock (singleton BIGINT PRIMARY KEY, observed BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_schema (singleton BIGINT PRIMARY KEY, digest TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_deployment (singleton BIGINT PRIMARY KEY, contract TEXT NOT NULL, incarnation TEXT NOT NULL, generation TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS nx_receipts_expiry ON nx_receipts(expires)",
    "CREATE INDEX IF NOT EXISTS nx_sessions_expiry ON nx_sessions(expires)",
    "INSERT INTO nx_clock(singleton,observed) VALUES(1,0) ON CONFLICT(singleton) DO NOTHING",
];
