use anyhow::{Context, Result, ensure};
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
        if tx.storage_tables().await?.is_empty() {
            for sql in SCHEMA {
                tx.execute(sql, &[]).await?;
            }
        } else {
            tx.check_storage()
                .await
                .context("storage requires explicit offline migration")?;
            tx.check_layout(true).await?;
        }
        tx.commit().await
    }

    /// Upgrade the framework's storage while all application servers are stopped.
    /// Migration is atomic and limited to five minutes; it never executes guest SQL.
    pub async fn migrate(&self) -> Result<()> {
        let mut tx = self
            .begin(Instant::now() + Duration::from_secs(300))
            .await?;
        if matches!(tx.backend, Backend::Postgres(_)) {
            tx.execute("SET LOCAL statement_timeout = '300s'", &[])
                .await?;
            tx.execute("SET LOCAL idle_in_transaction_session_timeout = '10s'", &[])
                .await?;
        }
        tx.migrate_storage().await?;
        tx.commit().await
    }

    /// Bounded operator maintenance. Authenticated expiry remains enforceable
    /// after receipts disappear, including when a persisted clock moves back.
    pub async fn maintain(&self) -> Result<()> {
        let mut tx = self.begin(Instant::now() + Duration::from_secs(2)).await?;
        tx.check_storage().await?;
        let now = crate::security::now()?;
        crate::security::observe_clock(&mut tx, now).await?;
        tx.execute("DELETE FROM nx_receipts WHERE nonce IN (SELECT nonce FROM nx_receipts WHERE expires<$1 ORDER BY expires LIMIT 256)",&[(now-60).into()]).await?;
        tx.execute("DELETE FROM nx_sessions WHERE id IN (SELECT id FROM nx_sessions WHERE expires<$1 ORDER BY expires LIMIT 256)",&[(now-60).into()]).await?;
        tx.commit().await
    }
}

impl Transaction {
    pub(crate) async fn check_storage(&mut self) -> Result<()> {
        let rows = self.fetch::<2>(
            "SELECT CAST(singleton AS TEXT),CAST(version AS TEXT) FROM nx_storage ORDER BY singleton LIMIT 2",
            &[],
        ).await?;
        ensure!(
            rows.as_slice() == [["1".to_owned(), STORAGE_VERSION.to_string()]],
            "unsupported framework storage version; an explicit offline migration is required"
        );
        Ok(())
    }

    async fn storage_tables(&mut self) -> Result<Vec<String>> {
        let sql = match self.backend {
            Backend::Sqlite(_) => {
                "SELECT name FROM sqlite_schema WHERE type='table' AND name GLOB 'nx_*' ORDER BY name LIMIT 65"
            }
            Backend::Postgres(_) => {
                "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname=current_schema() AND left(tablename,3)='nx_' ORDER BY tablename LIMIT 65"
            }
        };
        Ok(self
            .fetch::<1>(sql, &[])
            .await?
            .into_iter()
            .map(|[name]| name)
            .collect())
    }

    async fn check_layout(&mut self, current: bool) -> Result<()> {
        let mut expected: Vec<_> = TABLE_COLUMNS
            .iter()
            .filter(|(name, _)| current || *name != "nx_storage")
            .map(|(name, _)| (*name).to_owned())
            .collect();
        expected.sort();
        ensure!(
            self.storage_tables().await? == expected,
            "unsupported or incomplete framework storage schema"
        );
        for &(table, columns) in TABLE_COLUMNS {
            if table == "nx_storage" && !current {
                continue;
            }
            let sql = match self.backend {
                Backend::Sqlite(_) => {
                    "SELECT name,upper(type),COALESCE(dflt_value,''),CAST(\"notnull\" AS TEXT) FROM pragma_table_info($1) ORDER BY cid LIMIT 65"
                }
                Backend::Postgres(_) => {
                    "SELECT column_name,upper(data_type),COALESCE(column_default,''),CASE WHEN is_nullable='NO' THEN '1' ELSE '0' END FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 ORDER BY ordinal_position LIMIT 65"
                }
            };
            let actual = self.fetch::<4>(sql, &[table.into()]).await?;
            let columns = if table == "nx_records" && !current {
                &columns[..5]
            } else {
                columns
            };
            ensure!(
                actual.len() == columns.len(),
                "unsupported columns in {table}"
            );
            for ([name, kind, default, not_null], &(expected_name, expected_kind)) in
                actual.into_iter().zip(columns)
            {
                // SQLite's released single-column primary keys were not
                // explicitly NOT NULL. PostgreSQL marks primary keys non-null.
                let implicit_key = expected_name == "singleton"
                    || (matches!(table, "nx_accounts" | "nx_sessions") && expected_name == "id")
                    || (table == "nx_receipts" && expected_name == "nonce");
                let expected_not_null =
                    if matches!(self.backend, Backend::Sqlite(_)) && implicit_key {
                        "0"
                    } else {
                        "1"
                    };
                ensure!(
                    name == expected_name
                        && kind == expected_kind
                        && default.is_empty()
                        && not_null == expected_not_null,
                    "unsupported column definition in {table}"
                );
            }
        }
        Ok(())
    }

    async fn migrate_storage(&mut self) -> Result<()> {
        // Take this lock before any SELECT establishes PostgreSQL's transaction
        // snapshot. A writer finishing while we wait must appear in the copy.
        // Operators must still stop all application servers before migration.
        if matches!(self.backend, Backend::Postgres(_)) {
            self.execute(
                "LOCK TABLE nx_records, nx_deployment IN ACCESS EXCLUSIVE MODE",
                &[],
            )
            .await?;
        }
        let tables = self.storage_tables().await?;
        if tables.iter().any(|name| name == "nx_storage") {
            self.check_storage().await?;
            return self.check_layout(true).await;
        }
        self.check_layout(false).await?;
        self.execute("CREATE TABLE nx_records_migrating (resource BIGINT NOT NULL, id BIGINT NOT NULL, owner TEXT NOT NULL REFERENCES nx_accounts(id), tenant TEXT NOT NULL, fields TEXT NOT NULL, incarnation TEXT NOT NULL, revision BIGINT NOT NULL CHECK(revision>=1), PRIMARY KEY(resource,id))", &[]).await?;
        let total = self
            .fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
            .await?[0][0]
            .parse::<u64>()?;
        let mut copied_total = 0u64;
        let mut cursor = None;
        loop {
            let rows = if let Some((resource, id)) = cursor {
                self.fetch::<2>("SELECT CAST(resource AS TEXT),CAST(id AS TEXT) FROM nx_records WHERE resource>$1 OR (resource=$1 AND id>$2) ORDER BY nx_records.resource,nx_records.id LIMIT 32", &[Param::Number(resource), Param::Number(id)]).await?
            } else {
                self.fetch::<2>("SELECT CAST(resource AS TEXT),CAST(id AS TEXT) FROM nx_records ORDER BY nx_records.resource,nx_records.id LIMIT 32", &[]).await?
            };
            if rows.is_empty() {
                break;
            }
            for [resource, id] in rows {
                let resource = resource.parse::<i64>()?;
                let id = id.parse::<i64>()?;
                let incarnation = crate::security::random_id()?;
                let copied = self.execute("INSERT INTO nx_records_migrating(resource,id,owner,tenant,fields,incarnation,revision) SELECT resource,id,owner,tenant,fields,$3,1 FROM nx_records WHERE resource=$1 AND id=$2", &[resource.into(), id.into(), incarnation.into()]).await?;
                ensure!(copied == 1, "record changed during migration");
                copied_total = copied_total
                    .checked_add(copied)
                    .context("record count overflow")?;
                cursor = Some((resource, id));
            }
        }
        ensure!(copied_total == total, "migration did not copy every record");
        self.execute("DROP TABLE nx_records", &[]).await?;
        self.execute("ALTER TABLE nx_records_migrating RENAME TO nx_records", &[])
            .await?;
        self.execute(
            "CREATE INDEX nx_records_owner ON nx_records(resource,owner,id)",
            &[],
        )
        .await?;
        self.execute(
            "CREATE INDEX nx_records_tenant ON nx_records(resource,tenant,id)",
            &[],
        )
        .await?;
        self.execute(
            "UPDATE nx_deployment SET generation=$1",
            &[crate::security::random_id()?.into()],
        )
        .await?;
        self.execute("CREATE TABLE nx_storage (singleton BIGINT PRIMARY KEY CHECK(singleton=1), version BIGINT NOT NULL)", &[]).await?;
        self.execute(
            "INSERT INTO nx_storage(singleton,version) VALUES(1,$1)",
            &[STORAGE_VERSION.into()],
        )
        .await?;
        self.check_layout(true).await?;
        self.check_storage().await
    }

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

const STORAGE_VERSION: i64 = 2;
const TABLE_COLUMNS: &[(&str, &[(&str, &str)])] = &[
    (
        "nx_accounts",
        &[
            ("id", "TEXT"),
            ("password", "TEXT"),
            ("tenant", "TEXT"),
            ("epoch", "BIGINT"),
        ],
    ),
    (
        "nx_roles",
        &[("principal", "TEXT"), ("name", "TEXT"), ("tenant", "TEXT")],
    ),
    (
        "nx_sessions",
        &[
            ("id", "TEXT"),
            ("principal", "TEXT"),
            ("epoch", "BIGINT"),
            ("expires", "BIGINT"),
        ],
    ),
    (
        "nx_records",
        &[
            ("resource", "BIGINT"),
            ("id", "BIGINT"),
            ("owner", "TEXT"),
            ("tenant", "TEXT"),
            ("fields", "TEXT"),
            ("incarnation", "TEXT"),
            ("revision", "BIGINT"),
        ],
    ),
    (
        "nx_receipts",
        &[
            ("nonce", "TEXT"),
            ("subject", "TEXT"),
            ("contract", "TEXT"),
            ("action", "BIGINT"),
            ("input", "TEXT"),
            ("outcome", "TEXT"),
            ("expires", "BIGINT"),
        ],
    ),
    (
        "nx_clock",
        &[("singleton", "BIGINT"), ("observed", "BIGINT")],
    ),
    ("nx_schema", &[("singleton", "BIGINT"), ("digest", "TEXT")]),
    (
        "nx_deployment",
        &[
            ("singleton", "BIGINT"),
            ("contract", "TEXT"),
            ("incarnation", "TEXT"),
            ("generation", "TEXT"),
        ],
    ),
    (
        "nx_storage",
        &[("singleton", "BIGINT"), ("version", "BIGINT")],
    ),
];

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS nx_storage (singleton BIGINT PRIMARY KEY CHECK(singleton=1), version BIGINT NOT NULL)",
    "INSERT INTO nx_storage(singleton,version) VALUES(1,2)",
    "CREATE TABLE IF NOT EXISTS nx_accounts (id TEXT PRIMARY KEY, password TEXT NOT NULL, tenant TEXT NOT NULL, epoch BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_roles (principal TEXT NOT NULL REFERENCES nx_accounts(id), name TEXT NOT NULL, tenant TEXT NOT NULL, PRIMARY KEY(principal,name,tenant))",
    "CREATE TABLE IF NOT EXISTS nx_sessions (id TEXT PRIMARY KEY, principal TEXT NOT NULL REFERENCES nx_accounts(id), epoch BIGINT NOT NULL, expires BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_records (resource BIGINT NOT NULL, id BIGINT NOT NULL, owner TEXT NOT NULL REFERENCES nx_accounts(id), tenant TEXT NOT NULL, fields TEXT NOT NULL, incarnation TEXT NOT NULL, revision BIGINT NOT NULL CHECK(revision>=1), PRIMARY KEY(resource,id))",
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

#[cfg(test)]
mod storage_tests {
    use super::*;
    use base64::Engine;

    const LEGACY_RECORDS: &str = "CREATE TABLE nx_records (resource BIGINT NOT NULL, id BIGINT NOT NULL, owner TEXT NOT NULL REFERENCES nx_accounts(id), tenant TEXT NOT NULL, fields TEXT NOT NULL, PRIMARY KEY(resource,id))";

    async fn legacy(db: &Database) {
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        // This fixture deliberately creates the released, unversioned schema.
        for sql in SCHEMA {
            if sql.contains("nx_storage") {
                continue;
            }
            tx.execute(
                if sql.starts_with("CREATE TABLE") && sql.contains("nx_records (") {
                    LEGACY_RECORDS
                } else {
                    sql
                },
                &[],
            )
            .await
            .unwrap();
        }
        tx.execute("INSERT INTO nx_accounts(id,password,tenant,epoch) VALUES('alice','password-hash','team',7)", &[]).await.unwrap();
        tx.execute(
            "INSERT INTO nx_roles(principal,name,tenant) VALUES('alice','writer','team')",
            &[],
        )
        .await
        .unwrap();
        tx.execute("INSERT INTO nx_sessions(id,principal,epoch,expires) VALUES('session','alice',7,123456)", &[]).await.unwrap();
        tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'contract','host-key','old-generation')", &[]).await.unwrap();
        tx.execute(
            "INSERT INTO nx_schema(singleton,digest) VALUES(1,'resource-contract')",
            &[],
        )
        .await
        .unwrap();
        tx.execute("INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES('receipt','session','contract',3,'input-digest','outcome',123456)", &[]).await.unwrap();
        // Exceed one fetch's row and byte limits so migration must page safely.
        let fields = format!(r#"{{"body":"{}"}}"#, "x".repeat(8192));
        for id in 1..=80i64 {
            tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields) VALUES(1,$1,'alice','team',$2)", &[id.into(), fields.clone().into()]).await.unwrap();
        }
        tx.commit().await.unwrap();
    }

    async fn migration_contract(db: Database) {
        legacy(&db).await;
        let err = db.initialize().await.unwrap_err().to_string();
        assert!(err.contains("migration"), "{err}");
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(tx.check_storage().await.is_err());
        tx.rollback().await.unwrap();

        // Simulate termination after every migration write but before commit.
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.migrate_storage().await.unwrap();
        tx.rollback().await.unwrap();
        assert!(db.initialize().await.is_err());
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
                .await
                .unwrap()[0][0],
            "80"
        );
        assert_eq!(
            tx.fetch::<1>(
                "SELECT generation FROM nx_deployment WHERE singleton=1",
                &[]
            )
            .await
            .unwrap()[0][0],
            "old-generation"
        );
        tx.rollback().await.unwrap();

        db.migrate().await.unwrap();
        db.initialize().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.check_storage().await.unwrap();
        let records = tx
            .fetch::<2>(
                "SELECT incarnation,CAST(revision AS TEXT) FROM nx_records ORDER BY id LIMIT 64",
                &[],
            )
            .await
            .unwrap();
        let mut incarnations = std::collections::HashSet::new();
        for [incarnation, revision] in records {
            assert_eq!(revision, "1");
            assert_eq!(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&incarnation)
                    .unwrap()
                    .len(),
                32
            );
            assert!(incarnations.insert(incarnation));
        }
        let original = format!(r#"{{"body":"{}"}}"#, "x".repeat(8192));
        let expected = ["alice".into(), "team".into(), original];
        assert_eq!(
            tx.fetch::<3>(
                "SELECT owner,tenant,fields FROM nx_records WHERE resource=1 AND id=80",
                &[]
            )
            .await
            .unwrap()[0],
            expected
        );
        for (sql, expected) in [
            ("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", "80"),
            (
                "SELECT password FROM nx_accounts WHERE id='alice'",
                "password-hash",
            ),
            (
                "SELECT name FROM nx_roles WHERE principal='alice'",
                "writer",
            ),
            (
                "SELECT principal FROM nx_sessions WHERE id='session'",
                "alice",
            ),
            (
                "SELECT outcome FROM nx_receipts WHERE nonce='receipt'",
                "outcome",
            ),
            (
                "SELECT digest FROM nx_schema WHERE singleton=1",
                "resource-contract",
            ),
        ] {
            assert_eq!(tx.fetch::<1>(sql, &[]).await.unwrap()[0][0], expected);
        }
        let generation = tx
            .fetch::<1>(
                "SELECT generation FROM nx_deployment WHERE singleton=1",
                &[],
            )
            .await
            .unwrap()[0][0]
            .clone();
        assert_ne!(generation, "old-generation");
        tx.rollback().await.unwrap();
        db.migrate().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            tx.fetch::<1>(
                "SELECT generation FROM nx_deployment WHERE singleton=1",
                &[]
            )
            .await
            .unwrap()[0][0],
            generation
        );
        assert!(tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields) VALUES(1,81,'alice','team','{}')", &[]).await.is_err());
        tx.rollback().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision) VALUES(1,81,'alice','team','{}','new-record',0)", &[]).await.is_err());
        tx.rollback().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.execute("UPDATE nx_storage SET version=999", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(db.initialize().await.is_err());
        assert!(db.migrate().await.is_err());
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(tx.check_storage().await.is_err());
        assert_eq!(
            tx.fetch::<1>(
                "SELECT CAST(version AS TEXT) FROM nx_storage WHERE singleton=1",
                &[]
            )
            .await
            .unwrap()[0][0],
            "999"
        );
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_storage_migration() {
        let dir = tempfile::tempdir().unwrap();
        migration_contract(Database::sqlite(dir.path().join("migration.db"))).await;
    }

    #[tokio::test]
    async fn sqlite_storage_version_and_shape_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::sqlite(dir.path().join("version.db"));
        db.initialize().await.unwrap();
        db.initialize().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.execute("UPDATE nx_storage SET version=999", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(db.initialize().await.is_err());
        assert!(db.migrate().await.is_err());
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(tx.check_storage().await.is_err());
        tx.rollback().await.unwrap();

        let db = Database::sqlite(dir.path().join("partial.db"));
        legacy(&db).await;
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.execute("DROP TABLE nx_receipts", &[]).await.unwrap();
        tx.commit().await.unwrap();
        assert!(db.migrate().await.is_err());
        assert!(db.initialize().await.is_err());

        let db = Database::sqlite(dir.path().join("nullable.db"));
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        for sql in SCHEMA {
            tx.execute(
                &sql.replace(
                    "incarnation TEXT NOT NULL, revision",
                    "incarnation TEXT, revision",
                ),
                &[],
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
        assert!(db.initialize().await.is_err());
        assert!(db.migrate().await.is_err());
    }

    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable test cluster"]
    async fn postgres_storage_migration() {
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "nx_migrate_{}",
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
        migration_contract(Database::postgres(case.as_str()).unwrap()).await;
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable test cluster"]
    async fn postgres_migration_waits_for_writer_before_snapshot() {
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "nx_migrate_writer_{}",
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
        let db = Database::postgres(case.as_str()).unwrap();
        legacy(&db).await;
        let mut writer = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        writer.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields) VALUES(1,81,'alice','team','committed before migration lock')", &[]).await.unwrap();
        let migrating = db.clone();
        let migration = tokio::spawn(async move { migrating.migrate().await });
        // Observe the actual waiter, rather than relying on a scheduling delay.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let waiting: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=$1 AND l.mode='AccessExclusiveLock' AND NOT l.granted")
                    .bind(&name).fetch_one(&mut admin).await.unwrap();
                if waiting != 0 { break; }
                assert!(!migration.is_finished(), "migration stopped before acquiring its lock");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await.unwrap();
        writer.commit().await.unwrap();
        migration.await.unwrap().unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let rows = tx
            .fetch::<1>(
                "SELECT fields FROM nx_records WHERE resource=1 AND id=81",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(rows, [["committed before migration lock".to_owned()]]);
        assert_eq!(
            tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
                .await
                .unwrap()[0][0],
            "81"
        );
        tx.check_storage().await.unwrap();
        tx.rollback().await.unwrap();
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable test cluster"]
    async fn postgres_migration_blocks_legacy_writer_after_copy() {
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "nx_migrate_late_{}",
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
        let db = Database::postgres(case.as_str()).unwrap();
        legacy(&db).await;
        let mut migration = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        migration.migrate_storage().await.unwrap();
        let writing = db.clone();
        let writer = tokio::spawn(async move {
            let mut tx = writing
                .begin(Instant::now() + Duration::from_secs(10))
                .await?;
            tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields) VALUES(1,81,'alice','team','legacy write after migration')", &[]).await?;
            tx.commit().await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let waiting: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=$1 AND l.mode='RowExclusiveLock' AND NOT l.granted")
                    .bind(&name).fetch_one(&mut admin).await.unwrap();
                if waiting != 0 { break; }
                assert!(!writer.is_finished(), "writer stopped before reaching migration lock");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await.unwrap();
        migration.commit().await.unwrap();
        assert!(writer.await.unwrap().is_err());
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            tx.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
                .await
                .unwrap()[0][0],
            "80"
        );
        tx.check_storage().await.unwrap();
        tx.rollback().await.unwrap();
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}
