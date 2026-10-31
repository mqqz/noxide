mod blob_layout;
mod commit;
pub(crate) mod lifecycle;
mod maintenance;
mod schema;
mod search_layout;
use anyhow::{Context, Result, ensure};
pub(crate) use commit::CommitFailure;
use commit::CommitState;
pub(crate) use maintenance::{MaintenanceLease, MaintenanceUncertain};
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
pub struct Database {
    options: DatabaseOptions,
}
#[derive(Clone)]
enum DatabaseOptions {
    Sqlite {
        options: SqliteConnectOptions,
        path: std::path::PathBuf,
        busy: Duration,
    },
    Postgres(PgConnectOptions),
}

#[cfg(test)]
tokio::task_local! {pub(crate) static MAINTENANCE_CLOSE_PROBE: Arc<AtomicBool>;}

pub(crate) enum Backend {
    // Only installed while consuming a maintenance transaction during close.
    Closed,
    Sqlite(sqlx::SqliteConnection),
    Postgres(sqlx::PgConnection),
}
#[cfg(test)]
pub(crate) static CREATION_HOLD_MAX: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(crate) struct Transaction {
    #[cfg(test)]
    creation_acquired: Option<Instant>,
    backend: Backend,
    active: bool,
    // This frontier survives physical rollback/close. An acknowledgement of
    // cleanup never establishes whether a previously sent COMMIT committed.
    commit_state: CommitState,
    read_only: bool,
    cancelled: Arc<AtomicBool>,
    operator_ended: Arc<AtomicBool>,
    deadline: tokio::time::Instant,
    maintenance: Option<maintenance::Control>,
    ordinary: Option<lifecycle::Ordinary>,
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
        let path = path.as_ref().to_path_buf();
        let busy = Duration::from_millis(250);
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(busy)
            .pragma("trusted_schema", "OFF");
        Self {
            options: DatabaseOptions::Sqlite {
                options,
                path,
                busy,
            },
        }
    }
    #[cfg(test)]
    pub(crate) fn is_sqlite(&self) -> bool {
        matches!(self.options, DatabaseOptions::Sqlite { .. })
    }
    #[cfg(test)]
    pub(crate) fn with_sqlite_busy_timeout_for_test(mut self, timeout: Duration) -> Self {
        let DatabaseOptions::Sqlite { options, busy, .. } = &mut self.options else {
            panic!("SQLite fixture required")
        };
        *busy = timeout;
        *options = options.clone().busy_timeout(timeout);
        self
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
        Ok(Self {
            options: DatabaseOptions::Postgres(options),
        })
    }
    pub(crate) async fn begin(&self, deadline: Instant) -> Result<Transaction> {
        if let Some(result) = lifecycle::begin(self, deadline, false).await {
            return result;
        }
        tokio::time::timeout_at(deadline.into(), self.connect(deadline, false, false, None)).await?
    }
    pub(crate) async fn begin_read(&self, deadline: Instant) -> Result<Transaction> {
        if let Some(result) = lifecycle::begin(self, deadline, true).await {
            return result;
        }
        tokio::time::timeout_at(deadline.into(), self.connect(deadline, false, true, None)).await?
    }
    /// Clock-only private connection. SQLite must never queue a busy worker
    /// beyond the maintenance attempt: its BEGIN IMMEDIATE fails without waiting.
    pub(crate) async fn begin_maintenance(&self, deadline: Instant) -> Result<Transaction> {
        let work = deadline
            .checked_sub(maintenance::CLEANUP_RESERVE)
            .context("maintenance deadline")?;
        tokio::time::timeout_at(
            work.into(),
            self.connect(work, false, false, Some(deadline)),
        )
        .await?
    }
    async fn begin_schema(&self) -> Result<Transaction> {
        let deadline = Instant::now() + Duration::from_secs(60);
        tokio::time::timeout_at(deadline.into(), self.connect(deadline, true, false, None)).await?
    }
    async fn connect(
        &self,
        deadline: Instant,
        exclusive: bool,
        read_only: bool,
        maintenance: Option<Instant>,
    ) -> Result<Transaction> {
        ensure!(
            !lifecycle::RequestScope::active(),
            lifecycle::Unavailable::Closed
        );
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut control = None;
        let backend = match &self.options {
            DatabaseOptions::Sqlite { options, .. } => {
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
                let options = if maintenance.is_some() {
                    options
                        .clone()
                        .busy_timeout(Duration::ZERO)
                        .optimize_on_close(false, None)
                } else {
                    options.clone()
                };
                let mut cx = sqlx::SqliteConnection::connect_with(&options).await?;
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
                if read_only {
                    sqlx::query("PRAGMA query_only = ON")
                        .execute(&mut cx)
                        .await?;
                }
                let begin = sqlx::query(if read_only {
                    "BEGIN DEFERRED"
                } else {
                    "BEGIN IMMEDIATE"
                })
                .execute(&mut cx)
                .await;
                if let Err(error) = begin {
                    if maintenance.is_some() {
                        // Await the SQLx worker's shutdown acknowledgement before
                        // returning a failed lock attempt. No busy query remains.
                        cx.close().await?;
                        #[cfg(test)]
                        let _ = MAINTENANCE_CLOSE_PROBE.try_with(|probe| {
                            probe.store(true, Ordering::Release);
                        });
                    }
                    return Err(if maintenance.is_some() {
                        maintenance::ConnectStopped(error.into()).into()
                    } else {
                        error.into()
                    });
                }
                Backend::Sqlite(cx)
            }
            DatabaseOptions::Postgres(options) => {
                let scope = if maintenance.is_some() {
                    format!("nx-clock-{}", crate::security::random_id()?)
                } else {
                    String::new()
                };
                let options = if maintenance.is_some() {
                    let timeout = maintenance::remaining_ms(deadline)?;
                    options.clone().application_name(&scope).options([
                        ("statement_timeout", format!("{timeout}ms")),
                        ("lock_timeout", "1ms".into()),
                    ])
                } else {
                    options.clone()
                };
                let mut cx = sqlx::PgConnection::connect_with(&options).await?;
                for setting in ["SHOW fsync", "SHOW full_page_writes"] {
                    let value: String = sqlx::query_scalar(setting).fetch_one(&mut cx).await?;
                    ensure!(value == "on", "unsafe PostgreSQL durability");
                }
                sqlx::query("SET synchronous_commit = on")
                    .execute(&mut cx)
                    .await?;
                let statement_timeout = if maintenance.is_some() {
                    format!(
                        "SET statement_timeout = '{}ms'",
                        maintenance::remaining_ms(deadline)?
                    )
                } else if exclusive {
                    "SET statement_timeout = '60s'".into()
                } else {
                    "SET statement_timeout = '1500ms'".into()
                };
                sqlx::query(&statement_timeout).execute(&mut cx).await?;
                sqlx::query(if maintenance.is_some() {
                    "SET lock_timeout = '1ms'"
                } else {
                    "SET lock_timeout = '250ms'"
                })
                .execute(&mut cx)
                .await?;
                sqlx::query(if exclusive {
                    "SET idle_in_transaction_session_timeout = '10s'"
                } else {
                    "SET idle_in_transaction_session_timeout = '3000ms'"
                })
                .execute(&mut cx)
                .await?;
                // Session locks precede BEGIN so waiting never freezes a stale
                // serializable snapshot. Connections are private and close on drop.
                let lock = if exclusive {
                    "SELECT pg_try_advisory_lock(5642817467268123)"
                } else {
                    "SELECT pg_try_advisory_lock_shared(5642817467268123)"
                };
                let acquired: bool = sqlx::query_scalar(lock).fetch_one(&mut cx).await?;
                ensure!(acquired, "application database is busy with maintenance");
                if let Some(overall) = maintenance {
                    control = Some(
                        maintenance::Control::connect(&options, &mut cx, &scope, overall).await?,
                    );
                }
                sqlx::query(if read_only {
                    "BEGIN ISOLATION LEVEL SERIALIZABLE, READ ONLY"
                } else {
                    "BEGIN ISOLATION LEVEL SERIALIZABLE"
                })
                .execute(&mut cx)
                .await?;
                Backend::Postgres(cx)
            }
        };
        let tx = Transaction {
            #[cfg(test)]
            creation_acquired: None,
            backend,
            active: true,
            commit_state: CommitState::NotAttempted,
            read_only,
            cancelled,
            // A clock connection never acquires operator CPU authority, even
            // on SQLite where no PostgreSQL Control object is needed.
            operator_ended: Arc::new(AtomicBool::new(maintenance.is_some())),
            deadline: deadline.into(),
            maintenance: control,
            ordinary: None,
        };
        if maintenance.is_none() {
            let checkpoint: lifecycle::OperatorCheckpoint = tx.operator_checkpoint()?;
            checkpoint.checkpoint()?;
        }
        Ok(tx)
    }

    pub async fn initialize(&self) -> Result<()> {
        ensure!(
            !lifecycle::RequestScope::active(),
            lifecycle::Unavailable::Closed
        );
        let mut tx = self.begin(Instant::now() + Duration::from_secs(10)).await?;
        if tx.storage_tables().await?.is_empty() {
            for sql in SCHEMA
                .iter()
                .chain(blob_layout::TABLE_SQL)
                .chain(search_layout::table_sql(&tx)?)
                .chain(blob_layout::INDEXES.iter().map(|(_, sql)| sql))
                .chain(search_layout::INDEXES.iter().map(|(_, sql)| sql))
            {
                tx.execute(sql, &[]).await?;
            }
            match tx.backend {
                Backend::Closed => unreachable!("closed maintenance transaction"),
                Backend::Sqlite(_) => {
                    tx.execute("CREATE TRIGGER nx_accounts_no_delete BEFORE DELETE ON nx_accounts BEGIN SELECT RAISE(ABORT, 'account identities cannot be deleted'); END", &[]).await?;
                }
                Backend::Postgres(_) => {
                    tx.execute("CREATE FUNCTION nx_reject_identity_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'account identities cannot be deleted'; END $$", &[]).await?;
                    tx.execute("CREATE TRIGGER nx_accounts_no_delete BEFORE DELETE ON nx_accounts FOR EACH ROW EXECUTE FUNCTION nx_reject_identity_delete()", &[]).await?;
                }
            }
            tx.check_blob_layout().await?;
            tx.check_search_layout().await?;
        } else {
            tx.check_storage().await?;
            tx.check_layout().await?;
        }
        tx.commit().await
    }

    /// Recover from a large clock correction with a fresh host-key incarnation.
    /// Stop serving first. Old processes, sessions and forms are retired together
    /// with the credential-seconds reset; receipts and application records are
    /// preserved. Lifecycle milliseconds/version never reset or revive expiry.
    pub async fn recover_clock(&self, keys: &crate::HostKeys) -> Result<()> {
        let mut tx = self
            .begin(Instant::now() + Duration::from_secs(300))
            .await?;
        if matches!(&tx.backend, Backend::Postgres(_)) {
            tx.execute("SET LOCAL statement_timeout = '300s'", &[])
                .await?;
            tx.execute("SET LOCAL idle_in_transaction_session_timeout = '10s'", &[])
                .await?;
        }
        tx.check_storage().await?;
        let rows = tx
            .fetch::<1>(
                "SELECT incarnation FROM nx_deployment WHERE singleton=1",
                &[],
            )
            .await?;
        let old = rows
            .first()
            .ok_or_else(|| anyhow::anyhow!("deployment missing"))?;
        ensure!(
            old[0] != keys.incarnation(),
            "clock recovery requires a fresh host key"
        );
        let now = crate::security::now()?;
        let generation = crate::security::random_id()?;
        tx.execute(
            "UPDATE nx_deployment SET incarnation=$1,generation=$2 WHERE singleton=1",
            &[keys.incarnation().into(), generation.into()],
        )
        .await?;
        tx.execute("DELETE FROM nx_sessions", &[]).await?;
        tx.execute("DELETE FROM nx_invites WHERE redeemed_at IS NULL", &[])
            .await?;
        let changed = tx
            .execute(
                "UPDATE nx_clock SET observed=$1 WHERE singleton=1",
                &[now.into()],
            )
            .await?;
        ensure!(changed == 1, "clock missing");
        tx.commit().await
    }

    /// Bounded operator maintenance. Authenticated expiry remains enforceable
    /// after receipts disappear, including when a persisted clock moves back.
    pub async fn maintain(&self) -> Result<()> {
        let mut tx = self.begin(Instant::now() + Duration::from_secs(2)).await?;
        tx.check_storage().await?;
        let now = crate::security::now()?;
        let now = crate::security::observe_clock(&mut tx, now).await?;
        tx.execute("DELETE FROM nx_receipts WHERE nonce IN (SELECT nonce FROM nx_receipts WHERE expires<$1 ORDER BY expires LIMIT 256)",&[(now-60).into()]).await?;
        tx.execute("DELETE FROM nx_sessions WHERE id IN (SELECT id FROM nx_sessions WHERE expires<$1 ORDER BY expires LIMIT 256)",&[(now-60).into()]).await?;
        tx.commit().await
    }
}

impl Transaction {
    #[cfg(test)]
    pub(crate) async fn snapshot(&mut self) -> Result<Vec<(String, Vec<[String; 1]>)>> {
        let mut tables = Vec::new();
        for &(table, columns) in TABLE_COLUMNS
            .iter()
            .chain(blob_layout::TABLES)
            .chain(search_layout::TABLES)
        {
            let columns = columns
                .iter()
                .map(|(name, _)| format!("CAST({name} AS TEXT)"))
                .collect::<Vec<_>>()
                .join(",");
            let json = match self.backend {
                Backend::Closed => unreachable!("closed maintenance transaction"),
                Backend::Sqlite(_) => format!("json_array({columns})"),
                Backend::Postgres(_) => format!("CAST(json_build_array({columns}) AS TEXT)"),
            };
            let mut rows = self
                .fetch::<1>(&format!("SELECT {json} FROM {table}"), &[])
                .await?;
            rows.sort();
            tables.push((table.into(), rows));
        }
        Ok(tables)
    }

    #[cfg(test)]
    pub(crate) async fn explain(&mut self, query: &str) -> Result<Vec<String>> {
        match &mut self.backend {
            Backend::Closed => unreachable!("closed maintenance transaction"),
            Backend::Sqlite(cx) => Ok(sqlx::query(&format!("EXPLAIN QUERY PLAN {query}"))
                .fetch_all(cx)
                .await?
                .iter()
                .map(|r| r.try_get::<String, _>(3))
                .collect::<std::result::Result<Vec<_>, _>>()?),
            Backend::Postgres(cx) => Ok(sqlx::query(&format!("EXPLAIN {query}"))
                .fetch_all(cx)
                .await?
                .iter()
                .map(|r| r.try_get::<String, _>(0))
                .collect::<std::result::Result<Vec<_>, _>>()?),
        }
    }

    /// Test-only instrumentation. Enable SQLite's scanstatus build flag together
    /// with query-metrics; no raw database handle is exposed to applications.
    #[cfg(all(test, feature = "query-metrics"))]
    pub(crate) async fn examined_rows(&mut self, query: &str) -> Result<i64> {
        match &mut self.backend {
            Backend::Closed => unreachable!("closed maintenance transaction"),
            Backend::Sqlite(cx) => {
                use libsqlite3_sys::*;
                let mut handle = cx.lock_handle().await?;
                let query = std::ffi::CString::new(query)?;
                let mut statement = std::ptr::null_mut();
                // SAFETY: the sqlx lock exclusively owns the live connection;
                // prepare initializes statement, which is finalized on all paths.
                unsafe {
                    ensure!(
                        sqlite3_prepare_v2(
                            handle.as_raw_handle().as_ptr(),
                            query.as_ptr(),
                            -1,
                            &mut statement,
                            std::ptr::null_mut()
                        ) == SQLITE_OK,
                        "prepare benchmark"
                    );
                    let mut result = sqlite3_step(statement);
                    while result == SQLITE_ROW {
                        result = sqlite3_step(statement);
                    }
                    let mut visits = 0_i64;
                    let mut index = 0;
                    loop {
                        let mut count = 0_i64;
                        if sqlite3_stmt_scanstatus(
                            statement,
                            index,
                            SQLITE_SCANSTAT_NVISIT,
                            (&mut count as *mut i64).cast(),
                        ) != 0
                        {
                            break;
                        }
                        visits += count;
                        index += 1;
                    }
                    sqlite3_finalize(statement);
                    ensure!(
                        result == SQLITE_DONE && index > 0,
                        "scanstatus unavailable or benchmark failed"
                    );
                    Ok(visits)
                }
            }
            Backend::Postgres(cx) => {
                let row = sqlx::query(&format!("EXPLAIN (ANALYZE, FORMAT JSON) {query}"))
                    .fetch_one(cx)
                    .await?;
                let value: serde_json::Value = serde_json::from_slice(
                    row.try_get_raw(0)?
                        .as_bytes()
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                )?;
                fn scans(node: &serde_json::Value) -> i64 {
                    let own = if node["Node Type"]
                        .as_str()
                        .is_some_and(|s| s.contains("Scan"))
                    {
                        (node["Actual Rows"].as_f64().unwrap_or(0.0) as i64
                            + node["Rows Removed by Filter"].as_f64().unwrap_or(0.0) as i64)
                            * node["Actual Loops"].as_f64().unwrap_or(1.0) as i64
                    } else {
                        0
                    };
                    own + node["Plans"]
                        .as_array()
                        .map_or(0, |plans| plans.iter().map(scans).sum())
                }
                Ok(scans(&value[0]["Plan"]))
            }
        }
    }

    pub(crate) async fn allocate_creation(&mut self) -> Result<i64> {
        let rows=self.fetch::<1>("UPDATE nx_creation_counter SET value=value+1 WHERE singleton=1 AND value<9223372036854775807 RETURNING CAST(value AS TEXT)", &[]).await?;
        ensure!(rows.len() == 1, "creation sequence exhausted");
        #[cfg(test)]
        {
            self.creation_acquired = Some(Instant::now());
        }
        Ok(rows[0][0].parse()?)
    }

    pub(crate) async fn check_storage(&mut self) -> Result<()> {
        let rows = self.fetch::<2>(
            "SELECT CAST(singleton AS TEXT),CAST(version AS TEXT) FROM nx_storage ORDER BY singleton LIMIT 2",
            &[],
        ).await?;
        ensure!(
            rows.as_slice() == [["1".to_owned(), STORAGE_VERSION.to_string()]],
            "unsupported framework storage version; storage 13 requires an explicit reviewed migration or a new empty database; existing data is unchanged"
        );
        Ok(())
    }

    async fn storage_tables(&mut self) -> Result<Vec<String>> {
        let sql = match self.backend {
            Backend::Closed => unreachable!("closed maintenance transaction"),
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

    async fn check_layout(&mut self) -> Result<()> {
        let trigger = match self.backend {
            Backend::Closed => unreachable!("closed maintenance transaction"),
            Backend::Sqlite(_) => {
                "SELECT name FROM sqlite_schema WHERE type='trigger' AND name='nx_accounts_no_delete' AND tbl_name='nx_accounts'"
            }
            Backend::Postgres(_) => {
                "SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relname='nx_accounts' AND t.tgname='nx_accounts_no_delete' AND t.tgenabled='O'"
            }
        };
        ensure!(
            self.fetch::<1>(trigger, &[]).await?.len() == 1,
            "identity tombstone protection is missing"
        );
        let mut expected: Vec<_> = TABLE_COLUMNS
            .iter()
            .chain(blob_layout::TABLES)
            .chain(search_layout::TABLES)
            .map(|(name, _)| (*name).to_owned())
            .collect();
        expected.sort();
        ensure!(
            self.storage_tables().await? == expected,
            "unsupported or incomplete framework storage schema"
        );
        for &(table, columns) in TABLE_COLUMNS
            .iter()
            .chain(blob_layout::TABLES)
            .chain(search_layout::TABLES)
        {
            let sql = match self.backend {
                Backend::Closed => unreachable!("closed maintenance transaction"),
                Backend::Sqlite(_) => {
                    "SELECT name,upper(type),COALESCE(dflt_value,''),CAST(\"notnull\" AS TEXT) FROM pragma_table_info($1) ORDER BY cid LIMIT 65"
                }
                Backend::Postgres(_) => {
                    "SELECT column_name,upper(data_type),COALESCE(column_default,''),CASE WHEN is_nullable='NO' THEN '1' ELSE '0' END FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 ORDER BY ordinal_position LIMIT 65"
                }
            };
            let actual = self.fetch::<4>(sql, &[table.into()]).await?;
            ensure!(
                actual.len() == columns.len(),
                "unsupported columns in {table}"
            );
            for ([name, kind, default, not_null], &(expected_name, expected_kind)) in
                actual.into_iter().zip(columns)
            {
                // SQLite reports implicit single-column primary keys as nullable.
                // PostgreSQL marks primary keys non-null.
                let implicit_key = expected_name == "singleton"
                    || expected_name == "storage_id"
                    || (matches!(table, "nx_accounts" | "nx_sessions") && expected_name == "id")
                    || (table == "nx_receipts" && expected_name == "nonce")
                    || (table == "nx_invites" && expected_name == "code_hash");
                let expected_not_null = if (matches!(self.backend, Backend::Sqlite(_))
                    && implicit_key)
                    || (table == "nx_accounts"
                        && matches!(expected_name, "login_name" | "password"))
                    || (table == "nx_records" && matches!(expected_name, "owner" | "cap_version"))
                    || (table == "nx_invites"
                        && matches!(expected_name, "redeemed_at" | "redeemed_by"))
                {
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
        self.check_blob_layout().await?;
        self.check_search_layout().await
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
    pub(crate) fn field_expression(&self, field: &str) -> Result<String> {
        ensure!(crate::manifest::identifier(field), "invalid field");
        Ok(match self.backend {
            Backend::Closed => unreachable!("closed maintenance transaction"),
            Backend::Sqlite(_) => format!("json_extract(fields, '$.\"{field}\"')"),
            Backend::Postgres(_) => format!("(fields::jsonb ->> '{field}')"),
        })
    }

    pub(crate) fn bounded_text(&self, column: &str, maximum: usize) -> String {
        // Names and limits come only from trusted code. NULL rejects oversized
        // stored values before their contents cross the SQL driver.
        let size = match self.backend {
            Backend::Closed => unreachable!("closed maintenance transaction"),
            Backend::Sqlite(_) => format!("length(CAST({column} AS BLOB))"),
            Backend::Postgres(_) => format!("octet_length({column})"),
        };
        format!("CASE WHEN {size}<={maximum} THEN {column} ELSE NULL END")
    }
    pub(crate) async fn execute(&mut self, sql: &str, params: &[Param]) -> Result<u64> {
        ensure!(!self.read_only, "read-only transaction");
        self.execute_internal(sql, params).await
    }
    async fn prepare_statement(&mut self) -> Result<()> {
        self.maintenance_timeout().await?;
        self.ordinary_timeout().await?;
        self.ordinary_charge()?;
        Ok(())
    }
    async fn execute_internal(&mut self, sql: &str, params: &[Param]) -> Result<u64> {
        self.prepare_statement().await?;
        self.execute_prepared(sql, params).await
    }
    async fn execute_prepared(&mut self, sql: &str, params: &[Param]) -> Result<u64> {
        self.ordinary_in_flight(true);
        let result = tokio::time::timeout_at(self.deadline, async {
            Ok(match &mut self.backend {
                Backend::Closed => unreachable!("closed maintenance transaction"),
                Backend::Sqlite(cx) => bound_query!(sql, params).execute(cx).await?.rows_affected(),
                Backend::Postgres(cx) => {
                    bound_query!(sql, params).execute(cx).await?.rows_affected()
                }
            })
        })
        .await?;
        if result.is_ok() {
            self.ordinary_in_flight(false);
        }
        result
    }
    // Trusted queries cast selected columns to TEXT, keeping backend conversion
    // rules out of the semantic repository and receipt contracts.
    pub(crate) async fn fetch<const N: usize>(
        &mut self,
        sql: &str,
        params: &[Param],
    ) -> Result<Vec<[String; N]>> {
        self.maintenance_timeout().await?;
        self.ordinary_timeout().await?;
        self.ordinary_charge()?;
        self.ordinary_in_flight(true);
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
        let result = tokio::time::timeout_at(self.deadline, async {
            Ok(match &mut self.backend {
                Backend::Closed => unreachable!("closed maintenance transaction"),
                Backend::Sqlite(cx) => rows!(cx),
                Backend::Postgres(cx) => rows!(cx),
            })
        })
        .await?;
        if result.is_ok() {
            self.ordinary_in_flight(false);
        }
        result
    }
    async fn release_gate(&mut self) -> Result<()> {
        self.maintenance_timeout().await?;
        self.ordinary_timeout().await?;
        self.ordinary_charge()?;
        self.ordinary_in_flight(true);
        let result = if let Backend::Postgres(connection) = &mut self.backend {
            tokio::time::timeout_at(
                self.deadline,
                sqlx::query("SELECT pg_advisory_unlock_all()").execute(connection),
            )
            .await?
            .map(|_| ())
            .map_err(Into::into)
        } else {
            Ok(())
        };
        if result.is_ok() {
            self.ordinary_in_flight(false);
        }
        result
    }

    pub(crate) async fn commit(&mut self) -> Result<()> {
        self.operator_ended.store(true, Ordering::Release);
        ensure!(
            !self.commit_may_have_succeeded(),
            "COMMIT already attempted"
        );
        // Setup/quota refusal is known pre-send. Reserve the actual COMMIT unit
        // synchronously before entering the uncertain transmission frontier.
        self.prepare_statement().await?;
        // Set before polling the provider future: cancellation must conservatively
        // retain this state even if it interrupts transmission or acknowledgement.
        self.commit_state = CommitState::Sent;
        self.ordinary_commit_pending(true);
        if let Err(error) = self.execute_prepared("COMMIT", &[]).await {
            if commit::refused(&self.backend, &error) {
                self.commit_state = CommitState::Refused;
                self.ordinary_commit_pending(false);
                return Err(error);
            }
            return Err(commit::CommitFailure::uncertain(error));
        }
        #[cfg(test)]
        if let Some(started) = self.creation_acquired.take() {
            CREATION_HOLD_MAX.fetch_max(
                started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
        }
        self.active = false;
        #[cfg(test)]
        crate::failure_tests::after_commit()
            .await
            .map_err(commit::CommitFailure::uncertain)?;
        self.commit_state = CommitState::Acknowledged;
        self.ordinary_commit_pending(false);
        if self.ordinary.is_some() {
            // There is no await between observing COMMIT acknowledgement and
            // returning prepared success. Cleanup owns the gate independently.
            lifecycle::drop_transaction(self);
            return Ok(());
        }
        self.release_gate()
            .await
            .map_err(commit::CommitFailure::cleanup)
    }

    pub(crate) fn commit_acknowledged(&self) -> bool {
        self.commit_state == CommitState::Acknowledged
    }
    pub(crate) fn commit_may_have_succeeded(&self) -> bool {
        self.commit_state.may_have_committed()
    }
    pub(crate) async fn rollback(&mut self) -> Result<()> {
        self.operator_ended.store(true, Ordering::Release);
        let cleanup = if self.ordinary.is_some() {
            lifecycle::finish_transaction(self).await
        } else {
            tokio::time::timeout_at(self.deadline, async {
                if self.active {
                    if let Backend::Sqlite(cx) = &mut self.backend {
                        cx.lock_handle().await?.remove_progress_handler();
                    }
                    self.execute_internal("ROLLBACK", &[]).await?;
                    self.active = false;
                }
                self.release_gate().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .map_err(anyhow::Error::from)
            .and_then(|result| result)
        };
        // Preserve the semantic frontier on BOTH successful and failed cleanup.
        // The physical stop result is not evidence that COMMIT did not happen.
        match self.commit_state {
            CommitState::Sent => Err(commit::CommitFailure::uncertain(
                cleanup.err().unwrap_or_else(|| {
                    anyhow::anyhow!("cleanup cannot prove a previously sent COMMIT aborted")
                }),
            )),
            CommitState::Acknowledged => Err(commit::CommitFailure::cleanup(
                cleanup.err().unwrap_or_else(|| {
                    anyhow::anyhow!("ROLLBACK cannot undo an acknowledged COMMIT")
                }),
            )),
            _ => cleanup,
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        self.operator_ended.store(true, Ordering::Release);
        lifecycle::drop_transaction(self);
        // Connections are never returned to a pool with unresolved state.
        // SQLite's worker closes its connection; PostgreSQL disconnect rolls back.
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

pub(crate) fn retryable(error: &anyhow::Error) -> bool {
    if error.is::<commit::CommitFailure>() {
        return false;
    }
    if error.is::<crate::repository::ConditionalConflict>() {
        return true;
    }
    #[cfg(test)]
    if error.is::<crate::failure_tests::Aborted>() {
        return true;
    }
    if error.is::<tokio::time::error::Elapsed>() {
        return true;
    }
    let Some(sqlx::Error::Database(db)) = error.downcast_ref::<sqlx::Error>() else {
        return false;
    };
    matches!(
        db.code().as_deref(),
        Some("40001" | "40P01" | "55P03" | "57014" | "5" | "517")
    )
}

const STORAGE_VERSION: i64 = 13;
const TABLE_COLUMNS: &[(&str, &[(&str, &str)])] = &[
    (
        "nx_resource_catalog",
        &[("storage_id", "BIGINT"), ("resource_key", "TEXT")],
    ),
    (
        "nx_schema_definition",
        &[
            ("singleton", "BIGINT"),
            ("definition", "TEXT"),
            ("history", "TEXT"),
        ],
    ),
    (
        "nx_accounts",
        &[
            ("id", "TEXT"),
            ("login_name", "TEXT"),
            ("password", "TEXT"),
            ("tenant", "TEXT"),
            ("state", "TEXT"),
            ("epoch", "BIGINT"),
        ],
    ),
    (
        "nx_invites",
        &[
            ("code_hash", "TEXT"),
            ("issuer", "TEXT"),
            ("expires", "BIGINT"),
            ("redeemed_at", "BIGINT"),
            ("redeemed_by", "TEXT"),
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
            ("cap_version", "BIGINT"),
            ("created_seq", "BIGINT"),
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
        "nx_creation_counter",
        &[("singleton", "BIGINT"), ("value", "BIGINT")],
    ),
    (
        "nx_clock",
        &[
            ("singleton", "BIGINT"),
            ("observed", "BIGINT"),
            ("lifecycle_ms", "BIGINT"),
            ("lifecycle_version", "BIGINT"),
        ],
    ),
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
    "INSERT INTO nx_storage(singleton,version) VALUES(1,13)",
    "CREATE TABLE IF NOT EXISTS nx_resource_catalog (storage_id BIGINT PRIMARY KEY, resource_key TEXT NOT NULL UNIQUE)",
    "CREATE TABLE IF NOT EXISTS nx_schema_definition (singleton BIGINT PRIMARY KEY CHECK(singleton=1), definition TEXT NOT NULL, history TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_accounts (id TEXT PRIMARY KEY, login_name TEXT UNIQUE, password TEXT, tenant TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','disabled','deleted')), epoch BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_invites (code_hash TEXT PRIMARY KEY, issuer TEXT NOT NULL, expires BIGINT NOT NULL, redeemed_at BIGINT NULL, redeemed_by TEXT NULL REFERENCES nx_accounts(id))",
    "CREATE TABLE IF NOT EXISTS nx_roles (principal TEXT NOT NULL REFERENCES nx_accounts(id), name TEXT NOT NULL, tenant TEXT NOT NULL, PRIMARY KEY(principal,name,tenant))",
    "CREATE TABLE IF NOT EXISTS nx_sessions (id TEXT PRIMARY KEY, principal TEXT NOT NULL REFERENCES nx_accounts(id), epoch BIGINT NOT NULL, expires BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_records (resource BIGINT NOT NULL, id BIGINT NOT NULL, owner TEXT NULL REFERENCES nx_accounts(id), tenant TEXT NOT NULL, fields TEXT NOT NULL, incarnation TEXT NOT NULL, revision BIGINT NOT NULL CHECK(revision>=1), cap_version BIGINT NULL, created_seq BIGINT NOT NULL UNIQUE CHECK(created_seq>0), PRIMARY KEY(resource,id))",
    "CREATE TABLE nx_creation_counter (singleton BIGINT PRIMARY KEY CHECK(singleton=1), value BIGINT NOT NULL CHECK(value>=0))",
    "INSERT INTO nx_creation_counter(singleton,value) VALUES(1,0)",
    "CREATE INDEX nx_records_created ON nx_records(resource,created_seq)",
    "CREATE INDEX IF NOT EXISTS nx_records_owner ON nx_records(resource,owner,created_seq)",
    "CREATE INDEX nx_records_owner_tenant ON nx_records(resource,owner,tenant,created_seq)",
    "CREATE INDEX IF NOT EXISTS nx_records_tenant ON nx_records(resource,tenant,created_seq)",
    "CREATE TABLE IF NOT EXISTS nx_receipts (nonce TEXT PRIMARY KEY, subject TEXT NOT NULL, contract TEXT NOT NULL, action BIGINT NOT NULL, input TEXT NOT NULL, outcome TEXT NOT NULL, expires BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_clock (singleton BIGINT PRIMARY KEY, observed BIGINT NOT NULL, lifecycle_ms BIGINT NOT NULL, lifecycle_version BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_deployment (singleton BIGINT PRIMARY KEY, contract TEXT NOT NULL, incarnation TEXT NOT NULL, generation TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS nx_receipts_expiry ON nx_receipts(expires)",
    "CREATE INDEX IF NOT EXISTS nx_sessions_expiry ON nx_sessions(expires)",
    "INSERT INTO nx_clock(singleton,observed,lifecycle_ms,lifecycle_version) VALUES(1,0,0,0) ON CONFLICT(singleton) DO NOTHING",
];

#[cfg(test)]
mod storage_tests {
    use super::*;

    async fn current_storage_contract(db: Database) {
        db.initialize().await.unwrap();
        db.initialize().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.check_storage().await.unwrap();
        tx.check_layout().await.unwrap();
        tx.rollback().await.unwrap();
        // Unknown formats fail closed rather than attempting a conversion.
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.execute("UPDATE nx_storage SET version=999", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(db.initialize().await.is_err());
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(tx.check_storage().await.is_err());
        assert_eq!(
            tx.fetch::<1>("SELECT CAST(version AS TEXT) FROM nx_storage", &[])
                .await
                .unwrap()[0][0],
            "999"
        );
        tx.execute(
            "UPDATE nx_storage SET version=$1",
            &[STORAGE_VERSION.into()],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        for sql in [
            "DROP TABLE nx_receipts",
            "ALTER TABLE nx_records ADD COLUMN unexpected TEXT",
            "ALTER TABLE nx_records RENAME COLUMN fields TO unexpected",
        ] {
            let mut tx = db
                .begin(Instant::now() + Duration::from_secs(10))
                .await
                .unwrap();
            tx.execute(sql, &[]).await.unwrap();
            assert!(tx.check_layout().await.is_err(), "{sql}");
            tx.rollback().await.unwrap();
        }
        db.initialize().await.unwrap();
    }

    async fn version_four_contract(db: Database) {
        db.initialize().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        tx.check_layout().await.unwrap();
        tx.allocate_creation().await.unwrap();
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES(1,1,NULL,'','{}','layout-test',1,1,(SELECT value FROM nx_creation_counter WHERE singleton=1))", &[]).await.unwrap();
        assert_eq!(tx.fetch::<1>("SELECT CASE WHEN owner IS NULL AND cap_version=1 THEN 'yes' ELSE 'no' END FROM nx_records", &[]).await.unwrap()[0][0], "yes");
        tx.execute("UPDATE nx_storage SET version=3", &[])
            .await
            .unwrap();
        assert!(tx.check_storage().await.is_err());
        tx.rollback().await.unwrap();
        db.initialize().await.unwrap();
    }
    #[tokio::test]
    async fn sqlite_fresh_v4_and_rejected_v3_storage() {
        let temp = tempfile::tempdir().unwrap();
        version_four_contract(Database::sqlite(temp.path().join("v4.db"))).await;
    }
    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
    async fn postgres_fresh_v4_and_rejected_v3_storage() {
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "nx_v4_{}",
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
        version_four_contract(Database::postgres(case.as_str()).unwrap()).await;
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sqlite_current_storage_validation() {
        let dir = tempfile::tempdir().unwrap();
        current_storage_contract(Database::sqlite(dir.path().join("storage.db"))).await;
    }

    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable test cluster"]
    async fn postgres_current_storage_validation() {
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "nx_storage_{}",
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
        current_storage_contract(Database::postgres(case.as_str()).unwrap()).await;
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod application_schema_tests {
    use super::*;
    use crate::schema::{self, Conversion, Migration, MigrationOp};
    use noxide_protocol::{
        Assignment, Change, FieldKind, Fields, Input, Manifest, TextField, Value,
    };

    fn source() -> Manifest {
        crate::test_support::manifest()
    }
    fn target() -> Manifest {
        let mut manifest = source();
        manifest.resources[0].fields[0].kind = FieldKind::Integer {
            min: Some(0),
            max: Some(100),
        };
        manifest.resources[0].fields[0].max_bytes = 20;
        manifest.actions[0].inputs[0].kind = manifest.resources[0].fields[0].kind.clone();
        manifest.actions[0].inputs[0].max_bytes = 20;
        manifest.resources[0].fields.push(TextField {
            immutable: false,
            name: "completed".into(),
            label: "Completed".into(),
            max_bytes: 5,
            kind: FieldKind::Boolean,
            optional: false,
            initial: None,
        });
        manifest.actions[0].inputs.push(Input {
            name: "completed".into(),
            label: "completed".into(),
            kind: FieldKind::Boolean,
            optional: false,
            max_bytes: 5,
        });
        manifest.actions[0].steps[0].assign.push(Assignment {
            field: "completed".into(),
            change: Change::Set(Value::Input("completed".into())),
        });
        manifest
    }
    fn migration() -> Migration {
        Migration {
            version: 1,
            from: schema::digest(&source().resources).unwrap(),
            to: schema::digest(&target().resources).unwrap(),
            operations: vec![
                MigrationOp::ConvertField {
                    resource: "notes".into(),
                    field: "body".into(),
                    conversion: Conversion::TextToInteger,
                },
                MigrationOp::AddField {
                    resource: "notes".into(),
                    field: "completed".into(),
                    value: "false".into(),
                },
            ],
        }
    }
    async fn seed(db: &Database) {
        db.initialize().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.bind_schema(&source()).await.unwrap();
        tx.execute(
            "INSERT INTO nx_accounts(id,password,tenant,state,epoch) VALUES('alice','hash','team','active',1)",
            &[],
        )
        .await
        .unwrap();
        tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'contract','key','original')",&[]).await.unwrap();
        for (id, body) in [(1, "42"), (2, "invalid")] {
            let fields =
                serde_json::to_string(&Fields::from([("body".into(), body.into())])).unwrap();
            tx.allocate_creation().await.unwrap();
            tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES(1,$1,'alice','team',$2,$3,7,(SELECT value FROM nx_creation_counter WHERE singleton=1))",&[id.into(),fields.into(),format!("record-{id}").into()]).await.unwrap();
        }
        tx.commit().await.unwrap();
    }
    async fn contract(db: Database) {
        seed(&db).await;
        // The first row converts successfully; failure on the second must undo it.
        assert!(db.schema_apply(&target(), &migration()).await.is_err());
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            tx.row_fields(1, 1).await.unwrap(),
            Fields::from([("body".into(), "42".into())])
        );
        assert_eq!(
            tx.schema_definition().await.unwrap().unwrap().0,
            schema::normalized(&source().resources)
        );
        assert_eq!(
            tx.fetch::<1>(
                "SELECT generation FROM nx_deployment WHERE singleton=1",
                &[]
            )
            .await
            .unwrap()[0][0],
            "original"
        );
        tx.execute(
            "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=2",
            &[r#"{"body":"84"}"#.into()],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        db.schema_check(&target(), &migration()).await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!tx.row_fields(1, 1).await.unwrap().contains_key("completed"));
        tx.rollback().await.unwrap();
        db.schema_apply(&target(), &migration()).await.unwrap();
        // A lost acknowledgement can be retried without another mutation/fence.
        db.schema_apply(&target(), &migration()).await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            tx.row_fields(1, 1).await.unwrap(),
            Fields::from([
                ("body".into(), "42".into()),
                ("completed".into(), "false".into())
            ])
        );
        assert_eq!(tx.fetch::<4>("SELECT owner,tenant,incarnation,CAST(revision AS TEXT) FROM nx_records WHERE resource=1 AND id=1",&[]).await.unwrap()[0],["alice","team","record-1","7"]);
        assert_ne!(
            tx.fetch::<1>(
                "SELECT generation FROM nx_deployment WHERE singleton=1",
                &[]
            )
            .await
            .unwrap()[0][0],
            "original"
        );
        assert!(tx.bind_schema(&source()).await.is_err());
        let mut reordered = target();
        reordered.resources[0].id = 901;
        reordered.resources[0].fields.reverse();
        reordered.resources[0].fields[0].label = "New label".into();
        for op in &mut reordered.operations {
            op.resource = 901;
        }
        reordered.routes[1].resource = Some(901);
        tx.bind_schema(&reordered).await.unwrap();
        assert_eq!(tx.storage_resource(&reordered, 901).await.unwrap(), 1);
        tx.rollback().await.unwrap();
    }
    #[tokio::test]
    async fn sqlite_application_schema_atomicity_and_identity() {
        let dir = tempfile::tempdir().unwrap();
        contract(Database::sqlite(dir.path().join("schema.db"))).await;
    }
    #[tokio::test]
    async fn sqlite_schema_change_requires_explicit_operations() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::sqlite(dir.path().join("explicit.db"));
        seed(&db).await;
        let mut incomplete = migration();
        incomplete.operations.pop();
        assert!(db.schema_apply(&target(), &incomplete).await.is_err());
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            tx.schema_definition().await.unwrap().unwrap().0,
            schema::normalized(&source().resources)
        );
        tx.rollback().await.unwrap();
    }
    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable test cluster"]
    async fn postgres_application_schema_atomicity_and_identity() {
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "nx_schema_{}",
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
        contract(Database::postgres(case.as_str()).unwrap()).await;
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod creation_tests {
    use super::*;
    async fn fresh_postgres() -> Database {
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "nx_sequence_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&url).unwrap();
        url.set_path(&name);
        Database::postgres(url.as_str()).unwrap()
    }
    async fn rollback_case(db: Database) {
        db.initialize().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(tx.allocate_creation().await.unwrap(), 1);
        tx.rollback().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(tx.allocate_creation().await.unwrap(), 1);
        tx.commit().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(tx.allocate_creation().await.unwrap(), 2);
        tx.execute(
            "UPDATE nx_creation_counter SET value=9223372036854775807",
            &[],
        )
        .await
        .unwrap();
        assert!(tx.allocate_creation().await.is_err());
        tx.rollback().await.unwrap();
        db.initialize().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(tx.allocate_creation().await.unwrap(), 2);
        tx.rollback().await.unwrap();
    }
    #[tokio::test]
    async fn sqlite_creation_counter_rolls_back_and_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        rollback_case(Database::sqlite(tmp.path().join("counter.db"))).await;
    }
    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES"]
    async fn postgres_creation_counter_rollback_serialization_and_lock_timeout() {
        rollback_case(fresh_postgres().await).await;
        let db = fresh_postgres().await;
        db.initialize().await.unwrap();
        let mut first = db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(first.allocate_creation().await.unwrap(), 1);
        let mut second = db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            second
                .fetch::<1>("SELECT CAST(value AS TEXT) FROM nx_creation_counter", &[])
                .await
                .unwrap()[0][0],
            "0"
        );
        // A conflicting writer cannot pass the held counter lock.
        let error = second.allocate_creation().await.unwrap_err();
        assert!(format!("{error:#}").contains("lock timeout"), "{error:#}");
        second.rollback().await.unwrap();
        let mut stale = db
            .begin(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        stale
            .fetch::<1>("SELECT CAST(value AS TEXT) FROM nx_creation_counter", &[])
            .await
            .unwrap();
        first.commit().await.unwrap();
        let error = stale.allocate_creation().await.unwrap_err();
        assert!(format!("{error:#}").contains("serialize"), "{error:#}");
        stale.rollback().await.unwrap();
        let mut retry = db
            .begin(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(retry.allocate_creation().await.unwrap(), 2);
        retry.commit().await.unwrap();
    }
    // Manual evidence collection, not a latency-sensitive CI assertion. Includes
    // transaction setup, allocation, insertion across two resources, and commit.
    async fn benchmark(db: Database) {
        db.initialize().await.unwrap();
        for concurrency in [1usize, 4, 16] {
            let start = Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            for worker in 0..concurrency {
                let db = db.clone();
                tasks.spawn(async move {
                let mut samples=Vec::new();let mut failures=0;
                for index in 0..20 {let started=Instant::now();let result=async {
                    let mut tx=db.begin(Instant::now()+Duration::from_secs(3)).await?;
                    let lock=Instant::now();let sequence=tx.allocate_creation().await?;
                    let acquired=Instant::now();
                    tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,NULL,'','{}','benchmark',1,$3)",&[((worker%2+1) as i64).into(),((worker*20+index+1+concurrency*1000) as i64).into(),sequence.into()]).await?;
                    tx.commit().await?;
                    anyhow::Ok((started.elapsed(),lock.elapsed(),acquired.elapsed()))
                }.await;match result {Ok(sample)=>samples.push(sample),Err(_)=>failures+=1};}
                (samples,failures)
            });
            }
            let mut samples = Vec::new();
            let mut failures = 0;
            while let Some(result) = tasks.join_next().await {
                let (batch, failed) = result.unwrap();
                samples.extend(batch);
                failures += failed;
            }
            samples.sort_by_key(|x| x.0);
            let n = samples.len();
            assert!(n > 0);
            eprintln!(
                "creation concurrency={concurrency} committed={n} failures={failures} throughput={:.1}/s p50={:?} p95={:?} p99={:?} max_counter_wait_and_hold={:?} max_hold={:?}",
                n as f64 / start.elapsed().as_secs_f64(),
                samples[n / 2].0,
                samples[(n - 1) * 95 / 100].0,
                samples[(n - 1) * 99 / 100].0,
                samples.iter().map(|x| x.1).max(),
                samples.iter().map(|x| x.2).max()
            );
        }
    }
    #[tokio::test]
    #[ignore = "manual contention benchmark"]
    async fn sqlite_creation_contention_benchmark() {
        let tmp = tempfile::tempdir().unwrap();
        benchmark(Database::sqlite(tmp.path().join("bench.db"))).await;
    }
    #[tokio::test]
    #[ignore = "manual contention benchmark; requires NOXIDE_TEST_POSTGRES"]
    async fn postgres_creation_contention_benchmark() {
        benchmark(fresh_postgres().await).await;
    }
}
