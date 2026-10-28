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
        tokio::time::timeout_at(deadline.into(), self.connect(deadline, false)).await?
    }
    async fn begin_schema(&self) -> Result<Transaction> {
        let deadline = Instant::now() + Duration::from_secs(60);
        tokio::time::timeout_at(deadline.into(), self.connect(deadline, true)).await?
    }
    async fn connect(&self, deadline: Instant, exclusive: bool) -> Result<Transaction> {
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
                sqlx::query(if exclusive {
                    "SET statement_timeout = '60s'"
                } else {
                    "SET statement_timeout = '1500ms'"
                })
                .execute(&mut cx)
                .await?;
                sqlx::query("SET lock_timeout = '250ms'")
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
            tx.check_layout(STORAGE_VERSION).await?;
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

    /// Recover from a large clock correction with a fresh host-key incarnation.
    /// Stop serving first. Old processes, sessions and forms are retired together
    /// with the clock reset; receipts and application records are preserved.
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

    async fn check_layout(&mut self, version: i64) -> Result<()> {
        let mut expected: Vec<_> = TABLE_COLUMNS
            .iter()
            .filter(|(name, _)| {
                (version >= 2 || *name != "nx_storage")
                    && (version >= 3
                        || !matches!(*name, "nx_resource_catalog" | "nx_schema_definition"))
            })
            .map(|(name, _)| (*name).to_owned())
            .collect();
        expected.sort();
        ensure!(
            self.storage_tables().await? == expected,
            "unsupported or incomplete framework storage schema"
        );
        for &(table, columns) in TABLE_COLUMNS {
            if (table == "nx_storage" && version < 2)
                || (version < 3 && matches!(table, "nx_resource_catalog" | "nx_schema_definition"))
            {
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
            let columns = if table == "nx_records" && version < 2 {
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
                    || expected_name == "storage_id"
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
            let rows = self.fetch::<2>("SELECT CAST(singleton AS TEXT),CAST(version AS TEXT) FROM nx_storage ORDER BY singleton LIMIT 2", &[]).await?;
            ensure!(
                rows.len() == 1 && rows[0][0] == "1",
                "invalid storage version row"
            );
            let version = rows[0][1].parse::<i64>()?;
            ensure!(
                matches!(version, 2 | 3),
                "unsupported framework storage version"
            );
            self.check_layout(version).await?;
            if version == 2 {
                self.migrate_catalog().await?;
            }
            return self.check_storage().await;
        }
        self.check_layout(1).await?;
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
            &[2i64.into()],
        )
        .await?;
        self.migrate_catalog().await?;
        self.check_layout(STORAGE_VERSION).await?;
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
    async fn release_gate(&mut self) -> Result<()> {
        if let Backend::Postgres(connection) = &mut self.backend {
            // A completed transaction must release its session lock before its
            // caller starts another transaction, even if this handle stays alive.
            tokio::time::timeout(
                Duration::from_millis(500),
                sqlx::query("SELECT pg_advisory_unlock_all()").execute(connection),
            )
            .await??;
        }
        Ok(())
    }
    pub(crate) async fn commit(&mut self) -> Result<()> {
        self.execute("COMMIT", &[]).await?;
        self.active = false;
        self.release_gate().await?;
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
            self.release_gate().await?;
            Ok(())
        })
        .await?
    }
}

impl Database {
    /// Establish the approved legacy resource keys without reidentifying records.
    /// The supplied legacy contract must match the digest already stored by v2.
    pub async fn import_schema(&self, manifest: &noxide_protocol::Manifest) -> Result<()> {
        crate::manifest::validate(manifest)?;
        let mut tx = self.begin_schema().await?;
        tx.check_storage().await?;
        let result = tx.import_schema(manifest).await;
        match result {
            Ok(()) => tx.commit().await,
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        }
    }

    /// Rehearse the full transition with real data, then roll back every write.
    pub async fn schema_check(
        &self,
        target: &noxide_protocol::Manifest,
        migration: &crate::schema::Migration,
    ) -> Result<()> {
        crate::manifest::validate(target)?;
        let mut tx = self.begin_schema().await?;
        tx.check_storage().await?;
        let result = tx.apply_schema(target, migration).await;
        tx.rollback().await?;
        result
    }

    /// Apply a bounded declarative transition while application requests are fenced.
    pub async fn schema_apply(
        &self,
        target: &noxide_protocol::Manifest,
        migration: &crate::schema::Migration,
    ) -> Result<()> {
        crate::manifest::validate(target)?;
        let mut tx = self.begin_schema().await?;
        tx.check_storage().await?;
        let result = tx.apply_schema(target, migration).await;
        match result {
            Ok(()) => tx.commit().await,
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        }
    }
}

impl Transaction {
    async fn migrate_catalog(&mut self) -> Result<()> {
        self.execute("CREATE TABLE nx_resource_catalog (storage_id BIGINT PRIMARY KEY, resource_key TEXT NOT NULL UNIQUE)", &[]).await?;
        self.execute("CREATE TABLE nx_schema_definition (singleton BIGINT PRIMARY KEY CHECK(singleton=1), definition TEXT NOT NULL, history TEXT NOT NULL)", &[]).await?;
        self.execute("UPDATE nx_storage SET version=3 WHERE singleton=1", &[])
            .await?;
        self.execute(
            "UPDATE nx_deployment SET generation=$1",
            &[crate::security::random_id()?.into()],
        )
        .await?;
        Ok(())
    }

    async fn schema_definition(
        &mut self,
    ) -> Result<
        Option<(
            Vec<noxide_protocol::Resource>,
            Vec<crate::schema::AppliedMigration>,
        )>,
    > {
        let definition = self.bounded_text("definition", noxide_protocol::MAX_MANIFEST_BYTES);
        let history = self.bounded_text("history", 32_768);
        let rows = self
            .fetch::<2>(
                &format!(
                    "SELECT {definition},{history} FROM nx_schema_definition WHERE singleton=1"
                ),
                &[],
            )
            .await?;
        rows.first()
            .map(|[definition, history]| {
                Ok((
                    serde_json::from_str(definition)?,
                    serde_json::from_str(history)?,
                ))
            })
            .transpose()
    }

    async fn store_schema(
        &mut self,
        resources: &[noxide_protocol::Resource],
        history: &[crate::schema::AppliedMigration],
    ) -> Result<()> {
        let resources = crate::schema::normalized(resources);
        let definition = serde_json::to_string(&resources)?;
        let history = serde_json::to_string(history)?;
        ensure!(
            definition.len() <= noxide_protocol::MAX_MANIFEST_BYTES && history.len() <= 32_768,
            "stored schema history limit"
        );
        let hash = crate::schema::digest(&resources)?;
        self.execute("INSERT INTO nx_schema(singleton,digest) VALUES(1,$1) ON CONFLICT(singleton) DO UPDATE SET digest=excluded.digest", &[hash.into()]).await?;
        self.execute("INSERT INTO nx_schema_definition(singleton,definition,history) VALUES(1,$1,$2) ON CONFLICT(singleton) DO UPDATE SET definition=excluded.definition,history=excluded.history", &[definition.into(),history.into()]).await?;
        Ok(())
    }

    async fn next_storage_id(&mut self) -> Result<i64> {
        let rows = self
            .fetch::<1>(
                "SELECT CAST(COALESCE(MAX(storage_id),0) AS TEXT) FROM nx_resource_catalog",
                &[],
            )
            .await?;
        rows[0][0]
            .parse::<i64>()?
            .checked_add(1)
            .context("resource identity exhausted")
    }

    pub(crate) async fn storage_resource(
        &mut self,
        manifest: &noxide_protocol::Manifest,
        bundle_resource: u32,
    ) -> Result<i64> {
        let key = &crate::manifest::resource(manifest, bundle_resource)?.name;
        self.storage_key(key).await
    }

    async fn storage_key(&mut self, key: &str) -> Result<i64> {
        let rows = self
            .fetch::<1>(
                "SELECT CAST(storage_id AS TEXT) FROM nx_resource_catalog WHERE resource_key=$1",
                &[key.into()],
            )
            .await?;
        rows.first().context("resource schema is not bound")?[0]
            .parse::<i64>()
            .map_err(Into::into)
    }

    pub(crate) async fn bind_schema(&mut self, manifest: &noxide_protocol::Manifest) -> Result<()> {
        let hash = crate::schema::digest(&manifest.resources)?;
        if let Some((resources, _)) = self.schema_definition().await? {
            ensure!(
                crate::schema::digest(&resources)? == hash,
                "stored schema differs from approved resource contract; an explicit migration is required"
            );
            for resource in &manifest.resources {
                self.storage_resource(manifest, resource.id).await?;
            }
            return Ok(());
        }
        ensure!(
            self.fetch::<1>("SELECT digest FROM nx_schema WHERE singleton=1", &[])
                .await?
                .is_empty(),
            "legacy resource schema requires explicit approved schema import"
        );
        ensure!(
            self.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
                .await?[0][0]
                == "0",
            "unbound records require explicit schema import"
        );
        for resource in crate::schema::normalized(&manifest.resources) {
            let id = self.next_storage_id().await?;
            self.execute(
                "INSERT INTO nx_resource_catalog(storage_id,resource_key) VALUES($1,$2)",
                &[id.into(), resource.name.into()],
            )
            .await?;
        }
        self.store_schema(&manifest.resources, &[]).await
    }

    async fn import_schema(&mut self, manifest: &noxide_protocol::Manifest) -> Result<()> {
        ensure!(
            self.schema_definition().await?.is_none(),
            "schema was already imported"
        );
        let hashes = [
            crate::schema::hash(&serde_json::to_vec(&manifest.resources)?),
            {
                // v2 TextField predated kind/optional. Only exact legacy text fields
                // may use its serialization, never a newly typed schema.
                ensure!(
                    manifest
                        .resources
                        .iter()
                        .flat_map(|r| &r.fields)
                        .all(|f| f.kind == noxide_protocol::FieldKind::Text && !f.optional),
                    "legacy import requires the original text schema"
                );
                #[derive(serde::Serialize)]
                struct LegacyField<'a> {
                    name: &'a str,
                    label: &'a str,
                    max_bytes: u32,
                }
                #[derive(serde::Serialize)]
                struct LegacyResource<'a> {
                    id: u32,
                    name: &'a str,
                    fields: Vec<LegacyField<'a>>,
                }
                let legacy: Vec<_> = manifest
                    .resources
                    .iter()
                    .map(|r| LegacyResource {
                        id: r.id,
                        name: &r.name,
                        fields: r
                            .fields
                            .iter()
                            .map(|f| LegacyField {
                                name: &f.name,
                                label: &f.label,
                                max_bytes: f.max_bytes,
                            })
                            .collect(),
                    })
                    .collect();
                crate::schema::hash(&serde_json::to_vec(&legacy)?)
            },
        ];
        let stored = self
            .fetch::<1>("SELECT digest FROM nx_schema WHERE singleton=1", &[])
            .await?;
        ensure!(
            stored.len() == 1 && hashes.contains(&stored[0][0]),
            "legacy contract does not match stored schema digest"
        );
        ensure!(
            self.fetch::<1>(
                "SELECT CAST(COUNT(*) AS TEXT) FROM nx_resource_catalog",
                &[]
            )
            .await?[0][0]
                == "0",
            "legacy catalog is not empty"
        );
        for resource in &manifest.resources {
            self.execute(
                "INSERT INTO nx_resource_catalog(storage_id,resource_key) VALUES($1,$2)",
                &[i64::from(resource.id).into(), resource.name.as_str().into()],
            )
            .await?;
        }
        let unknown = self.fetch::<1>("SELECT CAST(resource AS TEXT) FROM nx_records WHERE resource NOT IN (SELECT storage_id FROM nx_resource_catalog) LIMIT 1", &[]).await?;
        ensure!(
            unknown.is_empty(),
            "legacy records contain undeclared resource identities"
        );
        // v2 accepted CR and CRLF verbatim through the host API. Validate
        // against that contract before adopting the current text encoding.
        for resource in &manifest.resources {
            let storage = self.storage_key(&resource.name).await?;
            self.transform_records(storage, |fields| {
                ensure!(
                    fields.len() == resource.fields.len(),
                    "unexpected legacy fields"
                );
                for field in &resource.fields {
                    let value = fields
                        .get_mut(&field.name)
                        .context("missing legacy field")?;
                    ensure!(
                        !value.trim().is_empty() && value.len() <= field.max_bytes as usize,
                        "invalid legacy field length"
                    );
                    ensure!(
                        !value
                            .chars()
                            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
                        "invalid legacy field text"
                    );
                    *value = field.canonical(value).map_err(anyhow::Error::msg)?;
                }
                crate::manifest::validate_fields(resource, fields)
            })
            .await?;
        }
        self.store_schema(&manifest.resources, &[]).await?;
        self.execute(
            "UPDATE nx_deployment SET generation=$1",
            &[crate::security::random_id()?.into()],
        )
        .await?;
        Ok(())
    }

    async fn row_fields(&mut self, storage: i64, id: i64) -> Result<noxide_protocol::Fields> {
        let value = self.bounded_text("fields", 32_768);
        let rows = self
            .fetch::<1>(
                &format!("SELECT {value} FROM nx_records WHERE resource=$1 AND id=$2"),
                &[storage.into(), id.into()],
            )
            .await?;
        serde_json::from_str(
            &rows
                .first()
                .context("record disappeared during migration")?[0],
        )
        .map_err(Into::into)
    }

    async fn transform_records(
        &mut self,
        storage: i64,
        mut transform: impl FnMut(&mut noxide_protocol::Fields) -> Result<()>,
    ) -> Result<()> {
        let mut cursor = 0i64;
        loop {
            // Page only identities, then fetch each bounded record. Even a full
            // page of maximum-sized records never accumulates in host memory.
            let rows = self.fetch::<1>("SELECT CAST(id AS TEXT) FROM nx_records WHERE resource=$1 AND id>$2 ORDER BY nx_records.id LIMIT 64", &[storage.into(),cursor.into()]).await?;
            if rows.is_empty() {
                break;
            }
            for [id] in rows {
                let id = id.parse::<i64>()?;
                let mut fields = self.row_fields(storage, id).await?;
                transform(&mut fields)?;
                let value = serde_json::to_string(&fields)?;
                ensure!(value.len() <= 32_768, "migrated record limit");
                self.execute(
                    "UPDATE nx_records SET fields=$3 WHERE resource=$1 AND id=$2",
                    &[storage.into(), id.into(), value.into()],
                )
                .await?;
                cursor = id;
            }
        }
        Ok(())
    }

    async fn validate_stored_resources(
        &mut self,
        resources: &[noxide_protocol::Resource],
    ) -> Result<()> {
        for resource in resources {
            let storage = self.storage_key(&resource.name).await?;
            self.transform_records(storage, |fields| {
                crate::manifest::validate_fields(resource, fields)
            })
            .await?;
        }
        Ok(())
    }

    async fn apply_schema(
        &mut self,
        target: &noxide_protocol::Manifest,
        migration: &crate::schema::Migration,
    ) -> Result<()> {
        use crate::schema::{self, Conversion, MigrationOp};
        let migration_digest = migration.validate()?;
        let (source, mut history) = self
            .schema_definition()
            .await?
            .context("schema must be bound or imported before migration")?;
        let current = schema::digest(&source)?;
        ensure!(
            schema::digest(&target.resources)? == migration.to,
            "migration target differs from approved bundle schema"
        );
        if current == migration.to
            && history
                .last()
                .is_some_and(|last| last.digest == migration_digest)
        {
            return Ok(());
        }
        ensure!(
            current == migration.from,
            "migration predecessor does not match stored schema"
        );
        ensure!(history.len() < 128, "migration history limit");
        schema::transition(&source, &target.resources, &migration.operations)?;
        for op in &migration.operations {
            match op {
                MigrationOp::AddResource { resource } => {
                    let id = self.next_storage_id().await?;
                    self.execute(
                        "INSERT INTO nx_resource_catalog(storage_id,resource_key) VALUES($1,$2)",
                        &[id.into(), resource.as_str().into()],
                    )
                    .await?;
                }
                MigrationOp::DropResource { resource } => {
                    let id = self.storage_key(resource).await?;
                    self.execute("DELETE FROM nx_records WHERE resource=$1", &[id.into()])
                        .await?;
                    self.execute(
                        "UPDATE nx_resource_catalog SET resource_key=$2 WHERE storage_id=$1",
                        &[id.into(), format!("__retired_{id}").into()],
                    )
                    .await?;
                }
                MigrationOp::RenameResource { from, to } => {
                    self.execute(
                        "UPDATE nx_resource_catalog SET resource_key=$2 WHERE resource_key=$1",
                        &[from.as_str().into(), to.as_str().into()],
                    )
                    .await?;
                }
                MigrationOp::AddField {
                    resource,
                    field,
                    value,
                } => {
                    let id = self.storage_key(resource).await?;
                    let declaration =
                        schema::field(schema::resource(&target.resources, resource)?, field)?;
                    let value = declaration.canonical(value).map_err(anyhow::Error::msg)?;
                    self.transform_records(id, |fields| {
                        ensure!(
                            fields.insert(field.clone(), value.clone()).is_none(),
                            "stored field already exists"
                        );
                        Ok(())
                    })
                    .await?;
                }
                MigrationOp::DropField { resource, field } => {
                    let id = self.storage_key(resource).await?;
                    self.transform_records(id, |fields| {
                        ensure!(fields.remove(field).is_some(), "stored field is missing");
                        Ok(())
                    })
                    .await?;
                }
                MigrationOp::RenameField { resource, from, to } => {
                    let id = self.storage_key(resource).await?;
                    self.transform_records(id, |fields| {
                        let value = fields.remove(from).context("stored field is missing")?;
                        ensure!(
                            fields.insert(to.clone(), value).is_none(),
                            "stored destination field exists"
                        );
                        Ok(())
                    })
                    .await?;
                }
                MigrationOp::ConvertField {
                    resource,
                    field,
                    conversion,
                } => {
                    let id = self.storage_key(resource).await?;
                    let destination =
                        schema::field(schema::resource(&target.resources, resource)?, field)?;
                    self.transform_records(id, |fields| {
                        let value = fields.get_mut(field).context("stored field is missing")?;
                        if !(value.is_empty() && destination.optional) {
                            *value = match conversion {
                                Conversion::TextToInteger => value
                                    .parse::<i64>()
                                    .context("text cannot be converted losslessly to integer")?
                                    .to_string(),
                                Conversion::IntegerToText => value
                                    .parse::<i64>()
                                    .context("invalid stored integer")?
                                    .to_string(),
                            };
                        }
                        destination.canonical(value).map_err(anyhow::Error::msg)?;
                        Ok(())
                    })
                    .await?;
                }
                MigrationOp::MapChoices {
                    resource,
                    field,
                    mapping,
                } => {
                    let id = self.storage_key(resource).await?;
                    self.transform_records(id, |fields| {
                        let value = fields.get_mut(field).context("stored field is missing")?;
                        if let Some(mapped) = mapping.get(value) {
                            *value = mapped.clone();
                        }
                        Ok(())
                    })
                    .await?;
                }
                MigrationOp::ChangeField { .. } => {}
            }
        }
        self.validate_stored_resources(&target.resources).await?;
        history.push(schema::AppliedMigration {
            from: migration.from.clone(),
            to: migration.to.clone(),
            digest: migration_digest,
        });
        self.store_schema(&target.resources, &history).await?;
        self.execute(
            "UPDATE nx_deployment SET generation=$1",
            &[crate::security::random_id()?.into()],
        )
        .await?;
        Ok(())
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

const STORAGE_VERSION: i64 = 3;
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
    "INSERT INTO nx_storage(singleton,version) VALUES(1,3)",
    "CREATE TABLE IF NOT EXISTS nx_resource_catalog (storage_id BIGINT PRIMARY KEY, resource_key TEXT NOT NULL UNIQUE)",
    "CREATE TABLE IF NOT EXISTS nx_schema_definition (singleton BIGINT PRIMARY KEY CHECK(singleton=1), definition TEXT NOT NULL, history TEXT NOT NULL)",
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
            if sql.contains("nx_storage")
                || sql.contains("nx_resource_catalog")
                || sql.contains("nx_schema_definition")
            {
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

#[cfg(test)]
mod application_schema_tests {
    use super::*;
    use crate::schema::{self, Conversion, Migration, MigrationOp};
    use noxide_protocol::{FieldKind, Fields, Manifest, TextField};

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
        manifest.resources[0].fields.push(TextField {
            name: "completed".into(),
            label: "Completed".into(),
            max_bytes: 5,
            kind: FieldKind::Boolean,
            optional: false,
        });
        manifest.actions[0].fields.push("completed".into());
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
            "INSERT INTO nx_accounts(id,password,tenant,epoch) VALUES('alice','hash','team',1)",
            &[],
        )
        .await
        .unwrap();
        tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'contract','key','original')",&[]).await.unwrap();
        for (id, body) in [(1, "42"), (2, "invalid")] {
            let fields =
                serde_json::to_string(&Fields::from([("body".into(), body.into())])).unwrap();
            tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision) VALUES(1,$1,'alice','team',$2,$3,7)",&[id.into(),fields.into(),format!("record-{id}").into()]).await.unwrap();
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
    async fn sqlite_version_two_requires_approved_schema_import() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::sqlite(dir.path().join("legacy-schema.db"));
        db.initialize().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.execute("DROP TABLE nx_resource_catalog", &[])
            .await
            .unwrap();
        tx.execute("DROP TABLE nx_schema_definition", &[])
            .await
            .unwrap();
        tx.execute("UPDATE nx_storage SET version=2", &[])
            .await
            .unwrap();
        let bytes=br#"[{"id":1,"name":"notes","fields":[{"name":"body","label":"Note","max_bytes":4096}]}]"#;
        tx.execute(
            "INSERT INTO nx_schema(singleton,digest) VALUES(1,$1)",
            &[schema::hash(bytes).into()],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert!(db.initialize().await.is_err());
        db.migrate().await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(tx.bind_schema(&source()).await.is_err());
        tx.rollback().await.unwrap();
        let mut wrong = source();
        wrong.resources[0].id = 2;
        assert!(db.import_schema(&wrong).await.is_err());
        db.import_schema(&source()).await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.bind_schema(&source()).await.unwrap();
        assert_eq!(tx.storage_resource(&source(), 1).await.unwrap(), 1);
        tx.rollback().await.unwrap();
    }

    async fn legacy_text_import_contract(db: Database) {
        use noxide_protocol::Fields;
        db.initialize().await.unwrap();
        let legacy = br#"[{"id":1,"name":"notes","fields":[{"name":"body","label":"Note","max_bytes":4096}]}]"#;
        let digest = schema::hash(legacy);
        let original = "first\r\nsecond\rthird\tend";
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.execute(
            "INSERT INTO nx_schema(singleton,digest) VALUES(1,$1)",
            &[digest.as_str().into()],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO nx_accounts(id,password,tenant,epoch) VALUES('alice','hash','team',1)",
            &[],
        )
        .await
        .unwrap();
        tx.execute("INSERT INTO nx_deployment(singleton,contract,incarnation,generation) VALUES(1,'contract','key','original')", &[]).await.unwrap();
        for id in [1i64, 2] {
            let fields =
                serde_json::to_string(&Fields::from([("body".into(), original.into())])).unwrap();
            tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision) VALUES(1,$1,'alice','team',$2,$3,7)", &[id.into(), fields.into(), format!("record-{id}").into()]).await.unwrap();
        }
        tx.commit().await.unwrap();
        // Each failure occurs after the first row has already been normalized.
        for invalid in [
            Fields::from([("body".into(), " \r\n\t".into())]),
            Fields::from([("body".into(), "x".repeat(4097))]),
            Fields::from([("body".into(), "bad\u{0001}".into())]),
            Fields::from([("wrong".into(), "text".into())]),
            Fields::from([
                ("body".into(), "text".into()),
                ("extra".into(), "text".into()),
            ]),
        ] {
            let mut tx = db
                .begin(Instant::now() + Duration::from_secs(10))
                .await
                .unwrap();
            tx.execute(
                "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=2",
                &[serde_json::to_string(&invalid).unwrap().into()],
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            assert!(db.import_schema(&source()).await.is_err());
            let mut tx = db
                .begin(Instant::now() + Duration::from_secs(10))
                .await
                .unwrap();
            assert_eq!(tx.row_fields(1, 1).await.unwrap()["body"], original);
            assert_eq!(tx.row_fields(1, 2).await.unwrap(), invalid);
            assert!(tx.schema_definition().await.unwrap().is_none());
            assert_eq!(
                tx.fetch::<1>(
                    "SELECT CAST(COUNT(*) AS TEXT) FROM nx_resource_catalog",
                    &[]
                )
                .await
                .unwrap()[0][0],
                "0"
            );
            assert_eq!(
                tx.fetch::<1>("SELECT digest FROM nx_schema WHERE singleton=1", &[])
                    .await
                    .unwrap()[0][0],
                digest
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
            for id in [1i64, 2] {
                assert_eq!(tx.fetch::<4>("SELECT owner,tenant,incarnation,CAST(revision AS TEXT) FROM nx_records WHERE resource=1 AND id=$1", &[id.into()]).await.unwrap()[0], ["alice".into(), "team".into(), format!("record-{id}"), "7".into()]);
            }
            tx.rollback().await.unwrap();
        }
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        tx.execute(
            "UPDATE nx_records SET fields=$1 WHERE resource=1 AND id=2",
            &[serde_json::to_string(&Fields::from([(
                "body".into(),
                "other\r\nline\r\tend".into(),
            )]))
            .unwrap()
            .into()],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        db.import_schema(&source()).await.unwrap();
        let mut tx = db
            .begin(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            tx.row_fields(1, 1).await.unwrap()["body"],
            "first\nsecond\nthird\tend"
        );
        assert_eq!(
            tx.row_fields(1, 2).await.unwrap()["body"],
            "other\nline\n\tend"
        );
        assert_eq!(tx.storage_resource(&source(), 1).await.unwrap(), 1);
        let (resources, history) = tx.schema_definition().await.unwrap().unwrap();
        assert_eq!(resources, schema::normalized(&source().resources));
        assert!(history.is_empty());
        assert_ne!(
            tx.fetch::<1>(
                "SELECT generation FROM nx_deployment WHERE singleton=1",
                &[]
            )
            .await
            .unwrap()[0][0],
            "original"
        );
        for id in [1i64, 2] {
            assert_eq!(tx.fetch::<4>("SELECT owner,tenant,incarnation,CAST(revision AS TEXT) FROM nx_records WHERE resource=1 AND id=$1", &[id.into()]).await.unwrap()[0], ["alice".into(), "team".into(), format!("record-{id}"), "7".into()]);
        }
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_legacy_text_import_is_canonical_and_atomic() {
        let dir = tempfile::tempdir().unwrap();
        legacy_text_import_contract(Database::sqlite(dir.path().join("legacy-text.db"))).await;
    }

    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable test cluster"]
    async fn postgres_legacy_text_import_is_canonical_and_atomic() {
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "nx_legacy_text_{}",
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
        legacy_text_import_contract(Database::postgres(case.as_str()).unwrap()).await;
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
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
