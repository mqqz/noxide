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
    read_only: bool,
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
        tokio::time::timeout_at(deadline.into(), self.connect(deadline, false, false)).await?
    }
    pub(crate) async fn begin_read(&self, deadline: Instant) -> Result<Transaction> {
        tokio::time::timeout_at(deadline.into(), self.connect(deadline, false, true)).await?
    }
    async fn begin_schema(&self) -> Result<Transaction> {
        let deadline = Instant::now() + Duration::from_secs(60);
        tokio::time::timeout_at(deadline.into(), self.connect(deadline, true, false)).await?
    }
    async fn connect(
        &self,
        deadline: Instant,
        exclusive: bool,
        read_only: bool,
    ) -> Result<Transaction> {
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
                if read_only {
                    sqlx::query("PRAGMA query_only = ON")
                        .execute(&mut cx)
                        .await?;
                }
                sqlx::query(if read_only {
                    "BEGIN DEFERRED"
                } else {
                    "BEGIN IMMEDIATE"
                })
                .execute(&mut cx)
                .await?;
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
        Ok(Transaction {
            backend,
            active: true,
            read_only,
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
            tx.check_storage().await?;
            tx.check_layout().await?;
        }
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
        for &(table, columns) in TABLE_COLUMNS {
            let columns = columns
                .iter()
                .map(|(name, _)| format!("CAST({name} AS TEXT)"))
                .collect::<Vec<_>>()
                .join(",");
            let json = match self.backend {
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

    pub(crate) async fn check_storage(&mut self) -> Result<()> {
        let rows = self.fetch::<2>(
            "SELECT CAST(singleton AS TEXT),CAST(version AS TEXT) FROM nx_storage ORDER BY singleton LIMIT 2",
            &[],
        ).await?;
        ensure!(
            rows.as_slice() == [["1".to_owned(), STORAGE_VERSION.to_string()]],
            "unsupported framework storage version"
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

    async fn check_layout(&mut self) -> Result<()> {
        let mut expected: Vec<_> = TABLE_COLUMNS
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        expected.sort();
        ensure!(
            self.storage_tables().await? == expected,
            "unsupported or incomplete framework storage schema"
        );
        for &(table, columns) in TABLE_COLUMNS {
            let sql = match self.backend {
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
        Ok(())
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
    pub(crate) fn field_text(&self, field: &str, index: usize) -> (String, Param) {
        match self.backend {
            Backend::Sqlite(_) => (
                format!("json_extract(fields, ${index})"),
                format!("$.\"{field}\"").into(),
            ),
            Backend::Postgres(_) => (format!("(fields::jsonb ->> ${index})"), field.into()),
        }
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
        ensure!(!self.read_only, "read-only transaction");
        self.execute_internal(sql, params).await
    }
    async fn execute_internal(&mut self, sql: &str, params: &[Param]) -> Result<u64> {
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
        self.execute_internal("COMMIT", &[]).await?;
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
                self.execute_internal("ROLLBACK", &[]).await?;
                self.active = false;
            }
            self.release_gate().await?;
            Ok(())
        })
        .await?
    }
}

impl Database {
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

    pub(crate) async fn check_schema(
        &mut self,
        manifest: &noxide_protocol::Manifest,
    ) -> Result<()> {
        let (resources, _) = self
            .schema_definition()
            .await?
            .context("application schema is not bound")?;
        ensure!(
            crate::schema::digest(&resources)? == crate::schema::digest(&manifest.resources)?,
            "stored schema differs from approved resource contract; an explicit migration is required"
        );
        for resource in &manifest.resources {
            self.storage_resource(manifest, resource.id).await?;
        }
        Ok(())
    }

    pub(crate) async fn bind_schema(&mut self, manifest: &noxide_protocol::Manifest) -> Result<()> {
        if self.schema_definition().await?.is_some() {
            return self.check_schema(manifest).await;
        }
        ensure!(
            self.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
                .await?[0][0]
                == "0"
                && self
                    .fetch::<1>(
                        "SELECT CAST(COUNT(*) AS TEXT) FROM nx_resource_catalog",
                        &[]
                    )
                    .await?[0][0]
                    == "0",
            "cannot bind nonempty storage without an application schema"
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
            .context("application schema must be bound before migration")?;
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

const STORAGE_VERSION: i64 = 5;
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
    "INSERT INTO nx_storage(singleton,version) VALUES(1,5)",
    "CREATE TABLE IF NOT EXISTS nx_resource_catalog (storage_id BIGINT PRIMARY KEY, resource_key TEXT NOT NULL UNIQUE)",
    "CREATE TABLE IF NOT EXISTS nx_schema_definition (singleton BIGINT PRIMARY KEY CHECK(singleton=1), definition TEXT NOT NULL, history TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_accounts (id TEXT PRIMARY KEY, password TEXT NOT NULL, tenant TEXT NOT NULL, epoch BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_invites (code_hash TEXT PRIMARY KEY, issuer TEXT NOT NULL, expires BIGINT NOT NULL, redeemed_at BIGINT NULL, redeemed_by TEXT NULL REFERENCES nx_accounts(id))",
    "CREATE TABLE IF NOT EXISTS nx_roles (principal TEXT NOT NULL REFERENCES nx_accounts(id), name TEXT NOT NULL, tenant TEXT NOT NULL, PRIMARY KEY(principal,name,tenant))",
    "CREATE TABLE IF NOT EXISTS nx_sessions (id TEXT PRIMARY KEY, principal TEXT NOT NULL REFERENCES nx_accounts(id), epoch BIGINT NOT NULL, expires BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_records (resource BIGINT NOT NULL, id BIGINT NOT NULL, owner TEXT NULL REFERENCES nx_accounts(id), tenant TEXT NOT NULL, fields TEXT NOT NULL, incarnation TEXT NOT NULL, revision BIGINT NOT NULL CHECK(revision>=1), cap_version BIGINT NULL, PRIMARY KEY(resource,id))",
    "CREATE INDEX IF NOT EXISTS nx_records_owner ON nx_records(resource,owner,id)",
    "CREATE INDEX IF NOT EXISTS nx_records_tenant ON nx_records(resource,tenant,id)",
    "CREATE TABLE IF NOT EXISTS nx_receipts (nonce TEXT PRIMARY KEY, subject TEXT NOT NULL, contract TEXT NOT NULL, action BIGINT NOT NULL, input TEXT NOT NULL, outcome TEXT NOT NULL, expires BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_clock (singleton BIGINT PRIMARY KEY, observed BIGINT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nx_deployment (singleton BIGINT PRIMARY KEY, contract TEXT NOT NULL, incarnation TEXT NOT NULL, generation TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS nx_receipts_expiry ON nx_receipts(expires)",
    "CREATE INDEX IF NOT EXISTS nx_sessions_expiry ON nx_sessions(expires)",
    "INSERT INTO nx_clock(singleton,observed) VALUES(1,0) ON CONFLICT(singleton) DO NOTHING",
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
        tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version) VALUES(1,1,NULL,'','{}','layout-test',1,1)", &[]).await.unwrap();
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
