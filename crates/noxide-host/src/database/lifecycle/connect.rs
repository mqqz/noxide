use super::*;

pub(super) async fn open(
    database: Database,
    lease: ProviderLease,
    read_only: bool,
) -> Result<Transaction> {
    let work = lease.work;
    tokio::time::timeout_at(work, open_inner(database, lease, read_only)).await?
}

async fn open_inner(
    database: Database,
    lease: ProviderLease,
    read_only: bool,
) -> Result<Transaction> {
    let deadline = lease.work.into_std();
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut tx = Transaction {
        #[cfg(test)]
        creation_acquired: None,
        backend: Backend::Closed,
        active: false,
        commit_state: CommitState::NotAttempted,
        read_only,
        cancelled,
        operator_ended: Arc::new(AtomicBool::new(true)),
        deadline: deadline.into(),
        maintenance: None,
        maintenance_work: false,
        ordinary: Some(Ordinary {
            lease,
            control: None,
            in_flight: false,
            setup: true,
        }),
    };
    match &database.options {
        DatabaseOptions::Sqlite { path, busy, .. } => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tx.ordinary.as_mut().unwrap().lease.started = true;
                let metadata = tokio::fs::metadata(path).await;
                tx.ordinary.as_mut().unwrap().lease.started = false;
                ensure!(
                    metadata?.permissions().mode() & 0o077 == 0,
                    "SQLite database must be private (mode0600)"
                );
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .context(Unavailable::Deadline)?;
            let options = SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(false)
                .foreign_keys(true)
                .synchronous(SqliteSynchronous::Full)
                .pragma("trusted_schema", "OFF")
                .busy_timeout((*busy).min(remaining))
                .optimize_on_close(false, None);
            // Bootstrap establishes WAL. An ordinary request never changes the
            // persisted journal mode to make uninitialized storage appear valid.
            tx.ordinary
                .as_ref()
                .unwrap()
                .lease
                .meter
                .charge(meter::ORDINARY_SQLITE_STARTUP)?;
            tx.ordinary.as_mut().unwrap().lease.started = true;
            let connection = sqlx::SqliteConnection::connect_with(&options).await?;
            tx.backend = Backend::Sqlite(connection);
            let Backend::Sqlite(connection) = &mut tx.backend else {
                unreachable!()
            };
            let cancel = tx.cancelled.clone();
            connection
                .lock_handle()
                .await?
                .set_progress_handler(1000, move || {
                    !cancel.load(Ordering::Relaxed) && Instant::now() < deadline
                });
            tx.ordinary.as_ref().unwrap().lease.meter.charge(1)?;
            let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
                .fetch_one(&mut *connection)
                .await?;
            tx.ordinary.as_ref().unwrap().lease.meter.charge(1)?;
            let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
                .fetch_one(&mut *connection)
                .await?;
            ensure!(
                synchronous == 2 && mode == "wal",
                "unsafe SQLite durability"
            );
            let timeout = busy
                .as_millis()
                .min(maintenance::remaining_ms(deadline)? as u128);
            tx.ordinary.as_ref().unwrap().lease.meter.charge(1)?;
            sqlx::query(&format!("PRAGMA busy_timeout={timeout}"))
                .execute(&mut *connection)
                .await?;
            if read_only {
                tx.ordinary.as_ref().unwrap().lease.meter.charge(1)?;
                sqlx::query("PRAGMA query_only = ON")
                    .execute(&mut *connection)
                    .await?;
            }
            tx.ordinary.as_ref().unwrap().lease.meter.charge(1)?;
            sqlx::query(if read_only {
                "BEGIN DEFERRED"
            } else {
                "BEGIN IMMEDIATE"
            })
            .execute(connection)
            .await?;
        }
        DatabaseOptions::Postgres(options) => {
            let remaining = maintenance::remaining_ms(deadline)?;
            let scope = format!("nx-request-{}", crate::security::random_id()?);
            let options = options.clone().application_name(&scope).options([
                ("statement_timeout", format!("{}ms", remaining.min(1500))),
                ("lock_timeout", format!("{}ms", remaining.min(250))),
                (
                    "idle_in_transaction_session_timeout",
                    format!("{}ms", remaining.min(3000)),
                ),
            ]);
            tx.ordinary.as_mut().unwrap().lease.started = true;
            tx.backend = Backend::Postgres(sqlx::PgConnection::connect_with(&options).await?);
            let Backend::Postgres(connection) = &mut tx.backend else {
                unreachable!()
            };
            let lease = &tx.ordinary.as_ref().unwrap().lease;
            let control = maintenance::Control::connect_metered(
                &options,
                connection,
                &scope,
                deadline,
                lease.meter.clone(),
                lease.cleanup.clone(),
            )
            .await?;
            tx.ordinary.as_mut().unwrap().control = Some(control);
            for setting in ["SHOW fsync", "SHOW full_page_writes"] {
                tx.ordinary.as_ref().unwrap().lease.meter.charge(1)?;
                let value: String = sqlx::query_scalar(setting)
                    .fetch_one(&mut *connection)
                    .await?;
                ensure!(value == "on", "unsafe PostgreSQL durability");
            }
            tx.ordinary.as_ref().unwrap().lease.meter.charge(1)?;
            sqlx::query("SET synchronous_commit = on")
                .execute(&mut *connection)
                .await?;
            tx.ordinary.as_ref().unwrap().lease.meter.charge(1)?;
            let acquired: bool =
                sqlx::query_scalar("SELECT pg_try_advisory_lock_shared(5642817467268123)")
                    .fetch_one(&mut *connection)
                    .await?;
            ensure!(acquired, "application database is busy with maintenance");
            tx.ordinary.as_ref().unwrap().lease.meter.charge(1)?;
            sqlx::query(if read_only {
                "BEGIN ISOLATION LEVEL SERIALIZABLE, READ ONLY"
            } else {
                "BEGIN ISOLATION LEVEL SERIALIZABLE"
            })
            .execute(connection)
            .await?;
        }
    }
    tx.active = true;
    tx.ordinary.as_mut().unwrap().setup = false;
    Ok(tx)
}
