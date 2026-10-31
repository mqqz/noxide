//! Host-owned PostgreSQL cancellation and stop acknowledgement. Clock and ordinary
//! lifecycles share identity checks; their capacity/deadline owners remain distinct.
use super::*;
use tokio::sync::OwnedSemaphorePermit;

pub(super) const CLEANUP_RESERVE: Duration = Duration::from_millis(50);
pub(super) fn remaining_ms(deadline: Instant) -> Result<u64> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("maintenance deadline elapsed")?;
    ensure!(
        remaining >= Duration::from_millis(1),
        "maintenance deadline elapsed"
    );
    Ok(remaining.as_millis().min(i32::MAX as u128) as u64)
}

#[derive(Debug)]
pub(crate) struct MaintenanceUncertain;
impl std::fmt::Display for MaintenanceUncertain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("maintenance cleanup is unconfirmed; capacity quarantined")
    }
}
impl std::error::Error for MaintenanceUncertain {}

#[derive(Debug)]
pub(super) struct ConnectStopped(pub(super) anyhow::Error);
impl std::fmt::Display for ConnectStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for ConnectStopped {}

pub(super) struct Control {
    connection: sqlx::PgConnection,
    pid: i32,
    scope: String,
    started: String,
}
impl Control {
    pub(super) async fn connect(
        options: &PgConnectOptions,
        work: &mut sqlx::PgConnection,
        scope: &str,
        deadline: Instant,
    ) -> Result<Self> {
        let row = sqlx::query("SELECT pg_catalog.pg_backend_pid(),CAST(backend_start AS TEXT) FROM pg_catalog.pg_stat_activity WHERE pid=pg_catalog.pg_backend_pid() AND application_name=$1")
            .bind(scope).fetch_one(work).await?;
        let pid = row.try_get(0)?;
        let started = row.try_get(1)?;
        let timeout = remaining_ms(deadline)?.min(CLEANUP_RESERVE.as_millis() as u64);
        let options = options
            .clone()
            .application_name(&format!("nx-ctl-{}", crate::security::random_id()?))
            .options([
                ("statement_timeout", format!("{timeout}ms")),
                ("lock_timeout", "1ms".into()),
            ]);
        let connection = sqlx::PgConnection::connect_with(&options).await?;
        Ok(Self {
            connection,
            pid,
            scope: scope.into(),
            started,
        })
    }
    pub(super) async fn close(self) -> Result<()> {
        self.connection.close().await.map_err(Into::into)
    }
    async fn configure(&mut self, deadline: Instant) -> Result<()> {
        let timeout = remaining_ms(deadline)?;
        sqlx::query(&format!("SET statement_timeout = '{timeout}ms'"))
            .execute(&mut self.connection)
            .await?;
        Ok(())
    }
    pub(super) async fn cancel(&mut self, deadline: Instant) -> Result<()> {
        self.configure(deadline).await?;
        // Only a host-created work connection is eligible. Its socket remains
        // owned until this check/cancel completes. Guest input supplies no ID.
        sqlx::query("SELECT pg_catalog.pg_cancel_backend(pid) FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND application_name=$2 AND CAST(backend_start AS TEXT)=$3 AND datname=pg_catalog.current_database() AND usename=current_user")
            .bind(self.pid).bind(&self.scope).bind(&self.started)
            .fetch_all(&mut self.connection).await?;
        Ok(())
    }
    pub(super) async fn stopped(&mut self, deadline: Instant) -> Result<()> {
        for _ in 0..16 {
            self.configure(deadline).await?;
            let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND application_name=$2 AND CAST(backend_start AS TEXT)=$3 AND datname=pg_catalog.current_database() AND usename=current_user)")
                .bind(self.pid).bind(&self.scope).bind(&self.started).fetch_one(&mut self.connection).await?;
            if !present {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        anyhow::bail!("maintenance backend termination unconfirmed")
    }
}

impl Transaction {
    pub(super) async fn maintenance_timeout(&mut self) -> Result<()> {
        if self.maintenance.is_some() {
            let timeout = remaining_ms(self.deadline.into_std())?;
            if let Backend::Postgres(connection) = &mut self.backend {
                tokio::time::timeout_at(
                    self.deadline,
                    sqlx::query(&format!("SET statement_timeout = '{timeout}ms'"))
                        .execute(connection),
                )
                .await??;
            }
        }
        Ok(())
    }

    async fn stop_maintenance(mut self, deadline: Instant) -> Result<()> {
        self.cancelled.store(true, Ordering::Release);
        tokio::time::timeout_at(deadline.into(), async {
            if let Some(mut control) = self.maintenance.take() {
                control.cancel(deadline).await?;
                if let Backend::Postgres(connection) = &mut self.backend {
                    // SQLx first drains any canceled response. Even if ROLLBACK
                    // reports that response as an error, closing + observed PID
                    // disappearance below proves the transaction has ended.
                    let _ = sqlx::query("ROLLBACK").execute(connection).await;
                }
                if let Backend::Postgres(connection) =
                    std::mem::replace(&mut self.backend, Backend::Closed)
                {
                    let _ = connection.close().await;
                }
                control.stopped(deadline).await?;
                let _ = control.connection.close().await;
            } else if let Backend::Sqlite(connection) =
                std::mem::replace(&mut self.backend, Backend::Closed)
            {
                connection.close().await?;
            }
            self.active = false;
            Ok(())
        })
        .await?
    }
}

/// Holds actual reserved capacity through provider cleanup, including when its
/// caller is canceled. Uncertain cleanup permanently quarantines that slot.
pub(crate) struct MaintenanceLease {
    tx: Option<Transaction>,
    permit: Option<OwnedSemaphorePermit>,
    deadline: Instant,
    known_stopped: bool,
    runtime: tokio::runtime::Handle,
    freshness: crate::lifecycle_clock::Freshness,
}
impl MaintenanceLease {
    pub(crate) fn new(
        permit: OwnedSemaphorePermit,
        deadline: Instant,
        freshness: crate::lifecycle_clock::Freshness,
    ) -> Self {
        Self {
            tx: None,
            permit: Some(permit),
            deadline,
            known_stopped: false,
            runtime: tokio::runtime::Handle::current(),
            freshness,
        }
    }
    pub(crate) async fn begin(&mut self, database: &Database) -> Result<()> {
        match database.begin_maintenance(self.deadline).await {
            Ok(tx) => {
                self.tx = Some(tx);
                if self.tx().maintenance.is_some() {
                    let locked = self.tx().fetch::<1>("SELECT CAST(singleton AS TEXT) FROM nx_clock WHERE singleton=1 FOR UPDATE NOWAIT", &[]).await;
                    if let Err(error) = locked {
                        self.finish().await?;
                        return Err(error);
                    }
                }
                Ok(())
            }
            Err(error) if error.is::<ConnectStopped>() => {
                self.known_stopped = true;
                Err(error)
            }
            Err(_) => Err(MaintenanceUncertain.into()),
        }
    }
    pub(crate) fn tx(&mut self) -> &mut Transaction {
        self.tx.as_mut().expect("maintenance began")
    }
    pub(crate) async fn finish(&mut self) -> Result<()> {
        if let Some(tx) = self.tx.take() {
            let capacity = CleanupCapacity {
                permit: self.permit.take(),
                freshness: self.freshness.clone(),
                stopped: false,
            };
            if tx.stop_maintenance(self.deadline).await.is_err() {
                return Err(MaintenanceUncertain.into());
            }
            capacity.confirmed();
        }
        self.known_stopped = true;
        drop(self.permit.take());
        Ok(())
    }
}
struct CleanupCapacity {
    permit: Option<OwnedSemaphorePermit>,
    freshness: crate::lifecycle_clock::Freshness,
    stopped: bool,
}
impl CleanupCapacity {
    fn confirmed(mut self) {
        self.stopped = true;
    }
}
impl Drop for CleanupCapacity {
    fn drop(&mut self) {
        if !self.stopped {
            self.freshness.quarantine();
            if let Some(permit) = self.permit.take() {
                permit.forget();
            }
        }
    }
}
impl Drop for MaintenanceLease {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        if let Some(tx) = self.tx.take() {
            let deadline = self.deadline;
            let capacity = CleanupCapacity {
                permit: Some(permit),
                freshness: self.freshness.clone(),
                stopped: false,
            };
            // One cleanup task per admitted slot, no queue, same finite deadline.
            // If even this task is canceled, its guard quarantines the capacity.
            self.runtime.spawn(async move {
                if tx.stop_maintenance(deadline).await.is_ok() {
                    capacity.confirmed();
                }
            });
        } else if !self.known_stopped {
            self.freshness.quarantine();
            permit.forget();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES disposable local server"]
    async fn postgres_control_does_not_cancel_a_different_backend_identity() {
        let root = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&root).await.unwrap();
        let name = format!(
            "p06_identity_{}",
            crate::security::random_id()
                .unwrap()
                .replace('-', "a")
                .replace('_', "b")
                .to_lowercase()
        );
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut url = url::Url::parse(&root).unwrap();
        url.set_path(&name);
        let database = Database::postgres(url.as_str()).unwrap();
        database.initialize().await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut work = database.begin_maintenance(deadline).await.unwrap();
        let mut other = sqlx::PgConnection::connect(url.as_str()).await.unwrap();
        let other_pid: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
            .fetch_one(&mut other)
            .await
            .unwrap();
        let other_query = tokio::spawn(async move {
            sqlx::query("SELECT pg_catalog.pg_sleep(0.1)")
                .execute(&mut other)
                .await
        });
        let mut monitor = sqlx::PgConnection::connect(url.as_str()).await.unwrap();
        tokio::time::timeout(Duration::from_millis(200),async {
            loop {
                let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep')").bind(other_pid).fetch_one(&mut monitor).await.unwrap();
                if active {break;}
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        let control = work.maintenance.as_mut().unwrap();
        let real_pid = control.pid;
        // Only this private negative fixture can alter a captured identity.
        // Matching a PID without its host tag/start must never authorize cancel.
        control.pid = other_pid;
        control.cancel(deadline).await.unwrap();
        let still_active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep')").bind(other_pid).fetch_one(&mut monitor).await.unwrap();
        assert!(still_active);
        other_query.await.unwrap().unwrap();
        control.pid = real_pid;
        work.stop_maintenance(deadline).await.unwrap();
    }
}
