use super::*;

pub(in crate::database) struct Ordinary {
    pub(super) lease: ProviderLease,
    pub(super) control: Option<maintenance::Control>,
    pub(super) in_flight: bool,
    pub(super) setup: bool,
}

async fn stop(
    mut backend: Backend,
    mut ordinary: Ordinary,
    cancelled: Arc<AtomicBool>,
    active: bool,
) -> Result<()> {
    cancelled.store(true, Ordering::Release);
    let deadline = ordinary.lease.total;
    tokio::time::timeout_at(deadline, async {
        match &mut backend {
            Backend::Sqlite(_) => {
                if let Backend::Sqlite(connection) =
                    std::mem::replace(&mut backend, Backend::Closed)
                {
                    // Fixed owned options disable optimize-on-close. The SQLx
                    // close acknowledgement follows destruction of the handle.
                    connection.close().await?;
                }
            }
            Backend::Postgres(connection) => {
                let control = ordinary
                    .control
                    .as_mut()
                    .context(Unavailable::Unconfirmed)?;
                if !active && !ordinary.in_flight && !ordinary.setup {
                    // Acknowledged COMMIT has already published its prepared result.
                    // Unlock is owned cleanup and may consume only remaining work time.
                    ordinary.in_flight = true;
                    let unlocked = tokio::time::timeout_at(ordinary.lease.work, async {
                        let remaining = maintenance::remaining_ms(ordinary.lease.work.into_std())?;
                        ordinary.lease.cleanup.charge(1)?;
                        sqlx::query(&format!("SET statement_timeout = '{remaining}ms'"))
                            .execute(&mut *connection)
                            .await?;
                        ordinary.lease.cleanup.charge(1)?;
                        sqlx::query("SELECT pg_advisory_unlock_all()")
                            .execute(&mut *connection)
                            .await?;
                        Ok::<(), anyhow::Error>(())
                    })
                    .await;
                    ordinary.in_flight = !matches!(unlocked, Ok(Ok(())));
                }
                if active || ordinary.in_flight || ordinary.setup {
                    control.cancel(deadline.into_std()).await?;
                    // This is physical cleanup, NEVER evidence of COMMIT abort.
                    ordinary.lease.cleanup.charge(1)?;
                    let _ = sqlx::query("ROLLBACK").execute(connection).await;
                }
                if let Backend::Postgres(connection) =
                    std::mem::replace(&mut backend, Backend::Closed)
                {
                    let _ = connection.close().await;
                }
                control.stopped(deadline.into_std()).await?;
                if let Some(control) = ordinary.control.take() {
                    control.close().await?;
                }
            }
            Backend::Closed => {
                ensure!(!ordinary.lease.started, Unavailable::Unconfirmed);
            }
        }
        ordinary.lease.confirmed();
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    Ok(())
}

pub(in crate::database) fn drop_transaction(transaction: &mut Transaction) {
    let Some(ordinary) = transaction.ordinary.take() else {
        return;
    };
    let runtime = ordinary.lease.runtime.clone();
    let backend = std::mem::replace(&mut transaction.backend, Backend::Closed);
    let cancelled = transaction.cancelled.clone();
    let active = transaction.active;
    // Exactly one task per admitted provider gate. Every field, capacity alias
    // and original deadline moves with it, even if this task is then canceled.
    runtime.spawn(async move {
        let _ = stop(backend, ordinary, cancelled, active).await;
    });
}

pub(in crate::database) async fn finish_transaction(transaction: &mut Transaction) -> Result<()> {
    let Some(ordinary) = transaction.ordinary.take() else {
        return Ok(());
    };
    let backend = std::mem::replace(&mut transaction.backend, Backend::Closed);
    let result = stop(
        backend,
        ordinary,
        transaction.cancelled.clone(),
        transaction.active,
    )
    .await;
    if result.is_ok() {
        transaction.active = false;
    }
    result
}

impl Transaction {
    pub(in crate::database) async fn ordinary_timeout(&mut self) -> Result<()> {
        let Some(ordinary) = &mut self.ordinary else {
            return Ok(());
        };
        RequestScope::checkpoint_current()?;
        let remaining = maintenance::remaining_ms(ordinary.lease.work.into_std())?.min(1500);
        if let Backend::Postgres(connection) = &mut self.backend {
            ordinary.lease.meter.charge(1)?;
            ordinary.in_flight = true;
            tokio::time::timeout_at(
                ordinary.lease.work,
                sqlx::query(&format!("SET statement_timeout = '{remaining}ms'"))
                    .execute(connection),
            )
            .await??;
            ordinary.in_flight = false;
        }
        Ok(())
    }
    pub(in crate::database) fn ordinary_charge(&self) -> Result<()> {
        if let Some(ordinary) = &self.ordinary {
            ordinary.lease.meter.charge(1)?;
        }
        Ok(())
    }
    pub(in crate::database) fn ordinary_commit_pending(&self, pending: bool) {
        if let Some(ordinary) = &self.ordinary {
            ordinary.lease.commit_pending(pending);
        }
    }
    pub(in crate::database) fn ordinary_in_flight(&mut self, value: bool) {
        if let Some(ordinary) = &mut self.ordinary {
            ordinary.in_flight = value;
        }
    }
}
