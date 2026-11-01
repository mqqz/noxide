//! Durable lifecycle time extends `nx_clock`; credential seconds stay separate.
//!
//! Only the reserved maintenance task calls `tick`, after the normal deployment
//! fence. Requests consume a fixed durable snapshot through `Freshness::attempt`.
//! Startup and the one maintenance service publish confirmed ticks. Resource
//! expiry declarations/enforcement are separate and remain unavailable.
#[cfg(test)]
use crate::database::Database;
use crate::database::{Param, Transaction};
pub(crate) use crate::temporal::{AttemptTime, TemporalUnavailable};
use anyhow::{Result, ensure};
use noxide_protocol::time::Timestamp;
use std::{
    sync::{Arc, Mutex, atomic::AtomicI64},
    time::{Duration, Instant, SystemTime},
};

pub(crate) const TICK_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const FRESHNESS_LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DurableClock {
    watermark: Timestamp,
    version: i64,
}

async fn read(tx: &mut Transaction) -> Result<DurableClock> {
    let rows = tx
        .fetch::<2>(
            "SELECT CAST(lifecycle_ms AS TEXT),CAST(lifecycle_version AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await?;
    ensure!(rows.len() == 1, "lifecycle clock missing");
    let watermark = Timestamp::from_unix_millis(rows[0][0].parse()?)?;
    let version = rows[0][1].parse()?;
    ensure!(version >= 0, "invalid lifecycle version");
    Ok(DurableClock { watermark, version })
}

/// Evidence of a confirmed durable tick. Cannot be constructed from an arbitrary
/// request snapshot or returned on an unknown commit outcome.
pub(crate) struct CommittedTick {
    clock: DurableClock,
    started: Instant,
    pub(crate) credential_seconds: i64,
}

/// Consume and commit a bounded, generation-fenced maintenance transaction.
/// Its caller must reserve independent maintenance capacity before opening it.
pub(crate) async fn tick(
    tx: &mut Transaction,
    credential_memory: &AtomicI64,
) -> Result<CommittedTick> {
    let started = Instant::now();
    let wall = Timestamp::from_system_time(SystemTime::now())?;
    tick_sampled(tx, credential_memory, wall, started).await
}

async fn tick_sampled(
    tx: &mut Transaction,
    credential_memory: &AtomicI64,
    wall: Timestamp,
    started: Instant,
) -> Result<CommittedTick> {
    // Reuse the existing seconds clock's persisted + process rollback checks.
    // Its effective seconds may include read-only credential observations. They
    // do not advance lifecycle time: only this sampled wall and durable history do.
    let seconds = observe_clock_read(tx, wall.unix_seconds_floor(), credential_memory).await?;
    let seconds = observe_clock(tx, seconds).await?;
    Timestamp::from_unix_seconds(seconds)?;

    let previous = read(tx).await?;
    let next = DurableClock {
        watermark: previous.watermark.max(wall),
        version: previous
            .version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("lifecycle version exhausted"))?,
    };
    let changed = tx
        .execute(
            "UPDATE nx_clock SET lifecycle_ms=$1,lifecycle_version=$2 WHERE singleton=1 AND lifecycle_ms=$3 AND lifecycle_version=$4",
            &[
                next.watermark.unix_millis().into(),
                next.version.into(),
                previous.watermark.unix_millis().into(),
                previous.version.into(),
            ],
        )
        .await?;
    ensure!(changed == 1, "concurrent lifecycle tick; retry maintenance");
    tx.commit().await?;
    Ok(CommittedTick {
        clock: next,
        started,
        credential_seconds: seconds,
    })
}

/// A separate, fresh read-only heartbeat transaction. Request transactions never
/// produce this evidence: their snapshots might predate a maintenance commit.
pub(crate) struct HeartbeatObservation {
    clock: DurableClock,
    started: Instant,
}

#[cfg(test)]
impl HeartbeatObservation {
    /// Caller holds reserved maintenance capacity. The monotonic observation
    /// time precedes BEGIN so a delayed database response cannot extend a lease.
    pub(crate) async fn read(database: &Database, deadline: Instant) -> Result<Self> {
        let started = Instant::now();
        let mut tx = database.begin_read(deadline).await?;
        let clock = read(&mut tx).await?;
        tx.commit().await?;
        Ok(Self { clock, started })
    }
}

#[derive(Default)]
struct State {
    quarantined: bool,
    startup_complete: bool,
    progress: Option<HeartbeatObservation>,
    fresh_since: Option<Instant>,
    /// Ticks published during the freshness window. A request snapshot taken
    /// before a newer tick committed still sees one of these exact clocks.
    published: std::collections::VecDeque<HeartbeatObservation>,
}

/// Bounds `State::published`: one tick per second covers the freshness limit.
const PUBLISHED_TICKS: usize = 8;

impl State {
    fn publish(&mut self, observation: HeartbeatObservation) {
        if self.published.len() == PUBLISHED_TICKS {
            self.published.pop_front();
        }
        self.published.push_back(HeartbeatObservation {
            clock: observation.clock,
            started: observation.started,
        });
        self.progress = Some(observation);
    }
}

/// One process's proof of recent durable maintenance progress. All access is
/// constant work under a short mutex; no database work runs under that mutex.
#[derive(Clone, Default)]
pub(crate) struct Freshness(Arc<Mutex<State>>);

impl Freshness {
    pub(crate) fn quarantine(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.quarantined = true;
        }
    }
    /// Startup must call this only after its own successful durable tick. A failed
    /// or ambiguous startup commit leaves this process unable to serve time.
    pub(crate) fn committed(&self, tick: CommittedTick) -> Result<()> {
        self.committed_at(tick, Instant::now())
    }

    fn committed_at(&self, tick: CommittedTick, now: Instant) -> Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| TemporalUnavailable::Inconsistent)?;
        validate_progress(&state, tick.clock, tick.started, now)?;
        state.startup_complete = true;
        state.fresh_since = Some(tick.started);
        state.publish(HeartbeatObservation {
            clock: tick.clock,
            started: tick.started,
        });
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn observe(&self, observation: HeartbeatObservation) -> Result<()> {
        self.observe_at(observation, Instant::now())
    }

    #[cfg(test)]
    fn observe_at(&self, observation: HeartbeatObservation, now: Instant) -> Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| TemporalUnavailable::Inconsistent)?;
        ensure!(state.startup_complete, TemporalUnavailable::NotStarted);
        validate_progress(&state, observation.clock, observation.started, now)?;
        if let Some(previous) = &state.progress {
            if observation.clock.version == previous.clock.version {
                // Crucially, do not update either monotonic time for a reread.
                return Ok(());
            }
            // A higher version proves a commit after the previous snapshot,
            // whose earliest possible time is the previous read's start. It
            // does not prove a commit after this read started. Anchor the lease
            // to that conservative lower bound, including delivery delay.
            // A stale proof only establishes the next observation baseline.
            state.fresh_since = if recent(previous.started, now) {
                Some(previous.started)
            } else {
                None
            };
        }
        state.publish(observation);
        Ok(())
    }

    /// Read once per transaction attempt, after the deployment fence. This never
    /// samples wall time, changes a lease, or writes any database state.
    pub(crate) async fn attempt(&self, tx: &mut Transaction) -> Result<AttemptTime> {
        let clock = read(tx).await?;
        self.attempt_at(clock, Instant::now())
    }

    fn attempt_at(&self, clock: DurableClock, now: Instant) -> Result<AttemptTime> {
        let state = self
            .0
            .lock()
            .map_err(|_| TemporalUnavailable::Inconsistent)?;
        ensure!(!state.quarantined, TemporalUnavailable::Quarantined);
        let since = state.fresh_since.ok_or(TemporalUnavailable::NotStarted)?;
        ensure!(recent(since, now), TemporalUnavailable::Stale);
        let progress = state
            .progress
            .as_ref()
            .ok_or(TemporalUnavailable::NotStarted)?;
        let current = clock.version >= progress.clock.version
            && clock.watermark >= progress.clock.watermark
            && clock.version > 0
            && (clock.version != progress.clock.version
                || clock.watermark == progress.clock.watermark);
        // A snapshot older than the latest publish must match a recent tick
        // exactly; anything else is a regression such as a restored database.
        let earlier = state
            .published
            .iter()
            .any(|tick| tick.clock == clock && recent(tick.started, now));
        ensure!(current || earlier, TemporalUnavailable::Inconsistent);
        Ok(AttemptTime::from_durable(clock.watermark))
    }
}

fn recent(start: Instant, now: Instant) -> bool {
    now.checked_duration_since(start)
        .is_some_and(|elapsed| elapsed < FRESHNESS_LIMIT)
}

fn validate_progress(
    state: &State,
    clock: DurableClock,
    started: Instant,
    now: Instant,
) -> Result<()> {
    ensure!(!state.quarantined, TemporalUnavailable::Quarantined);
    ensure!(recent(started, now), TemporalUnavailable::Stale);
    ensure!(clock.version > 0, TemporalUnavailable::NotStarted);
    if let Some(previous) = &state.progress {
        ensure!(
            started >= previous.started
                && clock.version >= previous.clock.version
                && clock.watermark >= previous.clock.watermark
                && (clock.version != previous.clock.version
                    || clock.watermark == previous.clock.watermark),
            TemporalUnavailable::Inconsistent
        );
    }
    Ok(())
}

/// A small wall-clock correction may delay expiry, but must never revive it.
/// Every caller uses the returned high-water time, including token verification.
pub(crate) const CLOCK_ROLLBACK_TOLERANCE: i64 = 60;

pub(crate) async fn observe_clock(tx: &mut Transaction, now: i64) -> Result<i64> {
    let rows = tx
        .fetch::<1>(
            "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await?;
    let previous: i64 = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("clock missing"))?[0]
        .parse()?;
    ensure!(now >= 0 && previous >= 0, "invalid clock");
    ensure!(
        previous.saturating_sub(now) <= CLOCK_ROLLBACK_TOLERANCE,
        "clock moved backwards beyond tolerance; use recover-clock with a fresh host key"
    );
    if now > previous {
        tx.execute(
            "UPDATE nx_clock SET observed=$1 WHERE singleton=1 AND observed<$1",
            &[Param::Number(now)],
        )
        .await?;
    }
    Ok(now.max(previous))
}

/// Gap beyond which a request persists the clock mark itself. The lifecycle tick
/// persists it every second, so while the tick runs requests never write
/// nx_clock and concurrent writes do not conflict on it. If the tick stalls,
/// requests keep the persisted mark within this bound, as before.
pub(crate) const CLOCK_PERSIST_LAG: i64 = 2;

/// Request-path clock observation with rollback checks. It writes nx_clock only
/// when the persisted mark is more than `CLOCK_PERSIST_LAG` seconds behind.
pub(crate) async fn observe_clock_bounded(
    tx: &mut Transaction,
    now: i64,
    memory: &std::sync::atomic::AtomicI64,
) -> Result<i64> {
    let rows = tx
        .fetch::<1>(
            "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await?;
    let persisted: i64 = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("clock missing"))?[0]
        .parse()?;
    let effective = observe_clock_read(tx, now, memory).await?;
    if effective.saturating_sub(persisted) > CLOCK_PERSIST_LAG {
        return observe_clock(tx, effective).await;
    }
    Ok(effective)
}

/// One clock tick's nonresetting budget, including connection, admission, COMMIT
/// and confirmed cleanup. It must fit a networked database while staying below the
/// one-second tick interval; requests never wait on it.
pub(crate) const CLOCK_CHECKPOINT_BEGIN_DEADLINE: std::time::Duration =
    std::time::Duration::from_millis(750);

pub(crate) async fn observe_clock_read(
    tx: &mut Transaction,
    now: i64,
    memory: &std::sync::atomic::AtomicI64,
) -> Result<i64> {
    use std::sync::atomic::Ordering;
    let rows = tx
        .fetch::<1>(
            "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await?;
    let previous: i64 = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("clock missing"))?[0]
        .parse()?;
    ensure!(now >= 0 && previous >= 0, "invalid clock");
    let prior = memory.fetch_max(now, Ordering::Relaxed);
    let high = previous.max(prior);
    ensure!(
        high.saturating_sub(now) <= CLOCK_ROLLBACK_TOLERANCE,
        "clock moved backwards beyond tolerance; use recover-clock with a fresh host key"
    );
    Ok(now.max(high))
}

#[cfg(test)]
mod tests;
