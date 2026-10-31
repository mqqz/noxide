//! Actual issued provider statements; supplements every existing semantic budget.
use super::*;

pub(in crate::database) const ORDINARY_SQLITE_STARTUP: u16 = 3;
#[cfg(test)]
pub(in crate::database) const BOOTSTRAP_SQLITE_STARTUP: u16 = 4;
pub(in crate::database) const POSTGRES_CLEANUP: u16 = 40;

#[derive(Debug)]
pub(crate) struct StatementLimit;
impl std::fmt::Display for StatementLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("actual database statement budget exhausted")
    }
}
impl std::error::Error for StatementLimit {}

struct State {
    free: u16,
    reserved: u16,
    spent: u16,
    #[cfg(test)]
    cleanup_charged: u16,
}
pub(in crate::database) struct Meter(Mutex<State>);
impl Meter {
    pub(super) fn new(limit: u16) -> Arc<Self> {
        assert!(
            (1..=256).contains(&limit),
            "host statement limit outside approved bound"
        );
        Arc::new(Self(Mutex::new(State {
            free: limit,
            reserved: 0,
            spent: 0,
            #[cfg(test)]
            cleanup_charged: 0,
        })))
    }
    pub(in crate::database) fn charge(&self, statements: u16) -> Result<()> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(state.free >= statements, StatementLimit);
        state.free -= statements;
        state.spent += statements;
        Ok(())
    }
    pub(super) fn reserve(self: &Arc<Self>, statements: u16) -> Result<Arc<Cleanup>> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(state.free >= statements, StatementLimit);
        state.free -= statements;
        state.reserved += statements;
        Ok(Arc::new(Cleanup {
            meter: self.clone(),
            remaining: Mutex::new(statements),
        }))
    }
    pub(super) fn remaining_work(&self) -> u16 {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .free
    }
    #[cfg(test)]
    pub(super) fn cleanup_charged(&self) -> u16 {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cleanup_charged
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> (u16, u16, u16) {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        (state.free, state.reserved, state.spent)
    }
}

/// One provider's protected portion of the root's same finite total. No refund
/// occurs on Drop: uncertainty cannot mint units or fund replacement work.
pub(in crate::database) struct Cleanup {
    meter: Arc<Meter>,
    remaining: Mutex<u16>,
}
impl Cleanup {
    pub(in crate::database) fn belongs_to(&self, meter: &Arc<Meter>) -> bool {
        Arc::ptr_eq(&self.meter, meter)
    }
    pub(in crate::database) fn charge(&self, statements: u16) -> Result<()> {
        let mut remaining = self.remaining.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(*remaining >= statements, StatementLimit);
        let mut state = self.meter.0.lock().unwrap_or_else(|e| e.into_inner());
        *remaining -= statements;
        state.reserved -= statements;
        state.spent += statements;
        #[cfg(test)]
        {
            state.cleanup_charged += statements;
        }
        Ok(())
    }
    pub(super) fn confirmed(&self) {
        let mut remaining = self.remaining.lock().unwrap_or_else(|e| e.into_inner());
        let mut state = self.meter.0.lock().unwrap_or_else(|e| e.into_inner());
        state.free += *remaining;
        state.reserved -= *remaining;
        *remaining = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_units_never_refund_consumed_work() {
        let meter = Meter::new(50);
        let cleanup = meter.reserve(40).unwrap();
        meter.charge(10).unwrap();
        assert!(meter.charge(1).is_err());
        cleanup.charge(7).unwrap();
        assert_eq!(meter.snapshot(), (0, 33, 17));
        cleanup.confirmed();
        assert_eq!(meter.snapshot(), (33, 0, 17));
        meter.charge(33).unwrap();
        assert!(meter.charge(1).is_err());
        assert_eq!(meter.snapshot(), (0, 0, 50));
        assert_eq!(BOOTSTRAP_SQLITE_STARTUP, ORDINARY_SQLITE_STARTUP + 1);
    }
    #[test]
    fn uncertain_drop_and_foreign_root_cannot_fund_work() {
        let first = Meter::new(50);
        let second = Meter::new(50);
        let cleanup = first.reserve(40).unwrap();
        assert!(cleanup.belongs_to(&first));
        assert!(!cleanup.belongs_to(&second));
        cleanup.charge(1).unwrap();
        drop(cleanup);
        assert_eq!(first.snapshot(), (10, 39, 1));
        assert!(first.charge(11).is_err());
    }
}
