//! Constant-work arithmetic after the caller's current row authorization.
//! No SQL, field loading, policy evaluation, clock or work owner is created here.
use noxide_protocol::{
    query::{AggregateValue, MAX_AGGREGATE_CANDIDATES, MAX_SEARCH_CANDIDATES, QueryError},
    time::Timestamp,
};

#[derive(Clone, Copy)]
pub enum Kind {
    Count,
    Sum,
    MinInteger,
    MaxInteger,
    MinTimestamp,
    MaxTimestamp,
}
/// Construct this only after current authorization, AND/selection and scope.
pub enum AuthorizedOperand {
    Count,
    Integer(i64),
    Timestamp(Timestamp),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    LimitExceeded,
    Overflow,
    InvalidOperand,
}
impl Error {
    pub fn wire(self) -> Option<QueryError> {
        match self {
            Self::LimitExceeded => Some(QueryError::LimitExceeded),
            Self::Overflow => Some(QueryError::Overflow),
            Self::InvalidOperand => None,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LimitExceeded => "aggregate candidate limit",
            Self::Overflow => "aggregate overflow",
            Self::InvalidOperand => "aggregate operand kind",
        })
    }
}
impl std::error::Error for Error {}

pub struct Scan {
    kind: Kind,
    limit: usize,
    seen: usize,
    count: u64,
    sum: i128,
    extreme: Option<i64>,
    failed: Option<Error>,
}
impl Scan {
    pub fn ordinary(kind: Kind) -> Self {
        Self::with_limit(kind, MAX_AGGREGATE_CANDIDATES)
    }
    /// This is a local stricter cap, not a new allowance. The executor must also
    /// charge its existing shared request search frontier before visiting rows.
    pub fn search(kind: Kind, remaining_search: usize) -> Result<Self, Error> {
        if remaining_search > MAX_SEARCH_CANDIDATES {
            return Err(Error::LimitExceeded);
        }
        Ok(Self::with_limit(kind, remaining_search))
    }
    fn with_limit(kind: Kind, limit: usize) -> Self {
        Self {
            kind,
            limit,
            seen: 0,
            count: 0,
            sum: 0,
            extreme: None,
            failed: None,
        }
    }
    /// Every seeded candidate, including hidden/nonmatching rows, visits once.
    /// A None operand exposes no field values and contributes nothing.
    /// The bounded lookahead visits too: it poisons any previously computed sum.
    pub fn visit(&mut self, authorized: Option<AuthorizedOperand>) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let result = self.visit_inner(authorized);
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }
    fn visit_inner(&mut self, authorized: Option<AuthorizedOperand>) -> Result<(), Error> {
        if self.seen == self.limit {
            return Err(Error::LimitExceeded);
        }
        self.seen += 1;
        let Some(operand) = authorized else {
            return Ok(());
        };
        match (self.kind, operand) {
            (Kind::Count, AuthorizedOperand::Count) => {
                self.count = self.count.checked_add(1).ok_or(Error::Overflow)?;
            }
            (Kind::Sum, AuthorizedOperand::Integer(value)) => {
                self.sum = self
                    .sum
                    .checked_add(i128::from(value))
                    .ok_or(Error::Overflow)?;
            }
            (Kind::MinInteger, AuthorizedOperand::Integer(value))
            | (Kind::MaxInteger, AuthorizedOperand::Integer(value)) => self.extreme(value),
            (Kind::MinTimestamp, AuthorizedOperand::Timestamp(value))
            | (Kind::MaxTimestamp, AuthorizedOperand::Timestamp(value)) => {
                self.extreme(value.unix_millis());
            }
            _ => return Err(Error::InvalidOperand),
        }
        Ok(())
    }
    fn extreme(&mut self, value: i64) {
        self.extreme = Some(self.extreme.map_or(value, |current| match self.kind {
            Kind::MinInteger | Kind::MinTimestamp => current.min(value),
            _ => current.max(value),
        }));
    }
    /// Only a proven exhausted source can produce a value. No partial getter
    /// exists. The executor's bounded lookahead must establish this argument.
    pub fn finish(self, exhausted: bool) -> Result<AggregateValue, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if !exhausted {
            return Err(Error::LimitExceeded);
        }
        Ok(match self.kind {
            Kind::Count => AggregateValue::Count(self.count),
            Kind::Sum => AggregateValue::Sum(self.sum.try_into().map_err(|_| Error::Overflow)?),
            Kind::MinInteger | Kind::MaxInteger => AggregateValue::Integer(self.extreme),
            Kind::MinTimestamp | Kind::MaxTimestamp => AggregateValue::Timestamp(
                self.extreme
                    .map(Timestamp::from_unix_millis)
                    .transpose()
                    .map_err(|_| Error::InvalidOperand)?,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum_cancellation_is_independent_of_scan_order_and_final_range_is_checked() {
        for values in [
            [i64::MAX, i64::MAX, -i64::MAX],
            [i64::MAX, -i64::MAX, i64::MAX],
            [-i64::MAX, i64::MAX, i64::MAX],
        ] {
            let mut scan = Scan::ordinary(Kind::Sum);
            for value in values {
                scan.visit(Some(AuthorizedOperand::Integer(value))).unwrap();
            }
            assert_eq!(scan.finish(true), Ok(AggregateValue::Sum(i64::MAX)));
        }
        for values in [[i64::MAX, 1], [i64::MIN, -1]] {
            let mut scan = Scan::ordinary(Kind::Sum);
            for value in values {
                scan.visit(Some(AuthorizedOperand::Integer(value))).unwrap();
            }
            assert_eq!(scan.finish(true), Err(Error::Overflow));
        }
    }

    #[test]
    fn empty_sources_and_authorized_only_extrema_have_exact_types() {
        for (kind, expected) in [
            (Kind::Count, AggregateValue::Count(0)),
            (Kind::Sum, AggregateValue::Sum(0)),
            (Kind::MinInteger, AggregateValue::Integer(None)),
            (Kind::MaxInteger, AggregateValue::Integer(None)),
            (Kind::MinTimestamp, AggregateValue::Timestamp(None)),
            (Kind::MaxTimestamp, AggregateValue::Timestamp(None)),
        ] {
            let mut scan = Scan::ordinary(kind);
            scan.visit(None).unwrap();
            assert_eq!(scan.finish(true), Ok(expected));
        }
        for (kind, expected) in [(Kind::MinInteger, -3), (Kind::MaxInteger, 9)] {
            let mut scan = Scan::ordinary(kind);
            for value in [9, -3, 2] {
                scan.visit(Some(AuthorizedOperand::Integer(value))).unwrap();
            }
            assert_eq!(
                scan.finish(true),
                Ok(AggregateValue::Integer(Some(expected)))
            );
        }
        for (kind, millis) in [(Kind::MinTimestamp, 0), (Kind::MaxTimestamp, 10)] {
            let mut scan = Scan::ordinary(kind);
            for millis in [10, 0, 2] {
                scan.visit(Some(AuthorizedOperand::Timestamp(
                    Timestamp::from_unix_millis(millis).unwrap(),
                )))
                .unwrap();
            }
            assert_eq!(
                scan.finish(true),
                Ok(AggregateValue::Timestamp(Some(
                    Timestamp::from_unix_millis(millis).unwrap()
                )))
            );
        }
    }

    #[test]
    fn first_candidate_past_1000_or_unproven_completion_never_returns_partial_values() {
        let mut exact = Scan::ordinary(Kind::Count);
        for _ in 0..1_000 {
            exact.visit(Some(AuthorizedOperand::Count)).unwrap();
        }
        assert_eq!(exact.finish(true), Ok(AggregateValue::Count(1_000)));
        let mut more = Scan::ordinary(Kind::Count);
        for _ in 0..1_000 {
            more.visit(Some(AuthorizedOperand::Count)).unwrap();
        }
        assert_eq!(more.visit(None), Err(Error::LimitExceeded));
        assert_eq!(more.finish(true), Err(Error::LimitExceeded));
        assert_eq!(
            Scan::ordinary(Kind::Sum).finish(false),
            Err(Error::LimitExceeded)
        );
    }

    #[test]
    fn search_is_capped_before_general_aggregate_limit_and_no_failure_is_refunded() {
        let mut scan = Scan::search(Kind::Count, 2).unwrap();
        scan.visit(None).unwrap();
        scan.visit(Some(AuthorizedOperand::Count)).unwrap();
        assert_eq!(scan.visit(None), Err(Error::LimitExceeded));
        assert_eq!(scan.finish(true), Err(Error::LimitExceeded));
        assert!(Scan::search(Kind::Count, 257).is_err());
        let mut maximum = Scan::search(Kind::Count, 256).unwrap();
        for _ in 0..256 {
            maximum.visit(None).unwrap();
        }
        assert_eq!(maximum.visit(None), Err(Error::LimitExceeded));
        assert_eq!(maximum.finish(true), Err(Error::LimitExceeded));
        let mut wrong = Scan::ordinary(Kind::Sum);
        assert_eq!(
            wrong.visit(Some(AuthorizedOperand::Count)),
            Err(Error::InvalidOperand)
        );
        assert_eq!(wrong.visit(None), Err(Error::InvalidOperand));
        assert_eq!(wrong.finish(true), Err(Error::InvalidOperand));
        assert_eq!(Error::InvalidOperand.wire(), None);
        assert_eq!(Error::LimitExceeded.wire(), Some(QueryError::LimitExceeded));
        assert_eq!(Error::Overflow.wire(), Some(QueryError::Overflow));
    }
}
