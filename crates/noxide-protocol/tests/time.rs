// This path inclusion also exercises the leaf before central root registration.
#[path = "../src/time.rs"]
mod time;
use time::{Duration, TimeError, Timestamp};

#[test]
fn seconds_and_milliseconds_have_explicit_checked_boundaries() {
    let timestamp = Timestamp::from_unix_seconds(1_700_000_001).unwrap();
    assert_eq!(timestamp.unix_millis(), 1_700_000_001_000);
    assert_eq!(timestamp.unix_seconds_floor(), 1_700_000_001);
    let fractional = Timestamp::from_unix_millis(1_700_000_001_999).unwrap();
    assert_eq!(fractional.unix_seconds_floor(), 1_700_000_001);
    assert_eq!(Timestamp::from_unix_seconds(-1), Err(TimeError::Negative));
    assert_eq!(
        Timestamp::from_unix_seconds(i64::MAX),
        Err(TimeError::Overflow)
    );
    assert_eq!(Duration::from_secs(i64::MAX), Err(TimeError::Overflow));
}

#[test]
fn timestamp_arithmetic_cannot_wrap_or_go_before_epoch() {
    let maximum = Timestamp::from_unix_millis(i64::MAX).unwrap();
    let one = Duration::from_millis(1).unwrap();
    assert_eq!(maximum.checked_add(one), Err(TimeError::Overflow));
    assert_eq!(
        Timestamp::UNIX_EPOCH.checked_sub(one),
        Err(TimeError::Negative)
    );
    assert_eq!(
        Timestamp::UNIX_EPOCH.duration_since(maximum),
        Err(TimeError::Negative)
    );
    assert_eq!(
        maximum
            .duration_since(Timestamp::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
        i64::MAX
    );
    assert_eq!(
        Timestamp::UNIX_EPOCH.checked_add(Duration::ZERO).unwrap(),
        Timestamp::UNIX_EPOCH
    );
}

#[test]
fn wire_values_reject_negative_fractional_and_out_of_range_values() {
    for invalid in ["-1", "1.2", "9223372036854775808", "null", "\"1000\""] {
        assert!(
            serde_json::from_str::<Timestamp>(invalid).is_err(),
            "{invalid}"
        );
        assert!(
            serde_json::from_str::<Duration>(invalid).is_err(),
            "{invalid}"
        );
    }
    let timestamp: Timestamp = serde_json::from_str("1001").unwrap();
    assert_eq!(serde_json::to_string(&timestamp).unwrap(), "1001");
    let duration: Duration = serde_json::from_str("1001").unwrap();
    assert_eq!(serde_json::to_string(&duration).unwrap(), "1001");
}

#[test]
fn wall_sampling_floors_fraction_but_duration_conversion_is_lossless() {
    use std::time::{Duration as StdDuration, SystemTime};
    let wall = SystemTime::UNIX_EPOCH + StdDuration::from_nanos(1_999_999);
    assert_eq!(Timestamp::from_system_time(wall).unwrap().unix_millis(), 1);
    assert_eq!(
        Timestamp::from_system_time(SystemTime::UNIX_EPOCH - StdDuration::from_nanos(1)),
        Err(TimeError::BeforeEpoch)
    );
    assert_eq!(
        Duration::try_from(StdDuration::from_nanos(1)),
        Err(TimeError::PrecisionLoss)
    );
    assert_eq!(
        Duration::try_from(StdDuration::from_secs(u64::MAX)),
        Err(TimeError::Overflow)
    );
    let duration = Duration::from_secs(123).unwrap();
    assert_eq!(StdDuration::from(duration), StdDuration::from_secs(123));
}
