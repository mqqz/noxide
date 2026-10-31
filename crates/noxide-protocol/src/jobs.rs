//! Declarative background actions. Declarations request authority; the host and
//! operator's current deployment/tenant grant remain authoritative.
use crate::{Value, computation::Literal, time::Duration};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_SCHEDULES_PER_ACTION: usize = 2;
pub const MAX_PENDING_JOBS: u16 = 1_000;
pub const MAX_JOB_BYTES: usize = 16_384;
pub const MAX_SCHEDULE_HORIZON_MILLIS: i64 = 30 * 24 * 60 * 60 * 1_000;
pub const MIN_RECURRENCE_MILLIS: i64 = 60_000;
pub const MAX_RECURRENCE_FANOUT: u8 = 20;
pub const JOB_LEASE_MILLIS: i64 = 30_000;
pub const MAX_JOB_ATTEMPTS: u8 = 5;
pub const JOB_RETRY_WINDOW_MILLIS: i64 = 24 * 60 * 60 * 1_000;
pub const MAX_WORKERS_PER_APP: u8 = 2;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobContract {
    pub workers: Vec<Worker>,
    pub schedules: Vec<Schedule>,
    pub recurring: Vec<RecurringSchedule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Worker {
    pub name: String,
    pub actions: Vec<WorkerAction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAction {
    pub action: u32,
    /// Exact independently read-authorized target bindings, keyed by action alias.
    #[serde(deserialize_with = "bounded_map")]
    pub targets: BTreeMap<String, WorkerTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerTarget {
    pub resource: u32,
    pub eligible: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub source_action: u32,
    /// Stable effect position, not an execution attempt number.
    pub ordinal: u8,
    pub worker: String,
    pub action: u32,
    #[serde(deserialize_with = "bounded_map")]
    pub targets: BTreeMap<String, ScheduledTarget>,
    #[serde(deserialize_with = "bounded_map")]
    pub inputs: BTreeMap<String, Value>,
    /// Evaluated once against the originating transaction's fixed lifecycle time.
    pub due_at: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ScheduledTarget {
    Target(String),
    Created(u8),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecurringSchedule {
    pub name: String,
    pub worker: String,
    pub action: u32,
    pub interval: Duration,
    #[serde(deserialize_with = "bounded_map")]
    pub inputs: BTreeMap<String, Literal>,
    /// A declared indexed query evaluated under this service's current authority.
    /// None supports target-free maintenance actions only.
    pub selection: Option<RecurringSelection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecurringSelection {
    pub operation: u32,
    pub target: String,
    /// Explicit repair deduplication by target incarnation and expiry value.
    pub expiry_repair: bool,
}

fn bounded_map<'de, D, T>(deserializer: D) -> Result<BTreeMap<String, T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Unique<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Unique<T> {
        type Value = BTreeMap<String, T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 32 distinct canonical names")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = BTreeMap::new();
            while let Some((name, value)) = access.next_entry::<String, T>()? {
                if !crate::identifier(&name)
                    || values.len() == 32
                    || values.insert(name, value).is_some()
                {
                    return Err(serde::de::Error::custom(
                        "duplicate, invalid or excessive job map key",
                    ));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_binding_and_input_keys_fail_closed() {
        assert!(serde_json::from_str::<WorkerAction>(r#"{"action":1,"targets":{"row":{"resource":1,"eligible":2},"row":{"resource":2,"eligible":3}}}"#).is_err());
        assert!(serde_json::from_str::<RecurringSchedule>(r#"{"name":"repair","worker":"worker","action":1,"interval":60000,"inputs":{"x":{"integer":1},"x":{"integer":2}},"selection":null}"#).is_err());
    }
    #[test]
    fn unknown_authority_fields_fail_closed() {
        for value in [
            r#"{"name":"worker","actions":[],"run_as_user":"alice"}"#,
            r#"{"action":1,"targets":{},"tenant":"any"}"#,
        ] {
            assert!(serde_json::from_str::<Worker>(value).is_err());
        }
        assert!(
            serde_json::from_str::<ScheduledTarget>(r#"{"created":0,"browser_cookie":"secret"}"#)
                .is_err()
        );
    }
}
