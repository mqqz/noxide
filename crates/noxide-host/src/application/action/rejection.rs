//! Bounded core rejection results shared by browser and headless adapters.
//! Values, identities and diagnostic error chains never enter this representation.
use anyhow::{Result, ensure};
use noxide_protocol::{Action, Change, Fields, GuardRejection};
use serde::{Deserialize, Serialize};

/// Terminal result metadata is separate from the 16 KiB job input payload.
/// This covers existing web error bounds even under maximum JSON escaping.
pub(crate) const MAX_ACTION_REJECTION_BYTES: usize = 24 * 1_024;

/// Structured action result before common host validation. It deliberately has
/// no serialization implementation; persistence accepts only the validated type.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ActionRejection {
    Rejected {
        field_errors: Fields,
        message: String,
    },
    GuardRejected {
        input: Option<String>,
        message: String,
    },
}

/// Private fields and no Deserialize implementation prevent a stored assertion
/// from becoming a validated result without the current admitted Action.
#[derive(Clone)]
pub(crate) struct ValidatedActionRejection {
    value: ActionRejection,
    encoded: String,
    action: (u32, u32),
}
impl ValidatedActionRejection {
    pub(crate) fn new(action: &Action, value: ActionRejection) -> Result<Self> {
        match &value {
            ActionRejection::Rejected {
                field_errors,
                message,
            } => {
                // Preserve the exact existing render/form limits, including an
                // empty action-level message and escaped control characters.
                ensure!(
                    message.len() <= 1_024
                        && field_errors.len() <= 8
                        && field_errors
                            .values()
                            .all(|error| !error.is_empty() && error.len() <= 256),
                    "rejection limit"
                );
                ensure!(
                    field_errors
                        .keys()
                        .all(|name| action.inputs.iter().any(|input| &input.name == name)),
                    "unexpected rejection input"
                );
            }
            ActionRejection::GuardRejected { input, message } => {
                ensure!(
                    input
                        .as_ref()
                        .is_none_or(|name| action.inputs.iter().any(|input| &input.name == name)),
                    "undeclared rejection input"
                );
                ensure!(
                    !message.is_empty()
                        && message.len() <= 256
                        && !message
                            .chars()
                            .any(|character| character.is_control()
                                && !matches!(character, '\n' | '\t')),
                    "invalid guard rejection message"
                );
                ensure!(
                    declared_guard_rejection(action, input, message),
                    "undeclared guard rejection"
                );
            }
        }
        let encoded = serde_json::to_string(&StoredRejection::from(&value))?;
        ensure!(
            encoded.len() <= MAX_ACTION_REJECTION_BYTES,
            "serialized rejection limit"
        );
        Ok(Self {
            value,
            encoded,
            action: (action.id, action.version),
        })
    }

    /// Operator inspection must supply the action associated with the captured
    /// contract, then repeat common validation before displaying stored text.
    pub(crate) fn from_stored(action: &Action, encoded: &str) -> Result<Self> {
        ensure!(
            encoded.len() <= MAX_ACTION_REJECTION_BYTES,
            "stored rejection limit"
        );
        let stored: StoredRejection = serde_json::from_str(encoded)?;
        Self::new(action, stored.into())
    }
    pub(crate) fn action(&self) -> (u32, u32) {
        self.action
    }
    pub(crate) fn as_rejection(&self) -> &ActionRejection {
        &self.value
    }
    pub(crate) fn into_rejection(self) -> ActionRejection {
        self.value
    }
    pub(crate) fn stored_json(&self) -> &str {
        &self.encoded
    }
}

fn declared_guard_rejection(action: &Action, input: &Option<String>, message: &str) -> bool {
    let matches =
        |rejection: &GuardRejection| &rejection.input == input && rejection.message == message;
    action.steps.iter().any(|step| {
        step.guards.iter().any(|guard| matches(&guard.rejection))
            || step
                .assign
                .iter()
                .any(|assignment| match &assignment.change {
                    Change::Increase { rejection, .. } | Change::Decrease { rejection, .. } => {
                        matches(rejection)
                    }
                    Change::Set(_) => false,
                })
    })
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredRejection {
    Rejected {
        #[serde(deserialize_with = "error_fields")]
        field_errors: Fields,
        message: String,
    },
    GuardRejected {
        #[serde(deserialize_with = "required_input")]
        input: Option<String>,
        message: String,
    },
}
impl From<&ActionRejection> for StoredRejection {
    fn from(value: &ActionRejection) -> Self {
        match value {
            ActionRejection::Rejected {
                field_errors,
                message,
            } => Self::Rejected {
                field_errors: field_errors.clone(),
                message: message.clone(),
            },
            ActionRejection::GuardRejected { input, message } => Self::GuardRejected {
                input: input.clone(),
                message: message.clone(),
            },
        }
    }
}
impl From<StoredRejection> for ActionRejection {
    fn from(value: StoredRejection) -> Self {
        match value {
            StoredRejection::Rejected {
                field_errors,
                message,
            } => Self::Rejected {
                field_errors,
                message,
            },
            StoredRejection::GuardRejected { input, message } => {
                Self::GuardRejected { input, message }
            }
        }
    }
}
fn required_input<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}
fn error_fields<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Fields, D::Error> {
    struct Errors;
    impl<'de> serde::de::Visitor<'de> for Errors {
        type Value = Fields;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most eight distinct rejection input names")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut fields = Fields::new();
            while let Some((name, message)) = access.next_entry::<String, String>()? {
                if fields.len() == 8 || fields.insert(name, message).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive rejection input",
                    ));
                }
            }
            Ok(fields)
        }
    }
    deserializer.deserialize_map(Errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxide_protocol::{
        Assignment, Comparison, FieldKind, Guard, GuardCondition, Input, Literal, Step, Target,
        Value,
    };

    fn action() -> Action {
        Action {
            id: 1,
            version: 1,
            name: "Bounded rejection".into(),
            targets: Vec::new(),
            inputs: (0..9)
                .map(|index| Input {
                    name: format!("field_{index}"),
                    label: "Field".into(),
                    kind: FieldKind::Text,
                    optional: false,
                    max_bytes: 256,
                })
                .collect(),
            steps: vec![Step {
                guards: vec![Guard {
                    condition: GuardCondition::Compare {
                        left: Value::Literal(Literal::Integer(0)),
                        comparison: Comparison::Less,
                        right: Value::Literal(Literal::Integer(1)),
                    },
                    rejection: GuardRejection {
                        input: None,
                        message: "Expired\nTry again.".into(),
                    },
                }],
                operation: 1,
                target: Target::None,
                assign: vec![Assignment {
                    field: "count".into(),
                    change: Change::Increase {
                        by: Value::Literal(Literal::Integer(1)),
                        rejection: GuardRejection {
                            input: Some("field_0".into()),
                            message: "Quantity too large.".into(),
                        },
                    },
                }],
            }],
        }
    }
    fn rejected(field_errors: Fields, message: String) -> ActionRejection {
        ActionRejection::Rejected {
            field_errors,
            message,
        }
    }

    #[test]
    fn maximum_web_text_with_json_escaping_fits_terminal_metadata() {
        let action = action();
        let fields = (0..8)
            .map(|index| (format!("field_{index}"), "\u{0001}".repeat(256)))
            .collect();
        let value = rejected(fields, "\u{0000}".repeat(1_024));
        let validated = ValidatedActionRejection::new(&action, value.clone()).unwrap();
        assert!(validated.stored_json().len() > 16 * 1_024);
        assert!(validated.stored_json().len() <= MAX_ACTION_REJECTION_BYTES);
        let recovered =
            ValidatedActionRejection::from_stored(&action, validated.stored_json()).unwrap();
        assert!(recovered.as_rejection() == &value);
        assert!(recovered.into_rejection() == value);
        assert!(
            ValidatedActionRejection::new(&action, rejected(Fields::new(), String::new())).is_ok()
        );
    }

    #[test]
    fn existing_field_names_counts_and_text_byte_limits_are_enforced() {
        let action = action();
        for (fields, message) in [
            (
                Fields::from([("unknown".into(), "Invalid".into())]),
                String::new(),
            ),
            (
                Fields::from([("field_0".into(), String::new())]),
                String::new(),
            ),
            (
                Fields::from([("field_0".into(), "x".repeat(257))]),
                String::new(),
            ),
            (
                (0..9)
                    .map(|index| (format!("field_{index}"), "Invalid".into()))
                    .collect(),
                String::new(),
            ),
            (Fields::new(), "x".repeat(1_025)),
            (Fields::new(), "ض".repeat(513)),
        ] {
            assert!(ValidatedActionRejection::new(&action, rejected(fields, message)).is_err());
        }
    }

    #[test]
    fn guard_rejections_preserve_optional_input_and_declared_provenance() {
        let action = action();
        for value in [
            ActionRejection::GuardRejected {
                input: None,
                message: "Expired\nTry again.".into(),
            },
            ActionRejection::GuardRejected {
                input: Some("field_0".into()),
                message: "Quantity too large.".into(),
            },
        ] {
            let validated = ValidatedActionRejection::new(&action, value.clone()).unwrap();
            assert!(
                ValidatedActionRejection::from_stored(&action, validated.stored_json())
                    .unwrap()
                    .as_rejection()
                    == &value
            );
        }
        for (input, message) in [
            (Some("unknown".into()), "Quantity too large.".into()),
            (None, String::new()),
            (None, "x".repeat(257)),
            (None, "Expired\u{0000}".into()),
            (None, "Undeclared message".into()),
            (Some("field_0".into()), "Expired\nTry again.".into()),
        ] {
            assert!(
                ValidatedActionRejection::new(
                    &action,
                    ActionRejection::GuardRejected { input, message }
                )
                .is_err()
            );
        }
    }

    #[test]
    fn stored_rejections_are_strict_bounded_and_revalidated_against_action() {
        let action = action();
        for invalid in [
            r#"{"kind":"rejected","field_errors":{},"message":"Invalid","target":1}"#,
            r#"{"kind":"rejected","field_errors":{"field_0":"first","field_0":"second"},"message":"Invalid"}"#,
            r#"{"kind":"rejected","field_errors":{"unknown":"Invalid"},"message":"Invalid"}"#,
            r#"{"kind":"guard_rejected","input":null,"message":"Undeclared"}"#,
            r#"{"kind":"guard_rejected","message":"Expired\nTry again."}"#,
            r#"{"kind":"other","message":"Invalid"}"#,
        ] {
            assert!(ValidatedActionRejection::from_stored(&action, invalid).is_err());
        }
        let validated =
            ValidatedActionRejection::new(&action, rejected(Fields::new(), "Invalid".into()))
                .unwrap();
        let oversized = format!(
            "{}{}",
            validated.stored_json(),
            " ".repeat(MAX_ACTION_REJECTION_BYTES)
        );
        assert!(ValidatedActionRejection::from_stored(&action, &oversized).is_err());
        let mut changed_action = action;
        changed_action.inputs.clear();
        let valid =
            r#"{"kind":"rejected","field_errors":{"field_0":"Invalid"},"message":"Invalid"}"#;
        assert!(ValidatedActionRejection::from_stored(&changed_action, valid).is_err());
    }
}
