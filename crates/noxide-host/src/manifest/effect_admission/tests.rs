use super::*;
use noxide_protocol::{jobs::*, time::Duration};
use std::collections::BTreeMap;
fn field(name: &str, kind: FieldKind, width: u32, value: Value) -> PayloadField {
    PayloadField {
        schema: Input {
            name: name.into(),
            label: name.into(),
            kind,
            optional: false,
            max_bytes: width,
        },
        value,
    }
}
fn fixture() -> Manifest {
    let mut m = crate::test_support::manifest();
    m.actions[0].inputs.push(Input {
        name: "caption".into(),
        label: "Caption".into(),
        kind: FieldKind::Text,
        optional: true,
        max_bytes: 64,
    });
    let mut caption = field(
        "caption",
        FieldKind::Text,
        64,
        Value::Input("caption".into()),
    );
    caption.schema.optional = true;
    m.effects = Some(EffectContract {
        endpoints: vec![
            EffectEndpoint {
                name: "events".into(),
                secret_slot: Some("token".into()),
            },
            EffectEndpoint {
                name: "audit".into(),
                secret_slot: None,
            },
        ],
        emissions: vec![EmitEffect {
            source_action: 1,
            ordinal: 0,
            endpoint: "events".into(),
            fields: vec![
                field(
                    "message",
                    FieldKind::Text,
                    4096,
                    Value::Input("body".into()),
                ),
                field(
                    "actor",
                    FieldKind::Account {
                        scope: AccountScope::SameTenant,
                    },
                    43,
                    Value::Principal,
                ),
                field(
                    "record",
                    FieldKind::Reference {
                        resource: "notes".into(),
                    },
                    19,
                    Value::Created(0),
                ),
                field("at", FieldKind::Timestamp, 20, Value::TransactionTime),
                caption,
            ],
        }],
    });
    m
}
fn admitted(m: &Manifest) -> Result<()> {
    validate(m)?;
    for action in &m.actions {
        super::super::validate_action(m, action)?;
    }
    super::super::job_admission::validate(m)
}
fn hash(m: &Manifest) -> [u8; 32] {
    admitted(m).unwrap();
    let mut canonical = m.clone();
    super::super::canonical_effects(&mut canonical);
    Sha256::digest(serde_json::to_vec(&canonical).unwrap()).into()
}
#[test]
fn explicit_identity_and_optional_disclosures_pass_independent_admission() {
    let m = fixture();
    admitted(&m).unwrap();
    super::super::validate(&m).unwrap();
    let summary = disclosures(&m, 1).unwrap();
    assert!(summary.iter().any(|entry| entry.field.kind
        == FieldKind::Account {
            scope: AccountScope::SameTenant
        }
        && entry.sources == [EffectSource::Principal]));
    assert!(summary.iter().any(
        |entry| matches!(entry.field.kind, FieldKind::Reference { .. })
            && entry.sources == [EffectSource::Created { step: 0 }]
    ));
    assert!(summary.iter().any(|entry| entry.field.name == "caption"
        && entry.field.optional
        && entry.sources
            == [EffectSource::Input {
                name: "caption".into()
            }]));
}
#[test]
fn canonical_field_endpoint_order_is_not_authority_but_every_mapping_is() {
    let mut m = fixture();
    let mut second = m.effects.as_ref().unwrap().emissions[0].clone();
    second.ordinal = 1;
    second.endpoint = "audit".into();
    m.effects.as_mut().unwrap().emissions.push(second);
    let expected = hash(&m);
    let mut reordered = m.clone();
    let effects = reordered.effects.as_mut().unwrap();
    effects.endpoints.reverse();
    effects.emissions.reverse();
    for emission in &mut effects.emissions {
        emission.fields.reverse();
    }
    assert_eq!(hash(&reordered), expected);
    for changed in 0..4 {
        let mut other = m.clone();
        let effects = other.effects.as_mut().unwrap();
        match changed {
            0 => effects.endpoints[0].secret_slot = Some("replacement".into()),
            1 => effects.emissions[0].endpoint = "audit".into(),
            2 => effects.emissions[0].fields[4].schema.max_bytes = 128,
            _ => {
                effects.emissions[0].fields[0].value =
                    Value::Literal(Literal::Text("different".into()))
            }
        }
        assert_ne!(hash(&other), expected);
    }
}
#[test]
fn forged_names_limits_kinds_and_domains_fail_closed() {
    for forged in 0..9 {
        let mut m = fixture();
        let effects = m.effects.as_mut().unwrap();
        match forged {
            0 => effects.endpoints.push(effects.endpoints[0].clone()),
            1 => effects.emissions.push(effects.emissions[0].clone()),
            2 => effects.emissions[0].ordinal = 2,
            3 => effects.emissions[0].endpoint = "unknown".into(),
            4 => {
                let duplicate = effects.emissions[0].fields[0].clone();
                effects.emissions[0].fields.push(duplicate);
            }
            5 => effects.emissions[0].fields[0].schema.kind = FieldKind::Blob { max_bytes: 10 },
            6 => {
                effects.emissions[0].fields[0].schema.kind =
                    FieldKind::UploadHandle { max_bytes: 10 }
            }
            7 => effects.emissions[0].fields[0].schema.max_bytes = 8,
            _ => {
                effects.emissions[0].fields[2].schema.kind = FieldKind::Reference {
                    resource: "other".into(),
                }
            }
        }
        assert!(admitted(&m).is_err());
    }
}
#[test]
fn snapshot_sources_require_current_eligible_projection_and_review_binding() {
    let mut m = fixture();
    m.routes[0].forms.clear();
    m.routes[1].forms.push(1);
    m.actions[0].targets = vec![ActionTarget {
        name: "record".into(),
        resource: 1,
        source: TargetSource::Page { reads: vec![2] },
        revision: Revision::Identity,
        projection: Some(Inspection {
            operation: 2,
            fields: vec!["body".into()],
        }),
        inspect: None,
    }];
    m.effects.as_mut().unwrap().emissions[0].fields[0].value = Value::SnapshotField {
        target: "record".into(),
        field: "body".into(),
        reviewed: false,
    };
    admitted(&m).unwrap();
    let summary = disclosures(&m, 1).unwrap();
    assert!(summary.iter().any(|entry| entry.sources
        == [EffectSource::Snapshot {
            target: "record".into(),
            field: "body".into(),
            read: 2,
            reviewed: false
        }]));
    let mut hidden = m.clone();
    hidden.actions[0].targets[0]
        .projection
        .as_mut()
        .unwrap()
        .fields
        .clear();
    assert!(admitted(&hidden).is_err());
    let mut current = m.clone();
    current.effects.as_mut().unwrap().emissions[0].fields[0].value = Value::CurrentField {
        target: "record".into(),
        field: "body".into(),
    };
    assert!(admitted(&current).is_err());
    m.effects.as_mut().unwrap().emissions[0].fields[0].value = Value::SnapshotField {
        target: "record".into(),
        field: "body".into(),
        reviewed: true,
    };
    assert!(admitted(&m).is_err());
    m.actions[0].targets[0].revision = Revision::Exact;
    admitted(&m).unwrap();
}
fn sum(leaves: usize) -> Value {
    if leaves == 1 {
        Value::Input("quantity".into())
    } else {
        Value::Add {
            left: Box::new(sum(leaves / 2)),
            right: Box::new(sum(leaves - leaves / 2)),
        }
    }
}
#[test]
fn steps_jobs_and_effects_share_the_same_sixty_four_nodes() {
    let mut m = fixture();
    m.actions[0].inputs.retain(|input| input.name != "caption");
    let kind = FieldKind::Integer {
        min: Some(0),
        max: Some(1000),
    };
    m.resources[0].fields.push(TextField {
        immutable: false,
        name: "quantity".into(),
        label: "Quantity".into(),
        kind: kind.clone(),
        optional: false,
        initial: None,
        max_bytes: 20,
    });
    m.actions[0].inputs.push(Input {
        name: "quantity".into(),
        label: "Quantity".into(),
        kind: FieldKind::Integer {
            min: Some(0),
            max: Some(1),
        },
        optional: false,
        max_bytes: 20,
    });
    m.actions[0].steps[0].assign.push(Assignment {
        field: "quantity".into(),
        change: Change::Set(Value::Input("quantity".into())),
    });
    let mut read = m.operations[1].clone();
    read.id = 4;
    read.policy = Policy {
        any: vec![vec![
            Predicate::Service {
                worker: "worker".into(),
            },
            Predicate::SameTenant,
        ]],
    };
    let mut update = read.clone();
    update.id = 5;
    update.kind = OperationKind::Update;
    m.operations.extend([read, update]);
    m.actions.push(Action {
        id: 2,
        version: 1,
        name: "Worker".into(),
        inputs: vec![Input {
            name: "quantity".into(),
            label: "Quantity".into(),
            kind: kind.clone(),
            optional: false,
            max_bytes: 20,
        }],
        targets: vec![ActionTarget {
            name: "record".into(),
            resource: 1,
            source: TargetSource::Service { eligible: 4 },
            revision: Revision::Identity,
            projection: Some(Inspection {
                operation: 4,
                fields: vec![],
            }),
            inspect: None,
        }],
        steps: vec![Step {
            operation: 5,
            target: Target::Named("record".into()),
            guards: vec![],
            assign: vec![Assignment {
                field: "quantity".into(),
                change: Change::Set(Value::Input("quantity".into())),
            }],
        }],
    });
    m.jobs = Some(JobContract {
        workers: vec![Worker {
            name: "worker".into(),
            actions: vec![WorkerAction {
                action: 2,
                targets: BTreeMap::from([(
                    "record".into(),
                    WorkerTarget {
                        resource: 1,
                        eligible: 4,
                    },
                )]),
            }],
        }],
        schedules: vec![Schedule {
            source_action: 1,
            ordinal: 0,
            worker: "worker".into(),
            action: 2,
            targets: BTreeMap::from([("record".into(), ScheduledTarget::Created(0))]),
            inputs: BTreeMap::from([("quantity".into(), sum(16))]),
            due_at: Value::TransactionTime,
        }],
        recurring: vec![],
    });
    m.effects.as_mut().unwrap().emissions[0].fields = vec![
        field("quantity", kind.clone(), 20, sum(15)),
        field(
            "flag",
            FieldKind::Boolean,
            5,
            Value::Literal(Literal::Boolean(true)),
        ),
    ];
    admitted(&m).unwrap(); // steps 2 + job 32 + emit 30 = 64, including effect-only data.
    m.effects.as_mut().unwrap().emissions[0].fields[0].value = sum(16);
    assert!(admitted(&m).is_err());
}
#[test]
fn effect_depth_uses_existing_eight_level_limit() {
    let mut m = fixture();
    let mut value = Value::TransactionTime;
    for _ in 0..7 {
        value = Value::Add {
            left: Box::new(value),
            right: Box::new(Value::Literal(Literal::Duration(
                Duration::from_millis(1).unwrap(),
            ))),
        };
    }
    m.effects.as_mut().unwrap().emissions[0].fields[3].value = value.clone();
    admitted(&m).unwrap();
    m.effects.as_mut().unwrap().emissions[0].fields[3].value = Value::Add {
        left: Box::new(value),
        right: Box::new(Value::Literal(Literal::Duration(
            Duration::from_millis(1).unwrap(),
        ))),
    };
    assert!(admitted(&m).is_err());
}
