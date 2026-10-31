use super::*;
use noxide_protocol::{jobs::*, time::Duration};

fn contract() -> Manifest {
    let mut m = crate::test_support::manifest();
    let service = Policy {
        any: vec![vec![
            Predicate::Service {
                worker: "repair".into(),
            },
            Predicate::SameTenant,
        ]],
    };
    let mut read = m.operations[1].clone();
    read.id = 4;
    read.policy = service;
    let mut update = read.clone();
    update.id = 5;
    update.kind = OperationKind::Update;
    m.operations.extend([read, update]);
    let mut worker = m.actions[0].clone();
    worker.id = 2;
    worker.name = "Worker".into();
    worker.targets = vec![ActionTarget {
        name: "record".into(),
        resource: 1,
        source: TargetSource::Service { eligible: 4 },
        revision: Revision::Identity,
        projection: Some(Inspection {
            operation: 4,
            fields: vec![],
        }),
        inspect: None,
    }];
    worker.steps[0].operation = 5;
    worker.steps[0].target = Target::Named("record".into());
    m.actions.push(worker);
    m.jobs = Some(JobContract {
        workers: vec![Worker {
            name: "repair".into(),
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
            worker: "repair".into(),
            action: 2,
            targets: BTreeMap::from([("record".into(), ScheduledTarget::Created(0))]),
            inputs: BTreeMap::from([("body".into(), Value::Input("body".into()))]),
            due_at: Value::TransactionTime,
        }],
        recurring: vec![],
    });
    m
}
fn sum(leaves: usize) -> Value {
    if leaves == 1 {
        Value::Input("number".into())
    } else {
        Value::Add {
            left: Box::new(sum(leaves / 2)),
            right: Box::new(sum(leaves - leaves / 2)),
        }
    }
}
fn counted() -> Manifest {
    let mut m = contract();
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
    m.actions[0].steps[0].assign.push(Assignment {
        field: "quantity".into(),
        change: Change::Set(Value::Literal(Literal::Integer(0))),
    });
    m.actions[0].inputs.push(Input {
        name: "number".into(),
        label: "Number".into(),
        kind: FieldKind::Integer {
            min: Some(0),
            max: Some(1),
        },
        optional: false,
        max_bytes: 20,
    });
    m.actions[1].inputs = vec![Input {
        name: "number".into(),
        label: "Number".into(),
        kind,
        optional: false,
        max_bytes: 20,
    }];
    m.actions[1].steps[0].assign = vec![Assignment {
        field: "quantity".into(),
        change: Change::Set(Value::Input("number".into())),
    }];
    let jobs = m.jobs.as_mut().unwrap();
    jobs.schedules[0].inputs = BTreeMap::from([("number".into(), sum(16))]);
    let mut second = jobs.schedules[0].clone();
    second.ordinal = 1;
    second.inputs.insert("number".into(), sum(15));
    jobs.schedules.push(second);
    m
}
fn recurring() -> Manifest {
    let mut m = contract();
    let mut query = m.operations.iter().find(|op| op.id == 4).unwrap().clone();
    query.id = 6;
    query.kind = OperationKind::List;
    query.list = Some(ListSettings {
        order: ListOrder::CreatedAsc,
        page_size: 3,
        preview: None,
    });
    m.operations.push(query);
    m.jobs.as_mut().unwrap().recurring.push(RecurringSchedule {
        name: "repair_tick".into(),
        worker: "repair".into(),
        action: 2,
        interval: Duration::from_millis(60_000).unwrap(),
        inputs: BTreeMap::from([("body".into(), Literal::Text("ready".into()))]),
        selection: Some(RecurringSelection {
            operation: 6,
            target: "record".into(),
            expiry_repair: false,
        }),
    });
    m
}
#[test]
fn shared_action_and_schedule_counter_and_effect_only_input() {
    let m = counted();
    super::super::validate(&m).unwrap(); // 2 step nodes + 31 + 29 + two due nodes = 64.
    let mut excessive = m.clone();
    excessive.jobs.as_mut().unwrap().schedules[1]
        .inputs
        .insert("number".into(), sum(16));
    assert!(
        super::super::validate(&excessive).is_err(),
        "each schedule cannot reset the source action's 64 nodes"
    );
    let mut unused = m;
    unused.jobs.as_mut().unwrap().schedules.clear();
    assert!(
        super::super::validate(&unused).is_err(),
        "schedule-only input must really be used"
    );
}
#[test]
fn schedules_share_expression_depth_and_refuse_current_or_principal_scalars() {
    let mut m = contract();
    let mut due = Value::TransactionTime;
    for _ in 0..7 {
        due = Value::Add {
            left: Box::new(due),
            right: Box::new(Value::Literal(Literal::Duration(
                Duration::from_millis(1).unwrap(),
            ))),
        };
    }
    m.jobs.as_mut().unwrap().schedules[0].due_at = due.clone();
    super::super::validate(&m).unwrap();
    m.jobs.as_mut().unwrap().schedules[0].due_at = Value::Add {
        left: Box::new(due),
        right: Box::new(Value::Literal(Literal::Duration(
            Duration::from_millis(1).unwrap(),
        ))),
    };
    assert!(super::super::validate(&m).is_err());
    for value in [
        Value::Principal,
        Value::CurrentField {
            target: "record".into(),
            field: "body".into(),
        },
        Value::Created(0),
        Value::Target("record".into()),
    ] {
        let mut forged = contract();
        forged.jobs.as_mut().unwrap().schedules[0]
            .inputs
            .insert("body".into(), value);
        assert!(super::super::validate(&forged).is_err());
    }
}
#[test]
fn scheduled_and_recurring_domains_are_independent_of_guest_checks() {
    let mut m = contract();
    super::super::validate(&m).unwrap();
    m.jobs.as_mut().unwrap().schedules[0].due_at = Value::Literal(Literal::Integer(1));
    assert!(super::super::validate(&m).is_err());
    let mut m = contract();
    m.jobs.as_mut().unwrap().schedules[0]
        .inputs
        .insert("body".into(), Value::Literal(Literal::Boolean(true)));
    assert!(super::super::validate(&m).is_err());
    let mut m = recurring();
    super::super::validate(&m).unwrap();
    m.jobs.as_mut().unwrap().recurring[0]
        .inputs
        .insert("body".into(), Literal::Integer(1));
    assert!(super::super::validate(&m).is_err());
}
#[test]
fn service_targets_and_maintenance_require_closed_worker_authority() {
    let mut m = contract();
    m.jobs = None;
    assert!(super::super::validate(&m).is_err());
    let mut m = contract();
    let mut web = m.web_bindings[0].clone();
    web.id = 2;
    web.action = 2;
    m.web_bindings.push(web);
    assert!(super::super::validate(&m).is_err());
    let mut m = contract();
    m.operations
        .iter_mut()
        .find(|op| op.id == 4)
        .unwrap()
        .maintenance = true;
    super::super::validate(&m).unwrap();
    m.operations
        .iter_mut()
        .find(|op| op.id == 4)
        .unwrap()
        .policy
        .any
        .push(vec![Predicate::SameTenant]);
    assert!(
        super::super::validate(&m).is_err(),
        "maintenance cannot inherit ordinary user rights"
    );
    let mut m = contract();
    m.operations[0].maintenance = true;
    assert!(
        super::super::validate(&m).is_err(),
        "maintenance cannot be an ordinary route operation"
    );
    let mut m = contract();
    m.jobs.as_mut().unwrap().schedules[0].source_action = 2;
    m.jobs.as_mut().unwrap().schedules[0]
        .targets
        .insert("record".into(), ScheduledTarget::Target("record".into()));
    assert!(
        super::super::validate(&m).is_err(),
        "guest scheduling graph cannot cycle"
    );
}
#[test]
fn recurring_selection_is_the_narrow_indexed_service_contract() {
    for extra in [
        Predicate::Owner,
        Predicate::Role {
            name: "admin".into(),
            tenant_scoped: false,
        },
    ] {
        let mut m = recurring();
        m.operations
            .iter_mut()
            .find(|op| op.id == 6)
            .unwrap()
            .policy
            .any[0]
            .push(extra);
        assert!(super::super::validate(&m).is_err());
    }
    let mut m = recurring();
    m.operations.iter_mut().find(|op| op.id == 6).unwrap().query =
        Some(noxide_protocol::query::Query {
            search: Some(noxide_protocol::query::Search {
                fields: vec!["body".into()],
                parameter: "terms".into(),
            }),
            ..Default::default()
        });
    assert!(super::super::validate(&m).is_err());
    let mut m = recurring();
    m.jobs.as_mut().unwrap().recurring[0]
        .selection
        .as_mut()
        .unwrap()
        .expiry_repair = true;
    assert!(super::super::validate(&m).is_err());
}
