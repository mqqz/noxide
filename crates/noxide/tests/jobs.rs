//! Public SDK lowering only; host execution authority is independently admitted.
#![allow(clippy::too_many_lines)]
use noxide::__private::{Action, Operation, OperationKind, Policy, Predicate, Revision, Target};
use noxide::{
    ActionType, ApplicationDefinition, CalculatedStep, Duration, Id, IntoActionResponse,
    JobContract, QueryType, RecurringSchedule, RecurringSelection, RequestKind, RequestView,
    Resource, ResourceType, ResponseIntent, Schedule, ScheduledTarget, Submission,
    TargetDeclarations, Timestamp, Worker, WorkerAction, WorkerTarget, guards, query, values,
};
use std::collections::BTreeMap;

#[derive(Resource)]
#[resource(key = "scheduled_tasks")]
pub struct Task {
    #[id]
    pub id: Id<Self>,
    #[field()]
    pub pending: bool,
    #[field()]
    pub at: Timestamp,
}
#[query(read(Task), allow = all(service("repair"), same_tenant))]
struct ReadTask;
#[query(list(Task), allow = all(service("repair"), same_tenant), page_size = 20)]
struct TaskCandidates;

struct CreateTask;
impl ActionType for CreateTask {
    type Resource = Task;
    type Input = ();
    type Original = ();
    fn definition() -> Action {
        Action {
            id: 1,
            version: 1,
            name: "Create task".into(),
            targets: vec![],
            inputs: vec![],
            steps: vec![
                CalculatedStep::new(2, Target::None)
                    .set("pending", values::boolean(true))
                    .set("at", values::transaction_time())
                    .finish(),
            ],
        }
    }
    fn operations() -> Vec<Operation> {
        let mut operation = ReadTask::operation();
        operation.id = 2;
        operation.kind = OperationKind::Create;
        operation.policy = Policy {
            any: vec![vec![Predicate::Owner]],
        };
        vec![operation]
    }
}

fn service_targets() -> TargetDeclarations {
    TargetDeclarations::new().service::<ReadTask>("task", Revision::Identity, &["pending"])
}
struct FinishTask;
impl ActionType for FinishTask {
    type Resource = Task;
    type Input = ();
    type Original = ();
    fn definition() -> Action {
        Action {
            id: 3,
            version: 1,
            name: "Finish task".into(),
            targets: service_targets().targets,
            inputs: vec![],
            steps: vec![
                CalculatedStep::new(4, Target::Named("task".into()))
                    .guard(guards::require(
                        guards::equal(values::current("task", "pending"), values::boolean(true)),
                        None,
                        "Already finished",
                    ))
                    .set("pending", values::boolean(false))
                    .finish(),
            ],
        }
    }
    fn operations() -> Vec<Operation> {
        let mut declarations = service_targets();
        let mut update = ReadTask::operation();
        update.id = 4;
        update.kind = OperationKind::Update;
        declarations.operations.push(update);
        declarations.operations
    }
}

#[test]
fn explicit_jobs_lower_without_web_bindings_or_placeholder_inputs() {
    let resource = Task::definition();
    let read = ReadTask::operation();
    let selection = TaskCandidates::operation();
    assert_eq!(
        read.policy.any,
        vec![vec![
            Predicate::Service {
                worker: "repair".into()
            },
            Predicate::SameTenant
        ]]
    );
    let jobs = JobContract {
        workers: vec![Worker {
            name: "repair".into(),
            actions: vec![WorkerAction {
                action: 3,
                targets: BTreeMap::from([(
                    "task".into(),
                    WorkerTarget {
                        resource: resource.id,
                        eligible: read.id,
                    },
                )]),
            }],
        }],
        schedules: vec![Schedule {
            source_action: 1,
            ordinal: 0,
            worker: "repair".into(),
            action: 3,
            targets: BTreeMap::from([("task".into(), ScheduledTarget::Created(0))]),
            inputs: BTreeMap::new(),
            due_at: values::add(
                values::transaction_time(),
                values::duration(Duration::from_secs(60).unwrap()),
            ),
        }],
        recurring: vec![RecurringSchedule {
            name: "repair_tasks".into(),
            worker: "repair".into(),
            action: 3,
            interval: Duration::from_secs(60).unwrap(),
            inputs: BTreeMap::new(),
            selection: Some(RecurringSelection {
                operation: selection.id,
                target: "task".into(),
                expiry_repair: false,
            }),
        }],
    };
    let mut builder = ApplicationDefinition::new();
    for declared in CreateTask::resources()
        .into_iter()
        .chain(FinishTask::resources())
    {
        builder.resource(declared);
    }
    for operation in CreateTask::operations()
        .into_iter()
        .chain(FinishTask::operations())
    {
        builder.operation(operation);
    }
    builder.operation(selection.clone());
    builder.action(CreateTask::definition());
    builder.action(FinishTask::definition());
    builder.jobs(jobs);
    let manifest = builder.manifest();
    assert!(manifest.routes.is_empty());
    assert!(manifest.web_bindings.is_empty());
    assert_eq!(manifest.resources, vec![resource.clone()]);
    assert_eq!(manifest.operations.len(), 4);
    let worker = manifest
        .actions
        .iter()
        .find(|action| action.id == 3)
        .unwrap();
    assert!(worker.inputs.is_empty());
    assert_eq!(
        serde_json::to_value(&worker.targets).unwrap(),
        serde_json::json!([{
            "name":"task", "resource":resource.id, "source":{"service":{"eligible":read.id}},
            "revision":"identity", "projection":{"operation":read.id,"fields":["pending"]}, "inspect":null
        }])
    );
    assert_eq!(
        serde_json::to_value(&manifest.jobs).unwrap(),
        serde_json::json!({
            "workers":[{"name":"repair","actions":[{"action":3,"targets":{"task":{"resource":resource.id,"eligible":read.id}}}]}],
            "schedules":[{"source_action":1,"ordinal":0,"worker":"repair","action":3,
                "targets":{"task":{"created":0}},"inputs":{},
                "due_at":{"add":{"left":"transaction_time","right":{"literal":{"duration":60000}}}}}],
            "recurring":[{"name":"repair_tasks","worker":"repair","action":3,"interval":60000,
                "inputs":{},"selection":{"operation":selection.id,"target":"task","expiry_repair":false}}]
        })
    );
    let serialized = serde_json::to_value(&manifest).unwrap();
    for action in serialized["actions"].as_array().unwrap() {
        assert!(action.get("redirect").is_none());
        assert!(action.get("layout").is_none());
    }
    let request = RequestView {
        version: noxide::__private::VERSION,
        kind: RequestKind::Action(3),
        target: None,
        input: Default::default(),
        inspection: Default::default(),
        params: Default::default(),
        available_forms: vec![],
    };
    let submission = Submission::<FinishTask>::new(&request);
    assert_eq!(submission.input(), &());
    assert_eq!(
        submission.execute().into_response(),
        ResponseIntent::Execute
    );
    assert_eq!(resource.fields[1].kind, noxide::FieldKind::Timestamp);
}
