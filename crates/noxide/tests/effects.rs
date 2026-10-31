//! Explicit untrusted declaration lowering; host admission and grants remain separate.
use noxide::__private::{
    AccountScope, Action, Input, Operation, OperationKind, Policy, Predicate, Target,
};
use noxide::{
    ActionType, ApplicationDefinition, CalculatedStep, EffectContract, EffectEndpoint, EmitEffect,
    FieldKind, Id, PayloadField, Resource, ResourceType, Timestamp, values,
};

#[derive(Resource)]
#[resource(key = "effect_events")]
pub struct Event {
    #[id]
    pub id: Id<Self>,
    #[field(max_bytes = 100)]
    pub title: String,
    #[field()]
    pub at: Timestamp,
}
struct RecordEvent;
impl ActionType for RecordEvent {
    type Resource = Event;
    type Input = ();
    type Original = ();
    fn definition() -> Action {
        Action {
            id: 1,
            version: 1,
            name: "Record event".into(),
            targets: vec![],
            inputs: vec![],
            steps: vec![
                CalculatedStep::new(2, Target::None)
                    .set("title", values::text("created"))
                    .set("at", values::transaction_time())
                    .finish(),
            ],
        }
    }
    fn operations() -> Vec<Operation> {
        vec![Operation {
            id: 2,
            resource: Event::definition().id,
            kind: OperationKind::Create,
            policy: Policy {
                any: vec![vec![Predicate::Owner]],
            },
            maintenance: false,
            query: None,
            bind: Default::default(),
            scope: None,
            via: None,
            filter: vec![],
            disclose: vec![],
            list: None,
            visibility: None,
            fields: None,
        }]
    }
}
fn field(name: &str, kind: FieldKind, width: u32, value: noxide::__private::Value) -> PayloadField {
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
#[test]
fn explicit_effects_preserve_scalar_schema_identity_and_fixed_destination() {
    let effects = EffectContract {
        endpoints: vec![EffectEndpoint {
            name: "events".into(),
            secret_slot: Some("receiver_token".into()),
        }],
        emissions: vec![EmitEffect {
            source_action: 1,
            ordinal: 0,
            endpoint: "events".into(),
            fields: vec![
                field(
                    "actor",
                    FieldKind::Account {
                        scope: AccountScope::SameTenant,
                    },
                    43,
                    values::principal(),
                ),
                field("at", FieldKind::Timestamp, 20, values::transaction_time()),
                field(
                    "record",
                    FieldKind::Reference {
                        resource: "effect_events".into(),
                    },
                    19,
                    noxide::__private::Value::Created(0),
                ),
                field(
                    "reviewed_at",
                    FieldKind::Timestamp,
                    20,
                    values::timestamp(Timestamp::from_unix_millis(1234).unwrap()),
                ),
            ],
        }],
    };
    let mut builder = ApplicationDefinition::new();
    for resource in RecordEvent::resources() {
        builder.resource(resource);
    }
    for operation in RecordEvent::operations() {
        builder.operation(operation);
    }
    builder.action(RecordEvent::definition());
    builder.effects(effects);
    let manifest = builder.manifest();
    assert!(manifest.routes.is_empty());
    assert!(manifest.web_bindings.is_empty());
    assert_eq!(manifest.actions, vec![RecordEvent::definition()]);
    assert_eq!(manifest.resources, vec![Event::definition()]);
    assert_eq!(
        serde_json::to_value(manifest.effects).unwrap(),
        serde_json::json!({
            "endpoints":[{"name":"events","secret_slot":"receiver_token"}],
            "emissions":[{"source_action":1,"ordinal":0,"endpoint":"events","fields":[
                {"schema":{"name":"actor","label":"actor","kind":{"account":{"scope":"same_tenant"}},"optional":false,"max_bytes":43},"value":"principal"},
                {"schema":{"name":"at","label":"at","kind":"timestamp","optional":false,"max_bytes":20},"value":"transaction_time"},
                {"schema":{"name":"record","label":"record","kind":{"reference":{"resource":"effect_events"}},"optional":false,"max_bytes":19},"value":{"created":0}},
                {"schema":{"name":"reviewed_at","label":"reviewed_at","kind":"timestamp","optional":false,"max_bytes":20},"value":{"literal":{"timestamp":1234}}}
            ]}]
        })
    );
}
