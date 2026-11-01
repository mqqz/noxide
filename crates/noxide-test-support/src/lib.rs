#![forbid(unsafe_code)]
// Shared fixtures are used selectively by each test target.
#[allow(dead_code)]
pub mod record_actions;

use noxide_protocol::*;

pub fn manifest() -> Manifest {
    let owner = Policy {
        any: vec![vec![Predicate::Owner]],
    };
    Manifest {
        effects: None,
        jobs: None,
        blobs: None,
        assets: Vec::new(),
        version: VERSION,
        resources: vec![Resource {
            search: None,
            expiry: None,
            unique: Vec::new(),
            gate: None,
            id: 1,
            name: "notes".into(),
            fields: vec![TextField {
                immutable: false,
                kind: FieldKind::Text,
                optional: false,
                initial: None,
                name: "body".into(),
                label: "Note".into(),
                max_bytes: 4096,
            }],
        }],
        operations: vec![
            Operation {
                maintenance: false,
                query: None,
                bind: Default::default(),
                scope: None,
                via: None,
                filter: Vec::new(),
                disclose: Vec::new(),
                list: None,
                visibility: None,
                fields: None,
                id: 1,
                resource: 1,
                kind: OperationKind::List,
                policy: owner.clone(),
            },
            Operation {
                maintenance: false,
                query: None,
                bind: Default::default(),
                scope: None,
                via: None,
                filter: Vec::new(),
                disclose: Vec::new(),
                list: None,
                visibility: None,
                fields: None,
                id: 2,
                resource: 1,
                kind: OperationKind::Read,
                policy: owner.clone(),
            },
            Operation {
                maintenance: false,
                query: None,
                bind: Default::default(),
                scope: None,
                via: None,
                filter: Vec::new(),
                disclose: Vec::new(),
                list: None,
                visibility: None,
                fields: None,
                id: 3,
                resource: 1,
                kind: OperationKind::Create,
                policy: owner,
            },
        ],
        routes: vec![
            Route {
                params: Vec::new(),
                access: noxide_protocol::Access::Authenticated,
                id: 1,
                path: "/".into(),
                resource: None,
                operations: vec![1],
                forms: vec![1],
            },
            Route {
                params: Vec::new(),
                access: noxide_protocol::Access::Authenticated,
                id: 2,
                path: "/notes/{note}".into(),
                resource: Some(1),
                operations: vec![2],
                forms: vec![],
            },
        ],
        web_bindings: vec![WebBinding {
            id: 1,
            version: 1,
            action: 1,
            layout: vec![],
            redirect: Redirect {
                route: 2,
                source: RedirectSource::Step(0),
            },
        }],
        actions: vec![Action {
            targets: vec![],
            id: 1,
            version: 1,
            name: "Save note".into(),
            inputs: vec![Input {
                name: "body".into(),
                label: "Note".into(),
                kind: FieldKind::Text,
                optional: false,
                max_bytes: 4096,
            }],
            steps: vec![Step {
                guards: vec![],
                operation: 3,
                target: Target::None,
                assign: vec![Assignment {
                    field: "body".into(),
                    change: Change::Set(Value::Input("body".into())),
                }],
            }],
        }],
    }
}

fn emit(bytes: &[u8]) -> String {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut word = [0; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            format!(
                "i64.const {} i32.const {} call $emit\n",
                i64::from_le_bytes(word),
                chunk.len()
            )
        })
        .collect()
}

pub fn component(failure: Option<&str>) -> Vec<u8> {
    let page = serde_json::to_vec(&ResponseIntent::Page(Document::new(
        "Private notes",
        vec![
            Instruction::Begin(Container::Heading1),
            Instruction::Text("Private notes".into()),
            Instruction::End,
            Instruction::Text("No notes yet".into()),
            Instruction::Form { action: 1 },
        ],
    )))
    .unwrap();
    let action = match failure {
        Some("trap") => "unreachable".into(),
        Some("loop") => "(loop $forever br $forever)".into(),
        Some("invalid") => emit(br#"{"page":{"title":"x","nodes":[{"raw":"<script>"}]}}"#),
        Some("twice") => "i32.const 3 i64.const 0 call $invoke drop".into(),
        _ => emit(br#""execute""#),
    };
    let kind_offset = format!(r#"{{"version":{VERSION},"kind":{{"#).len() + 1;
    wat::parse_str(format!(r#"(component
      (import "noxide:application/host@0.1.0" (instance $h
        (export "emit" (func (param "word" u64) (param "length" u32)))
        (export "request-chunk" (func (param "offset" u32) (result u64)))
        (export "invoke" (func (param "operation" u32) (param "target" u64) (result u32)))
        (export "result-chunk" (func (param "offset" u32) (result u64)))))
      (alias export $h "emit" (func $emit)) (core func $emit (canon lower (func $emit)))
      (alias export $h "request-chunk" (func $request)) (core func $request (canon lower (func $request)))
      (alias export $h "invoke" (func $invoke)) (core func $invoke (canon lower (func $invoke)))
      (alias export $h "result-chunk" (func $result)) (core func $result (canon lower (func $result)))
      (core module $m
        (import "h" "emit" (func $emit (param i64 i32)))
        (import "h" "request" (func $request (param i32) (result i64)))
        (import "h" "invoke" (func $invoke (param i32 i64) (result i32)))
        (import "h" "result" (func $result (param i32) (result i64)))
        (global $seen (mut i32) (i32.const 0))
        (func (export "handle") (local $i i32) (local $c i32)
          global.get $seen if unreachable end i32.const 1 global.set $seen
          i32.const {kind_offset} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 97 i32.eq
          if {action}
          else {page} end))
      (core instance $i (instantiate $m (with "h" (instance
        (export "emit" (func $emit)) (export "request" (func $request))
        (export "invoke" (func $invoke)) (export "result" (func $result))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#,page=if failure==Some("list") {format!("i32.const 1 i64.const 0 call $invoke drop {}",emit(&page))} else {emit(&page)})).unwrap()
}

pub fn hidden(html: &str, name: &str) -> String {
    html.split_once(&format!("name=\"{name}\" value=\""))
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
        .into()
}

#[allow(dead_code)]
pub fn add_input(action: &mut Action, resource: &Resource, name: &str) {
    let field = resource
        .fields
        .iter()
        .find(|field| field.name == name)
        .expect("fixture field");
    action.inputs.push(Input {
        name: field.name.clone(),
        label: field.label.clone(),
        kind: field.kind.clone(),
        optional: field.optional,
        max_bytes: field.max_bytes,
    });
    action.steps[0].assign.push(Assignment {
        field: name.into(),
        change: Change::Set(Value::Input(name.into())),
    });
}

#[allow(dead_code)]
pub fn action(
    id: u32,
    name: &str,
    operation: u32,
    target: Target,
    resource: &Resource,
    names: &[&str],
    route: u32,
) -> FixtureAction {
    let mut action = Action {
        id,
        version: 1,
        name: name.into(),
        targets: if target == Target::None {
            vec![]
        } else {
            vec![page_target(resource.id, vec![2], Revision::Exact)]
        },
        inputs: vec![],
        steps: vec![Step {
            guards: vec![],
            operation,
            target: target.clone(),
            assign: vec![],
        }],
    };
    for name in names {
        add_input(&mut action, resource, name);
    }
    FixtureAction {
        core: action,
        redirect: Redirect {
            route,
            source: if target == Target::None {
                RedirectSource::Step(0)
            } else {
                RedirectSource::Target("target".into())
            },
        },
    }
}
#[allow(dead_code)]
pub struct FixtureAction {
    pub core: Action,
    pub redirect: Redirect,
}
impl std::ops::Deref for FixtureAction {
    type Target = Action;
    fn deref(&self) -> &Action {
        &self.core
    }
}
impl std::ops::DerefMut for FixtureAction {
    fn deref_mut(&mut self) -> &mut Action {
        &mut self.core
    }
}
#[allow(dead_code)]
pub fn register_action(m: &mut Manifest, mut action: FixtureAction) {
    for target in &mut action.core.targets {
        if let TargetSource::Page { reads } = &mut target.source {
            *reads = m
                .operations
                .iter()
                .filter(|op| {
                    op.kind == OperationKind::Read
                        && op.via.is_none()
                        && op.resource == target.resource
                })
                .map(|op| op.id)
                .collect();
            reads.sort_unstable();
            reads.dedup();
        }
    }
    m.web_bindings.push(WebBinding {
        id: action.core.id,
        version: action.core.version,
        action: action.core.id,
        layout: vec![],
        redirect: action.redirect,
    });
    m.actions.push(action.core);
}

#[allow(dead_code)]
pub fn page_target(resource: u32, reads: Vec<u32>, revision: Revision) -> ActionTarget {
    ActionTarget {
        name: "target".into(),
        resource,
        source: TargetSource::Page { reads },
        revision,
        projection: None,
        inspect: None,
    }
}

fn boolean_field(name: &str) -> TextField {
    TextField {
        immutable: false,
        name: name.into(),
        label: name.into(),
        kind: FieldKind::Boolean,
        optional: false,
        initial: None,
        max_bytes: 5,
    }
}
pub fn parent_declarations() -> Manifest {
    let mut m = crate::manifest();
    m.resources[0].fields.extend([
        boolean_field("published"),
        TextField {
            immutable: false,
            name: "thread".into(),
            label: "Thread".into(),
            max_bytes: 20,
            optional: false,
            initial: None,
            kind: FieldKind::Reference {
                resource: "threads".into(),
            },
        },
    ]);
    m.resources[0].gate = Some(Gate {
        field: "thread".into(),
        visible: Visibility {
            field: "published".into(),
            equals: "true".into(),
        },
        create_when: Visibility {
            field: "locked".into(),
            equals: "false".into(),
        },
    });
    m.resources.push(Resource {
        search: None,
        expiry: None,
        unique: Vec::new(),
        gate: None,
        id: 2,
        name: "threads".into(),
        fields: vec![boolean_field("published"), boolean_field("locked")],
    });
    for op in &mut m.operations {
        op.policy.any = vec![vec![Predicate::Public]];
        if op.kind != OperationKind::Create {
            op.visibility = Some(Visibility {
                field: "published".into(),
                equals: "true".into(),
            });
            op.fields = Some(vec!["body".into()]);
        }
    }
    m.operations.push(Operation {
        maintenance: false,
        query: None,
        bind: Default::default(),
        scope: None,
        via: None,
        filter: Vec::new(),
        disclose: Vec::new(),
        list: None,
        id: 4,
        resource: 2,
        kind: OperationKind::Read,
        policy: Policy {
            any: vec![vec![Predicate::Public]],
        },
        visibility: Some(Visibility {
            field: "published".into(),
            equals: "true".into(),
        }),
        fields: Some(vec!["locked".into()]),
    });
    m.routes[0].operations.clear();
    m.routes[0].forms.clear();
    m.routes[0].access = Access::Public;
    m.routes[1].access = Access::Public;
    m.routes.push(Route {
        params: Vec::new(),
        id: 3,
        path: "/threads/{thread}".into(),
        resource: Some(2),
        operations: vec![4, 1],
        forms: vec![1],
        access: Access::PublicOptional,
    });
    m.actions[0].targets = vec![crate::page_target(2, vec![4], Revision::Exact)];
    m.actions[0].steps[0].assign.push(Assignment {
        field: "thread".into(),
        change: Change::Set(Value::Target("target".into())),
    });
    m.operations[2].bind = ::std::collections::BTreeMap::from([("thread".into(), 4)]);
    m.operations
        .iter_mut()
        .find(|op| op.kind == OperationKind::List)
        .unwrap()
        .scope = Some("thread".into());
    crate::add_input(&mut m.actions[0], &m.resources[0], "published");
    m
}
