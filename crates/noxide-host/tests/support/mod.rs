// Shared fixtures are used selectively by each test target.
#[allow(dead_code)]
pub mod record_actions;

use noxide_protocol::*;

pub fn manifest() -> Manifest {
    let owner = Policy {
        any: vec![vec![Predicate::Owner]],
    };
    Manifest {
        version: VERSION,
        resources: vec![Resource {
            gate: None,
            id: 1,
            name: "notes".into(),
            fields: vec![TextField {
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
                bind: None,
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
                bind: None,
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
                bind: None,
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
        actions: vec![Action {
            layout: Vec::new(),
            id: 1,
            version: 1,
            name: "Save note".into(),
            redirect: Redirect {
                route: 2,
                source: RedirectSource::Step(0),
            },
            revision: Revision::Exact,
            inputs: vec![Input {
                name: "body".into(),
                label: "Note".into(),
                kind: FieldKind::Text,
                optional: false,
                max_bytes: 4096,
            }],
            steps: vec![Step {
                operation: 3,
                target: Target::None,
                assign: vec![Assignment {
                    field: "body".into(),
                    change: Change::Set(Value::Input("body".into())),
                }],
            }],
            inspect: None,
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
    let kind_offset = br#"{"version":1,"kind":{"#.len() + 1;
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
) -> Action {
    let mut action = Action {
        id,
        version: 1,
        name: name.into(),
        layout: vec![],
        redirect: Redirect {
            route,
            source: if target == Target::None {
                RedirectSource::Step(0)
            } else {
                RedirectSource::Signed
            },
        },
        inspect: None,
        inputs: vec![],
        revision: Revision::Exact,
        steps: vec![Step {
            operation,
            target,
            assign: vec![],
        }],
    };
    for name in names {
        add_input(&mut action, resource, name);
    }
    action
}
