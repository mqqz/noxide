use noxide_protocol::*;

pub fn manifest() -> Manifest {
    let owner = Policy {
        any: vec![vec![Predicate::Owner]],
    };
    Manifest {
        version: VERSION,
        resources: vec![Resource {
            id: 1,
            name: "notes".into(),
            fields: vec![TextField {
                name: "body".into(),
                label: "Note".into(),
                max_bytes: 4096,
            }],
        }],
        operations: vec![
            Operation {
                id: 1,
                resource: 1,
                kind: OperationKind::List,
                policy: owner.clone(),
            },
            Operation {
                id: 2,
                resource: 1,
                kind: OperationKind::Read,
                policy: owner.clone(),
            },
            Operation {
                id: 3,
                resource: 1,
                kind: OperationKind::Create,
                policy: owner,
            },
        ],
        routes: vec![
            Route {
                id: 1,
                path: "/".into(),
                record: false,
                operations: vec![1],
                forms: vec![1],
            },
            Route {
                id: 2,
                path: "/notes".into(),
                record: true,
                operations: vec![2],
                forms: vec![],
            },
        ],
        actions: vec![Action {
            id: 1,
            version: 1,
            name: "Save note".into(),
            operation: 3,
            redirect: 2,
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
    let offset = br#"{"resource":1,"id":"#.len();
    let digits = format!(
        r#"i32.const {offset} local.set $i
      block $done loop $next
        local.get $i call $result i32.wrap_i64 i32.const 255 i32.and local.tee $c
        i32.const 44 i32.eq br_if $done
        local.get $c i64.extend_i32_u i32.const 1 call $emit
        local.get $i i32.const 1 i32.add local.set $i br $next
      end end"#
    );
    let action = match failure {
        Some("trap") => "unreachable".into(),
        Some("loop") => "(loop $forever br $forever)".into(),
        Some("invalid") => emit(br#"{"page":{"title":"x","nodes":[{"raw":"<script>"}]}}"#),
        Some("twice") => "i32.const 3 i64.const 0 call $invoke drop".into(),
        _ => format!(
            "{} {digits} {} {digits} {}",
            emit(br#"{"created":{"resource":1,"id":"#),
            emit(br#", "destination":{"route":2,"target":"#),
            emit(b"}}}")
        ),
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
          if i32.const 3 i64.const 0 call $invoke drop {action}
          else {page} end))
      (core instance $i (instantiate $m (with "h" (instance
        (export "emit" (func $emit)) (export "request" (func $request))
        (export "invoke" (func $invoke)) (export "result" (func $result))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#,page=emit(&page))).unwrap()
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
