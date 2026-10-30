use noxide_protocol::{Manifest, VERSION};

pub fn declarations() -> Manifest {
    serde_json::from_value(serde_json::json!({
        "version": VERSION,
        "resources": [{"id":1,"name":"notes","fields":[
            {"kind":"text","optional":false,"initial":null,"name":"body","label":"Note","max_bytes":4096},
            {"kind":"text","optional":false,"initial":null,"name":"tag","label":"Tag","max_bytes":128}]}],
        "operations": [
            {"id":2,"resource":1,"kind":"read","policy":{"any":[["owner"]]}},
            {"id":4,"resource":1,"kind":"update","policy":{"any":[["owner",{"role":{"name":"writer","tenant_scoped":false}}]]}},
            {"id":5,"resource":1,"kind":"delete","policy":{"any":[["owner",{"role":{"name":"writer","tenant_scoped":false}}]]}}
        ],
        "routes":[
            {"id":1,"path":"/","resource":null,"operations":[],"forms":[]},
            {"id":2,"path":"/notes/{note}","resource":1,"operations":[2],"forms":[2,3]}
        ],
        "actions":[
            {"id":2,"version":1,"name":"Save changes","redirect":{"route":2,"source":"signed"},
             "revision":"exact", "inputs":[{"name":"body","label":"Note","kind":"text","optional":false,"max_bytes":4096}],
             "steps":[{"operation":4,"target":"signed","assign":[{"field":"body","change":{"set":{"input":"body"}}}]}],
             "layout":[],"inspect":{"operation":2,"fields":["body"]}},
            {"id":3,"version":1,"name":"Delete note","redirect":{"route":1,"source":"signed"},"revision":"exact","inputs":[],
             "steps":[{"operation":5,"target":"signed","assign":[]}],"layout":[]}
        ]
    })).unwrap()
}

fn emit(bytes: &[u8]) -> String {
    bytes
        .chunks(8)
        .map(|part| {
            let mut word = [0; 8];
            word[..part.len()].copy_from_slice(part);
            format!(
                "i64.const {} i32.const {} call $emit\n",
                i64::from_le_bytes(word),
                part.len()
            )
        })
        .collect()
}

fn echo_request() -> String {
    format!(
        "{} i32.const 0 local.set $i call $request_len local.set $len
        block $done loop $copy
          local.get $i local.get $len i32.ge_u br_if $done
          local.get $i call $request i32.wrap_i64 i32.const 255 i32.and local.set $c
          local.get $c i32.const 34 i32.eq local.get $c i32.const 92 i32.eq i32.or
          if i64.const 92 i32.const 1 call $emit end
          local.get $c i64.extend_i32_u i32.const 1 call $emit
          local.get $i i32.const 1 i32.add local.set $i br $copy
        end end {}",
        emit(br#"{"rejected":{"field_errors":{},"message":""#),
        emit(br#""}}"#),
    )
}

// A deliberately small hostile guest that decides execution, traps, or misuses storage imports.
pub fn component(mode: &str) -> Vec<u8> {
    let page =
        emit(br#"{"page":{"title":"Note","nodes":[{"form":{"action":2}},{"form":{"action":3}}]}}"#);
    let kind = br#"{"version":1,"kind":{"#.len() + 1;
    let action = br#"{"version":1,"kind":{"action":"#.len();
    let before = match mode {
        "target" => "local.get $op i64.const 43 call $invoke drop".into(),
        "read" => "i32.const 2 i64.const 42 call $invoke drop".into(),
        "follow_source" => "i32.const 1 i64.const 42 call $follow_source".into(),
        "follow" => "i32.const 2 call $follow drop".into(),
        "snapshot" => format!("{} return", echo_request()),
        _ => String::new(),
    };
    let copy_outcome = emit(br#""execute""#);
    let after = match mode {
        "trap" => "unreachable".into(),
        "loop" => "(loop $forever br $forever)".into(),
        "invalid" => emit(br#"{"page":{"title":"bad","nodes":[{"raw":"<script>"}]}}"#),
        "reject" => emit(br#"{"rejected":{"field_errors":{},"message":"Application rule <script>"}}"#),
        "bad_reject" => emit(br#"{"rejected":{"field_errors":{"owner":"change this"},"message":"bad"}}"#),
        "twice" => "local.get $op i64.const 0 call $invoke drop".into(),
        "snapshot_after" => echo_request(),
        "correctable" => format!(
            "i32.const {} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 99 i32.eq if {copy_outcome} else {} end",
            br#"{"version":1,"kind":{"action":2},"target":42,"input":{"body":""#.len(),
            emit(br#"{"rejected":{"field_errors":{"body":"Correct this body <script>"},"message":"Nothing saved"}}"#),
        ),
        _ => copy_outcome.clone(),
    };
    wat::parse_str(format!(r#"(component
      (import "noxide:application/host@0.1.0" (instance $h
        (export "emit" (func (param "word" u64) (param "length" u32)))
        (export "request-length" (func (result u32)))
        (export "request-chunk" (func (param "offset" u32) (result u64)))
        (export "invoke" (func (param "operation" u32) (param "target" u64) (result u32)))
        (export "follow-source" (func (param "resource" u32) (param "id" u64)))
        (export "follow" (func (param "operation" u32) (result u32)))
        (export "result-chunk" (func (param "offset" u32) (result u64)))))
      (alias export $h "emit" (func $emit)) (core func $emit (canon lower (func $emit)))
      (alias export $h "request-length" (func $request_len)) (core func $request_len (canon lower (func $request_len)))
      (alias export $h "request-chunk" (func $request)) (core func $request (canon lower (func $request)))
      (alias export $h "invoke" (func $invoke)) (core func $invoke (canon lower (func $invoke)))
      (alias export $h "follow-source" (func $follow_source)) (core func $follow_source (canon lower (func $follow_source)))
      (alias export $h "follow" (func $follow)) (core func $follow (canon lower (func $follow)))
      (alias export $h "result-chunk" (func $result)) (core func $result (canon lower (func $result)))
      (core module $m
        (import "h" "emit" (func $emit (param i64 i32)))
        (import "h" "request-len" (func $request_len (result i32)))
        (import "h" "request" (func $request (param i32) (result i64)))
        (import "h" "invoke" (func $invoke (param i32 i64) (result i32)))
        (import "h" "follow-source" (func $follow_source (param i32 i64)))
        (import "h" "follow" (func $follow (param i32) (result i32)))
        (import "h" "result" (func $result (param i32) (result i64)))
        (func (export "handle") (local $op i32) (local $len i32) (local $i i32) (local $c i32)
          i32.const {kind} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 97 i32.eq
          if
            i32.const {action} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 50 i32.eq
            if (result i32) i32.const 4 else i32.const 5 end local.set $op
            {before}
            {after}
          else {page} end))
      (core instance $i (instantiate $m (with "h" (instance
        (export "emit" (func $emit)) (export "request" (func $request))
        (export "request-len" (func $request_len))
        (export "invoke" (func $invoke)) (export "result" (func $result))
        (export "follow-source" (func $follow_source)) (export "follow" (func $follow))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#)).unwrap()
}
