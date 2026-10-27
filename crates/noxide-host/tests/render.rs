use noxide_host::render::{FormCredentials, RenderContext, render};
use noxide_protocol::{Container, Document, Fields, Instruction, ResponseIntent};
use std::collections::BTreeMap;

#[allow(dead_code)]
#[path = "support/record_actions.rs"]
mod record_actions;

#[test]
fn textarea_preserves_browser_normalized_newlines() {
    let manifest = record_actions::declarations();
    let mut fixtures = Vec::new();
    for (input, expected) in [
        ("", ""),
        ("Alice", "Alice"),
        ("\rAlice", "\nAlice"),
        ("\r\nAlice", "\nAlice"),
        ("\nAlice", "\nAlice"),
        ("\r\r\nAlice", "\n\nAlice"),
        ("\n\nAlice", "\n\nAlice"),
        ("A\rB\r\nC\nD", "A\nB\nC\nD"),
    ] {
        let context = RenderContext {
            manifest: Some(&manifest),
            forms: BTreeMap::from([(
                2,
                Some(FormCredentials {
                    csrf: "fixture".into(),
                    submission: "fixture".into(),
                    values: Fields::from([("body".into(), input.into())]),
                }),
            )]),
            ..RenderContext::empty()
        };
        let page = render(
            &ResponseIntent::Page(Document::new(
                "Edit note",
                vec![Instruction::Form { action: 2 }],
            )),
            &context,
        )
        .unwrap();
        let html = String::from_utf8(page.body).unwrap();
        let content = html.split_once("<textarea").unwrap().1;
        let content = content.split_once('>').unwrap().1;
        let content = content.split_once("</textarea>").unwrap().0;
        // HTML normalizes CR/CRLF before dropping one initial textarea LF.
        // These fixtures contain only plain text and line endings. The browser
        // suite also checks their actual DOM values with JavaScript disabled.
        let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
        assert_eq!(
            normalized.strip_prefix('\n').unwrap_or(&normalized),
            expected,
            "input {input:?}"
        );
        fixtures.push(serde_json::json!({"input": input, "expected": expected, "html": html}));
    }
    if let Some(path) = std::env::var_os("NOXIDE_TEST_FORM_FIXTURES") {
        std::fs::write(path, serde_json::to_vec(&fixtures).unwrap()).unwrap();
    }
}

#[test]
fn text_is_literal_and_headers_are_not_part_of_the_protocol() {
    let page = Document::new(
        "Private notes",
        vec![
            Instruction::Begin(Container::Heading1),
            Instruction::Text("Private notes".into()),
            Instruction::End,
            Instruction::Text("<script>alert('x')</script> & \"note\"".into()),
        ],
    );
    let rendered = render(&ResponseIntent::Page(page), &RenderContext::empty()).unwrap();
    let html = String::from_utf8(rendered.body).unwrap();
    assert!(
        html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;note&quot;")
    );
    assert!(!html.contains("<script>"));
    assert!(
        serde_json::from_str::<ResponseIntent>(
            r#"{"page":{"title":"x","nodes":[],"headers":{"Set-Cookie":"x"}}}"#
        )
        .is_err()
    );
}

#[test]
fn pre_preserves_empty_plain_and_initial_newline_content() {
    for text in ["", "plain", "\nfirst", "\n\nfirst"] {
        let nodes = vec![
            Instruction::Begin(Container::Pre),
            Instruction::Text(String::new()),
            Instruction::Text(text.into()),
            Instruction::End,
        ];
        let rendered = render(
            &ResponseIntent::Page(Document::new("Pre", nodes)),
            &RenderContext::empty(),
        )
        .unwrap();
        assert!(
            String::from_utf8(rendered.body)
                .unwrap()
                .contains(&format!("<pre>\n{text}</pre>"))
        );
    }
}

#[test]
fn reject_browser_reparenting_and_unbalanced_ir() {
    for nodes in [
        vec![Instruction::End],
        vec![Instruction::Begin(Container::Article)],
        vec![
            Instruction::Begin(Container::Paragraph),
            Instruction::Begin(Container::Article),
            Instruction::End,
            Instruction::End,
        ],
        vec![
            Instruction::Begin(Container::List),
            Instruction::Text("outside li".into()),
            Instruction::End,
        ],
        vec![Instruction::Begin(Container::Item), Instruction::End],
    ] {
        assert!(
            render(
                &ResponseIntent::Page(Document::new("Test", nodes)),
                &RenderContext::empty()
            )
            .is_err()
        );
    }
}

#[test]
fn untrusted_wire_shapes_and_oversized_input_fail_closed() {
    assert!(
        noxide_protocol::decode_response(
            br#"{"page":{"title":"x","nodes":[{"raw":"<script/>"}]}}"#
        )
        .is_err()
    );
    assert!(
        noxide_protocol::decode_response(&vec![b' '; noxide_protocol::MAX_IR_BYTES + 1]).is_err()
    );
    let nodes = vec![Instruction::Text("x".into()); noxide_protocol::MAX_NODES + 1];
    assert!(
        render(
            &ResponseIntent::Page(Document::new("x", nodes)),
            &RenderContext::empty()
        )
        .is_err()
    );
}
