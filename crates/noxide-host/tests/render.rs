use noxide_host::render::{RenderContext, render};
use noxide_protocol::{Container, Document, Instruction, ResponseIntent};

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
