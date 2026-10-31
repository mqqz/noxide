use noxide::{Fragment, IntoPageResponse, Page, QueryForm, ResponseIntent, RouteRef};

#[test]
fn query_form_owned_and_borrowed_render_to_the_explicit_instruction() {
    let destination = RouteRef {
        route: 7,
        target: Some(23),
        params: [("minimum".into(), "1".into())].into(),
    };
    let form = QueryForm::new(destination.clone())
        .search_label("<Find>")
        .submit("Apply");
    let mut fragment = Fragment::new();
    fragment.append(&form);
    fragment.append(form);
    let ResponseIntent::Page(document) = Page::new("Queries", fragment).into_response() else {
        unreachable!()
    };
    let explicit = noxide::Instruction::QueryForm(noxide_protocol::query::QueryForm {
        destination,
        search_label: "<Find>".into(),
        submit: "Apply".into(),
    });
    assert_eq!(document.nodes, [explicit.clone(), explicit]);
}
