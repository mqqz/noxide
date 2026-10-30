use super::{action::ActionType, form::Form};
use crate::{Document, Instruction, ResponseIntent, RouteRef};
use noxide_protocol::Container;
/// An escaped, composable document instruction sequence.
#[derive(Clone, Default)]
pub struct Fragment {
    nodes: Vec<Instruction>,
}
impl Fragment {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn begin(&mut self, container: Container) {
        self.nodes.push(Instruction::Begin(container));
    }
    pub fn end(&mut self) {
        self.nodes.push(Instruction::End);
    }
    pub fn text(&mut self, text: impl ToString) {
        self.nodes.push(Instruction::Text(text.to_string()));
    }
    pub fn append(&mut self, value: impl Render) {
        value.render(self);
    }
    pub fn link(&mut self, destination: RouteRef, body: Fragment) {
        self.nodes.push(Instruction::BeginLink { destination });
        self.nodes.extend(body.nodes);
        self.nodes.push(Instruction::EndLink);
    }
}
pub trait Render {
    fn render(self, fragment: &mut Fragment);
}
impl Render for Fragment {
    fn render(self, fragment: &mut Fragment) {
        fragment.nodes.extend(self.nodes);
    }
}
impl Render for &Fragment {
    fn render(self, fragment: &mut Fragment) {
        fragment.nodes.extend(self.nodes.clone());
    }
}
macro_rules! text_render {
    ($($t:ty),*) => { $(impl Render for $t { fn render(self, fragment: &mut Fragment) { fragment.text(self); } })* };
}
text_render!(&str, String, &String, char, bool, i64, u64, usize, i32, u32);
impl<A: ActionType> Render for Form<A> {
    fn render(self, fragment: &mut Fragment) {
        fragment.nodes.push(Instruction::Form {
            action: A::definition().id,
        });
    }
}
impl<A: ActionType> Render for &Form<A> {
    fn render(self, fragment: &mut Fragment) {
        fragment.nodes.push(Instruction::Form {
            action: A::definition().id,
        });
    }
}
impl<'a, T> Render for &'a Option<T>
where
    &'a T: Render,
{
    fn render(self, fragment: &mut Fragment) {
        if let Some(value) = self {
            value.render(fragment);
        }
    }
}
impl<T: Render> Render for Option<T> {
    fn render(self, fragment: &mut Fragment) {
        if let Some(value) = self {
            value.render(fragment);
        }
    }
}

pub struct Page {
    document: Document,
}
impl Page {
    pub fn new(title: impl Into<String>, content: Fragment) -> Self {
        Self {
            document: Document::new(title, content.nodes),
        }
    }
}
#[derive(Debug)]
pub struct NotFound;
pub type PageResult = Result<Page, NotFound>;
pub trait IntoPageResponse {
    fn into_response(self) -> ResponseIntent;
}
impl IntoPageResponse for Page {
    fn into_response(self) -> ResponseIntent {
        ResponseIntent::Page(self.document)
    }
}
impl IntoPageResponse for PageResult {
    fn into_response(self) -> ResponseIntent {
        match self {
            Ok(page) => page.into_response(),
            Err(NotFound) => ResponseIntent::NotFound(Document::new(
                "Not found",
                vec![Instruction::Text("This page is not available.".into())],
            )),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Id;
    #[test]
    fn identifiers_do_not_require_resource_traits() {
        struct ResourceWithoutTraits;
        let id = Id::<ResourceWithoutTraits>::new(9);
        assert_eq!(id, id);
        assert_eq!(format!("{id:?}"), "Id(9)");
    }
    #[test]
    fn interpolation_stays_text_and_links_keep_fragments() {
        let mut content = Fragment::new();
        content.append("<script>bad</script>");
        let mut link = Fragment::new();
        link.begin(Container::Strong);
        link.append("Open");
        link.end();
        content.link(
            RouteRef {
                params: Default::default(),
                route: 1,
                target: None,
            },
            link,
        );
        assert!(
            matches!(&content.nodes[0],Instruction::Text(value) if value=="<script>bad</script>")
        );
        assert!(matches!(content.nodes[1], Instruction::BeginLink { .. }));
        assert_eq!(content.nodes.last(), Some(&Instruction::EndLink));
    }
}
