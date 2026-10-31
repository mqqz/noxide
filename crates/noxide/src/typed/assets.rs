//! Explicit typed asset declarations. Bytes remain in the public package.
use crate::{Fragment, Instruction, RouteRef};
pub use noxide_protocol::assets::{AssetDeclaration, AssetMediaType};
pub use noxide_protocol::document::{ClassTokens, Element, PresentationNode};

pub trait AssetType {
    fn declaration() -> AssetDeclaration;
    fn reference() -> AssetRef {
        AssetRef::new(Self::declaration().name).expect("asset declaration name")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRef(String);
impl AssetRef {
    pub fn new(name: impl Into<String>) -> Result<Self, String> {
        let name = name.into();
        if !noxide_protocol::assets::valid_asset_name(&name) {
            return Err("invalid logical asset name".into());
        }
        Ok(Self(name))
    }
    pub fn name(&self) -> &str {
        &self.0
    }
    pub fn image(&self, alt: impl Into<String>) -> PresentationNode {
        PresentationNode::Image {
            asset: self.0.clone(),
            alt: alt.into(),
            classes: ClassTokens::default(),
        }
    }
}
impl crate::Render for PresentationNode {
    fn render(self, fragment: &mut Fragment) {
        fragment.rich(self);
    }
}
impl Fragment {
    pub fn rich(&mut self, node: PresentationNode) {
        self.nodes.push(Instruction::Rich(node));
    }
    pub fn stylesheet(&mut self, asset: &AssetRef) {
        self.nodes.push(Instruction::Stylesheet {
            asset: asset.0.clone(),
        });
    }
}
pub fn element(
    element: Element,
    classes: ClassTokens,
    children: Vec<PresentationNode>,
) -> PresentationNode {
    PresentationNode::Element {
        element,
        classes,
        children,
    }
}
pub fn navigation(
    label: impl Into<String>,
    classes: ClassTokens,
    children: Vec<PresentationNode>,
) -> PresentationNode {
    PresentationNode::Navigation {
        label: label.into(),
        classes,
        children,
    }
}
pub fn route_link(destination: RouteRef, text: impl Into<String>) -> PresentationNode {
    PresentationNode::Link {
        destination,
        text: text.into(),
        classes: ClassTokens::default(),
    }
}

pub trait ImageAsset: AssetType {}
pub trait StylesheetAsset: AssetType {}
pub trait FontAsset: AssetType {}
pub fn image<A: ImageAsset>(alt: impl Into<String>) -> PresentationNode {
    A::reference().image(alt)
}
pub struct Stylesheet(AssetRef);
pub fn stylesheet<A: StylesheetAsset>() -> Stylesheet {
    Stylesheet(A::reference())
}
impl crate::Render for Stylesheet {
    fn render(self, fragment: &mut Fragment) {
        fragment.stylesheet(&self.0);
    }
}
