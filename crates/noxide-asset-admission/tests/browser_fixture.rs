//! Writes the fixture tools/test_asset_browser.py loads in a real browser.
#![allow(clippy::too_many_lines)]
use noxide_asset_admission::{AssetInput, admit};
use noxide_assets::{
    AssetDeclaration, AssetMediaType, asset_path,
    document::{fragment, stylesheet},
};
use noxide_protocol::document::{ClassTokens, Element, PresentationNode};

fn node(e: Element, children: Vec<PresentationNode>) -> PresentationNode {
    PresentationNode::Element {
        element: e,
        classes: ClassTokens::default(),
        children,
    }
}
#[test]
fn browser_fixture() {
    let Ok(output) = std::env::var("NOXIDE_TEST_ASSET_FIXTURE") else {
        return;
    };
    use image::ImageEncoder;
    use sha2::{Digest, Sha256};
    let declaration = |name: &str, kind, bytes: &Vec<u8>| AssetDeclaration {
        name: name.into(),
        media_type: kind,
        digest: format!("{:x}", Sha256::digest(bytes)),
    };
    let mut png = Vec::new();
    image::codecs::png::PngEncoder::new(&mut png)
        .write_image(&[255, 0, 0, 255], 1, 1, image::ExtendedColorType::Rgba8)
        .unwrap();
    let mut inputs = vec![AssetInput {
        declaration: declaration("pixel.png", AssetMediaType::Png, &png),
        bytes: png,
    }];
    let mut css="p{color:rgb(1,2,3)} .card{display:grid;grid-template-columns:1fr 2fr;gap:1rem} img{max-width:100%}".to_string();
    let mut font_expected = false;
    if let Ok(path) = std::env::var("NOXIDE_TEST_WOFF2") {
        let bytes = std::fs::read(path).unwrap();
        let d = declaration("face.woff2", AssetMediaType::Woff2, &bytes);
        css.push_str(&format!("@font-face{{font-family:'nxa-test';src:url('{}')}} p{{font-family:'nxa-test',sans-serif}}",asset_path(&d.digest).unwrap()));
        inputs.push(AssetInput {
            declaration: d,
            bytes,
        });
        font_expected = true;
    }
    let bytes = css.into_bytes();
    inputs.push(AssetInput {
        declaration: declaration("site.css", AssetMediaType::Css, &bytes),
        bytes,
    });
    let bundle = admit(inputs).unwrap();
    let rich = PresentationNode::Navigation {
        label: "Example navigation".into(),
        classes: ClassTokens::new(vec!["card".into()]).unwrap(),
        children: vec![
            node(
                Element::Paragraph,
                vec![PresentationNode::Text(
                    "<script src='https://attacker.invalid/x'></script>".into(),
                )],
            ),
            PresentationNode::Image {
                asset: "pixel.png".into(),
                alt: "A red pixel".into(),
                classes: ClassTokens::default(),
            },
            node(
                Element::Details,
                vec![
                    node(
                        Element::Summary,
                        vec![PresentationNode::Text("More information".into())],
                    ),
                    node(
                        Element::Paragraph,
                        vec![PresentationNode::Text("Native disclosure works".into())],
                    ),
                ],
            ),
            node(
                Element::Table,
                vec![
                    node(
                        Element::Caption,
                        vec![PresentationNode::Text("Counts".into())],
                    ),
                    node(
                        Element::Row,
                        vec![
                            node(
                                Element::HeaderCell,
                                vec![PresentationNode::Text("Total".into())],
                            ),
                            node(Element::Cell, vec![PresentationNode::Text("1".into())]),
                        ],
                    ),
                ],
            ),
        ],
    };
    let html = format!(
        "<!doctype html><html><head>{}</head><body><p id='host-control'>Host account</p><main class='noxide-app'>{}</main></body></html>",
        stylesheet("site.css", &bundle).unwrap(),
        fragment(&rich, &bundle, &|_| Ok("/".into()), &mut 1024, 32).unwrap()
    );
    let routes: Vec<_> = bundle
        .declarations()
        .map(|d| {
            let a = bundle.get(&d.name).unwrap();
            serde_json::json!({"path":a.path(),"mime":d.media_type.mime(),"bytes":a.bytes()})
        })
        .collect();
    std::fs::write(
        output,
        serde_json::to_vec(
            &serde_json::json!({"html":html,"assets":routes,"font_expected":font_expected}),
        )
        .unwrap(),
    )
    .unwrap();
}
