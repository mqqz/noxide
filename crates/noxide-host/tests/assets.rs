#[allow(dead_code)]
mod support;
use noxide_host::{
    Application, Database, HostKeys,
    assets::*,
    manifest,
    render::{self, RenderContext},
};
use noxide_protocol::{
    document::{ClassTokens, Element, PresentationNode},
    *,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;
fn input(name: &str, media_type: AssetMediaType, bytes: Vec<u8>) -> AssetInput {
    AssetInput {
        declaration: AssetDeclaration {
            name: name.into(),
            media_type,
            digest: format!("{:x}", Sha256::digest(&bytes)),
        },
        bytes,
    }
}
fn fixture() -> (Manifest, AssetBundle) {
    let bundle = AssetBundle::admit(vec![
        input("site.css", AssetMediaType::Css, b"p{color:red}".to_vec()),
        input("other.css", AssetMediaType::Css, b"p{color:blue}".to_vec()),
    ])
    .unwrap();
    let mut m = support::manifest();
    m.assets = bundle.declarations().cloned().collect();
    (m, bundle)
}
fn text_group(count: usize) -> PresentationNode {
    PresentationNode::Element {
        element: Element::Div,
        classes: ClassTokens::default(),
        children: (0..count)
            .map(|_| PresentationNode::Text("x".into()))
            .collect(),
    }
}
#[test]
fn canonical_hash_binds_every_asset_authority_field() {
    let (m, bundle) = fixture();
    let hash = manifest::digest(&m).unwrap();
    let mut other = m.clone();
    other.assets.reverse();
    assert_eq!(manifest::digest(&other).unwrap(), hash);
    other = m.clone();
    other.assets[0].name = "renamed.css".into();
    assert_ne!(manifest::digest(&other).unwrap(), hash);
    assert!(bundle.verify_declarations(&other.assets).is_err());
    other = m.clone();
    other.assets[0].digest = "0".repeat(64);
    assert_ne!(manifest::digest(&other).unwrap(), hash);
    assert!(bundle.verify_declarations(&other.assets).is_err());
    other = m.clone();
    other.assets[0].media_type = AssetMediaType::Woff2;
    assert_ne!(manifest::digest(&other).unwrap(), hash);
    assert!(bundle.verify_declarations(&other.assets).is_err());
    for path in ["/_noxide/assets", "/_noxide/assets/{asset}"] {
        other = m.clone();
        other.routes[0].path = path.into();
        assert!(manifest::validate(&other).is_err());
    }
}
#[test]
fn constructor_cannot_substitute_empty_bundle_for_approved_assets() {
    let (m, _) = fixture();
    let temporary = tempfile::tempdir().unwrap();
    assert!(
        Application::new(
            &support::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            Database::sqlite(temporary.path().join("db")),
            HostKeys::generate().unwrap(),
            Default::default(),
            noxide_host::DeploymentResources {
                effects: None,
                jobs: None,
                assets: AssetBundle::default(),
                blobs: None
            }
        )
        .is_err()
    );
}
#[test]
fn canonical_document_has_one_shared_node_depth_and_style_boundary() {
    let (m, bundle) = fixture();
    let context = RenderContext {
        assets: &bundle,
        manifest: Some(&m),
        ..RenderContext::empty()
    };
    let page = |nodes| ResponseIntent::Page(Document::new("Assets", nodes));
    let good = page(vec![
        Instruction::Stylesheet {
            asset: "site.css".into(),
        },
        Instruction::Rich(PresentationNode::Text("<script>evil</script>".into())),
    ]);
    let html = String::from_utf8(render::render(&good, &context).unwrap().body).unwrap();
    assert!(html.contains("class=\"noxide-app\""));
    assert!(html.contains("&lt;script&gt;evil&lt;/script&gt;"));
    for nodes in [
        vec![
            Instruction::Rich(text_group(600)),
            Instruction::Rich(text_group(600)),
        ],
        vec![
            Instruction::Begin(Container::Div),
            Instruction::Stylesheet {
                asset: "site.css".into(),
            },
            Instruction::End,
        ],
        vec![
            Instruction::Stylesheet {
                asset: "site.css".into(),
            },
            Instruction::Stylesheet {
                asset: "site.css".into(),
            },
        ],
        vec![Instruction::Stylesheet {
            asset: "//attacker.invalid/style.css".into(),
        }],
        vec![Instruction::Rich(PresentationNode::Image {
            asset: "site.css".into(),
            alt: "wrong MIME".into(),
            classes: ClassTokens::default(),
        })],
    ] {
        assert!(render::render(&page(nodes), &context).is_err());
    }
    let mut nodes = vec![Instruction::Begin(Container::Div); MAX_DEPTH];
    nodes.push(Instruction::Rich(text_group(1)));
    nodes.extend(vec![Instruction::End; MAX_DEPTH]);
    assert!(render::render(&page(nodes), &context).is_err());
    let forged=br#"{"page":{"title":"x","nodes":[{"rich":{"element":{"element":"div","classes":["noxide-app"],"children":[]}}}]}}"#;
    assert!(decode_response(forged).is_err());
    let mut wrong = m.clone();
    wrong.version = 6;
    assert!(manifest::validate(&wrong).is_err());
}
#[tokio::test]
async fn public_assets_are_exact_no_store_typed_and_bounded_until_body_drop() {
    let (m, bundle) = fixture();
    let path = bundle.get("site.css").unwrap().path();
    let expected = bundle.get("site.css").unwrap().bytes().to_vec();
    let temp = tempfile::tempdir().unwrap();
    let app = Arc::new(
        Application::new(
            &support::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            Database::sqlite(temp.path().join("db")),
            HostKeys::generate().unwrap(),
            Default::default(),
            noxide_host::DeploymentResources {
                effects: None,
                jobs: None,
                assets: bundle,
                blobs: None,
            },
        )
        .unwrap(),
    );
    let router = noxide_host::http::router(
        app,
        noxide_host::http::Origin::parse("http://localhost").unwrap(),
    );
    let request = |path: &str| {
        axum::http::Request::builder()
            .uri(path)
            .header("Host", "localhost")
            .body(axum::body::Body::empty())
            .unwrap()
    };
    let mut responses = Vec::new();
    for _ in 0..8 {
        let r = router.clone().oneshot(request(&path)).await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["Cache-Control"], "no-store");
        assert_eq!(r.headers()["X-Content-Type-Options"], "nosniff");
        assert_eq!(r.headers()["Content-Type"], "text/css; charset=utf-8");
        assert!(
            r.headers()["Content-Security-Policy"]
                .to_str()
                .unwrap()
                .contains("font-src 'self'")
        );
        assert!(!r.headers().contains_key("etag"));
        responses.push(r);
    }
    assert_eq!(
        router
            .clone()
            .oneshot(request(&path))
            .await
            .unwrap()
            .status(),
        503
    );
    let response = responses.pop().unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), MAX_ASSET_BYTES)
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), expected);
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        path.strip_prefix(ASSET_PATH_PREFIX).unwrap()
    );
    drop(bytes);
    assert_eq!(
        router
            .clone()
            .oneshot(request(&path))
            .await
            .unwrap()
            .status(),
        200
    );
    drop(responses);
    for alias in [
        format!("{path}?x=1"),
        format!("{path}/"),
        path.replacen("/_noxide", "/%5fnoxide", 1),
        path.to_uppercase(),
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request(&alias))
                .await
                .unwrap()
                .status(),
            404,
            "{alias}"
        );
    }
    let post = axum::http::Request::builder()
        .method("POST")
        .uri(&path)
        .header("Host", "localhost")
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(router.oneshot(post).await.unwrap().status(), 404);
}
