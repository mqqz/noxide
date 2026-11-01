//! Host-owned rendering for safe rich document subtrees.
use super::{AssetBundle, AssetMediaType, valid_asset_name};
use anyhow::{Result, bail, ensure};
use noxide_protocol::{
    RouteRef,
    document::{ClassTokens, Element, PresentationNode},
};

/// Render inside the host's `.noxide-app` root, never on credential pages.
/// The caller supplies the shared remaining node budget and subtracts enclosing
/// document depth. The outer renderer also charges these bytes to its Buffer.
pub fn fragment(
    node: &PresentationNode,
    bundle: &AssetBundle,
    resolve: &dyn Fn(&RouteRef) -> Result<String>,
    remaining_nodes: &mut usize,
    depth_limit: usize,
) -> Result<String> {
    ensure!(flow(node), "rich root flow structure");
    let mut out = String::new();
    render(
        node,
        bundle,
        resolve,
        remaining_nodes,
        depth_limit,
        &mut out,
    )?;
    Ok(out)
}
pub fn stylesheet(name: &str, bundle: &AssetBundle) -> Result<String> {
    ensure!(valid_asset_name(name), "stylesheet asset name");
    let asset = bundle
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("undeclared stylesheet"))?;
    ensure!(
        asset.declaration().media_type == AssetMediaType::Css,
        "stylesheet media type"
    );
    Ok(format!(
        "<link rel=\"stylesheet\" href=\"{}\">",
        asset.path()
    ))
}
fn push(out: &mut String, s: &str) -> Result<()> {
    ensure!(
        out.len().saturating_add(s.len()) <= 262_144,
        "fragment byte limit"
    );
    out.push_str(s);
    Ok(())
}
fn text(out: &mut String, s: &str) -> Result<()> {
    ensure!(
        !s.chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
        "invalid fragment text"
    );
    for c in s.chars() {
        match c {
            '&' => push(out, "&amp;")?,
            '<' => push(out, "&lt;")?,
            '>' => push(out, "&gt;")?,
            '"' => push(out, "&quot;")?,
            '\'' => push(out, "&#39;")?,
            _ => push(out, c.encode_utf8(&mut [0; 4]))?,
        }
    }
    Ok(())
}
fn classes(out: &mut String, c: &ClassTokens) -> Result<()> {
    if !c.tokens().is_empty() {
        push(out, " class=\"")?;
        for (i, c) in c.tokens().iter().enumerate() {
            if i > 0 {
                push(out, " ")?;
            }
            text(out, c)?;
        }
        push(out, "\"")?;
    }
    Ok(())
}
fn element(n: &PresentationNode) -> Option<Element> {
    if let PresentationNode::Element { element, .. } = n {
        Some(*element)
    } else {
        None
    }
}
pub fn inline(n: &PresentationNode) -> bool {
    matches!(
        n,
        PresentationNode::Text(_) | PresentationNode::Image { .. } | PresentationNode::Link { .. }
    ) || element(n).is_some_and(|e| matches!(e, Element::Strong | Element::Emphasis))
}
fn flow(n: &PresentationNode) -> bool {
    !element(n).is_some_and(|e| {
        matches!(
            e,
            Element::Caption
                | Element::TableHead
                | Element::TableBody
                | Element::Row
                | Element::HeaderCell
                | Element::Cell
                | Element::Summary
        )
    })
}
fn children_valid(e: Element, c: &[PresentationNode]) -> Result<()> {
    use Element::*;
    match e {
        Paragraph | Heading2 | Strong | Emphasis | Caption | Summary => {
            ensure!(c.iter().all(inline), "rich phrasing structure")
        }
        Table => {
            let mut head = false;
            let mut body = false;
            let mut rows = false;
            let mut caption = false;
            for (i, n) in c.iter().enumerate() {
                match element(n) {
                    Some(Caption) => {
                        ensure!(i == 0 && !caption, "table caption");
                        caption = true;
                    }
                    Some(TableHead) => {
                        ensure!(!head && !body && !rows, "table head");
                        head = true;
                    }
                    Some(TableBody) => {
                        ensure!(!body && !rows, "table body");
                        body = true;
                    }
                    Some(Row) => {
                        ensure!(!body, "mixed table rows");
                        rows = true;
                    }
                    _ => bail!("table structure"),
                }
            }
        }
        TableHead | TableBody => ensure!(
            c.iter().all(|n| element(n) == Some(Row)),
            "table section structure"
        ),
        Row => ensure!(
            c.iter()
                .all(|n| matches!(element(n), Some(HeaderCell | Cell))),
            "table row structure"
        ),
        Details => ensure!(
            c.first().and_then(element) == Some(Summary) && c[1..].iter().all(flow),
            "details summary structure"
        ),
        Div | Section | HeaderCell | Cell => ensure!(c.iter().all(flow), "rich flow structure"),
    }
    Ok(())
}
fn tag(e: Element) -> &'static str {
    use Element::*;
    match e {
        Div => "div",
        Section => "section",
        Paragraph => "p",
        Heading2 => "h2",
        Strong => "strong",
        Emphasis => "em",
        Table => "table",
        Caption => "caption",
        TableHead => "thead",
        TableBody => "tbody",
        Row => "tr",
        HeaderCell => "th",
        Cell => "td",
        Details => "details",
        Summary => "summary",
    }
}
fn render(
    n: &PresentationNode,
    bundle: &AssetBundle,
    resolve: &dyn Fn(&RouteRef) -> Result<String>,
    remaining: &mut usize,
    depth: usize,
    out: &mut String,
) -> Result<()> {
    ensure!(
        *remaining > 0 && depth > 0,
        "rich document node or depth limit"
    );
    *remaining -= 1;
    match n {
        PresentationNode::Text(s) => text(out, s)?,
        PresentationNode::Image {
            asset,
            alt,
            classes: c,
        } => {
            ensure!(valid_asset_name(asset), "image asset name");
            ensure!(alt.len() <= 1024, "image alternative text limit");
            let a = bundle
                .get(asset)
                .ok_or_else(|| anyhow::anyhow!("undeclared image"))?;
            ensure!(a.declaration().media_type.is_image(), "image media type");
            let (width, height) = a
                .dimensions()
                .ok_or_else(|| anyhow::anyhow!("image metadata"))?;
            push(out, "<img src=\"")?;
            push(out, &a.path())?;
            push(out, "\" alt=\"")?;
            text(out, alt)?;
            push(out, "\"")?;
            classes(out, c)?;
            push(
                out,
                &format!(
                    " width=\"{width}\" height=\"{height}\" loading=\"lazy\" decoding=\"async\">"
                ),
            )?;
        }
        PresentationNode::Link {
            destination,
            text: s,
            classes: c,
        } => {
            let path = resolve(destination)?;
            ensure!(
                path.starts_with('/')
                    && !path.starts_with("//")
                    && !path.chars().any(char::is_control),
                "resolved link path"
            );
            push(out, "<a href=\"")?;
            text(out, &path)?;
            push(out, "\"")?;
            classes(out, c)?;
            push(out, ">")?;
            text(out, s)?;
            push(out, "</a>")?;
        }
        PresentationNode::Element {
            element,
            classes: c,
            children,
        } => {
            children_valid(*element, children)?;
            push(out, "<")?;
            push(out, tag(*element))?;
            classes(out, c)?;
            push(out, ">")?;
            for child in children {
                render(child, bundle, resolve, remaining, depth - 1, out)?;
            }
            push(out, "</")?;
            push(out, tag(*element))?;
            push(out, ">")?;
        }
        PresentationNode::Navigation {
            label,
            classes: c,
            children,
        } => {
            ensure!(
                !label.trim().is_empty() && label.len() <= 128 && children.iter().all(flow),
                "labeled navigation"
            );
            push(out, "<nav aria-label=\"")?;
            text(out, label)?;
            push(out, "\"")?;
            classes(out, c)?;
            push(out, ">")?;
            for child in children {
                render(child, bundle, resolve, remaining, depth - 1, out)?;
            }
            push(out, "</nav>")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(e: Element, children: Vec<PresentationNode>) -> PresentationNode {
        PresentationNode::Element {
            element: e,
            classes: ClassTokens::default(),
            children,
        }
    }
    fn run(n: &PresentationNode) -> Result<String> {
        fragment(
            n,
            &AssetBundle::default(),
            &|_| Ok("/safe".into()),
            &mut 1024,
            32,
        )
    }
    #[test]
    fn semantic_tables_details_and_labels_are_escaped() {
        let details = node(
            Element::Details,
            vec![
                node(
                    Element::Summary,
                    vec![PresentationNode::Text("Show <more>".into())],
                ),
                node(
                    Element::Table,
                    vec![
                        node(
                            Element::Caption,
                            vec![PresentationNode::Text("Totals".into())],
                        ),
                        node(
                            Element::Row,
                            vec![
                                node(
                                    Element::HeaderCell,
                                    vec![PresentationNode::Text("Count".into())],
                                ),
                                node(Element::Cell, vec![PresentationNode::Text("1".into())]),
                            ],
                        ),
                    ],
                ),
            ],
        );
        let nav = PresentationNode::Navigation {
            label: "Example \"nav\"".into(),
            classes: ClassTokens::new(vec!["card".into()]).unwrap(),
            children: vec![details],
        };
        let html = run(&nav).unwrap();
        assert!(html.contains("aria-label=\"Example &quot;nav&quot;\" class=\"card\""));
        assert!(html.contains("<summary>Show &lt;more&gt;</summary><table>"));
    }
    #[test]
    fn parser_reparenting_and_missing_labels_fail_closed() {
        for n in [
            node(
                Element::Table,
                vec![PresentationNode::Text("foster".into())],
            ),
            node(Element::Table, vec![node(Element::Cell, vec![])]),
            node(Element::Row, vec![node(Element::Paragraph, vec![])]),
            node(Element::Details, vec![]),
            node(Element::Details, vec![node(Element::Paragraph, vec![])]),
            node(Element::Summary, vec![node(Element::Table, vec![])]),
            PresentationNode::Navigation {
                label: " ".into(),
                classes: ClassTokens::default(),
                children: vec![],
            },
        ] {
            assert!(run(&n).is_err());
        }
    }
    #[test]
    fn shared_budgets_and_undeclared_assets_are_enforced() {
        let n = node(Element::Div, vec![PresentationNode::Text("x".into())]);
        assert!(fragment(&n, &AssetBundle::default(), &|_| Ok("/".into()), &mut 1, 32).is_err());
        assert!(
            fragment(
                &n,
                &AssetBundle::default(),
                &|_| Ok("/".into()),
                &mut 1024,
                1
            )
            .is_err()
        );
        assert!(
            run(&PresentationNode::Image {
                asset: "x".into(),
                alt: "x".into(),
                classes: ClassTokens::default()
            })
            .is_err()
        );
        assert!(stylesheet("x", &AssetBundle::default()).is_err());
    }
}
