//! Fail-closed static CSS grammar. Every lexical token comes from Servo cssparser.
use anyhow::{Result, bail, ensure};
use cssparser::{Parser, ToCss, Token};
use std::collections::BTreeMap;

const MAX_TOKENS: usize = 16_384;
const MAX_RULES: usize = 512;
const MAX_NESTING: usize = 8;
const ROOT: &str = ".noxide-app ";

#[derive(Clone, Debug)]
enum Atom {
    Space,
    Ident(String),
    String(String),
    Hash(String),
    At(String),
    Number(f32),
    Percent(f32),
    Dimension(f32, String),
    Symbol(char),
    Url(String),
    Function(String, Vec<Atom>),
    Parens(Vec<Atom>),
    Block(Vec<Atom>),
}
fn lex<'i>(
    p: &mut Parser<'i>,
    count: &mut usize,
    depth: usize,
    source_len: usize,
) -> std::result::Result<Vec<Atom>, cssparser::ParseError<()>> {
    if depth > MAX_NESTING {
        return Err(cssparser::ParseError::custom(()));
    }
    let mut out = Vec::new();
    loop {
        *count += 1;
        if *count > MAX_TOKENS {
            return Err(cssparser::ParseError::custom(()));
        }
        let before = p.position();
        let token = match p.next_including_whitespace_and_comments() {
            Ok(token) => token.clone(),
            Err(e) if e.kind == cssparser::BasicParseErrorKind::EndOfInput => break,
            Err(e) => return Err(e.into()),
        };
        let a = match token {
            Token::WhiteSpace(_) => Atom::Space,
            Token::Comment(_) => {
                if !p.slice_from(before).ends_with("*/") {
                    return Err(cssparser::ParseError::custom(()));
                }
                Atom::Space
            }
            Token::Ident(v) => Atom::Ident(v.to_string()),
            Token::QuotedString(v) => {
                let raw = p.slice_from(before);
                if raw.len() < 2 || raw.as_bytes().first() != raw.as_bytes().last() {
                    return Err(cssparser::ParseError::custom(()));
                }
                Atom::String(v.to_string())
            }
            Token::Hash(v) | Token::IDHash(v) => Atom::Hash(v.to_string()),
            Token::AtKeyword(v) => Atom::At(v.to_string()),
            Token::Number { value, .. } if value.is_finite() => Atom::Number(value),
            Token::Percentage { unit_value, .. } if unit_value.is_finite() => {
                Atom::Percent(unit_value * 100.0)
            }
            Token::Dimension { value, unit, .. } if value.is_finite() => {
                Atom::Dimension(value, unit.to_string())
            }
            Token::Colon => Atom::Symbol(':'),
            Token::Semicolon => Atom::Symbol(';'),
            Token::Comma => Atom::Symbol(','),
            Token::Delim(v) => Atom::Symbol(v),
            Token::UnquotedUrl(v) => {
                if !p.slice_from(before).ends_with(')') {
                    return Err(cssparser::ParseError::custom(()));
                }
                Atom::Url(v.to_string())
            }
            Token::Function(v) => Atom::Function(
                v.to_string(),
                p.parse_nested_block(|p| lex(p, count, depth + 1, source_len))?,
            ),
            Token::ParenthesisBlock => {
                Atom::Parens(p.parse_nested_block(|p| lex(p, count, depth + 1, source_len))?)
            }
            Token::CurlyBracketBlock => {
                Atom::Block(p.parse_nested_block(|p| lex(p, count, depth + 1, source_len))?)
            }
            _ => return Err(cssparser::ParseError::custom(())),
        };
        out.push(a);
    }
    if depth > 0 && p.position().byte_index() >= source_len {
        return Err(cssparser::ParseError::custom(()));
    }
    Ok(out)
}
fn compact(a: &[Atom]) -> Vec<&Atom> {
    a.iter().filter(|a| !matches!(a, Atom::Space)).collect()
}
fn ident(a: &Atom) -> Option<&str> {
    if let Atom::Ident(v) = a {
        Some(v)
    } else {
        None
    }
}
fn safe_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}
fn serialize(a: &Atom) -> String {
    match a {
        Atom::Space => " ".into(),
        Atom::Ident(v) => {
            let mut out = String::new();
            cssparser::serialize_identifier(v, &mut out).unwrap();
            out
        }
        Atom::String(v) => {
            let mut out = String::new();
            Token::QuotedString(v.as_str().into())
                .to_css(&mut out)
                .unwrap();
            out
        }
        Atom::Hash(v) => format!("#{v}"),
        Atom::At(v) => format!("@{v}"),
        Atom::Number(v) => v.to_string(),
        Atom::Percent(v) => format!("{v}%"),
        Atom::Dimension(v, u) => format!("{v}{u}"),
        Atom::Symbol(c) => c.to_string(),
        Atom::Url(v) => format!("url(\"{v}\")"),
        Atom::Function(n, v) => format!("{n}({})", text(v)),
        Atom::Parens(v) => format!("({})", text(v)),
        Atom::Block(v) => format!("{{{}}}", text(v)),
    }
}
fn text(a: &[Atom]) -> String {
    a.iter().map(serialize).collect()
}

pub(super) fn validate(
    source: &str,
    urls: &BTreeMap<String, super::AssetMediaType>,
) -> Result<Vec<u8>> {
    ensure!(
        source.len() <= super::MAX_CSS_BYTES && !source.contains('\0'),
        "CSS byte limit or NUL"
    );
    let atoms = lex(&mut Parser::new(source), &mut 0, 0, source.len())
        .map_err(|_| anyhow::anyhow!("CSS token grammar or limit"))?;
    let mut rules = 0;
    let output = ruleset(&atoms, urls, &mut rules, 0)?;
    ensure!(output.len() <= 262_144, "compiled CSS limit");
    Ok(output.into_bytes())
}
fn ruleset(
    atoms: &[Atom],
    urls: &BTreeMap<String, super::AssetMediaType>,
    count: &mut usize,
    depth: usize,
) -> Result<String> {
    ensure!(depth <= MAX_NESTING, "CSS rule nesting");
    let mut out = String::new();
    let mut start = 0;
    for (i, a) in atoms.iter().enumerate() {
        if let Atom::Block(body) = a {
            let header = &atoms[start..i];
            let h = compact(header);
            ensure!(!h.is_empty(), "empty CSS rule");
            *count += 1;
            ensure!(*count <= MAX_RULES, "CSS rule limit");
            match h[0] {
                Atom::At(n) if n == "media" || n == "container" => {
                    condition(&h[1..], n == "container")?;
                    out.push_str(&text(header));
                    out.push('{');
                    out.push_str(&ruleset(body, urls, count, depth + 1)?);
                    out.push('}');
                }
                Atom::At(n) if n == "keyframes" => {
                    ensure!(
                        h.len() == 2
                            && ident(h[1]).is_some_and(|n| safe_ident(n) && n.starts_with("nxa-")),
                        "keyframe name"
                    );
                    out.push_str(&text(header));
                    out.push('{');
                    out.push_str(&frames(body, urls, count)?);
                    out.push('}');
                }
                Atom::At(n) if n == "font-face" => {
                    ensure!(h.len() == 1, "font-face prelude");
                    out.push_str("@font-face{");
                    out.push_str(&declarations(body, urls, true)?);
                    out.push('}');
                }
                Atom::At(_) => bail!("unsupported CSS at-rule"),
                _ => {
                    out.push_str(&selectors(header)?);
                    out.push('{');
                    out.push_str(&declarations(body, urls, false)?);
                    out.push('}');
                }
            }
            start = i + 1;
        }
    }
    ensure!(compact(&atoms[start..]).is_empty(), "incomplete CSS rule");
    Ok(out)
}
fn selectors(a: &[Atom]) -> Result<String> {
    let mut out = String::new();
    let mut groups = 0;
    for selector in a.split(|a| matches!(a, Atom::Symbol(','))) {
        groups += 1;
        ensure!(
            groups <= 32 && selector.len() <= 256,
            "selector count or size"
        );
        let mut at = 0;
        while matches!(selector.get(at), Some(Atom::Space)) {
            at += 1;
        }
        compound(selector, &mut at)?;
        loop {
            let before = at;
            while matches!(selector.get(at), Some(Atom::Space)) {
                at += 1;
            }
            if at == selector.len() {
                break;
            }
            if matches!(selector.get(at), Some(Atom::Symbol('>' | '+' | '~'))) {
                at += 1;
                while matches!(selector.get(at), Some(Atom::Space)) {
                    at += 1;
                }
            } else {
                ensure!(at > before, "selector combinator");
            }
            compound(selector, &mut at)?;
        }
        if groups > 1 {
            out.push(',');
        }
        out.push_str(ROOT);
        out.push_str(text(selector).trim());
    }
    Ok(out)
}
fn compound(a: &[Atom], at: &mut usize) -> Result<()> {
    let begin = *at;
    match a.get(*at) {
        Some(Atom::Ident(n)) if safe_ident(n) => *at += 1,
        Some(Atom::Symbol('*')) => *at += 1,
        _ => {}
    }
    while let Some(Atom::Symbol(marker @ ('.' | ':'))) = a.get(*at) {
        let pseudo = *marker == ':';
        *at += 1;
        let Some(Atom::Ident(n)) = a.get(*at) else {
            bail!("selector name")
        };
        ensure!(safe_ident(n), "selector identifier");
        if pseudo {
            ensure!(
                [
                    "hover",
                    "focus",
                    "focus-visible",
                    "focus-within",
                    "active",
                    "first-child",
                    "last-child",
                    "only-child",
                    "empty",
                    "checked",
                    "disabled",
                    "enabled",
                    "open"
                ]
                .contains(&n.as_str()),
                "unsupported pseudo-class"
            );
        }
        *at += 1;
    }
    ensure!(*at > begin, "selector compound");
    Ok(())
}
fn condition(a: &[&Atom], container: bool) -> Result<()> {
    ensure!(!a.is_empty() && a.len() <= 16, "query size");
    let mut start = 0;
    if container && a.first().and_then(|a| ident(a)).is_some_and(safe_ident) {
        start = 1;
    }
    let a = &a[start..];
    ensure!(!a.is_empty(), "empty query");
    for (i, t) in a.iter().enumerate() {
        if i % 2 == 1 {
            ensure!(ident(t) == Some("and"), "query conjunction");
            continue;
        }
        let Atom::Parens(v) = t else {
            bail!("query grammar")
        };
        let v = compact(v);
        ensure!(
            v.len() == 3 && matches!(v[1], Atom::Symbol(':')),
            "query feature grammar"
        );
        ensure!(
            ident(v[0]).is_some_and(
                |n| ["min-width", "max-width", "min-height", "max-height"].contains(&n)
            ),
            "query feature"
        );
        ensure!(
            length(v[2], false) && !matches!(v[2], Atom::Percent(_)),
            "query length"
        );
    }
    ensure!(a.len() % 2 == 1, "incomplete query");
    Ok(())
}
fn frames(
    a: &[Atom],
    urls: &BTreeMap<String, super::AssetMediaType>,
    count: &mut usize,
) -> Result<String> {
    let mut out = String::new();
    let mut start = 0;
    let mut frames = 0;
    for (i, t) in a.iter().enumerate() {
        if let Atom::Block(body) = t {
            frames += 1;
            *count += 1;
            ensure!(frames <= 32 && *count <= MAX_RULES, "keyframe limit");
            for h in a[start..i].split(|a| matches!(a, Atom::Symbol(','))) {
                let h = compact(h);
                ensure!(
                    h.len() == 1
                        && match h[0] {
                            Atom::Ident(n) => n == "from" || n == "to",
                            Atom::Percent(p) => (0.0..=100.0).contains(p),
                            _ => false,
                        },
                    "keyframe selector"
                );
            }
            out.push_str(&text(&a[start..i]));
            out.push('{');
            out.push_str(&declarations(body, urls, false)?);
            out.push('}');
            start = i + 1;
        }
    }
    ensure!(
        frames > 0 && compact(&a[start..]).is_empty(),
        "keyframe grammar"
    );
    Ok(out)
}
fn length(a: &Atom, negative: bool) -> bool {
    match a {
        Atom::Number(v) => *v == 0.0,
        Atom::Percent(v) => v.abs() <= 10_000.0 && (negative || *v >= 0.0),
        Atom::Dimension(v, u) => {
            v.abs() <= 10_000.0
                && (negative || *v >= 0.0)
                && ["px", "em", "rem", "ch", "ex", "vw", "vh", "vmin", "vmax"].contains(&u.as_str())
        }
        _ => false,
    }
}
fn keywords(a: &[&Atom], words: &[&str]) -> bool {
    a.iter()
        .all(|a| ident(a).is_some_and(|n| words.contains(&n)))
}
fn color(a: &[&Atom]) -> bool {
    if a.len() != 1 {
        return false;
    }
    match a[0] {
        Atom::Hash(v) => {
            [3, 4, 6, 8].contains(&v.len()) && v.bytes().all(|c| c.is_ascii_hexdigit())
        }
        Atom::Ident(n) => [
            "transparent",
            "currentcolor",
            "black",
            "white",
            "red",
            "green",
            "blue",
            "gray",
            "silver",
            "navy",
            "teal",
            "purple",
            "maroon",
            "yellow",
            "orange",
            "lime",
            "aqua",
            "fuchsia",
            "olive",
        ]
        .contains(&n.as_str()),
        Atom::Function(n, v) if ["rgb", "rgba", "hsl", "hsla"].contains(&n.as_str()) => {
            let components: Vec<_> = v
                .split(|a| matches!(a, Atom::Symbol(',')))
                .map(compact)
                .collect();
            let alpha = n == "rgba" || n == "hsla";
            if components.len() != if alpha { 4 } else { 3 }
                || components.iter().any(|c| c.len() != 1)
            {
                return false;
            }
            components.iter().enumerate().all(|(i, c)| {
                let value = c[0];
                if i == 3 {
                    return matches!(value,Atom::Number(n) if (0.0..=1.0).contains(n))
                        || matches!(value,Atom::Percent(n) if (0.0..=100.0).contains(n));
                }
                if n == "hsl" || n == "hsla" {
                    if i == 0 {
                        matches!(value,Atom::Number(n) if (0.0..=360.0).contains(n))
                    } else {
                        matches!(value,Atom::Percent(n) if (0.0..=100.0).contains(n))
                    }
                } else {
                    matches!(value,Atom::Number(n) if (0.0..=255.0).contains(n))
                        || matches!(value,Atom::Percent(n) if (0.0..=100.0).contains(n))
                }
            })
        }
        _ => false,
    }
}
fn declarations(
    a: &[Atom],
    urls: &BTreeMap<String, super::AssetMediaType>,
    font: bool,
) -> Result<String> {
    let mut out = String::new();
    let mut count = 0;
    let mut seen = std::collections::BTreeSet::new();
    for d in a.split(|a| matches!(a, Atom::Symbol(';'))) {
        let c = compact(d);
        if c.is_empty() {
            continue;
        }
        count += 1;
        ensure!(count <= 128 && c.len() <= 128, "declaration limit");
        ensure!(
            c.len() >= 3 && matches!(c[1], Atom::Symbol(':')),
            "declaration grammar"
        );
        let Some(name) = ident(c[0]) else {
            bail!("property name")
        };
        ensure!(seen.insert(name), "duplicate CSS property");
        let v = &c[2..];
        let ok = if font {
            match name {
                "font-family" => {
                    v.len() == 1
                        && matches!(v[0],Atom::String(n) if safe_ident(n) && n.starts_with("nxa-"))
                }
                "src" => v.len() == 1 && asset_url(v[0], urls, true),
                "font-style" => v.len() == 1 && keywords(v, &["normal", "italic", "oblique"]),
                "font-weight" => weight(v),
                "font-display" => {
                    v.len() == 1 && keywords(v, &["swap", "fallback", "optional", "block", "auto"])
                }
                _ => false,
            }
        } else {
            property(name, v, urls)
        };
        ensure!(ok, "unsupported CSS declaration: {name}");
        out.push_str(&text(d));
        out.push(';');
    }
    if font {
        ensure!(
            seen.contains("font-family") && seen.contains("src"),
            "incomplete font-face"
        );
    }
    Ok(out)
}
fn asset_url(a: &Atom, urls: &BTreeMap<String, super::AssetMediaType>, font: bool) -> bool {
    let u = match a {
        Atom::Url(u) => Some(u.as_str()),
        Atom::Function(n, v) if n == "url" => {
            let c = compact(v);
            if c.len() == 1 {
                if let Atom::String(s) = c[0] {
                    Some(s.as_str())
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    };
    u.and_then(|u| urls.get(u)).is_some_and(|m| {
        if font {
            *m == super::AssetMediaType::Woff2
        } else {
            m.is_image()
        }
    })
}
fn weight(v: &[&Atom]) -> bool {
    v.len() == 1
        && (keywords(v, &["normal", "bold", "bolder", "lighter"])
            || matches!(v[0],Atom::Number(n) if (1.0..=1000.0).contains(n)))
}
#[allow(clippy::too_many_lines)]
fn property(n: &str, v: &[&Atom], urls: &BTreeMap<String, super::AssetMediaType>) -> bool {
    match n {
        "color"
        | "background-color"
        | "border-color"
        | "outline-color"
        | "text-decoration-color" => color(v),
        "background-image" => {
            v.len() == 1 && (keywords(v, &["none"]) || asset_url(v[0], urls, false))
        }
        "width" | "height" | "min-width" | "max-width" | "min-height" | "max-height" => {
            v.len() == 1
                && (length(v[0], false)
                    || keywords(
                        v,
                        &["auto", "none", "min-content", "max-content", "fit-content"],
                    ))
        }
        "font-size" | "row-gap" | "column-gap" | "padding-top" | "padding-right"
        | "padding-bottom" | "padding-left" => v.len() == 1 && length(v[0], false),
        "outline-width" => v.len() == 1 && length(v[0], false) && !matches!(v[0], Atom::Percent(_)),
        "border-width" => {
            v.len() <= 4
                && v.iter()
                    .all(|a| length(a, false) && !matches!(a, Atom::Percent(_)))
        }
        "gap" => v.len() <= 2 && v.iter().all(|a| length(a, false)),
        "border-radius" | "padding" => v.len() <= 4 && v.iter().all(|a| length(a, false)),
        "margin" => {
            v.len() <= 4
                && v.iter()
                    .all(|a| length(a, true) || ident(a) == Some("auto"))
        }
        "margin-top" | "margin-right" | "margin-bottom" | "margin-left" => {
            v.len() == 1 && (length(v[0], true) || keywords(v, &["auto"]))
        }
        "text-indent" => v.len() == 1 && length(v[0], true),
        "display" => {
            v.len() == 1
                && keywords(
                    v,
                    &[
                        "none",
                        "block",
                        "inline",
                        "inline-block",
                        "flex",
                        "inline-flex",
                        "grid",
                        "inline-grid",
                        "contents",
                        "table",
                        "table-row",
                        "table-cell",
                    ],
                )
        }
        "position" => v.len() == 1 && keywords(v, &["static", "relative"]),
        "box-sizing" => v.len() == 1 && keywords(v, &["border-box", "content-box"]),
        "overflow" | "overflow-x" | "overflow-y" => {
            v.len() == 1 && keywords(v, &["visible", "hidden", "clip", "scroll", "auto"])
        }
        "text-align" => {
            v.len() == 1 && keywords(v, &["start", "end", "left", "right", "center", "justify"])
        }
        "white-space" => {
            v.len() == 1
                && keywords(
                    v,
                    &[
                        "normal",
                        "nowrap",
                        "pre",
                        "pre-wrap",
                        "pre-line",
                        "break-spaces",
                    ],
                )
        }
        "overflow-wrap" | "word-break" => {
            v.len() == 1
                && keywords(
                    v,
                    &["normal", "anywhere", "break-word", "break-all", "keep-all"],
                )
        }
        "font-style" => v.len() == 1 && keywords(v, &["normal", "italic", "oblique"]),
        "font-weight" => weight(v),
        "font-family" => {
            v.len() <= 15
                && v.len() % 2 == 1
                && v.iter().enumerate().all(|(i, a)| {
                    if i % 2 == 1 {
                        matches!(a, Atom::Symbol(','))
                    } else {
                        matches!(a,Atom::String(s) if safe_ident(s))
                            || ident(a).is_some_and(|n| {
                                [
                                    "serif",
                                    "sans-serif",
                                    "monospace",
                                    "system-ui",
                                    "cursive",
                                    "fantasy",
                                ]
                                .contains(&n)
                            })
                    }
                })
        }
        "line-height" => {
            v.len() == 1
                && (length(v[0], false)
                    || keywords(v, &["normal"])
                    || matches!(v[0],Atom::Number(n) if (0.0..=10.0).contains(n)))
        }
        "letter-spacing" | "word-spacing" => {
            v.len() == 1 && (length(v[0], true) || keywords(v, &["normal"]))
        }
        "border-style" => {
            v.len() <= 4 && keywords(v, &["none", "solid", "dashed", "dotted", "double"])
        }
        "outline-style" => {
            v.len() == 1 && keywords(v, &["none", "solid", "dashed", "dotted", "double"])
        }
        "border" | "outline" => {
            v.len() <= 3
                && v.iter().all(|a| {
                    (length(a, false) && !matches!(a, Atom::Percent(_)))
                        || keywords(&[*a], &["none", "solid", "dashed", "dotted", "double"])
                        || color(&[*a])
                })
                && v.iter().filter(|a| length(a, false)).count() <= 1
                && v.iter().filter(|a| color(&[a])).count() <= 1
                && v.iter()
                    .filter(|a| keywords(&[a], &["none", "solid", "dashed", "dotted", "double"]))
                    .count()
                    <= 1
        }
        "text-decoration" | "text-decoration-line" => {
            v.len() <= 3 && keywords(v, &["none", "underline", "overline", "line-through"])
        }
        "flex-direction" => {
            v.len() == 1 && keywords(v, &["row", "row-reverse", "column", "column-reverse"])
        }
        "flex-wrap" => v.len() == 1 && keywords(v, &["nowrap", "wrap", "wrap-reverse"]),
        "align-items" | "align-self" | "justify-content" | "justify-items" | "place-items" => {
            v.len() <= 2
                && keywords(
                    v,
                    &[
                        "normal",
                        "stretch",
                        "start",
                        "end",
                        "center",
                        "baseline",
                        "flex-start",
                        "flex-end",
                        "space-between",
                        "space-around",
                        "space-evenly",
                        "auto",
                    ],
                )
        }
        "flex-grow" | "flex-shrink" => {
            v.len() == 1 && matches!(v[0],Atom::Number(n) if (0.0..=100.0).contains(n))
        }
        "flex-basis" => v.len() == 1 && (length(v[0], false) || keywords(v, &["auto", "content"])),
        "grid-template-columns" | "grid-template-rows" | "grid-auto-columns" | "grid-auto-rows" => {
            v.len() <= 16
                && v.iter().all(|a| {
                    length(a, false)
                        || ident(a).is_some_and(|n| {
                            ["auto", "min-content", "max-content", "none"].contains(&n)
                        })
                        || matches!(a,Atom::Dimension(n,u) if u=="fr"&&(0.0..=100.0).contains(n))
                })
        }
        "container-type" => v.len() == 1 && keywords(v, &["normal", "size", "inline-size"]),
        "container-name" => v.len() == 1 && ident(v[0]).is_some_and(safe_ident),
        "opacity" => v.len() == 1 && matches!(v[0],Atom::Number(n) if (0.0..=1.0).contains(n)),
        "animation-name" => {
            v.len() == 1 && ident(v[0]).is_some_and(|n| safe_ident(n) && n.starts_with("nxa-"))
        }
        "animation-duration" | "animation-delay" => {
            v.len() == 1
                && matches!(v[0],Atom::Dimension(n,u) if *n>=0.0&&((u=="s"&&*n<=10.0)||(u=="ms"&&*n<=10_000.0)))
        }
        "animation-iteration-count" => {
            v.len() == 1 && matches!(v[0],Atom::Number(n) if (1.0..=10.0).contains(n))
        }
        "animation-timing-function" => {
            v.len() == 1
                && keywords(
                    v,
                    &[
                        "linear",
                        "ease",
                        "ease-in",
                        "ease-out",
                        "ease-in-out",
                        "step-start",
                        "step-end",
                    ],
                )
        }
        "animation-direction" => {
            v.len() == 1 && keywords(v, &["normal", "reverse", "alternate", "alternate-reverse"])
        }
        "animation-fill-mode" => {
            v.len() == 1 && keywords(v, &["none", "forwards", "backwards", "both"])
        }
        _ => false,
    }
}
