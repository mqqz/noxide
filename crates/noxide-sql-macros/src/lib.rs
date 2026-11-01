//! `sql!("SELECT {column} FROM t WHERE id=${}", n)`: `format!` syntax whose text
//! must be a literal and whose arguments must implement `noxide_sql::SqlArg`.
#![forbid(unsafe_code)]
use proc_macro::{Delimiter, Group, Punct, Spacing, TokenStream, TokenTree};

fn fail(message: &str) -> TokenStream {
    format!("::core::compile_error!({message:?})")
        .parse()
        .unwrap()
}

/// Split at top-level commas. Groups keep their own commas as one token.
fn arguments(input: TokenStream) -> Vec<TokenStream> {
    let mut out = vec![TokenStream::new()];
    for token in input {
        match &token {
            TokenTree::Punct(p) if p.as_char() == ',' => out.push(TokenStream::new()),
            _ => out.last_mut().unwrap().extend([token]),
        }
    }
    if out.last().is_some_and(TokenStream::is_empty) {
        out.pop();
    }
    out
}

/// The literal's contents as written, so escapes survive re-emission.
fn body(source: &str) -> Option<(&str, &str, &str)> {
    if let Some(rest) = source.strip_prefix('r') {
        let hashes = rest.len() - rest.trim_start_matches('#').len();
        let (open, close) = (hashes + 2, hashes + 1);
        Some((
            &source[..open],
            &source[open..source.len() - close],
            &source[source.len() - close..],
        ))
    } else {
        let inner = source.strip_prefix('"')?.strip_suffix('"')?;
        Some(("\"", inner, "\""))
    }
}

enum Hole {
    Next,
    Named(String),
}

/// Text runs separated by holes. `{{` and `}}` remain escaped braces.
fn parse(template: &str) -> Result<(Vec<String>, Vec<Hole>), String> {
    let (mut runs, mut holes, mut text) = (Vec::new(), Vec::new(), String::new());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                text.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                text.push('}');
            }
            '{' => {
                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(c) if c == '_' || c.is_alphanumeric() => name.push(c),
                        _ => return Err("sql! holes are {} or {name}, without format specs".into()),
                    }
                }
                runs.push(std::mem::take(&mut text));
                holes.push(if name.is_empty() {
                    Hole::Next
                } else {
                    Hole::Named(name)
                });
            }
            '}' => return Err("unmatched } in sql! template".into()),
            c => text.push(c),
        }
    }
    runs.push(text);
    Ok((runs, holes))
}

#[proc_macro]
pub fn sql(input: TokenStream) -> TokenStream {
    let mut args = arguments(input).into_iter();
    let Some(first) = args.next() else {
        return fail("sql! requires a string literal");
    };
    let mut tokens = first.into_iter();
    let (Some(TokenTree::Literal(literal)), None) = (tokens.next(), tokens.next()) else {
        return fail("sql! text must be a string literal, never a runtime value");
    };
    let source = literal.to_string();
    let Some((open, template, close)) = body(&source) else {
        return fail("sql! text must be a string literal, never a runtime value");
    };
    let (runs, holes) = match parse(template) {
        Ok(parsed) => parsed,
        Err(message) => return fail(&message),
    };
    let mut positional = args;
    let mut inner = TokenStream::new();
    let path: TokenStream = "::noxide_sql".parse().unwrap();
    let text_piece = |run: &str, into: &mut TokenStream| {
        if run.is_empty() {
            return;
        }
        let run: TokenStream = format!("{open}{run}{close}").parse().unwrap();
        let mut piece = path.clone();
        piece.extend("::Piece::Text".parse::<TokenStream>().unwrap());
        piece.extend([TokenTree::Group(Group::new(Delimiter::Parenthesis, run))]);
        piece.extend([TokenTree::Punct(Punct::new(',', Spacing::Alone))]);
        into.extend(piece);
    };
    let mut runs_iter = runs.iter();
    for hole in &holes {
        text_piece(runs_iter.next().unwrap(), &mut inner);
        let argument = match hole {
            Hole::Named(name) => name.parse::<TokenStream>().unwrap(),
            Hole::Next => match positional.next() {
                Some(argument) => argument,
                None => return fail("sql! template has more holes than arguments"),
            },
        };
        let mut piece = path.clone();
        piece.extend("::SqlArg::piece".parse::<TokenStream>().unwrap());
        let mut call = TokenStream::new();
        call.extend([TokenTree::Punct(Punct::new('&', Spacing::Alone))]);
        call.extend([TokenTree::Group(Group::new(
            Delimiter::Parenthesis,
            argument,
        ))]);
        piece.extend([TokenTree::Group(Group::new(Delimiter::Parenthesis, call))]);
        piece.extend([TokenTree::Punct(Punct::new(',', Spacing::Alone))]);
        inner.extend(piece);
    }
    text_piece(runs_iter.next().unwrap(), &mut inner);
    if positional.next().is_some() {
        return fail("sql! has more arguments than template holes");
    }
    let mut out = path;
    out.extend("::Sql::__assemble".parse::<TokenStream>().unwrap());
    let mut array = TokenStream::new();
    array.extend([TokenTree::Punct(Punct::new('&', Spacing::Alone))]);
    array.extend([TokenTree::Group(Group::new(Delimiter::Bracket, inner))]);
    out.extend([TokenTree::Group(Group::new(Delimiter::Parenthesis, array))]);
    out
}
