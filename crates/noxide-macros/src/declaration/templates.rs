use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use syn::{
    Expr, Ident, LitStr, Pat, Token, braced, parenthesized,
    parse::{Parse, ParseStream},
    spanned::Spanned,
};

#[derive(Debug)]
enum Node {
    Text(LitStr),
    Interpolation(Expr),
    Container(Ident, Vec<Node>),
    Link(Expr, Vec<Node>),
    For(Pat, Expr, Vec<Node>),
    If(Expr, Vec<Node>, Vec<Node>),
}

pub(crate) struct Template(Vec<Node>);
impl Parse for Template {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        nodes(input).map(Self)
    }
}

fn body(input: ParseStream<'_>) -> syn::Result<Vec<Node>> {
    let content;
    braced!(content in input);
    nodes(&content)
}

fn nodes(input: ParseStream<'_>) -> syn::Result<Vec<Node>> {
    let mut result = Vec::new();
    while !input.is_empty() {
        if input.peek(LitStr) {
            result.push(Node::Text(input.parse()?));
        } else if input.peek(syn::token::Paren) {
            let content;
            parenthesized!(content in input);
            let expression = content.parse()?;
            if !content.is_empty() {
                return Err(content.error("expected one interpolation expression"));
            }
            result.push(Node::Interpolation(expression));
        } else if input.peek(Token![@]) {
            input.parse::<Token![@]>()?;
            if input.peek(Token![for]) {
                input.parse::<Token![for]>()?;
                let pattern = Pat::parse_multi_with_leading_vert(input)?;
                input.parse::<Token![in]>()?;
                let expression = Expr::parse_without_eager_brace(input)?;
                result.push(Node::For(pattern, expression, body(input)?));
            } else if input.peek(Token![if]) {
                input.parse::<Token![if]>()?;
                let expression = Expr::parse_without_eager_brace(input)?;
                let then = body(input)?;
                let otherwise = if input.peek(Token![@]) && input.peek2(Token![else]) {
                    input.parse::<Token![@]>()?;
                    input.parse::<Token![else]>()?;
                    if input.peek(Token![if]) {
                        input.parse::<Token![if]>()?;
                        let condition = Expr::parse_without_eager_brace(input)?;
                        vec![Node::If(condition, body(input)?, Vec::new())]
                    } else {
                        body(input)?
                    }
                } else {
                    Vec::new()
                };
                result.push(Node::If(expression, then, otherwise));
            } else {
                return Err(input.error("templates support @for and @if"));
            }
        } else {
            let tag: Ident = input.parse()?;
            if tag == "a" {
                let href: Ident = input.parse()?;
                if href != "href" {
                    return Err(syn::Error::new(
                        href.span(),
                        "anchors require href=(typed_route)",
                    ));
                }
                input.parse::<Token![=]>()?;
                let destination;
                parenthesized!(destination in input);
                let destination = destination.parse()?;
                result.push(Node::Link(destination, body(input)?));
            } else {
                container(&tag)?;
                if !input.peek(syn::token::Brace) {
                    return Err(
                        input.error("this element accepts no attributes; use a typed component")
                    );
                }
                result.push(Node::Container(tag, body(input)?));
            }
        }
    }
    Ok(result)
}

fn container(tag: &Ident) -> syn::Result<Ident> {
    let name = match tag.to_string().as_str() {
        "article" => "Article",
        "section" => "Section",
        "h1" => "Heading1",
        "h2" => "Heading2",
        "p" => "Paragraph",
        "ul" => "List",
        "li" => "Item",
        "strong" => "Strong",
        "em" => "Emphasis",
        "code" => "Code",
        "pre" => "Pre",
        "main" => "Main",
        "nav" => "Nav",
        "header" => "Header",
        "footer" => "Footer",
        "div" => "Div",
        _ => return Err(syn::Error::new(tag.span(), "unsupported document element")),
    };
    Ok(format_ident!("{name}", span = tag.span()))
}

fn emit(nodes: &[Node], target: &Ident, form: bool) -> syn::Result<Tokens> {
    let mut output = Tokens::new();
    for node in nodes {
        output.extend(match node {
            Node::Text(text) => quote!(#target.text(#text);),
            Node::Interpolation(expr) => quote!(#target.append(#expr);),
            Node::Container(tag, children) => {
                let tag = container(tag)?;
                let children = emit(children, target, form)?;
                quote!(#target.begin(::noxide::Container::#tag); #children #target.end();)
            }
            Node::Link(destination, children) => {
                if form { return Err(syn::Error::new(destination.span(), "form blueprints support field controls and structural content; links belong in the page")); }
                let child = Ident::new("__noxide_link_content", proc_macro2::Span::mixed_site());
                let children = emit(children, &child, false)?;
                quote! {
                    { let mut #child = ::noxide::Fragment::new(); #children #target.link(#destination, #child); }
                }
            }
            Node::For(pattern, expression, children) => {
                let children = emit(children, target, form)?;
                quote!(for #pattern in #expression { #children })
            }
            Node::If(expression, then, otherwise) => {
                let then = emit(then, target, form)?;
                let otherwise = emit(otherwise, target, form)?;
                quote!(if #expression { #then } else { #otherwise })
            }
        });
    }
    Ok(output)
}

pub(crate) fn expand_template(template: Template, form: bool) -> syn::Result<Tokens> {
    let builder = Ident::new("__noxide_fragment", proc_macro2::Span::mixed_site());
    let construction = if form {
        quote!(::noxide::FormLayout::new())
    } else {
        quote!(::noxide::Fragment::new())
    };
    let output = emit(&template.0, &builder, form)?;
    Ok(quote!({ let mut #builder = #construction; #output #builder }))
}
