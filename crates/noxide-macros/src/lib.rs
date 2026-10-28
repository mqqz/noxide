//! Declarations and templates for the Noxide guest SDK.
//!
//! Macro expansion happens inside the isolated application build.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use std::collections::{BTreeMap, BTreeSet};
use syn::{
    Attribute, Data, DeriveInput, Expr, Fields, Ident, LitInt, LitStr, Pat, Token, Type, braced,
    parenthesized,
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned,
};

fn finish(result: syn::Result<Tokens>) -> TokenStream {
    result.unwrap_or_else(syn::Error::into_compile_error).into()
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn key(value: LitStr) -> syn::Result<LitStr> {
    if identifier(&value.value()) {
        Ok(value)
    } else {
        Err(syn::Error::new(
            value.span(),
            "persistent keys must be lowercase ASCII identifiers of at most 32 bytes",
        ))
    }
}

fn stable_id(value: &str) -> u32 {
    value.bytes().fold(2_166_136_261_u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(16_777_619)
    })
}

fn reject_generics(input: &DeriveInput) -> syn::Result<()> {
    if input.generics.params.is_empty() && input.generics.where_clause.is_none() {
        Ok(())
    } else {
        Err(syn::Error::new(
            input.generics.span(),
            "application declarations cannot be generic",
        ))
    }
}

fn required_key(attrs: &[Attribute], attribute: &str) -> syn::Result<LitStr> {
    let mut found = None;
    let mut count = 0;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident(attribute)) {
        count += 1;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("key") && found.is_none() {
                found = Some(key(meta.value()?.parse()?)?);
                Ok(())
            } else {
                Err(meta.error("expected one explicit key = \"persistent_name\""))
            }
        })?;
    }
    if count != 1 {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            format!("expected one #[{attribute}(key = \"persistent_name\")]"),
        ));
    }
    found.ok_or_else(|| syn::Error::new(proc_macro2::Span::call_site(), "missing persistent key"))
}

fn text_type(ty: &Type) -> bool {
    let Type::Path(path) = ty else { return false };
    let Some(last) = path.path.segments.last() else {
        return false;
    };
    if last.ident == "String" {
        return true;
    }
    if last.ident == "Option"
        && let syn::PathArguments::AngleBracketed(args) = &last.arguments
        && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
    {
        return text_type(inner);
    }
    false
}

fn validate_field_type(ty: &Type, inside_option: bool) -> syn::Result<()> {
    let Type::Path(path) = ty else {
        return Err(syn::Error::new(
            ty.span(),
            "fields support String, bool, i64, Choice enums, and Option<T>",
        ));
    };
    let segment = path
        .path
        .segments
        .last()
        .ok_or_else(|| syn::Error::new(ty.span(), "missing field type"))?;
    if segment.ident == "Option" {
        if inside_option {
            return Err(syn::Error::new(
                ty.span(),
                "nested Option fields are not representable",
            ));
        }
        let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
            return Err(syn::Error::new(ty.span(), "Option requires one field type"));
        };
        if arguments.args.len() != 1 {
            return Err(syn::Error::new(ty.span(), "Option requires one field type"));
        }
        let Some(syn::GenericArgument::Type(inner)) = arguments.args.first() else {
            return Err(syn::Error::new(ty.span(), "Option requires one field type"));
        };
        return validate_field_type(inner, true);
    }
    if !matches!(segment.arguments, syn::PathArguments::None)
        || matches!(
            segment.ident.to_string().as_str(),
            "Id" | "Vec"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i128"
                | "isize"
                | "f32"
                | "f64"
                | "char"
                | "str"
        )
    {
        return Err(syn::Error::new(
            ty.span(),
            "fields support String, bool, i64, Choice enums, and Option<T>",
        ));
    }
    Ok(())
}

#[proc_macro_derive(Resource, attributes(resource, field, id))]
pub fn resource(input: TokenStream) -> TokenStream {
    finish(expand_resource(parse_macro_input!(input as DeriveInput)))
}

fn expand_resource(input: DeriveInput) -> syn::Result<Tokens> {
    reject_generics(&input)?;
    let persistent_key = required_key(&input.attrs, "resource")?;
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(
            input.span(),
            "Resource requires a named struct",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new(
            data.fields.span(),
            "Resource requires named fields",
        ));
    };
    let mut definitions = Vec::new();
    let mut decoding = Vec::new();
    let mut specs = Vec::new();
    let mut handles = Vec::new();
    let mut keys = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let mut identity = false;
    let name = &input.ident;
    for field in &fields.named {
        let rust_name = field.ident.as_ref().expect("named field");
        let ty = &field.ty;
        let ids: Vec<_> = field
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("id"))
            .collect();
        if !ids.is_empty() {
            if identity || ids.len() != 1 || !matches!(ids[0].meta, syn::Meta::Path(_)) {
                return Err(syn::Error::new(
                    field.span(),
                    "Resource requires exactly one #[id] field",
                ));
            }
            if field.attrs.iter().any(|attr| attr.path().is_ident("field")) {
                return Err(syn::Error::new(
                    field.span(),
                    "the host-generated id cannot be a stored application field",
                ));
            }
            identity = true;
            decoding.push(quote!(#rust_name: ::noxide::Id::<Self>::new(record.id)));
            continue;
        }
        validate_field_type(ty, false)?;
        let mut field_key = None;
        let mut label = None;
        let mut maximum = None;
        let mut min = None;
        let mut max = None;
        let attrs: Vec<_> = field
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("field"))
            .collect();
        if attrs.len() != 1 {
            return Err(syn::Error::new(
                field.span(),
                "stored fields require #[field(key = \"persistent_name\", ...)]",
            ));
        }
        attrs[0].parse_nested_meta(|meta| {
            if meta.path.is_ident("key") && field_key.is_none() {
                field_key = Some(key(meta.value()?.parse()?)?);
            } else if meta.path.is_ident("label") && label.is_none() {
                label = Some(meta.value()?.parse::<LitStr>()?);
            } else if meta.path.is_ident("max_bytes") && maximum.is_none() {
                maximum = Some(meta.value()?.parse::<LitInt>()?);
            } else if meta.path.is_ident("min") && min.is_none() {
                min = Some(meta.value()?.parse::<Expr>()?);
            } else if meta.path.is_ident("max") && max.is_none() {
                max = Some(meta.value()?.parse::<Expr>()?);
            } else {
                return Err(meta.error("unknown or duplicate field option"));
            }
            Ok(())
        })?;
        let field_key = field_key
            .ok_or_else(|| syn::Error::new(field.span(), "missing persistent field key"))?;
        if !keys.insert(field_key.value()) {
            return Err(syn::Error::new(
                field_key.span(),
                "duplicate persistent field key",
            ));
        }
        if text_type(ty) && maximum.is_none() {
            return Err(syn::Error::new(
                ty.span(),
                "text fields require an explicit max_bytes bound",
            ));
        }
        let maximum = maximum.unwrap_or_else(|| LitInt::new("64", field.span()));
        let maximum_value = maximum.base10_parse::<u32>()?;
        if maximum_value == 0 || maximum_value > 4096 {
            return Err(syn::Error::new(
                maximum.span(),
                "max_bytes must be between 1 and 4096",
            ));
        }
        let label = label.unwrap_or_else(|| {
            let mut text = rust_name.to_string().replace('_', " ");
            if let Some(first) = text.get_mut(..1) {
                first.make_ascii_uppercase();
            }
            LitStr::new(&text, rust_name.span())
        });
        if label.value().is_empty()
            || label.value().len() > 128
            || label.value().chars().any(char::is_control)
        {
            return Err(syn::Error::new(
                label.span(),
                "labels must contain 1 to 128 bytes without control characters",
            ));
        }
        let bounds = if min.is_some() || max.is_some() {
            let lower = min.map_or_else(|| quote!(None), |v| quote!(Some(#v)));
            let upper = max.map_or_else(|| quote!(None), |v| quote!(Some(#v)));
            quote! {
                match <#ty as ::noxide::FieldValue>::kind() {
                    ::noxide::FieldKind::Integer { .. } => ::noxide::FieldKind::Integer { min: #lower, max: #upper },
                    _ => panic!("min/max bounds require an integer field"),
                }
            }
        } else {
            quote!(<#ty as ::noxide::FieldValue>::kind())
        };
        definitions.push(quote! {
            ::noxide::__private::TextField {
                name: #field_key.into(), label: #label.into(), max_bytes: #maximum,
                kind: { #bounds }, optional: <#ty as ::noxide::FieldValue>::OPTIONAL,
            }
        });
        decoding.push(quote! {
            #rust_name: <#ty as ::noxide::FieldValue>::decode(record.fields.get(#field_key).expect("host resource field"))
        });
        let hash = stable_id(&rust_name.to_string());
        if !hashes.insert(hash) {
            return Err(syn::Error::new(
                rust_name.span(),
                "field identifier collision",
            ));
        }
        specs.push(quote! {
            impl ::noxide::FieldSpec<#hash> for #name {
                type Value = #ty;
                const KEY: &'static str = #field_key;
            }
        });
        handles.push(quote! {
            #[allow(non_upper_case_globals)]
            pub const #rust_name: ::noxide::Field<Self, #ty> = ::noxide::Field::new(#field_key);
        });
    }
    if !identity {
        return Err(syn::Error::new(
            name.span(),
            "Resource requires one #[id] field",
        ));
    }
    if definitions.is_empty() || definitions.len() > 8 {
        return Err(syn::Error::new(
            name.span(),
            "Resource requires between 1 and 8 stored fields",
        ));
    }
    Ok(quote! {
        impl ::noxide::ResourceType for #name {
            const KEY: &'static str = #persistent_key;
            fn definition() -> ::noxide::__private::Resource {
                ::noxide::__private::Resource {
                    id: ::noxide::stable_id(<Self as ::noxide::ResourceType>::KEY), name: <Self as ::noxide::ResourceType>::KEY.into(), fields: vec![#(#definitions),*],
                }
            }
            fn from_record(record: ::noxide::__private::Record) -> Self {
                assert_eq!(record.resource, ::noxide::stable_id(<Self as ::noxide::ResourceType>::KEY), "host resource type");
                Self { #(#decoding),* }
            }
        }
        impl #name { #(#handles)* }
        #(#specs)*
    })
}

#[proc_macro_derive(Choice, attributes(choice))]
pub fn choice(input: TokenStream) -> TokenStream {
    finish(expand_choice(parse_macro_input!(input as DeriveInput)))
}

fn expand_choice(input: DeriveInput) -> syn::Result<Tokens> {
    reject_generics(&input)?;
    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new(input.span(), "Choice requires an enum"));
    };
    if data.variants.is_empty() || data.variants.len() > 32 {
        return Err(syn::Error::new(
            input.span(),
            "Choice requires between 1 and 32 variants",
        ));
    }
    let mut keys = BTreeSet::new();
    let mut variants = Vec::new();
    let mut encoding = Vec::new();
    let mut decoding = Vec::new();
    let mut rendering = Vec::new();
    let enum_name = &input.ident;
    for variant in &data.variants {
        if variant.fields != Fields::Unit || variant.discriminant.is_some() {
            return Err(syn::Error::new(
                variant.span(),
                "Choice variants must be unit variants without discriminants",
            ));
        }
        let attrs: Vec<_> = variant
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("choice"))
            .collect();
        if attrs.len() != 1 {
            return Err(syn::Error::new(
                variant.span(),
                "each variant requires #[choice(key = \"stable_key\", label = \"Label\")]",
            ));
        }
        let mut variant_key = None;
        let mut label = None;
        attrs[0].parse_nested_meta(|meta| {
            if meta.path.is_ident("key") && variant_key.is_none() {
                variant_key = Some(key(meta.value()?.parse()?)?);
            } else if meta.path.is_ident("label") && label.is_none() {
                label = Some(meta.value()?.parse::<LitStr>()?);
            } else {
                return Err(meta.error("unknown or duplicate choice option"));
            }
            Ok(())
        })?;
        let variant_key =
            variant_key.ok_or_else(|| syn::Error::new(variant.span(), "missing choice key"))?;
        let label = label.ok_or_else(|| syn::Error::new(variant.span(), "missing choice label"))?;
        if !keys.insert(variant_key.value()) {
            return Err(syn::Error::new(variant_key.span(), "duplicate choice key"));
        }
        if label.value().is_empty()
            || label.value().len() > 128
            || label.value().chars().any(char::is_control)
        {
            return Err(syn::Error::new(label.span(), "invalid choice label"));
        }
        let name = &variant.ident;
        variants.push(
            quote!(::noxide::ChoiceVariant { key: #variant_key.into(), label: #label.into() }),
        );
        encoding.push(quote!(Self::#name => #variant_key.into()));
        decoding.push(quote!(#variant_key => Self::#name));
        rendering.push(quote!(#enum_name::#name => #label));
    }
    let name = &input.ident;
    Ok(quote! {
        impl ::noxide::SelectValue for #name {}
        impl ::noxide::Render for #name {
            fn render(self, fragment: &mut ::noxide::Fragment) {
                <&Self as ::noxide::Render>::render(&self, fragment);
            }
        }
        impl ::noxide::Render for &#name {
            fn render(self, fragment: &mut ::noxide::Fragment) {
                fragment.text(match self { #(#rendering),* });
            }
        }
        impl ::noxide::FieldValue for #name {
            const OPTIONAL: bool = false;
            fn kind() -> ::noxide::FieldKind {
                ::noxide::FieldKind::Choice { variants: vec![#(#variants),*] }
            }
            fn encode(&self) -> String { match self { #(#encoding),* } }
            fn decode(value: &str) -> Self {
                match value { #(#decoding,)* _ => panic!("host choice contract") }
            }
        }
    })
}

#[derive(Debug)]
enum Node {
    Text(LitStr),
    Interpolation(Expr),
    Container(Ident, Vec<Node>),
    Link(Expr, Vec<Node>),
    For(Pat, Expr, Vec<Node>),
    If(Expr, Vec<Node>, Vec<Node>),
}

struct Template(Vec<Node>);
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

fn expand_template(template: Template, form: bool) -> syn::Result<Tokens> {
    let builder = Ident::new("__noxide_fragment", proc_macro2::Span::mixed_site());
    let construction = if form {
        quote!(::noxide::FormLayout::new())
    } else {
        quote!(::noxide::Fragment::new())
    };
    let output = emit(&template.0, &builder, form)?;
    Ok(quote!({ let mut #builder = #construction; #output #builder }))
}

/// Build a constrained document fragment.
#[proc_macro]
pub fn html(input: TokenStream) -> TokenStream {
    finish(expand_template(
        parse_macro_input!(input as Template),
        false,
    ))
}

/// Build a static form layout from typed field placeholders.
#[proc_macro]
pub fn form(input: TokenStream) -> TokenStream {
    finish(expand_template(parse_macro_input!(input as Template), true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_requires_stable_keys_and_text_bounds() {
        let input = syn::parse_quote! {
            #[resource(key = "notes")]
            struct Note { #[id] id: Id<Self>, #[field(key = "body")] body: String }
        };
        assert!(
            expand_resource(input)
                .unwrap_err()
                .to_string()
                .contains("max_bytes")
        );
        let input = syn::parse_quote! {
            #[resource(key = "notes")]
            struct Note { #[id] id: Id<Self>, #[field(key = "body", max_bytes = 100)] body: String }
        };
        assert!(expand_resource(input).is_ok());
    }

    #[test]
    fn resource_rejects_duplicate_keys() {
        let input = syn::parse_quote! {
            #[resource(key = "tasks")]
            struct Task { #[id] id: Id<Self>, #[field(key = "same")] left: bool, #[field(key = "same")] right: bool }
        };
        assert!(
            expand_resource(input)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn templates_reject_raw_tags_and_attributes() {
        assert!(syn::parse_str::<Template>("script { \"alert()\" }").is_err());
        assert!(syn::parse_str::<Template>("p onclick=(x) { \"x\" }").is_err());
        assert!(syn::parse_str::<Template>("img src=(x) {}").is_err());
    }

    #[test]
    fn templates_compose_rust_control_flow() {
        let template = syn::parse_str::<Template>("@for task in &tasks { @if task.done { p { (&task.title) } } @else { a href=(routes::show(task.id)) { \"Open\" } } }").unwrap();
        let output = expand_template(template, false).unwrap();
        assert!(syn::parse2::<Expr>(output).is_ok());
    }

    #[test]
    fn choices_render_display_labels_as_text_for_owned_and_borrowed_values() {
        let input = syn::parse_quote! {
            enum Priority {
                #[choice(key = "normal", label = "Normal <work>")] Normal,
                #[choice(key = "urgent", label = "Urgent")] Urgent,
            }
        };
        let tokens = expand_choice(input).unwrap();
        let text = tokens.to_string();
        assert!(text.contains("Render for Priority"));
        assert!(text.contains("Render for & Priority"));
        assert!(text.contains("fragment . text (match self"));
        assert!(text.contains("Normal <work>"));
        assert!(!text.contains("Display for"));
        assert!(syn::parse2::<syn::File>(tokens).is_ok());
    }

    #[test]
    fn choices_require_unique_stable_keys() {
        let input = syn::parse_quote! {
            enum Priority { #[choice(key = "low", label = "Low")] Low, #[choice(key = "low", label = "Other")] Other }
        };
        assert!(
            expand_choice(input)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }
}

#[derive(Clone)]
enum PolicyAtom {
    Public,
    Owner,
    Tenant,
    Role(LitStr, bool),
}

fn policy(input: ParseStream<'_>) -> syn::Result<Vec<Vec<PolicyAtom>>> {
    let name: Ident = input.parse()?;
    match name.to_string().as_str() {
        "public" => Ok(vec![vec![PolicyAtom::Public]]),
        "owner" => Ok(vec![vec![PolicyAtom::Owner]]),
        "same_tenant" => Ok(vec![vec![PolicyAtom::Tenant]]),
        "role" | "tenant_role" => {
            let content;
            parenthesized!(content in input);
            let role = key(content.parse()?)?;
            if !content.is_empty() {
                return Err(content.error("expected one role name"));
            }
            Ok(vec![vec![PolicyAtom::Role(role, name == "tenant_role")]])
        }
        "all" | "any" => {
            let content;
            parenthesized!(content in input);
            if content.is_empty() {
                return Err(content.error("policy groups cannot be empty"));
            }
            let conjunction = name == "all";
            let mut rules = if conjunction {
                vec![Vec::new()]
            } else {
                Vec::new()
            };
            while !content.is_empty() {
                let term = policy(&content)?;
                if term
                    .iter()
                    .flatten()
                    .any(|p| matches!(p, PolicyAtom::Public))
                {
                    return Err(syn::Error::new(
                        name.span(),
                        "public cannot appear inside any or all",
                    ));
                }
                if conjunction {
                    let mut combined = Vec::new();
                    for left in &rules {
                        for right in &term {
                            if combined.len() == 8 || left.len() + right.len() > 4 {
                                return Err(syn::Error::new(
                                    name.span(),
                                    "policy limit: at most 8 alternatives of 4 predicates",
                                ));
                            }
                            let mut rule = left.clone();
                            rule.extend(right.clone());
                            combined.push(rule);
                        }
                    }
                    rules = combined;
                } else {
                    rules.extend(term);
                    if rules.len() > 8 {
                        return Err(syn::Error::new(name.span(), "policy alternative limit"));
                    }
                }
                if !content.is_empty() {
                    content.parse::<Token![,]>()?;
                }
            }
            Ok(rules)
        }
        _ => Err(syn::Error::new(
            name.span(),
            "expected owner, same_tenant, role, tenant_role, all, or any",
        )),
    }
}

fn policy_tokens(rules: &[Vec<PolicyAtom>]) -> Tokens {
    let rules = rules.iter().map(|rule| {
        let predicates = rule.iter().map(|atom| match atom {
            PolicyAtom::Public => quote!(::noxide::__private::Predicate::Public),
            PolicyAtom::Owner => quote!(::noxide::__private::Predicate::Owner),
            PolicyAtom::Tenant => quote!(::noxide::__private::Predicate::SameTenant),
            PolicyAtom::Role(name, tenant_scoped) => quote!(::noxide::__private::Predicate::Role { name: #name.into(), tenant_scoped: #tenant_scoped }),
        });
        quote!(vec![#(#predicates),*])
    });
    quote!(::noxide::__private::Policy {
        any: vec![#(#rules),*]
    })
}

struct OperationDeclaration {
    kind: Ident,
    resource: Type,
    policy: Vec<Vec<PolicyAtom>>,
    fields: Vec<Ident>,
    visible: Option<(Ident, Expr)>,
    redirect: Option<syn::Path>,
    inspect: Option<Type>,
    inspection_fields: Vec<Ident>,
    version: u32,
}

impl Parse for OperationDeclaration {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let kind: Ident = input.parse()?;
        let resource;
        parenthesized!(resource in input);
        let resource_type = resource.parse()?;
        if !resource.is_empty() {
            return Err(resource.error("expected one resource type"));
        }
        let mut result = Self {
            kind,
            resource: resource_type,
            policy: Vec::new(),
            fields: Vec::new(),
            visible: None,
            redirect: None,
            inspect: None,
            inspection_fields: Vec::new(),
            version: 1,
        };
        let mut options = BTreeSet::new();
        while !input.is_empty() {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
            let option: Ident = input.parse()?;
            if !options.insert(option.to_string()) {
                return Err(syn::Error::new(
                    option.span(),
                    "duplicate declaration option",
                ));
            }
            match option.to_string().as_str() {
                "allow" => {
                    input.parse::<Token![=]>()?;
                    result.policy = policy(input)?;
                }
                "visible" => {
                    let content;
                    parenthesized!(content in input);
                    let field = content.parse()?;
                    content.parse::<Token![=]>()?;
                    let value = content.parse()?;
                    if !content.is_empty() {
                        return Err(content.error("expected one visibility predicate"));
                    }
                    result.visible = Some((field, value));
                }
                "fields" | "inspect_fields" => {
                    let content;
                    parenthesized!(content in input);
                    let names = content.parse_terminated(Ident::parse, Token![,])?;
                    let mut seen = BTreeSet::new();
                    for name in &names {
                        if !seen.insert(name.to_string()) {
                            return Err(syn::Error::new(name.span(), "duplicate projected field"));
                        }
                    }
                    if option == "fields" {
                        result.fields = names.into_iter().collect();
                    } else {
                        result.inspection_fields = names.into_iter().collect();
                    }
                }
                "redirect" => {
                    input.parse::<Token![=]>()?;
                    result.redirect = Some(input.parse()?);
                }
                "inspect" => {
                    input.parse::<Token![=]>()?;
                    result.inspect = Some(input.parse()?);
                }
                "version" => {
                    input.parse::<Token![=]>()?;
                    let value: LitInt = input.parse()?;
                    result.version = value.base10_parse()?;
                    if result.version == 0 {
                        return Err(syn::Error::new(
                            value.span(),
                            "action version must be positive",
                        ));
                    }
                }
                _ => return Err(syn::Error::new(option.span(), "unknown declaration option")),
            }
        }
        if result.policy.is_empty() {
            return Err(input.error("an explicit allow policy is required"));
        }
        Ok(result)
    }
}

fn marker(item: &syn::ItemStruct) -> syn::Result<()> {
    if !matches!(item.fields, Fields::Unit)
        || !item.generics.params.is_empty()
        || item.generics.where_clause.is_some()
    {
        return Err(syn::Error::new(
            item.span(),
            "operations are nongeneric unit structs",
        ));
    }
    Ok(())
}

#[proc_macro_attribute]
pub fn query(attr: TokenStream, input: TokenStream) -> TokenStream {
    finish(expand_query(
        parse_macro_input!(attr as OperationDeclaration),
        parse_macro_input!(input as syn::ItemStruct),
    ))
}

fn expand_query(declaration: OperationDeclaration, item: syn::ItemStruct) -> syn::Result<Tokens> {
    marker(&item)?;
    let kind = match declaration.kind.to_string().as_str() {
        "list" => quote!(::noxide::__private::OperationKind::List),
        "read" => quote!(::noxide::__private::OperationKind::Read),
        _ => {
            return Err(syn::Error::new(
                declaration.kind.span(),
                "queries support list(Resource) or read(Resource)",
            ));
        }
    };
    let public = declaration
        .policy
        .iter()
        .flatten()
        .any(|p| matches!(p, PolicyAtom::Public));
    if public && (declaration.visible.is_none() || declaration.fields.is_empty()) {
        return Err(syn::Error::new(
            item.span(),
            "public queries require visible(...) and nonempty fields(...)",
        ));
    }
    if declaration.redirect.is_some()
        || declaration.inspect.is_some()
        || (!public && (!declaration.fields.is_empty() || declaration.visible.is_some()))
        || !declaration.inspection_fields.is_empty()
        || declaration.version != 1
    {
        return Err(syn::Error::new(
            item.span(),
            "query declarations accept only an operation and allow policy",
        ));
    }
    let query_trait = if declaration.kind == "list" {
        quote!(::noxide::ListQuery)
    } else {
        quote!(::noxide::ReadQuery)
    };
    let name = &item.ident;
    let resource = &declaration.resource;
    let policy = policy_tokens(&declaration.policy);
    let vis = &item.vis;
    let output_name = format_ident!("{name}Record");
    let (projection, output, decode, visibility, fields) = if public {
        let names = &declaration.fields;
        let mut identity = "__noxide_record_id".to_owned();
        while names.iter().any(|name| name == identity.as_str()) {
            identity.push('_');
        }
        let identity = format_ident!("{identity}");
        let hashes: Vec<_> = names
            .iter()
            .map(|name| stable_id(&name.to_string()))
            .collect();
        let types: Vec<_> = hashes
            .iter()
            .map(|hash| quote!(<#resource as ::noxide::FieldSpec<#hash>>::Value))
            .collect();
        let keys: Vec<_> = hashes
            .iter()
            .map(|hash| quote!(<#resource as ::noxide::FieldSpec<#hash>>::KEY))
            .collect();
        let (field, value) = declaration.visible.as_ref().expect("checked visibility");
        let hash = stable_id(&field.to_string());
        (
            quote! {
                #vis struct #output_name { #identity: ::noxide::Id<#resource>, #(pub #names: #types),* }
                impl #output_name { pub fn id(&self) -> ::noxide::Id<#resource> { self.#identity } }
            },
            quote!(#output_name),
            quote!({
                assert_eq!(record.resource, <#resource as ::noxide::ResourceType>::definition().id, "host resource type");
                #output_name { #identity: ::noxide::Id::new(record.id), #(#names: <#types as ::noxide::FieldValue>::decode(record.fields.get(#keys).expect("host projected field"))),* }
            }),
            quote!(Some(::noxide::__private::Visibility { field: <#resource as ::noxide::FieldSpec<#hash>>::KEY.into(), equals: ::noxide::FieldValue::encode(&(#value)) })),
            quote!(Some(vec![#(#keys.into()),*])),
        )
    } else {
        (
            Tokens::new(),
            quote!(#resource),
            quote!(<#resource as ::noxide::ResourceType>::from_record(record)),
            quote!(None),
            quote!(None),
        )
    };
    Ok(quote! {
        #item
        #projection
        impl #query_trait for #name {}
        impl ::noxide::QueryType for #name {
            type Resource = #resource;
            type Output = #output;
            fn from_record(record: ::noxide::__private::Record) -> Self::Output { #decode }
            fn operation() -> ::noxide::__private::Operation {
                ::noxide::__private::Operation {
                    visibility: #visibility, fields: #fields,
                    id: ::noxide::stable_id(concat!("query:", module_path!(), "::", stringify!(#name))),
                    resource: <#resource as ::noxide::ResourceType>::definition().id,
                    kind: #kind, policy: #policy,
                }
            }
        }
    })
}

#[proc_macro_attribute]
pub fn action(attr: TokenStream, input: TokenStream) -> TokenStream {
    finish(expand_action(
        parse_macro_input!(attr as OperationDeclaration),
        parse_macro_input!(input as syn::ItemStruct),
    ))
}

fn action_label(identifier: &str) -> String {
    let characters: Vec<_> = identifier.chars().collect();
    let mut words = Vec::new();
    let mut word = String::new();
    for (index, character) in characters.iter().copied().enumerate() {
        let boundary = character.is_uppercase()
            && index > 0
            && (characters[index - 1].is_lowercase()
                || characters[index - 1].is_numeric()
                || characters[index - 1].is_uppercase()
                    && characters
                        .get(index + 1)
                        .is_some_and(|next| next.is_lowercase()));
        if (boundary || character == '_') && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        if character != '_' {
            word.push(character);
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
        .into_iter()
        .enumerate()
        .map(|(index, word)| {
            if word
                .chars()
                .all(|character| character.is_uppercase() || character.is_numeric())
            {
                word
            } else if index == 0 {
                let mut characters = word.chars();
                characters
                    .next()
                    .map(|first| first.to_uppercase().collect::<String>() + characters.as_str())
                    .unwrap_or_default()
            } else {
                word.to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn expand_action(declaration: OperationDeclaration, item: syn::ItemStruct) -> syn::Result<Tokens> {
    marker(&item)?;
    if declaration.visible.is_some()
        || declaration
            .policy
            .iter()
            .flatten()
            .any(|p| matches!(p, PolicyAtom::Public))
    {
        return Err(syn::Error::new(
            item.span(),
            "public is only available on read queries",
        ));
    }
    let kind = match declaration.kind.to_string().as_str() {
        "create" => quote!(::noxide::__private::OperationKind::Create),
        "update" => quote!(::noxide::__private::OperationKind::Update),
        "delete" => quote!(::noxide::__private::OperationKind::Delete),
        _ => {
            return Err(syn::Error::new(
                declaration.kind.span(),
                "actions support create, update, or delete",
            ));
        }
    };
    if declaration.kind == "delete" && !declaration.fields.is_empty() {
        return Err(syn::Error::new(
            item.span(),
            "delete actions cannot project writable fields",
        ));
    }
    if declaration.kind != "delete" && declaration.fields.is_empty() {
        return Err(syn::Error::new(
            item.span(),
            "create and update actions require explicit fields(...)",
        ));
    }
    let redirect = declaration
        .redirect
        .ok_or_else(|| syn::Error::new(item.span(), "actions require a declared redirect page"))?;
    if declaration.inspect.is_some() != !declaration.inspection_fields.is_empty() {
        return Err(syn::Error::new(
            item.span(),
            "inspection requires both inspect=Query and inspect_fields(...)",
        ));
    }
    if declaration.inspect.is_some() && declaration.kind == "create" {
        return Err(syn::Error::new(
            item.span(),
            "create actions cannot inspect an existing record",
        ));
    }
    let name = &item.ident;
    let label = LitStr::new(&action_label(&name.to_string()), name.span());
    let vis = &item.vis;
    let input_name = format_ident!("{name}Input");
    let controls_name = format_ident!("{name}Controls");
    let original_name = format_ident!("{name}Original");
    let resource = &declaration.resource;
    let policy = policy_tokens(&declaration.policy);
    let version = declaration.version;
    let names = &declaration.fields;
    let hashes: Vec<_> = names
        .iter()
        .map(|field| stable_id(&field.to_string()))
        .collect();
    let values: Vec<_> = hashes
        .iter()
        .map(|hash| quote!(<#resource as ::noxide::FieldSpec<#hash>>::Value))
        .collect();
    let keys: Vec<_> = hashes
        .iter()
        .map(|hash| quote!(<#resource as ::noxide::FieldSpec<#hash>>::KEY))
        .collect();
    let inspection = if let Some(query) = &declaration.inspect {
        let inspection_keys = declaration.inspection_fields.iter().map(|field| {
            let hash = stable_id(&field.to_string());
            quote!(<#resource as ::noxide::FieldSpec<#hash>>::KEY.into())
        });
        quote!(Some(::noxide::__private::Inspection {
            operation: <#query as ::noxide::QueryType>::operation().id,
            fields: vec![#(#inspection_keys),*],
        }))
    } else {
        quote!(None)
    };
    let inspection_operation = if let Some(query) = &declaration.inspect {
        quote!(Some(<#query as ::noxide::QueryType>::operation()))
    } else {
        quote!(None)
    };
    let original = if declaration.inspect.is_some() {
        let original_fields = &declaration.inspection_fields;
        let original_hashes: Vec<_> = original_fields
            .iter()
            .map(|field| stable_id(&field.to_string()))
            .collect();
        let original_types: Vec<_> = original_hashes
            .iter()
            .map(|hash| quote!(<#resource as ::noxide::FieldSpec<#hash>>::Value))
            .collect();
        let original_keys: Vec<_> = original_hashes
            .iter()
            .map(|hash| quote!(<#resource as ::noxide::FieldSpec<#hash>>::KEY))
            .collect();
        quote! {
            #vis struct #original_name { #(pub #original_fields: #original_types),* }
            impl ::noxide::ActionInput for #original_name {
                fn from_fields(_fields: &::noxide::Fields) -> Self {
                    Self { #(#original_fields: <#original_types as ::noxide::FieldValue>::decode(_fields.get(#original_keys).expect("host inspection field"))),* }
                }
            }
        }
    } else {
        Tokens::new()
    };
    let original_type = if declaration.inspect.is_some() {
        quote!(#original_name)
    } else {
        quote!(())
    };
    Ok(quote! {
        #item
        #original
        #vis struct #input_name { #(pub #names: #values),* }
        #vis struct #controls_name { #(pub #names: ::noxide::ControlField<#values>),* }
        impl ::noxide::ActionInput for #input_name {
            fn from_fields(_fields: &::noxide::Fields) -> Self {
                Self { #(#names: <#values as ::noxide::FieldValue>::decode(_fields.get(#keys).expect("host action field"))),* }
            }
        }
        impl #name {
            #(
                #[allow(non_upper_case_globals)]
                pub const #names: ::noxide::Field<Self, #values> = ::noxide::Field::new(#keys);
            )*
        }
        impl ::noxide::ActionType for #name {
            type Resource = #resource;
            type Input = #input_name;
            type Controls = #controls_name;
            type Original = #original_type;
            fn controls() -> Self::Controls {
                #controls_name { #(#names: ::noxide::ControlField::new(#keys)),* }
            }
            fn operation() -> ::noxide::__private::Operation {
                ::noxide::__private::Operation {
                    visibility: None, fields: None,
                    id: ::noxide::stable_id(concat!("mutation:", module_path!(), "::", stringify!(#name))),
                    resource: <#resource as ::noxide::ResourceType>::definition().id,
                    kind: #kind, policy: #policy,
                }
            }
            fn definition() -> ::noxide::__private::Action {
                ::noxide::__private::Action {
                    id: ::noxide::stable_id(concat!("action:", module_path!(), "::", stringify!(#name))),
                    version: #version, name: #label.into(),
                    operation: <Self as ::noxide::ActionType>::operation().id, redirect: #redirect::id(),
                    fields: vec![#(#keys.into()),*], inspect: #inspection, layout: vec![],
                }
            }
            fn inspection() -> Option<::noxide::__private::Operation> { #inspection_operation }
        }
    })
}

struct PageDeclaration {
    path: LitStr,
    access: Ident,
}
impl Parse for PageDeclaration {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let option: Ident = input.parse()?;
        if option != "path" {
            return Err(syn::Error::new(
                option.span(),
                "pages require path = \"/path\"",
            ));
        }
        input.parse::<Token![=]>()?;
        let path: LitStr = input.parse()?;
        let mut access = Ident::new("Authenticated", path.span());
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            if !input.is_empty() {
                let option: Ident = input.parse()?;
                if option != "access" {
                    return Err(syn::Error::new(option.span(), "unknown page option"));
                }
                input.parse::<Token![=]>()?;
                let value: Ident = input.parse()?;
                access = Ident::new(
                    match value.to_string().as_str() {
                        "authenticated" => "Authenticated",
                        "public" => "Public",
                        "public_optional" => "PublicOptional",
                        _ => {
                            return Err(syn::Error::new(
                                value.span(),
                                "expected authenticated, public, or public_optional",
                            ));
                        }
                    },
                    value.span(),
                );
                if input.peek(Token![,]) {
                    input.parse::<Token![,]>()?;
                }
            }
        }
        if !input.is_empty() {
            return Err(input.error("unknown page option"));
        }
        Ok(Self { path, access })
    }
}

fn generic_argument(ty: &Type) -> syn::Result<(&Ident, &Type)> {
    let Type::Path(path) = ty else {
        return Err(syn::Error::new(
            ty.span(),
            "page inputs must be owned Query<Q>, Form<A>, or Id<R> values",
        ));
    };
    let segment = path
        .path
        .segments
        .last()
        .ok_or_else(|| syn::Error::new(ty.span(), "missing page input type"))?;
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return Err(syn::Error::new(
            ty.span(),
            "expected a typed capability argument",
        ));
    };
    if arguments.args.len() != 1 {
        return Err(syn::Error::new(
            ty.span(),
            "expected one capability type parameter",
        ));
    }
    let Some(syn::GenericArgument::Type(inner)) = arguments.args.first() else {
        return Err(syn::Error::new(
            ty.span(),
            "expected one capability type parameter",
        ));
    };
    Ok((&segment.ident, inner))
}

#[proc_macro_attribute]
pub fn page(attr: TokenStream, input: TokenStream) -> TokenStream {
    finish(expand_page(
        parse_macro_input!(attr as PageDeclaration),
        parse_macro_input!(input as syn::ItemFn),
    ))
}

fn expand_page(declaration: PageDeclaration, item: syn::ItemFn) -> syn::Result<Tokens> {
    if item.sig.asyncness.is_some()
        || item.sig.unsafety.is_some()
        || item.sig.abi.is_some()
        || !item.sig.generics.params.is_empty()
        || item.sig.generics.where_clause.is_some()
    {
        return Err(syn::Error::new(
            item.sig.span(),
            "page handlers are safe, synchronous, nongeneric Rust functions",
        ));
    }
    let name = &item.sig.ident;
    let vis = &item.vis;
    let path = &declaration.path;
    let access = &declaration.access;
    let mut target = None;
    let mut query_operations = Vec::new();
    let mut forms = Vec::new();
    let mut resources = Vec::new();
    let mut args = Vec::new();
    for input in &item.sig.inputs {
        let syn::FnArg::Typed(input) = input else {
            return Err(syn::Error::new(
                input.span(),
                "page functions cannot have a receiver",
            ));
        };
        let ty = &input.ty;
        let (kind, inner) = generic_argument(ty)?;
        match kind.to_string().as_str() {
            "Query" => {
                query_operations.push(quote!(<#inner as ::noxide::QueryType>::operation()));
                resources.push(quote!(<<#inner as ::noxide::QueryType>::Resource as ::noxide::ResourceType>::definition()));
            }
            "Form" => {
                forms.push(quote!(<#inner as ::noxide::ActionType>::definition().id));
            }
            "Id" => {
                if target.is_some() {
                    return Err(syn::Error::new(
                        input.span(),
                        "record routes have exactly one record ID",
                    ));
                }
                let Pat::Ident(pattern) = input.pat.as_ref() else {
                    return Err(syn::Error::new(
                        input.pat.span(),
                        "record ID arguments need a simple name",
                    ));
                };
                target = Some((pattern.ident.clone(), inner.clone()));
                resources.push(quote!(<#inner as ::noxide::ResourceType>::definition()));
            }
            _ => {
                return Err(syn::Error::new(
                    kind.span(),
                    "expected Query<Q>, Form<A>, or Id<R>",
                ));
            }
        }
        args.push(quote!(<#ty as ::noxide::FromRequest>::from_request(_request)));
    }
    let (resource, link_args, link_target) = if let Some((parameter, resource)) = &target {
        let placeholder = format!("{{{parameter}}}");
        if !path.value().contains(&placeholder) {
            return Err(syn::Error::new(
                path.span(),
                format!("record path must contain {placeholder}"),
            ));
        }
        (
            quote!(Some(<#resource as ::noxide::ResourceType>::definition().id)),
            quote!(#parameter: ::noxide::Id<#resource>),
            quote!(Some(#parameter.get())),
        )
    } else {
        if path.value().contains(['{', '}']) {
            return Err(syn::Error::new(
                path.span(),
                "path parameters need a matching Id<Resource> argument",
            ));
        }
        (quote!(None), quote!(), quote!(None))
    };
    Ok(quote! {
        #item
        #vis mod #name {
            #[allow(unused_imports)]
            use super::*;
            pub fn id() -> u32 {
                ::noxide::stable_id(concat!("route:", module_path!()))
            }
            pub fn definition() -> ::noxide::__private::Route {
                ::noxide::__private::Route {
                    access: ::noxide::__private::Access::#access,
                    id: self::id(),
                    path: #path.into(), resource: #resource,
                    operations: vec![#(#query_operations.id),*], forms: vec![#(#forms),*],
                }
            }
            pub fn register(builder: &mut ::noxide::ApplicationDefinition) {
                #(builder.resource(#resources);)*
                #(builder.operation(#query_operations);)*
                builder.page(definition());
            }
            pub fn link(#link_args) -> ::noxide::RouteRef {
                ::noxide::RouteRef { route: self::id(), target: #link_target }
            }
            pub fn dispatch(_request: &::noxide::RequestView) -> ::noxide::ResponseIntent {
                ::noxide::IntoPageResponse::into_response(super::#name(#(#args),*))
            }
        }
    })
}

struct Registration {
    pages: Vec<syn::Path>,
    actions: Vec<(Type, Option<syn::Path>)>,
    forms: Vec<(Type, syn::Path)>,
}
impl Parse for Registration {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut result = Self {
            pages: Vec::new(),
            actions: Vec::new(),
            forms: Vec::new(),
        };
        let mut sections = BTreeSet::new();
        while !input.is_empty() {
            let section: Ident = input.parse()?;
            if !sections.insert(section.to_string()) {
                return Err(syn::Error::new(
                    section.span(),
                    "duplicate application section",
                ));
            }
            input.parse::<Token![:]>()?;
            let content;
            syn::bracketed!(content in input);
            match section.to_string().as_str() {
                "pages" => {
                    result.pages = content
                        .parse_terminated(syn::Path::parse, Token![,])?
                        .into_iter()
                        .collect();
                }
                "actions" => {
                    while !content.is_empty() {
                        let action: Type = content.parse()?;
                        let handler = if content.peek(Token![=>]) {
                            content.parse::<Token![=>]>()?;
                            Some(content.parse()?)
                        } else {
                            None
                        };
                        result.actions.push((action, handler));
                        if !content.is_empty() {
                            content.parse::<Token![,]>()?;
                        }
                    }
                }
                "forms" => {
                    while !content.is_empty() {
                        let action: Type = content.parse()?;
                        content.parse::<Token![=>]>()?;
                        let layout: syn::Path = content.parse()?;
                        result.forms.push((action, layout));
                        if !content.is_empty() {
                            content.parse::<Token![,]>()?;
                        }
                    }
                }
                _ => {
                    return Err(syn::Error::new(
                        section.span(),
                        "expected pages, actions, or forms",
                    ));
                }
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        if result.pages.is_empty() {
            return Err(input.error("register at least one page"));
        }
        Ok(result)
    }
}

#[proc_macro]
pub fn application(input: TokenStream) -> TokenStream {
    finish(expand_application(parse_macro_input!(
        input as Registration
    )))
}

#[derive(Default)]
struct RouteNamespace {
    modules: BTreeMap<String, (Ident, RouteNamespace)>,
    links: BTreeMap<String, (Ident, syn::Path)>,
}

impl RouteNamespace {
    fn insert(&mut self, path: &syn::Path) -> syn::Result<()> {
        if path.segments.iter().any(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "self" | "super" | "Self"
            ) || !matches!(segment.arguments, syn::PathArguments::None)
        }) {
            return Err(syn::Error::new(
                path.span(),
                "registered pages use plain module paths or crate:: paths; self/super paths are unsupported",
            ));
        }
        let mut segments = path
            .segments
            .iter()
            .map(|segment| &segment.ident)
            .collect::<Vec<_>>();
        if segments.first().is_some_and(|ident| *ident == "crate") {
            segments.remove(0);
        }
        let (name, modules) = segments
            .split_last()
            .ok_or_else(|| syn::Error::new(path.span(), "expected a page path"))?;
        let mut namespace = self;
        for module in modules {
            namespace = &mut namespace
                .modules
                .entry(module.to_string())
                .or_insert_with(|| ((*module).clone(), Self::default()))
                .1;
        }
        if namespace
            .links
            .insert(name.to_string(), ((*name).clone(), path.clone()))
            .is_some()
        {
            return Err(syn::Error::new(
                path.span(),
                "duplicate named route; use distinct registered module paths",
            ));
        }
        Ok(())
    }

    fn emit(&self, depth: usize) -> Tokens {
        let modules = self.modules.values().map(|(name, namespace)| {
            let content = namespace.emit(depth + 1);
            quote!(pub mod #name { #content })
        });
        let links = self.links.values().map(|(name, path)| {
            let target = if path.leading_colon.is_some()
                || path
                    .segments
                    .first()
                    .is_some_and(|segment| segment.ident == "crate")
            {
                quote!(#path)
            } else {
                // Climb out of every generated namespace before resolving the
                // original path; a generated module may share its name.
                let ancestors: Tokens = (0..depth).map(|_| quote!(super::)).collect();
                quote!(#ancestors #path)
            };
            quote!(pub use #target::link as #name;)
        });
        quote!(#(#modules)* #(#links)*)
    }
}

fn expand_application(registration: Registration) -> syn::Result<Tokens> {
    let pages = &registration.pages;
    let actions: Vec<_> = registration
        .actions
        .iter()
        .map(|(action, _)| action)
        .collect();
    let mut route_namespace = RouteNamespace::default();
    for path in pages {
        route_namespace.insert(path)?;
    }
    let route_exports = route_namespace.emit(1);
    let form_types: Vec<_> = registration
        .forms
        .iter()
        .map(|(action, _)| action)
        .collect();
    let form_functions: Vec<_> = registration
        .forms
        .iter()
        .map(|(_, function)| function)
        .collect();
    let dispatch: Vec<_> = registration
        .actions
        .iter()
        .map(|(action, handler)| {
            let invoke = if let Some(handler) = handler {
                quote!(#handler(::noxide::Submission::<#action>::new(&request)))
            } else {
                quote!(::noxide::Submission::<#action>::new(&request).apply())
            };
            quote! {
                id if id == <#action as ::noxide::ActionType>::definition().id =>
                    ::noxide::IntoActionResponse::into_response(#invoke),
            }
        })
        .collect();
    Ok(quote! {
        pub mod routes { #route_exports }
        pub fn noxide_manifest() -> String {
            let mut builder = ::noxide::ApplicationDefinition::new();
            #(#pages::register(&mut builder);)*
            #(
                builder.resource(<<#actions as ::noxide::ActionType>::Resource as ::noxide::ResourceType>::definition());
                builder.operation(<#actions as ::noxide::ActionType>::operation());
                if let Some(operation) = <#actions as ::noxide::ActionType>::inspection() { builder.operation(operation); }
                builder.action(<#actions as ::noxide::ActionType>::definition());
            )*
            #(builder.layout(<#form_types as ::noxide::ActionType>::definition().id, #form_functions(::noxide::FormFields::<#form_types>::new()).instructions);)*
            builder.json()
        }
        struct __NoxideApplication;
        impl ::noxide::Handler for __NoxideApplication {
            fn handle(request: ::noxide::RequestView, _context: &mut ::noxide::Context) -> ::noxide::ResponseIntent {
                match request.kind {
                    ::noxide::RequestKind::Route(id) => match id {
                        #(id if id == #pages::id() => #pages::dispatch(&request),)*
                        _ => ::noxide::ResponseIntent::NotFound(::noxide::Document::new("Not found", vec![])),
                    },
                    ::noxide::RequestKind::Action(id) => match id {
                        #(#dispatch)*
                        _ => ::noxide::ResponseIntent::NotFound(::noxide::Document::new("Not found", vec![])),
                    },
                }
            }
        }
        ::noxide::export!(__NoxideApplication);
    })
}

#[cfg(test)]
mod declaration_tests {
    use super::*;

    #[test]
    fn declarations_emit_rust_items() {
        let query = expand_query(
            syn::parse_str("list(Task), allow = all(owner, any(same_tenant, role(\"writer\")))")
                .unwrap(),
            syn::parse_quote!(
                pub struct ListTasks;
            ),
        )
        .unwrap();
        assert!(syn::parse2::<syn::File>(query).is_ok());
        let action = expand_action(
            syn::parse_str("update(Task), fields(title, completed), allow = owner, redirect = show_task, inspect = ReadTask, inspect_fields(title)").unwrap(),
            syn::parse_quote!(pub struct EditTask;),
        ).unwrap();
        assert!(syn::parse2::<syn::File>(action).is_ok());
        let page = expand_page(
            syn::parse_str("path = \"/tasks/{task}\"").unwrap(),
            syn::parse_quote!(
                fn show_task(
                    task: Id<Task>,
                    read: Query<ReadTask>,
                    edit: Form<EditTask>,
                ) -> PageResult {
                    todo!()
                }
            ),
        )
        .unwrap();
        assert!(syn::parse2::<syn::File>(page).is_ok());
        let application = expand_application(
            syn::parse_str("pages: [index, show_task], actions: [CreateTask, EditTask => edit_task, DeleteTask], forms: [EditTask => task_editor],").unwrap(),
        ).unwrap();
        assert!(syn::parse2::<syn::File>(application).is_ok());
    }

    #[test]
    fn resource_identity_is_bound_to_its_own_type() {
        let tokens = expand_resource(syn::parse_quote! {
            #[resource(key = "tasks")]
            struct Task {
                #[id] id: Id<Self>,
                #[field(key = "title", max_bytes = 100)] title: String,
            }
        })
        .unwrap();
        assert!(tokens.to_string().contains("Id :: < Self > :: new"));
    }

    #[test]
    fn absolute_page_paths_are_not_prefixed_with_super() {
        let tokens = expand_application(
            syn::parse_str("pages: [crate::pages::index], actions: []").unwrap(),
        )
        .unwrap();
        assert!(!tokens.to_string().contains("super :: crate"));
        assert!(syn::parse2::<syn::File>(tokens).is_ok());
    }

    #[test]
    fn named_routes_preserve_module_namespaces() {
        let tokens = expand_application(
            syn::parse_str(
                "pages: [index, notes::index, tasks::index, crate::admin::show], actions: []",
            )
            .unwrap(),
        )
        .unwrap();
        let file = syn::parse2::<syn::File>(tokens.clone()).unwrap();
        let routes = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Mod(item) if item.ident == "routes" => Some(item),
                _ => None,
            })
            .unwrap();
        let items = &routes.content.as_ref().unwrap().1;
        let modules = items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Mod(item) => Some(item.ident.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(modules, ["admin", "notes", "tasks"]);
        let text = tokens.to_string();
        assert!(text.contains("pub use super :: index :: link as index"));
        assert!(text.contains("pub use super :: super :: notes :: index :: link as index"));
        assert!(text.contains("pub use super :: super :: tasks :: index :: link as index"));
        assert!(text.contains("pub use crate :: admin :: show :: link as show"));
        assert!(!text.contains("pub mod crate"));
    }

    #[test]
    fn relative_parent_page_paths_have_an_explicit_diagnostic() {
        for path in ["self::index", "super::index"] {
            let registration = syn::parse_str(&format!("pages: [{path}], actions: []")).unwrap();
            assert!(
                expand_application(registration)
                    .unwrap_err()
                    .to_string()
                    .contains("self/super")
            );
        }
        let registration =
            syn::parse_str("pages: [notes::index, notes::index], actions: []").unwrap();
        assert!(
            expand_application(registration)
                .unwrap_err()
                .to_string()
                .contains("duplicate named route")
        );
    }

    #[test]
    fn query_kinds_emit_distinct_capability_traits() {
        for (kind, marker) in [("list", "ListQuery"), ("read", "ReadQuery")] {
            let declaration = syn::parse_str(&format!("{kind}(Task), allow = owner")).unwrap();
            let generated = expand_query(
                declaration,
                syn::parse_quote!(
                    struct Query;
                ),
            )
            .unwrap();
            let file = syn::parse2::<syn::File>(generated).unwrap();
            assert!(file.items.iter().any(|item| matches!(item,
                syn::Item::Impl(item) if item.trait_.as_ref().is_some_and(|(_,path,_)|path.is_ident(marker) || path.segments.last().is_some_and(|segment|segment.ident == marker))
            )));
        }
    }

    #[test]
    fn bundle_identifiers_include_the_declaration_module() {
        let query = expand_query(
            syn::parse_str("list(Task), allow = owner").unwrap(),
            syn::parse_quote!(
                struct List;
            ),
        )
        .unwrap();
        let action = expand_action(
            syn::parse_str("create(Task), fields(title), allow = owner, redirect = show").unwrap(),
            syn::parse_quote!(
                struct Create;
            ),
        )
        .unwrap();
        let page = expand_page(
            syn::parse_str("path = \"/\"").unwrap(),
            syn::parse_quote!(
                fn index() -> Page {
                    todo!()
                }
            ),
        )
        .unwrap();
        for tokens in [query, action, page] {
            let text = tokens.to_string();
            assert!(text.contains("module_path !"));
        }
    }

    #[test]
    fn redirects_use_page_identity_without_reentering_definitions() {
        let tokens = expand_action(
            syn::parse_str("update(Task), fields(operation), allow = owner, redirect = show")
                .unwrap(),
            syn::parse_quote!(
                struct Edit;
            ),
        )
        .unwrap();
        let text = tokens.to_string();
        assert!(text.contains("redirect : show :: id ()"));
        assert!(!text.contains("show :: definition"));
        assert!(text.contains("< Self as :: noxide :: ActionType > :: operation ()"));
        assert!(!text.contains("Self :: operation ()"));
        let page = expand_page(
            syn::parse_str("path = \"/tasks/{id}\"").unwrap(),
            syn::parse_quote!(
                fn show(id: Id<Task>, edit: Form<Edit>) -> Page {
                    todo!()
                }
            ),
        )
        .unwrap();
        let text = page.to_string();
        assert!(text.contains("pub fn id () -> u32"));
        assert!(text.contains("route : self :: id ()"));
        assert!(!text.contains("route : definition ()"));
        assert!(syn::parse2::<syn::File>(page).is_ok());
    }

    #[test]
    fn action_names_have_readable_default_labels() {
        for (identifier, label) in [
            ("CreateNote", "Create note"),
            ("CreateTask", "Create task"),
            ("EditHTTPConfig", "Edit HTTP config"),
            ("DeleteXMLParser", "Delete XML parser"),
            ("UpdateVersion2Note", "Update version2 note"),
        ] {
            assert_eq!(action_label(identifier), label);
        }
    }

    #[test]
    fn actions_require_explicit_fields_and_redirect() {
        let action = syn::parse_quote!(
            struct Edit;
        );
        assert!(
            expand_action(
                syn::parse_str("update(Task), allow = owner, redirect = show").unwrap(),
                action
            )
            .is_err()
        );
        let action = syn::parse_quote!(
            struct Edit;
        );
        assert!(
            expand_action(
                syn::parse_str("update(Task), fields(title), allow = owner").unwrap(),
                action
            )
            .is_err()
        );
    }

    #[test]
    fn policy_normalization_has_a_compile_time_limit() {
        let declaration =
            "list(Task), allow = all(any(owner, owner, owner), any(owner, owner, owner))";
        assert!(syn::parse_str::<OperationDeclaration>(declaration).is_err());
        assert!(
            syn::parse_str::<OperationDeclaration>(
                "list(Task), allow = all(owner, owner, owner, owner, owner)"
            )
            .is_err()
        );
    }

    #[test]
    fn page_parameters_need_matching_record_ids() {
        assert!(
            expand_page(
                syn::parse_str("path = \"/tasks/{other}\"").unwrap(),
                syn::parse_quote!(
                    fn show(task: Id<Task>) -> Page {
                        todo!()
                    }
                ),
            )
            .is_err()
        );
        assert!(
            expand_page(
                syn::parse_str("path = \"/tasks/{task}\"").unwrap(),
                syn::parse_quote!(
                    fn show() -> Page {
                        todo!()
                    }
                ),
            )
            .is_err()
        );
    }

    #[test]
    fn nested_option_and_resource_relations_are_rejected() {
        let input = syn::parse_quote! {
            #[resource(key = "tasks")]
            struct Task { #[id] id: Id<Self>, #[field(key = "name")] name: Option<Option<String>> }
        };
        assert!(
            expand_resource(input)
                .unwrap_err()
                .to_string()
                .contains("nested Option")
        );
        let input = syn::parse_quote! {
            #[resource(key = "tasks")]
            struct Task { #[id] id: Id<Self>, #[field(key = "other")] other: Id<Task> }
        };
        assert!(expand_resource(input).is_err());
    }
}

#[cfg(test)]
mod public_tests {
    use super::*;
    #[test]
    fn public_queries_require_visibility_and_fields() {
        for declaration in [
            "list(Article), allow = public",
            "list(Article), allow = public, visible(published = true)",
            "list(Article), allow = public, fields(title)",
            "read(Article), allow = public, visible(published = true), fields()",
        ] {
            assert!(
                expand_query(
                    syn::parse_str(declaration).unwrap(),
                    syn::parse_quote!(
                        struct Articles;
                    )
                )
                .is_err(),
                "{declaration}"
            );
        }
        for declaration in [
            "list(Article), allow = any(public)",
            "list(Article), allow = all(owner, public)",
            "list(Article), allow = any(owner, all(public))",
        ] {
            assert!(
                syn::parse_str::<OperationDeclaration>(declaration).is_err(),
                "{declaration}"
            );
        }
        for declaration in [
            "list(Article), allow = owner, visible(published = true)",
            "list(Article), allow = owner, fields(title)",
        ] {
            assert!(
                expand_query(
                    syn::parse_str(declaration).unwrap(),
                    syn::parse_quote!(
                        struct Articles;
                    )
                )
                .is_err(),
                "{declaration}"
            );
        }
        assert!(
            expand_action(
                syn::parse_str("create(Article), allow = public, fields(title), redirect = index")
                    .unwrap(),
                syn::parse_quote!(
                    struct CreateArticle;
                )
            )
            .is_err()
        );
    }
}
