use crate::declaration::policy::{PolicyAtom, policy};
use std::collections::BTreeSet;
use syn::{
    Expr, Fields, Ident, LitInt, Token, Type, parenthesized,
    parse::{Parse, ParseStream},
    spanned::Spanned,
};
pub(crate) struct OperationDeclaration {
    pub(crate) order: Option<Ident>,
    pub(crate) page_size: Option<u8>,
    pub(crate) kind: Ident,
    pub(crate) resource: Type,
    pub(crate) policy: Vec<Vec<PolicyAtom>>,
    pub(crate) fields: Vec<Ident>,
    pub(crate) visible: Option<(Ident, Expr)>,
    pub(crate) redirect: Option<syn::Path>,
    pub(crate) redirect_parent: bool,
    pub(crate) inspect: Option<Type>,
    pub(crate) inspection_fields: Vec<Ident>,
    pub(crate) version: u32,
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
            order: None,
            page_size: None,
            kind,
            resource: resource_type,
            policy: Vec::new(),
            fields: Vec::new(),
            visible: None,
            redirect: None,
            redirect_parent: false,
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
                "order" => {
                    input.parse::<Token![=]>()?;
                    let order: Ident = input.parse()?;
                    if (order != "created_asc" && order != "created_desc") || result.kind != "list"
                    {
                        return Err(syn::Error::new(
                            order.span(),
                            "list order must be created_asc or created_desc",
                        ));
                    }
                    result.order = Some(order);
                }
                "page_size" => {
                    input.parse::<Token![=]>()?;
                    let n: LitInt = input.parse()?;
                    let size: u8 = n.base10_parse()?;
                    if result.kind != "list" || !(1..=20).contains(&size) {
                        return Err(syn::Error::new(n.span(), "list page_size must be 1..=20"));
                    }
                    result.page_size = Some(size);
                }
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
                    let path: syn::Path = input.parse()?;
                    if path.is_ident("parent") && input.peek(syn::token::Paren) {
                        let args;
                        parenthesized!(args in input);
                        result.redirect = Some(args.parse()?);
                        if !args.is_empty() {
                            return Err(args.error("expected one parent page"));
                        }
                        result.redirect_parent = true;
                    } else {
                        result.redirect = Some(path);
                    }
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

pub(crate) fn marker(item: &syn::ItemStruct) -> syn::Result<()> {
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
