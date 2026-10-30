use proc_macro2::TokenStream as Tokens;
use quote::quote;
use std::collections::{BTreeMap, BTreeSet};
use syn::Type;
use syn::{
    Expr, Ident, Token, braced, parenthesized,
    parse::{Parse, ParseStream},
};
pub(crate) struct CrudBlock {
    pub(crate) resource: Ident,
    pub(crate) entries: Vec<CrudEntry>,
}
pub(crate) struct CrudEntry {
    pub(crate) kind: Ident,
    pub(crate) name: Ident,
    pub(crate) options: Tokens,
    pub(crate) policy: bool,
    pub(crate) handler: Option<syn::Path>,
    pub(crate) layout: Option<syn::Path>,
}
impl Parse for CrudBlock {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let resource = input.parse()?;
        let body;
        braced!(body in input);
        let mut entries = Vec::new();
        while !body.is_empty() {
            let kind: Ident = body.parse()?;
            if !["create", "update", "delete"].contains(&kind.to_string().as_str()) {
                return Err(syn::Error::new(
                    kind.span(),
                    "expected create, update, or delete",
                ));
            }
            let name = body.parse()?;
            let content;
            braced!(content in body);
            let mut options = Tokens::new();
            let mut policy = false;
            let mut handler = None;
            let mut layout = None;
            let mut seen = BTreeSet::new();
            while !content.is_empty() {
                let option: Ident = content.parse()?;
                if !seen.insert(option.to_string()) {
                    return Err(syn::Error::new(option.span(), "duplicate CRUD option"));
                }
                if option == "allow" {
                    content.parse::<Token![=]>()?;
                    let expression: Expr = content.parse()?;
                    policy = true;
                    options.extend(quote!(, allow = #expression));
                } else {
                    let args;
                    parenthesized!(args in content);
                    let tokens: Tokens = args.parse()?;
                    match option.to_string().as_str() {
                        "bind" => options.extend(quote!(, bind(#tokens))),
                        "fields" => options.extend(quote!(, fields(#tokens))),
                        "redirect" => {
                            options.extend(quote!(, redirect = #tokens));
                        }
                        "handler" => handler = Some(syn::parse2(tokens)?),
                        "layout" => layout = Some(syn::parse2(tokens)?),
                        _ => return Err(syn::Error::new(option.span(), "unknown CRUD option")),
                    }
                }
                if !content.is_empty() {
                    content.parse::<Token![,]>()?;
                }
            }
            if kind != "delete" && !seen.contains("fields") {
                return Err(syn::Error::new(
                    kind.span(),
                    "CRUD create/update require explicit fields(...)",
                ));
            }
            if kind == "delete" && seen.contains("fields") {
                return Err(syn::Error::new(
                    kind.span(),
                    "CRUD delete accepts no fields",
                ));
            }
            if !seen.contains("redirect") {
                return Err(syn::Error::new(kind.span(), "CRUD requires redirect(...)"));
            }
            entries.push(CrudEntry {
                kind,
                name,
                options,
                policy,
                handler,
                layout,
            });
        }
        if entries.is_empty() {
            return Err(body.error("enable at least one CRUD operation"));
        }
        if !input.is_empty() {
            return Err(input.error("expected one resource per CRUD block"));
        }
        Ok(Self { resource, entries })
    }
}

use crate::declaration::{OperationDeclaration, action::expand_action};
pub(super) fn lower_crud(
    crud: CrudBlock,
    owners: &BTreeSet<String>,
    names: &mut BTreeSet<String>,
    generated: &mut BTreeMap<String, Tokens>,
    actions: &mut BTreeMap<String, (Type, Option<syn::Path>)>,
    layouts: &mut BTreeMap<String, syn::Path>,
) -> syn::Result<()> {
    for entry in crud.entries {
        let resource = &crud.resource;
        let name = &entry.name;
        if !names.insert(name.to_string()) {
            return Err(syn::Error::new(
                name.span(),
                "generated action name collision",
            ));
        }
        let kind = &entry.kind;
        let mut options = entry.options;
        if !entry.policy {
            if !owners.contains(&resource.to_string()) {
                return Err(syn::Error::new(
                    resource.span(),
                    "CRUD requires an explicit policy or owner resource",
                ));
            }
            options.extend(quote!(, allow = owner));
        }
        // Validate with the same parser used by explicit action declarations.
        let declaration: OperationDeclaration = syn::parse2(quote!(#kind(#resource) #options))?;
        let marker: syn::ItemStruct = syn::parse_quote!(struct #name;);
        generated.insert(name.to_string(), expand_action(declaration, marker)?);
        actions.insert(name.to_string(), (syn::parse_quote!(#name), entry.handler));
        if let Some(layout) = entry.layout {
            layouts.insert(name.to_string(), layout);
        }
    }
    Ok(())
}
