use super::app::app_attribute_path;
use crate::declaration::{page::generic_argument, query::expand_query};
use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use std::collections::{BTreeMap, BTreeSet};
use syn::{Ident, Type, spanned::Spanned};
pub(super) fn lower_inputs(
    i: &mut syn::ItemFn,
    owners: &BTreeSet<String>,
    names: &BTreeSet<String>,
    generated: &mut BTreeMap<String, Tokens>,
) -> syn::Result<()> {
    for input in &mut i.sig.inputs {
        let syn::FnArg::Typed(arg) = input else {
            continue;
        };
        let Ok((kind, resource)) = generic_argument(&arg.ty) else {
            continue;
        };
        let operation = match kind.to_string().as_str() {
            "List" => "list",
            "Read" => "read",
            _ => continue,
        };
        let Type::Path(capability) = arg.ty.as_ref() else {
            unreachable!()
        };
        let mut capability_path = capability.path.clone();
        for segment in &mut capability_path.segments {
            segment.arguments = syn::PathArguments::None;
        }
        if !app_attribute_path(&capability_path, &kind.to_string()) {
            return Err(syn::Error::new(
                capability.span(),
                "read shorthand must use List<Resource> or Read<Resource>, optionally qualified by noxide",
            ));
        }
        let Type::Path(path) = resource else {
            return Err(syn::Error::new(
                resource.span(),
                "expected local resource name",
            ));
        };
        let Some(resource_name) = path.path.get_ident() else {
            return Err(syn::Error::new(
                resource.span(),
                "expected local resource name",
            ));
        };
        if !owners.contains(&resource_name.to_string()) {
            return Err(syn::Error::new(
                resource.span(),
                "read shorthand requires a local owner resource; use Query<ExplicitQuery>",
            ));
        }
        let query_name = format_ident!("__Noxide_{}_{}", operation, resource_name);
        let query_key = query_name.to_string();
        if names.contains(&query_key) {
            return Err(syn::Error::new(
                resource.span(),
                "generated query name collision",
            ));
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = generated.entry(query_key) {
            let operation = Ident::new(operation, resource.span());
            let declaration = syn::parse2(quote!(#operation(#resource), allow = owner))?;
            entry.insert(expand_query(
                declaration,
                syn::parse_quote!(#[allow(non_camel_case_types)] struct #query_name;),
            )?);
        }
        *arg.ty = syn::parse_quote!(::noxide::Query<#query_name>);
    }
    Ok(())
}
