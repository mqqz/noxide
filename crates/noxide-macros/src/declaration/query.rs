use crate::declaration::policy::{PolicyAtom, policy_tokens};
use crate::declaration::{OperationDeclaration, marker};
use crate::syntax::stable_id;
use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use syn::spanned::Spanned;

pub(crate) fn expand_query(
    declaration: OperationDeclaration,
    item: syn::ItemStruct,
) -> syn::Result<Tokens> {
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
    if declaration
        .policy
        .iter()
        .flatten()
        .any(|p| matches!(p, PolicyAtom::Capability))
    {
        return Err(syn::Error::new(
            item.span(),
            "capability requires update or delete",
        ));
    }
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
    let inferred: std::collections::BTreeSet<_> = declaration
        .filter
        .iter()
        .filter(|(f, _)| public && !declaration.fields.contains(f))
        .map(|(f, _)| f.to_string())
        .collect();
    let disclosed: std::collections::BTreeSet<_> = declaration
        .disclose
        .iter()
        .map(ToString::to_string)
        .collect();
    if inferred != disclosed || disclosed.len() != declaration.disclose.len() {
        return Err(syn::Error::new(
            item.span(),
            "disclose must name exactly unprojected public filter fields",
        ));
    }
    let query_trait = if declaration.kind == "list" {
        quote!(::noxide::ListQuery)
    } else {
        quote!(::noxide::ReadQuery)
    };
    let page_size = declaration.page_size.unwrap_or(3);
    let order = if declaration
        .order
        .as_ref()
        .is_some_and(|o| o == "created_desc")
    {
        quote!(::noxide::__private::ListOrder::CreatedDesc)
    } else {
        quote!(::noxide::__private::ListOrder::CreatedAsc)
    };
    let list = if declaration.kind == "list" {
        quote!(Some(::noxide::__private::ListSettings { order: #order, page_size: #page_size }))
    } else {
        quote!(None)
    };
    let name = &item.ident;
    let resource = &declaration.resource;
    let policy = policy_tokens(&declaration.policy, &declaration.resource);
    let vis = &item.vis;
    let output_name = format_ident!("{name}Record");
    let filters: Vec<_> = declaration.filter.iter().map(|(field, value)| {
        let hash = stable_id(&field.to_string());
        quote!({
            const _: () = assert!(<<#resource as ::noxide::FieldSpec<#hash>>::Value as ::noxide::FieldValue>::FILTERABLE, "filter requires boolean or choice");
            let value: &<#resource as ::noxide::FieldSpec<#hash>>::Value = &(#value);
            ::noxide::__private::Condition { field: <#resource as ::noxide::FieldSpec<#hash>>::KEY.into(), equals: ::noxide::__private::Operand::Literal(::noxide::FieldValue::encode(value)) }
        })
    }).collect();
    let disclosures: Vec<_> = declaration
        .disclose
        .iter()
        .map(|field| {
            let hash = stable_id(&field.to_string());
            quote!(<#resource as ::noxide::FieldSpec<#hash>>::KEY.into())
        })
        .collect();
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
                        filter: vec![#(#filters),*], disclose: vec![#(#disclosures),*],
    list: #list, visibility: #visibility, fields: #fields,
                        id: ::noxide::stable_id(concat!("query:", module_path!(), "::", stringify!(#name))),
                        resource: <#resource as ::noxide::ResourceType>::definition().id,
                        kind: #kind, policy: #policy,
                    }
                }
            }
        })
}
