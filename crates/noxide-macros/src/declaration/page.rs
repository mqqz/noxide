use proc_macro2::TokenStream as Tokens;
use quote::quote;
use syn::{
    Ident, LitStr, Pat, Token, Type,
    parse::{Parse, ParseStream},
    spanned::Spanned,
};
pub(crate) struct PageDeclaration {
    pub(crate) path: LitStr,
    pub(crate) params: Vec<Ident>,
    pub(crate) access: Ident,
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
        let mut params = Vec::new();
        let mut options = std::collections::BTreeSet::new();
        while !input.is_empty() {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
            let option: Ident = input.parse()?;
            if !options.insert(option.to_string()) {
                return Err(syn::Error::new(option.span(), "duplicate page option"));
            }
            if option == "params" {
                let names;
                syn::parenthesized!(names in input);
                params = names
                    .parse_terminated(Ident::parse, Token![,])?
                    .into_iter()
                    .collect();
                let unique: std::collections::BTreeSet<_> =
                    params.iter().map(ToString::to_string).collect();
                if params.len() > 4 || unique.len() != params.len() || unique.contains("cursor") {
                    return Err(syn::Error::new(option.span(), "invalid route parameters"));
                }
            } else if option == "access" {
                input.parse::<Token![=]>()?;
                let value: Ident = input.parse()?;
                access = Ident::new(
                    match value.to_string().as_str() {
                        "authenticated" => "Authenticated",
                        "public" => "Public",
                        "public_optional" => "PublicOptional",
                        _ => return Err(syn::Error::new(value.span(), "invalid page access")),
                    },
                    value.span(),
                );
            } else {
                return Err(syn::Error::new(option.span(), "unknown page option"));
            }
        }
        Ok(Self {
            path,
            access,
            params,
        })
    }
}

pub(crate) fn generic_argument(ty: &Type) -> syn::Result<(&Ident, &Type)> {
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

pub(crate) fn expand_page(declaration: PageDeclaration, item: syn::ItemFn) -> syn::Result<Tokens> {
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
    let params = &declaration.params;
    let param_names: Vec<_> = params.iter().map(ToString::to_string).collect();
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
    let separator = if target.is_some() && !params.is_empty() {
        quote!(,)
    } else {
        quote!()
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
                        params: vec![#(#param_names.into()),*],
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
                pub fn link(#link_args #separator #(#params: impl ::noxide::ParamValue),*) -> ::noxide::RouteRef {
                    ::noxide::RouteRef { params: ::std::collections::BTreeMap::from([#((#param_names.into(), ::noxide::FieldValue::encode(&#params))),*]),
    route: self::id(), target: #link_target }
                }
                pub fn dispatch(_request: &::noxide::RequestView) -> ::noxide::ResponseIntent {
                    ::noxide::IntoPageResponse::into_response(super::#name(#(#args),*))
                }
            }
        })
}
