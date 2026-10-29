use super::*;

pub(super) fn expand_page(declaration: PageDeclaration, item: syn::ItemFn) -> syn::Result<Tokens> {
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
