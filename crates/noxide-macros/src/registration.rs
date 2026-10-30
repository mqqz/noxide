use proc_macro2::TokenStream as Tokens;
use quote::quote;
use std::collections::{BTreeMap, BTreeSet};
use syn::{
    Ident, Token, Type,
    parse::{Parse, ParseStream},
    spanned::Spanned,
};
pub(crate) struct Registration {
    pub(crate) pages: Vec<syn::Path>,
    pub(crate) actions: Vec<(Type, Option<syn::Path>)>,
    pub(crate) forms: Vec<(Type, syn::Path)>,
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

pub(crate) fn expand_application(registration: Registration) -> syn::Result<Tokens> {
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
                quote!(::noxide::Submission::<#action>::new(&request).execute())
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
                for resource in <#actions as ::noxide::ActionType>::resources() { builder.resource(resource); }
                for operation in <#actions as ::noxide::ActionType>::operations() { builder.operation(operation); }
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
