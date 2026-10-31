use proc_macro2::TokenStream as Tokens;
use quote::quote;
use std::collections::{BTreeMap, BTreeSet};
use syn::{
    Ident, Token, Type,
    parse::{Parse, ParseStream},
    spanned::Spanned,
};
pub(crate) struct Registration {
    pub(crate) assets: Vec<Type>,
    pub(crate) pages: Vec<syn::Path>,
    pub(crate) actions: Vec<(Type, Option<syn::Path>)>,
    pub(crate) forms: Vec<(Type, syn::Path)>,
    pub(crate) blobs: Option<syn::Path>,
    pub(crate) services: Vec<Type>,
    pub(crate) operations: Vec<syn::Path>,
    pub(crate) jobs: Option<syn::Path>,
    pub(crate) effects: Option<syn::Path>,
}

/// One explicit contract function; the section never infers authority.
fn single_function(content: ParseStream<'_>, section: &str) -> syn::Result<syn::Path> {
    let function: syn::Path = content.parse()?;
    if !content.is_empty() {
        return Err(content.error(format!("register exactly one {section} function")));
    }
    Ok(function)
}
impl Parse for Registration {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut result = Self {
            assets: Vec::new(),
            pages: Vec::new(),
            actions: Vec::new(),
            forms: Vec::new(),
            blobs: None,
            services: Vec::new(),
            operations: Vec::new(),
            jobs: None,
            effects: None,
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
                "assets" => {
                    result.assets = content
                        .parse_terminated(Type::parse, Token![,])?
                        .into_iter()
                        .collect();
                }
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
                // No authority is inferred from fields or action shapes; each
                // section names the explicit contract the operator approves.
                "blobs" => result.blobs = Some(single_function(&content, "blob policy")?),
                "jobs" => result.jobs = Some(single_function(&content, "job contract")?),
                "effects" => result.effects = Some(single_function(&content, "effect contract")?),
                "services" => {
                    result.services = content
                        .parse_terminated(Type::parse, Token![,])?
                        .into_iter()
                        .collect();
                }
                "operations" => {
                    result.operations = content
                        .parse_terminated(syn::Path::parse, Token![,])?
                        .into_iter()
                        .collect();
                }
                _ => {
                    return Err(syn::Error::new(
                        section.span(),
                        "expected assets, pages, actions, forms, services, operations, blobs, jobs, or effects",
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
    let assets = &registration.assets;
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
    let blobs = registration
        .blobs
        .as_ref()
        .map(|policy| quote!(builder.blobs(#policy());));
    let jobs = registration
        .jobs
        .as_ref()
        .map(|contract| quote!(builder.jobs(#contract());));
    let effects = registration
        .effects
        .as_ref()
        .map(|contract| quote!(builder.effects(#contract());));
    let services = &registration.services;
    let operations = &registration.operations;
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
            #(builder.asset(<#assets as ::noxide::AssetType>::declaration());)*
            #(#pages::register(&mut builder);)*
            #(
                for resource in <#actions as ::noxide::ActionType>::resources() { builder.resource(resource); }
                for operation in <#actions as ::noxide::ActionType>::operations() { builder.operation(operation); }
                if let Some(operation) = <#actions as ::noxide::ActionType>::inspection() { builder.operation(operation); }
                builder.action(<#actions as ::noxide::ActionType>::definition());
                builder.web_binding(<#actions as ::noxide::WebActionType>::web_binding());
            )*
            #(builder.layout(<#form_types as ::noxide::WebActionType>::web_binding().id, #form_functions(::noxide::FormFields::<#form_types>::new()).instructions);)*
            #(
                for resource in <#services as ::noxide::ActionType>::resources() { builder.resource(resource); }
                for operation in <#services as ::noxide::ActionType>::operations() { builder.operation(operation); }
                if let Some(operation) = <#services as ::noxide::ActionType>::inspection() { builder.operation(operation); }
                builder.action(<#services as ::noxide::ActionType>::definition());
            )*
            #(builder.operation(#operations());)*
            #blobs
            #jobs
            #effects
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
                        // Services have no web binding; only host job invocation reaches them.
                        #(id if id == <#services as ::noxide::ActionType>::definition().id =>
                            ::noxide::IntoActionResponse::into_response(::noxide::Submission::<#services>::new(&request).execute()),)*
                        _ => ::noxide::ResponseIntent::NotFound(::noxide::Document::new("Not found", vec![])),
                    },
                }
            }
        }
        ::noxide::export!(__NoxideApplication);
    })
}
