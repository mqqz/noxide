//! Declarations and templates for the Noxide guest SDK.
//!
//! Macro expansion happens inside the isolated application build.
mod query;
use query::expand_query;
mod action;
use action::expand_action;
mod page;
use page::expand_page;
mod app;
use app::expand_app;
mod choice;
use choice::expand_choice;
mod resource;
use resource::expand_resource;
mod policy;
use policy::{PolicyAtom, policy, policy_tokens};
mod templates;
use templates::{Template, expand_template};

use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::{ToTokens, format_ident, quote};
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

use noxide_protocol::identifier;

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

#[proc_macro_derive(Choice, attributes(choice))]
pub fn choice(input: TokenStream) -> TokenStream {
    finish(expand_choice(parse_macro_input!(input as DeriveInput)))
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

#[proc_macro_attribute]
pub fn action(attr: TokenStream, input: TokenStream) -> TokenStream {
    finish(expand_action(
        parse_macro_input!(attr as OperationDeclaration),
        parse_macro_input!(input as syn::ItemStruct),
    ))
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
            assert_eq!(crate::action::action_label(identifier), label);
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
            .is_ok()
        );
    }
}

#[cfg(test)]
mod anonymous_action_tests {
    use super::*;
    #[test]
    fn public_create_and_capability_mutations_are_the_only_anonymous_action_policies() {
        for declaration in [
            "create(Article), allow = public, fields(title), redirect = index",
            "update(Article), allow = capability, fields(title), redirect = index",
            "delete(Article), allow = capability, redirect = index",
        ] {
            assert!(
                expand_action(
                    syn::parse_str(declaration).unwrap(),
                    syn::parse_quote!(
                        struct Mutate;
                    )
                )
                .is_ok()
            );
        }
        for declaration in [
            "create(Article), allow = capability, fields(title), redirect = index",
            "update(Article), allow = public, fields(title), redirect = index",
            "delete(Article), allow = public, redirect = index",
        ] {
            assert!(
                expand_action(
                    syn::parse_str(declaration).unwrap(),
                    syn::parse_quote!(
                        struct Mutate;
                    )
                )
                .is_err()
            );
        }
        assert!(
            syn::parse_str::<OperationDeclaration>(
                "update(Article), allow = any(capability,owner), fields(title), redirect = index"
            )
            .is_err()
        );
    }
}

/// Discover an application's immediate declarations and lower read shorthand.
#[proc_macro_attribute]
pub fn app(attr: TokenStream, input: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return syn::Error::new(proc_macro2::Span::call_site(), "app takes no options")
            .into_compile_error()
            .into();
    }
    finish(expand_app(parse_macro_input!(input as syn::ItemMod)))
}
