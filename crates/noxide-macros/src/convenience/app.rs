use super::crud::CrudBlock;
use crate::registration::{Registration, expand_application};
use proc_macro2::TokenStream as Tokens;
use quote::{ToTokens, quote};
use std::collections::{BTreeMap, BTreeSet};
use syn::{
    Attribute, Ident, LitStr, Token, Type, braced, parenthesized,
    parse::{Parse, ParseStream},
    spanned::Spanned,
};

fn app_attribute(attr: &Attribute, name: &str) -> bool {
    let path = attr.path();
    path.is_ident(name)
        || (path.segments.len() == 2
            && path.segments[0].ident == "noxide"
            && path.segments[1].ident == name)
}

fn unconditional(attrs: &[Attribute]) -> syn::Result<()> {
    if let Some(attr) = attrs
        .iter()
        .find(|a| a.path().is_ident("cfg") || a.path().is_ident("cfg_attr"))
    {
        return Err(syn::Error::new(
            attr.span(),
            "conditional application declarations are unsupported",
        ));
    }
    Ok(())
}

pub(crate) fn expand_app(mut module: syn::ItemMod) -> syn::Result<Tokens> {
    unconditional(&module.attrs)?;
    let (_, items) = module
        .content
        .as_mut()
        .ok_or_else(|| syn::Error::new(module.ident.span(), "app requires an inline module"))?;
    let mut owners = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut functions = BTreeMap::new();
    for item in items.iter() {
        let name = match item {
            syn::Item::Struct(i) => Some(&i.ident),
            syn::Item::Enum(i) => Some(&i.ident),
            syn::Item::Fn(i) => {
                functions.insert(i.sig.ident.to_string(), i.attrs.clone());
                Some(&i.sig.ident)
            }
            syn::Item::Mod(i) => Some(&i.ident),
            syn::Item::Type(i) => Some(&i.ident),
            syn::Item::Const(i) => Some(&i.ident),
            syn::Item::Static(i) => Some(&i.ident),
            syn::Item::Trait(i) => Some(&i.ident),
            _ => None,
        };
        if let Some(name) = name {
            if ["routes", "noxide_manifest", "__NoxideApplication"]
                .contains(&name.to_string().as_str())
            {
                return Err(syn::Error::new(
                    name.span(),
                    "name reserved for application registration",
                ));
            }
            names.insert(name.to_string());
        }
    }
    for item in items.iter_mut() {
        if let syn::Item::Struct(resource) = item {
            for attr in &mut resource.attrs {
                if app_attribute(attr, "resource") {
                    unconditional(
                        &resource
                            .fields
                            .iter()
                            .flat_map(|f| f.attrs.clone())
                            .collect::<Vec<_>>(),
                    )?;
                    let mut persistent = None;
                    let mut owner = false;
                    attr.parse_nested_meta(|meta| {
                        if meta.path.is_ident("owner") && !owner {
                            owner = true;
                            Ok(())
                        } else if meta.path.is_ident("key") && persistent.is_none() {
                            persistent = Some(meta.value()?.parse::<LitStr>()?);
                            Ok(())
                        } else {
                            Err(meta.error("expected one key and optional owner"))
                        }
                    })?;
                    if owner {
                        owners.insert(resource.ident.to_string());
                    }
                    let persistent = persistent.ok_or_else(|| {
                        syn::Error::new(attr.span(), "explicit resource key required")
                    })?;
                    *attr = syn::parse_quote!(#[resource(key = #persistent)]);
                }
            }
        }
    }
    let mut generated = BTreeMap::new();
    let mut pages = BTreeMap::new();
    let mut actions: BTreeMap<String, (Type, Option<syn::Path>)> = BTreeMap::new();
    let mut layouts = BTreeMap::new();
    let mut associations = Vec::new();
    let mut retained = Vec::new();
    for item in std::mem::take(items) {
        if let syn::Item::Macro(ref invocation) = item {
            if app_attribute_path(&invocation.mac.path, "crud") {
                unconditional(&invocation.attrs)?;
                let crud = syn::parse2::<CrudBlock>(invocation.mac.tokens.clone())?;
                super::crud::lower_crud(
                    crud,
                    &owners,
                    &mut names,
                    &mut generated,
                    &mut actions,
                    &mut layouts,
                )?;
                continue;
            }
            if app_attribute_path(&invocation.mac.path, "hooks") {
                unconditional(&invocation.attrs)?;
                associations
                    .extend(syn::parse2::<HookAssociations>(invocation.mac.tokens.clone())?.0);
                continue;
            }
        }
        retained.push(item);
    }
    *items = retained;
    for item in items.iter_mut() {
        let attrs = match item {
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            _ => continue,
        };
        let declaration = attrs.iter().any(|a| {
            ["page", "resource", "query", "action", "choice"]
                .iter()
                .any(|name| app_attribute(a, name))
        }) || attrs.iter().any(|a| {
            a.path().is_ident("derive")
                && a.meta
                    .to_token_stream()
                    .to_string()
                    .split(|c: char| !c.is_alphanumeric())
                    .any(|n| n == "Choice" || n == "Resource")
        });
        if !declaration {
            continue;
        }
        unconditional(attrs)?;
        match item {
            syn::Item::Enum(i) => {
                for v in &i.variants {
                    unconditional(&v.attrs)?;
                }
            }
            syn::Item::Struct(i) => {
                for field in &i.fields {
                    unconditional(&field.attrs)?;
                }
                if i.attrs.iter().any(|a| app_attribute(a, "action")) {
                    let name = &i.ident;
                    if actions
                        .insert(name.to_string(), (syn::parse_quote!(#name), None))
                        .is_some()
                    {
                        return Err(syn::Error::new(name.span(), "duplicate action"));
                    }
                }
            }
            syn::Item::Fn(i) if i.attrs.iter().any(|a| app_attribute(a, "page")) => {
                for attr in &mut i.attrs {
                    if app_attribute(attr, "page")
                        && let Ok(path) = attr.parse_args::<LitStr>()
                    {
                        *attr = syn::parse_quote!(#[::noxide::page(path = #path)]);
                    }
                }
                let name = &i.sig.ident;
                pages.insert(name.to_string(), syn::parse_quote!(#name));
                super::inferred_queries::lower_inputs(i, &owners, &names, &mut generated)?;
            }
            _ => {}
        }
    }
    let mut associated = BTreeSet::new();
    for association in associations {
        let key = association.name.to_string();
        if !associated.insert(key.clone()) {
            return Err(syn::Error::new(
                association.name.span(),
                "duplicate hook association",
            ));
        }
        let Some((_, handler)) = actions.get_mut(&key) else {
            return Err(syn::Error::new(
                association.name.span(),
                "hooks require a registered action",
            ));
        };
        if handler.is_some() || layouts.contains_key(&key) {
            return Err(syn::Error::new(
                association.name.span(),
                "declare hooks once per action",
            ));
        }
        *handler = association.handler;
        if let Some(layout) = association.layout {
            layouts.insert(key, layout);
        }
    }
    for hook in actions
        .values()
        .filter_map(|(_, h)| h.as_ref())
        .chain(layouts.values())
    {
        let Some(name) = hook.get_ident() else {
            return Err(syn::Error::new(
                hook.span(),
                "hooks must name an immediate application function",
            ));
        };
        let Some(attrs) = functions.get(&name.to_string()) else {
            return Err(syn::Error::new(
                hook.span(),
                "hooks must name an immediate application function",
            ));
        };
        unconditional(attrs)?;
    }
    for tokens in generated.values() {
        items.extend(syn::parse2::<syn::File>(tokens.clone())?.items);
    }
    // Reuse the parsed action type, including raw identifiers, rather than
    // reconstructing a Rust identifier from its display string.
    let forms = layouts
        .into_iter()
        .map(|(name, function)| (actions[&name].0.clone(), function))
        .collect();
    let registration = Registration {
        pages: pages.into_values().collect(),
        actions: actions.into_values().collect(),
        forms,
    };
    if registration.pages.is_empty() {
        return Err(syn::Error::new(
            module.ident.span(),
            "register at least one page",
        ));
    }
    items.extend(syn::parse2::<syn::File>(expand_application(registration)?)?.items);
    let name = &module.ident;
    Ok(quote! {
        // A single root collector also makes multiple app modules a compiler error.
        const _: () = {
            let path = module_path!().as_bytes();
            let mut i = 0;
            while i < path.len() { assert!(path[i] != b':', "app must be declared at crate root"); i += 1; }
        };
        #module
        pub use #name::noxide_manifest;
    })
}

pub(super) fn app_attribute_path(path: &syn::Path, name: &str) -> bool {
    path.is_ident(name)
        || (path.segments.len() == 2
            && path.segments[0].ident == "noxide"
            && path.segments[1].ident == name)
}

struct HookAssociation {
    name: Ident,
    handler: Option<syn::Path>,
    layout: Option<syn::Path>,
}
struct HookAssociations(Vec<HookAssociation>);
impl Parse for HookAssociations {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut entries = Vec::new();
        while !input.is_empty() {
            let name = input.parse()?;
            let content;
            braced!(content in input);
            let mut handler = None;
            let mut layout = None;
            while !content.is_empty() {
                let option: Ident = content.parse()?;
                let args;
                parenthesized!(args in content);
                let path: syn::Path = args.parse()?;
                if !args.is_empty() {
                    return Err(args.error("expected one function path"));
                }
                if option == "handler" && handler.is_none() {
                    handler = Some(path);
                } else if option == "layout" && layout.is_none() {
                    layout = Some(path);
                } else {
                    return Err(syn::Error::new(
                        option.span(),
                        "expected one handler and/or layout",
                    ));
                }
                if !content.is_empty() {
                    content.parse::<Token![,]>()?;
                }
            }
            if handler.is_none() && layout.is_none() {
                return Err(content.error("expected handler or layout"));
            }
            entries.push(HookAssociation {
                name,
                handler,
                layout,
            });
        }
        Ok(Self(entries))
    }
}

#[cfg(test)]
mod app_tests {
    use super::*;

    #[test]
    fn raw_action_names_preserve_the_registered_type_in_layouts() {
        let expanded = expand_app(syn::parse_quote! {
            mod notes {
                #[resource(key = "notes", owner)] struct Note;
                crud! { Note { update r#EditNote { fields(body), redirect(show), layout(editor) } } }
                fn editor() -> FormLayout { todo!() }
                #[page("/")] fn index() -> Page { todo!() }
            }
        }).unwrap();
        syn::parse2::<syn::File>(expanded).unwrap();
    }

    #[test]
    fn inline_app_lowers_owner_reads_and_crud() {
        let output = expand_app(syn::parse_quote! {
            mod notes {
                #[derive(Resource)]
                #[resource(key = "notes", owner)]
                struct Note { #[id] id: Id<Self>, #[field(max_bytes = 4096)] body: String }
                crud! { Note { create CreateNote { fields(body), redirect(index) } } }
                #[page("/")]
                fn index(notes: List<Note>, create: Form<CreateNote>) -> Page { todo!() }
            }
        })
        .unwrap();
        syn::parse2::<syn::File>(output.clone()).unwrap();
        let text = output.to_string();
        assert!(text.contains("Predicate :: Owner"));
        assert!(text.contains("__Noxide_list_Note"));
        assert!(text.contains("pub use notes :: noxide_manifest"));
    }

    #[test]
    fn shorthand_never_invents_a_policy() {
        let error = expand_app(syn::parse_quote! {
            mod posts {
                #[derive(Resource)] #[resource(key = "posts")]
                struct Post { #[id] id: Id<Self> }
                #[page("/")] fn index(posts: List<Post>) -> Page { todo!() }
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("owner resource"));
    }

    #[test]
    fn external_modules_are_rejected() {
        assert!(
            expand_app(syn::parse_quote!(
                mod notes;
            ))
            .is_err()
        );
    }
}

#[cfg(test)]
mod app_policy_tests {
    use super::*;

    #[test]
    fn crud_requires_explicit_field_projections_and_redirects() {
        for input in [
            "Note { create CreateNote { redirect(show) } }",
            "Note { update EditNote { fields(body) } }",
            "Note { delete DeleteNote { fields(body), redirect(index) } }",
            "Note { create A { fields(body), fields(title), redirect(index) } }",
            "Note { update A { fields(body), redirect(index), redirect(show) } }",
            "Note { delete A { redirect(index), allow = owner, allow = public } }",
        ] {
            assert!(syn::parse_str::<CrudBlock>(input).is_err(), "{input}");
        }
    }

    #[test]
    fn repeated_named_actions_keep_independent_policies_and_destinations() {
        let output = expand_app(syn::parse_quote! {
            mod app {
                #[resource(key = "notes", owner)] struct Note;
                crud! { Note {
                    create Create { fields(body), redirect(parent(show)) }
                    create Anonymous { fields(body), allow = public, redirect(show) }
                    update Edit { fields(body), redirect(show) }
                    update Secret { fields(body), allow = capability, redirect(parent(show)) }
                    update Moderate { fields(published), allow = role("moderator"), redirect(show) }
                    delete Delete { redirect(index) }
                    delete Remove { allow = capability, redirect(parent(show)) }
                } }
                #[page("/")] fn index() -> Page { todo!() }
            }
        })
        .unwrap()
        .to_string();
        assert_eq!(output.matches("Predicate :: Owner").count(), 3);
        assert_eq!(output.matches("Predicate :: Public").count(), 1);
        assert_eq!(output.matches("Predicate :: Capability").count(), 2);
        assert_eq!(output.matches("Redirect :: Parent").count(), 3);
        assert_eq!(output.matches("Redirect :: Page").count(), 4);
    }

    #[test]
    fn repeated_names_use_the_module_collision_check() {
        for declarations in [
            quote!(
                crud! { Note { delete Delete { redirect(index) } delete Delete { redirect(index) } } }
            ),
            quote!(crud! { Note { delete Delete { redirect(index) } } } crud! { Note { create Delete { fields(body), redirect(index) } } }),
            quote! {
                struct Delete;
                crud! { Note { delete Delete { redirect(index) } } }
            },
        ] {
            let error = expand_app(
                syn::parse2(quote! {
                    mod app {
                        #[resource(key = "notes", owner)] struct Note;
                        #declarations
                        #[page("/")] fn index() -> Page { todo!() }
                    }
                })
                .unwrap(),
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("generated action name collision")
            );
        }
    }

    #[test]
    fn each_repeated_entry_requires_its_own_policy() {
        let error = expand_app(syn::parse_quote! {
            mod app {
                #[resource(key = "notes")] struct Note;
                crud! { Note {
                    create Public { fields(body), allow = public, redirect(show) }
                    create Missing { fields(body), redirect(show) }
                } }
                #[page("/")] fn index() -> Page { todo!() }
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("explicit policy"));
    }

    #[test]
    fn default_policy_never_applies_to_unmarked_resource() {
        let error = expand_app(syn::parse_quote! {
            mod app {
                #[derive(Resource)] #[resource(key = "posts")]
                struct Post { #[id] id: Id<Self> }
                crud! { Post { delete DeletePost { redirect(index) } } }
                #[page("/")] fn index() -> Page { todo!() }
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("explicit policy"));
    }

    #[test]
    fn explicit_crud_policy_reuses_existing_policy_validation() {
        let error = expand_app(syn::parse_quote! {
            mod app {
                crud! { Post { update EditPost { fields(body), redirect(show), allow = public } } }
                #[page("/")] fn index() -> Page { todo!() }
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("public"));
    }

    #[test]
    fn ordinary_conditional_helpers_are_allowed() {
        assert!(
            expand_app(syn::parse_quote! {
                mod app {
                    #[cfg(any())] struct Helper;
                    #[cfg(any())] fn helper() {}
                    #[page("/")] fn index() -> Page { todo!() }
                }
            })
            .is_ok()
        );
    }

    #[test]
    fn conditional_hook_cannot_change_the_contract_by_target() {
        let error = expand_app(syn::parse_quote! {
            mod app {
                #[action(delete(Note), allow = owner, redirect = index)] struct DeleteNote;
                hooks! { DeleteNote { handler(remove) } }
                #[cfg(any())] fn remove() {}
                #[page("/")] fn index() -> Page { todo!() }
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("conditional"));
    }

    #[test]
    fn crud_cannot_shadow_an_explicit_action() {
        let error = expand_app(syn::parse_quote! {
            mod app {
                #[resource(key = "notes", owner)] struct Note;
                #[action(delete(Note), allow = owner, redirect = index)] struct DeleteNote;
                crud! { Note { delete DeleteNote { redirect(index) } } }
                #[page("/")] fn index() -> Page { todo!() }
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("collision"));
    }
}
