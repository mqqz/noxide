//! Declarations and templates for the Noxide guest SDK.
//!
//! Macro expansion happens inside the isolated application build.
mod convenience;
mod declaration;
mod registration;
mod syntax;
use convenience::app::expand_app;
use declaration::{
    OperationDeclaration,
    action::expand_action,
    choice::expand_choice,
    page::{PageDeclaration, expand_page},
    query::expand_query,
    resource::expand_resource,
    templates::{Template, expand_template},
};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
#[cfg(test)]
use quote::quote;
use registration::{Registration, expand_application};
#[cfg(test)]
use syn::Expr;
use syn::{DeriveInput, parse_macro_input};
fn finish(result: syn::Result<Tokens>) -> TokenStream {
    result.unwrap_or_else(syn::Error::into_compile_error).into()
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
    fn initial_create_typed_surface_uses_only_action_projection() {
        let declaration =
            syn::parse_str("create(Article), fields(title), allow = owner, redirect = show")
                .unwrap();
        let tokens = expand_action(
            declaration,
            syn::parse_quote!(
                pub struct CreateArticle;
            ),
        )
        .unwrap()
        .to_string();
        assert!(tokens.contains("pub title"));
        assert!(!tokens.contains("published"));
    }
    #[test]
    fn initial_accepts_only_bounded_boolean_literals() {
        for attrs in [quote!(initial = false), quote!(initial = true)] {
            let input = syn::parse_quote! {
                #[resource(key = "notes")]
                struct Note { #[id] id: Id<Self>, #[field(#attrs)] flag: bool }
            };
            assert!(
                expand_resource(input)
                    .unwrap()
                    .to_string()
                    .contains("initial")
            );
        }
        for (ty, attrs) in [
            (quote!(bool), quote!(initial = false, initial = true)),
            (quote!(bool), quote!(initial = make_value())),
            (quote!(bool), quote!(initial = "false")),
            (quote!(bool), quote!(initial = false, max_bytes = 4)),
            (quote!(Option<bool>), quote!(initial = false)),
            (quote!(String), quote!(initial = false, max_bytes = 20)),
            (quote!(i64), quote!(initial = 0)),
            (quote!(Id<Parent>), quote!(initial = false)),
        ] {
            let input = syn::parse_quote! {
                #[resource(key = "notes")]
                struct Note { #[id] id: Id<Self>, #[field(#attrs)] flag: #ty }
            };
            assert!(expand_resource(input).is_err(), "{ty} {attrs}");
        }
        assert!(
            expand_resource(syn::parse_quote! {
                #[resource(key = "notes")]
                struct Note { #[id] #[field(initial = false)] id: Id<Self>, #[field()] flag: bool }
            })
            .is_err()
        );
    }
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

#[proc_macro_attribute]
pub fn page(attr: TokenStream, input: TokenStream) -> TokenStream {
    finish(expand_page(
        parse_macro_input!(attr as PageDeclaration),
        parse_macro_input!(input as syn::ItemFn),
    ))
}

#[proc_macro]
pub fn application(input: TokenStream) -> TokenStream {
    finish(expand_application(parse_macro_input!(
        input as Registration
    )))
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
        assert!(text.contains("Redirect :: Page (show :: id ())"));
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
            assert_eq!(crate::declaration::action::action_label(identifier), label);
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
                syn::parse_str::<OperationDeclaration>(&format!("{declaration}, allow=owner"))
                    .is_err(),
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

#[cfg(test)]
mod pagination_tests {
    use super::*;
    #[test]
    fn list_settings_are_narrow_and_bounded() {
        for declaration in [
            "list(Reply), order=created_asc, page_size=20",
            "list(Reply)",
        ] {
            assert!(
                syn::parse_str::<OperationDeclaration>(&format!("{declaration}, allow=owner"))
                    .is_ok()
            );
        }
        for declaration in [
            "list(Reply),order=updated_desc",
            "list(Reply),page_size=0",
            "list(Reply),page_size=21",
            "read(Reply),page_size=3",
            "create(Reply),order=created_asc",
            "list(Reply),page_size=3,page_size=4",
        ] {
            assert!(
                syn::parse_str::<OperationDeclaration>(&format!("{declaration}, allow=owner"))
                    .is_err(),
                "{declaration}"
            );
        }
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

#[cfg(test)]
mod parent_redirect_tests {
    use super::*;
    #[test]
    fn parent_redirect_lowering_is_typed_for_each_mutation() {
        for kind in ["create", "update", "delete"] {
            let fields = if kind == "delete" {
                ""
            } else {
                ", fields(body)"
            };
            let declaration: OperationDeclaration = syn::parse_str(&format!(
                "{kind}(Reply), allow = owner{fields}, redirect = parent(thread)"
            ))
            .unwrap();
            let item: syn::ItemStruct = syn::parse_quote!(
                struct ChangeReply;
            );
            let lowered = declaration::action::expand_action(declaration, item);
            // The public expansion path enforces operation semantics separately.
            assert!(lowered.is_ok());
            assert!(lowered.unwrap().to_string().contains("Redirect :: Parent"));
        }
        for bad in ["parent()", "parent(thread, other)", "parent(thread(other))"] {
            assert!(
                syn::parse_str::<OperationDeclaration>(&format!(
                    "delete(Reply), allow = owner, redirect = {bad}"
                ))
                .is_err()
            );
        }
    }
}
