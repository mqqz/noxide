use crate::declaration::policy::{PolicyAtom, policy_tokens};
use crate::declaration::{OperationDeclaration, marker};
use crate::syntax::stable_id;
use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use syn::{LitStr, spanned::Spanned};

pub(crate) fn action_label(identifier: &str) -> String {
    let characters: Vec<_> = identifier.chars().collect();
    let mut words = Vec::new();
    let mut word = String::new();
    for (index, character) in characters.iter().copied().enumerate() {
        let boundary = character.is_uppercase()
            && index > 0
            && (characters[index - 1].is_lowercase()
                || characters[index - 1].is_numeric()
                || characters[index - 1].is_uppercase()
                    && characters
                        .get(index + 1)
                        .is_some_and(|next| next.is_lowercase()));
        if (boundary || character == '_') && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        if character != '_' {
            word.push(character);
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
        .into_iter()
        .enumerate()
        .map(|(index, word)| {
            if word
                .chars()
                .all(|character| character.is_uppercase() || character.is_numeric())
            {
                word
            } else if index == 0 {
                let mut characters = word.chars();
                characters
                    .next()
                    .map(|first| first.to_uppercase().collect::<String>() + characters.as_str())
                    .unwrap_or_default()
            } else {
                word.to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn expand_action(
    declaration: OperationDeclaration,
    item: syn::ItemStruct,
) -> syn::Result<Tokens> {
    marker(&item)?;
    if declaration
        .policy
        .iter()
        .flatten()
        .any(|p| matches!(p, PolicyAtom::PrincipalIs(_)))
    {
        return Err(syn::Error::new(
            item.span(),
            "principal_is requires read or list",
        ));
    }
    if declaration.visible.is_some()
        || (declaration
            .policy
            .iter()
            .flatten()
            .any(|p| matches!(p, PolicyAtom::Public))
            && declaration.kind != "create")
        || (declaration
            .policy
            .iter()
            .flatten()
            .any(|p| matches!(p, PolicyAtom::Capability))
            && !matches!(declaration.kind.to_string().as_str(), "update" | "delete"))
    {
        return Err(syn::Error::new(
            item.span(),
            "public requires create; capability requires update or delete; actions cannot declare visibility",
        ));
    }
    let kind = match declaration.kind.to_string().as_str() {
        "create" => quote!(::noxide::__private::OperationKind::Create),
        "update" => quote!(::noxide::__private::OperationKind::Update),
        "delete" => quote!(::noxide::__private::OperationKind::Delete),
        _ => {
            return Err(syn::Error::new(
                declaration.kind.span(),
                "actions support create, update, or delete",
            ));
        }
    };
    if declaration.kind == "delete" && !declaration.fields.is_empty() {
        return Err(syn::Error::new(
            item.span(),
            "delete actions cannot project writable fields",
        ));
    }
    if declaration.kind != "delete" && declaration.fields.is_empty() {
        return Err(syn::Error::new(
            item.span(),
            "create and update actions require explicit fields(...)",
        ));
    }
    let redirect = declaration
        .redirect
        .ok_or_else(|| syn::Error::new(item.span(), "actions require a declared redirect page"))?;
    let redirect_value = if declaration.redirect_parent {
        quote!(::noxide::__private::Redirect::Parent { parent: #redirect::id() })
    } else {
        quote!(::noxide::__private::Redirect::Page(#redirect::id()))
    };
    if declaration.inspect.is_some() != !declaration.inspection_fields.is_empty() {
        return Err(syn::Error::new(
            item.span(),
            "inspection requires both inspect=Query and inspect_fields(...)",
        ));
    }
    if declaration.inspect.is_some() && declaration.kind == "create" {
        return Err(syn::Error::new(
            item.span(),
            "create actions cannot inspect an existing record",
        ));
    }
    let name = &item.ident;
    let label = LitStr::new(&action_label(&name.to_string()), name.span());
    let vis = &item.vis;
    let input_name = format_ident!("{name}Input");
    let controls_name = format_ident!("{name}Controls");
    let original_name = format_ident!("{name}Original");
    let resource = &declaration.resource;
    let policy = policy_tokens(&declaration.policy, &declaration.resource);
    let version = declaration.version;
    let names = &declaration.fields;
    let hashes: Vec<_> = names
        .iter()
        .map(|field| stable_id(&field.to_string()))
        .collect();
    let values: Vec<_> = hashes
        .iter()
        .map(|hash| quote!(<#resource as ::noxide::FieldSpec<#hash>>::Value))
        .collect();
    let keys: Vec<_> = hashes
        .iter()
        .map(|hash| quote!(<#resource as ::noxide::FieldSpec<#hash>>::KEY))
        .collect();
    let inspection = if let Some(query) = &declaration.inspect {
        let inspection_keys = declaration.inspection_fields.iter().map(|field| {
            let hash = stable_id(&field.to_string());
            quote!(<#resource as ::noxide::FieldSpec<#hash>>::KEY.into())
        });
        quote!(Some(::noxide::__private::Inspection {
            operation: <#query as ::noxide::QueryType>::operation().id,
            fields: vec![#(#inspection_keys),*],
        }))
    } else {
        quote!(None)
    };
    let inspection_operation = if let Some(query) = &declaration.inspect {
        quote!(Some(<#query as ::noxide::QueryType>::operation()))
    } else {
        quote!(None)
    };
    let original = if declaration.inspect.is_some() {
        let original_fields = &declaration.inspection_fields;
        let original_hashes: Vec<_> = original_fields
            .iter()
            .map(|field| stable_id(&field.to_string()))
            .collect();
        let original_types: Vec<_> = original_hashes
            .iter()
            .map(|hash| quote!(<#resource as ::noxide::FieldSpec<#hash>>::Value))
            .collect();
        let original_keys: Vec<_> = original_hashes
            .iter()
            .map(|hash| quote!(<#resource as ::noxide::FieldSpec<#hash>>::KEY))
            .collect();
        quote! {
            #vis struct #original_name { #(pub #original_fields: #original_types),* }
            impl ::noxide::ActionInput for #original_name {
                fn from_fields(_fields: &::noxide::Fields) -> Self {
                    Self { #(#original_fields: <#original_types as ::noxide::FieldValue>::decode(_fields.get(#original_keys).expect("host inspection field"))),* }
                }
            }
        }
    } else {
        Tokens::new()
    };
    let original_type = if declaration.inspect.is_some() {
        quote!(#original_name)
    } else {
        quote!(())
    };
    let immutable_check = if declaration.kind == "update" {
        quote!(const _: () = { #(assert!(!<#values as ::noxide::FieldValue>::IMMUTABLE, "account fields are immutable");)* };)
    } else {
        Tokens::new()
    };
    Ok(quote! {
        #immutable_check
        #item
        #original
        #vis struct #input_name { #(pub #names: #values),* }
        #vis struct #controls_name { #(pub #names: ::noxide::ControlField<#values>),* }
        impl ::noxide::ActionInput for #input_name {
            fn from_fields(_fields: &::noxide::Fields) -> Self {
                Self { #(#names: <#values as ::noxide::FieldValue>::decode(_fields.get(#keys).expect("host action field"))),* }
            }
        }
        impl #name {
            #(
                #[allow(non_upper_case_globals)]
                pub const #names: ::noxide::Field<Self, #values> = ::noxide::Field::new(#keys);
            )*
        }
        impl ::noxide::ActionType for #name {
            type Resource = #resource;
            type Input = #input_name;
            type Controls = #controls_name;
            type Original = #original_type;
            fn controls() -> Self::Controls {
                #controls_name { #(#names: ::noxide::ControlField::new(#keys)),* }
            }
            fn operation() -> ::noxide::__private::Operation {
                ::noxide::__private::Operation {
                    filter: Vec::new(), disclose: Vec::new(),
                list: None, visibility: None, fields: None,
                    id: ::noxide::stable_id(concat!("mutation:", module_path!(), "::", stringify!(#name))),
                    resource: <#resource as ::noxide::ResourceType>::definition().id,
                    kind: #kind, policy: #policy,
                }
            }
            fn definition() -> ::noxide::__private::Action {
                ::noxide::__private::Action {
                    id: ::noxide::stable_id(concat!("action:", module_path!(), "::", stringify!(#name))),
                    version: #version, name: #label.into(),
                    operation: <Self as ::noxide::ActionType>::operation().id, redirect: #redirect_value,
                    fields: vec![#(#keys.into()),*], inspect: #inspection, layout: vec![],
                }
            }
            fn inspection() -> Option<::noxide::__private::Operation> { #inspection_operation }
        }
    })
}
