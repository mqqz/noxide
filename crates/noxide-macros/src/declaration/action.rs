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
    let redirect_value = if let Some(field) = &declaration.redirect_reference {
        let resource = &declaration.resource;
        let hash = stable_id(&field.to_string());
        quote!(::noxide::__private::Redirect { route: #redirect::id(), source: ::noxide::__private::RedirectSource::Reference { step: 0, field: <#resource as ::noxide::FieldSpec<#hash>>::KEY.into() } })
    } else {
        quote!(::noxide::__private::Redirect { route: #redirect::id(), source: ::noxide::__private::RedirectSource::Step(0) })
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
    if declaration.scope.is_some() || declaration.via.is_some() {
        return Err(syn::Error::new(
            item.span(),
            "scope and via require queries",
        ));
    }
    let bind = if let Some((field, query)) = &declaration.bind {
        let hash = stable_id(&field.to_string());
        quote!(Some(::noxide::__private::Bind {
            field: <#resource as ::noxide::FieldSpec<#hash>>::KEY.into(),
            eligible: <#query as ::noxide::QueryType>::operation().id,
        }))
    } else {
        quote!(None)
    };
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
    let target = if declaration.kind == "create" {
        quote!(::noxide::__private::Target::None)
    } else {
        quote!(::noxide::__private::Target::Signed)
    };
    let reference_assignment = if let Some((field, _)) = &declaration.bind {
        let hash = stable_id(&field.to_string());
        quote!(let assign = { let mut assign = assign; assign.push(::noxide::__private::Assignment { field: <#resource as ::noxide::FieldSpec<#hash>>::KEY.into(), change: ::noxide::__private::Change::Set(::noxide::__private::Value::SignedTarget) }); assign };)
    } else {
        Tokens::new()
    };
    let eligibility_operation = declaration
        .bind
        .as_ref()
        .map(|(_, query)| quote!(<#query as ::noxide::QueryType>::operation()))
        .into_iter();
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
            fn operations() -> Vec<::noxide::__private::Operation> {
                vec![::noxide::__private::Operation { bind: #bind, scope: None, via: None,
                    filter: Vec::new(), disclose: Vec::new(),
                list: None, visibility: None, fields: None,
                    id: ::noxide::stable_id(concat!("mutation:", module_path!(), "::", stringify!(#name))),
                    resource: <#resource as ::noxide::ResourceType>::definition().id,
                    kind: #kind, policy: #policy,
                }, #(#eligibility_operation),*]
            }
            fn definition() -> ::noxide::__private::Action {
                let schema = <#resource as ::noxide::ResourceType>::definition();
                let inputs = vec![#(#keys),*].into_iter().map(|key: &str| {
                    let field = schema.fields.iter().find(|field| field.name == key).expect("declared action field");
                    ::noxide::__private::Input { name: field.name.clone(), label: field.label.clone(), kind: field.kind.clone(), optional: field.optional, max_bytes: field.max_bytes }
                }).collect();
                let assign = vec![#(::noxide::__private::Assignment { field: #keys.into(), change: ::noxide::__private::Change::Set(::noxide::__private::Value::Input(#keys.into())) }),*];
                #reference_assignment
                ::noxide::__private::Action {
                    id: ::noxide::stable_id(concat!("action:", module_path!(), "::", stringify!(#name))),
                    version: #version, name: #label.into(),
                    steps: vec![::noxide::__private::Step { operation: <Self as ::noxide::ActionType>::operations()[0].id, target: #target, assign }], redirect: #redirect_value,
                    inputs, revision: ::noxide::__private::Revision::Exact, inspect: #inspection, layout: vec![],
                }
            }
            fn inspection() -> Option<::noxide::__private::Operation> { #inspection_operation }
        }
    })
}

pub(crate) enum ActionDeclaration {
    Single(Box<OperationDeclaration>),
    Transaction(Box<TransactionDeclaration>),
}
impl syn::parse::Parse for ActionDeclaration {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let fork = input.fork();
        let first: syn::Ident = fork.parse()?;
        if matches!(
            first.to_string().as_str(),
            "inputs" | "transaction" | "revision"
        ) {
            Ok(Self::Transaction(Box::new(input.parse()?)))
        } else {
            Ok(Self::Single(Box::new(input.parse()?)))
        }
    }
}

pub(crate) fn expand_declared_action(
    declaration: ActionDeclaration,
    item: syn::ItemStruct,
) -> syn::Result<Tokens> {
    match declaration {
        ActionDeclaration::Single(single) => expand_action(*single, item),
        ActionDeclaration::Transaction(transaction) => expand_transaction(*transaction, item),
    }
}

struct InputDeclaration {
    name: syn::Ident,
    ty: syn::Type,
    bound: Option<syn::Expr>,
}
struct TransactionStep {
    name: Option<syn::Ident>,
    kind: syn::Ident,
    resource: syn::Type,
    assignments: Vec<(syn::Ident, DeclaredChange)>,
    eligible: Option<syn::Type>,
}
enum DeclaredChange {
    Set(syn::Expr),
    Adjustment {
        increase: bool,
        by: syn::Ident,
        input: syn::Ident,
        message: syn::LitStr,
    },
}
pub(crate) struct TransactionDeclaration {
    inputs: Vec<InputDeclaration>,
    steps: Vec<TransactionStep>,
    identity: bool,
    policy: Vec<Vec<PolicyAtom>>,
    redirect: syn::Path,
    redirect_source: syn::Ident,
    redirect_reference: Option<syn::Ident>,
    inspect: Option<syn::Type>,
    inspection_fields: Vec<syn::Ident>,
    version: u32,
}
impl syn::parse::Parse for TransactionDeclaration {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        use syn::{Token, parenthesized};
        let mut inputs = Vec::new();
        let mut steps = Vec::new();
        let mut identity = false;
        let mut rules = None;
        let mut redirect = None;
        let mut redirect_reference = None;
        let mut inspect = None;
        let mut inspection_fields = Vec::new();
        let mut version = 1;
        let mut seen = std::collections::BTreeSet::new();
        while !input.is_empty() {
            let option: syn::Ident = input.parse()?;
            if !seen.insert(option.to_string()) {
                return Err(syn::Error::new(option.span(), "duplicate action option"));
            }
            match option.to_string().as_str() {
                "inputs" => {
                    let content;
                    parenthesized!(content in input);
                    let mut names = std::collections::BTreeSet::new();
                    while !content.is_empty() {
                        let name: syn::Ident = content.parse()?;
                        if !names.insert(name.to_string()) {
                            return Err(syn::Error::new(name.span(), "duplicate input"));
                        }
                        content.parse::<Token![:]>()?;
                        let ty = content.parse()?;
                        let bound = if content.peek(Token![=]) {
                            content.parse::<Token![=]>()?;
                            Some(content.parse()?)
                        } else {
                            None
                        };
                        inputs.push(InputDeclaration { name, ty, bound });
                        if !content.is_empty() {
                            content.parse::<Token![,]>()?;
                        }
                    }
                }
                "revision" => {
                    input.parse::<Token![=]>()?;
                    let value: syn::Ident = input.parse()?;
                    identity = match value.to_string().as_str() {
                        "identity" => true,
                        "exact" => false,
                        _ => {
                            return Err(syn::Error::new(
                                value.span(),
                                "expected exact or identity",
                            ));
                        }
                    };
                }
                "allow" => {
                    input.parse::<Token![=]>()?;
                    rules = Some(crate::declaration::policy::policy(input)?);
                }
                "inspect" => {
                    input.parse::<Token![=]>()?;
                    inspect = Some(input.parse()?);
                }
                "inspect_fields" => {
                    let content;
                    parenthesized!(content in input);
                    inspection_fields = content
                        .parse_terminated(syn::Ident::parse, Token![,])?
                        .into_iter()
                        .collect();
                }
                "version" => {
                    input.parse::<Token![=]>()?;
                    let value: syn::LitInt = input.parse()?;
                    version = value.base10_parse()?;
                    if version == 0 {
                        return Err(syn::Error::new(
                            value.span(),
                            "action version must be positive",
                        ));
                    }
                }
                "redirect" => {
                    input.parse::<Token![=]>()?;
                    let mut path: syn::Path = input.parse()?;
                    let content;
                    parenthesized!(content in input);
                    let source = content.parse()?;
                    if path.is_ident("reference") {
                        content.parse::<Token![.]>()?;
                        redirect_reference = Some(content.parse()?);
                        content.parse::<Token![,]>()?;
                        path = content.parse()?;
                    }
                    if !content.is_empty() {
                        return Err(content.error("expected one navigation source"));
                    }
                    redirect = Some((path, source));
                }
                "transaction" => {
                    let content;
                    parenthesized!(content in input);
                    while !content.is_empty() {
                        let first: syn::Ident = content.parse()?;
                        let (name, kind) = if content.peek(Token![=]) {
                            content.parse::<Token![=]>()?;
                            (Some(first), content.parse()?)
                        } else {
                            (None, first)
                        };
                        if !matches!(kind.to_string().as_str(), "create" | "update" | "delete") {
                            return Err(syn::Error::new(
                                kind.span(),
                                "expected create, update, or delete",
                            ));
                        }
                        let args;
                        parenthesized!(args in content);
                        let resource = args.parse()?;
                        if kind != "create" {
                            args.parse::<Token![,]>()?;
                            let target: syn::Ident = args.parse()?;
                            if target != "target" {
                                return Err(syn::Error::new(
                                    target.span(),
                                    "updates and deletes require target",
                                ));
                            }
                        }
                        let mut assignments = Vec::new();
                        let mut eligible = None;
                        while !args.is_empty() {
                            args.parse::<Token![,]>()?;
                            if args.is_empty() {
                                break;
                            }
                            let change: syn::Ident = args.parse()?;
                            if change == "eligible" {
                                args.parse::<Token![=]>()?;
                                if eligible.is_some() {
                                    return Err(syn::Error::new(
                                        change.span(),
                                        "duplicate eligibility",
                                    ));
                                }
                                eligible = Some(args.parse()?);
                                continue;
                            }
                            let values;
                            parenthesized!(values in args);
                            if change == "set" {
                                while !values.is_empty() {
                                    let field = values.parse()?;
                                    values.parse::<Token![=]>()?;
                                    assignments.push((field, DeclaredChange::Set(values.parse()?)));
                                    if !values.is_empty() {
                                        values.parse::<Token![,]>()?;
                                    }
                                }
                            } else if change == "decrease" || change == "increase" {
                                if kind != "update" {
                                    return Err(syn::Error::new(
                                        change.span(),
                                        "adjustments require a signed update",
                                    ));
                                }
                                let field = values.parse()?;
                                values.parse::<Token![,]>()?;
                                let by_key: syn::Ident = values.parse()?;
                                if by_key != "by" {
                                    return Err(syn::Error::new(by_key.span(), "expected by"));
                                }
                                values.parse::<Token![=]>()?;
                                let by = values.parse()?;
                                values.parse::<Token![,]>()?;
                                let reject: syn::Ident = values.parse()?;
                                if reject != "reject" {
                                    return Err(syn::Error::new(reject.span(), "expected reject"));
                                }
                                let rejection;
                                parenthesized!(rejection in values);
                                let error_input = rejection.parse()?;
                                rejection.parse::<Token![,]>()?;
                                let message = rejection.parse()?;
                                if !rejection.is_empty() || !values.is_empty() {
                                    return Err(values.error("invalid guard rejection"));
                                }
                                assignments.push((
                                    field,
                                    DeclaredChange::Adjustment {
                                        increase: change == "increase",
                                        by,
                                        input: error_input,
                                        message,
                                    },
                                ));
                            } else {
                                return Err(syn::Error::new(
                                    change.span(),
                                    "expected set, decrease, or increase",
                                ));
                            }
                        }
                        steps.push(TransactionStep {
                            name,
                            kind,
                            resource,
                            assignments,
                            eligible,
                        });
                        if !content.is_empty() {
                            content.parse::<Token![,]>()?;
                        }
                    }
                    if steps.is_empty()
                        || steps.len() > 4
                        || steps.iter().filter(|s| s.kind == "create").count() > 2
                        || steps.len() > 1 && steps.iter().any(|s| s.kind == "delete")
                    {
                        return Err(content.error("transaction step limit"));
                    }
                }
                _ => return Err(syn::Error::new(option.span(), "unknown action option")),
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        let (redirect, redirect_source) =
            redirect.ok_or_else(|| input.error("actions require redirect"))?;
        if steps.is_empty() {
            return Err(input.error("actions require transaction"));
        }
        if inspect.is_some() != !inspection_fields.is_empty() {
            return Err(input.error("inspection requires inspect and inspect_fields"));
        }
        Ok(Self {
            inputs,
            steps,
            identity,
            policy: rules.ok_or_else(|| input.error("explicit allow required"))?,
            redirect,
            redirect_source,
            redirect_reference,
            inspect,
            inspection_fields,
            version,
        })
    }
}

fn expand_transaction(
    declaration: TransactionDeclaration,
    item: syn::ItemStruct,
) -> syn::Result<Tokens> {
    use std::collections::{BTreeMap, BTreeSet};
    marker(&item)?;
    let name = &item.ident;
    let vis = &item.vis;
    let input_name = format_ident!("{name}Input");
    let controls_name = format_ident!("{name}Controls");
    let original_name = format_ident!("{name}Original");
    let names: Vec<_> = declaration.inputs.iter().map(|i| &i.name).collect();
    let types: Vec<_> = declaration.inputs.iter().map(|i| &i.ty).collect();
    let keys: Vec<_> = names
        .iter()
        .map(|n| LitStr::new(&n.to_string(), n.span()))
        .collect();
    let mut schemas = Vec::new();
    for input in &declaration.inputs {
        let ty = &input.ty;
        let key = input.name.to_string();
        let label = action_label(&key);
        let mut kind = quote!(<#ty as ::noxide::FieldValue>::kind());
        let mut max_bytes = quote!(match <#ty as ::noxide::FieldValue>::kind() {
            ::noxide::__private::FieldKind::Boolean => 5,
            ::noxide::__private::FieldKind::Integer { .. } => 20,
            ::noxide::__private::FieldKind::Account { .. } => 43,
            ::noxide::__private::FieldKind::Choice { variants } => variants.iter().map(|v| v.key.len() as u32).max().unwrap_or(1),
            _ => 4096,
        });
        if let Some(bound) = &input.bound {
            match bound {
                syn::Expr::Range(range)
                    if matches!(range.limits, syn::RangeLimits::Closed(_))
                        && range.start.is_some()
                        && range.end.is_some() =>
                {
                    let min = range.start.as_ref().unwrap();
                    let max = range.end.as_ref().unwrap();
                    if !integer_literal(min) || !integer_literal(max) {
                        return Err(syn::Error::new(
                            bound.span(),
                            "integer input bounds require literals",
                        ));
                    }
                    kind = quote!({ assert!(matches!(<#ty as ::noxide::FieldValue>::kind(), ::noxide::__private::FieldKind::Integer { .. }), "integer bounds require integer input"); ::noxide::__private::FieldKind::Integer { min: Some(#min), max: Some(#max) } });
                    max_bytes = quote!(20u32);
                }
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(bytes),
                    ..
                }) => {
                    let bound: u32 = bytes.base10_parse()?;
                    if bound == 0 || bound > 4096 {
                        return Err(syn::Error::new(
                            bytes.span(),
                            "input byte bound must be 1..=4096",
                        ));
                    }
                    max_bytes = quote!(#bound);
                }
                _ => {
                    return Err(syn::Error::new(
                        bound.span(),
                        "expected inclusive integer range or byte bound",
                    ));
                }
            }
        }
        schemas.push(quote!(::noxide::__private::Input { name: #key.into(), label: #label.into(), kind: #kind, optional: <#ty as ::noxide::FieldValue>::OPTIONAL, max_bytes: #max_bytes }));
    }
    let declared: BTreeSet<_> = names.iter().map(|n| n.to_string()).collect();
    let mut created = BTreeMap::new();
    let mut all_names = BTreeSet::new();
    let mut steps = Vec::new();
    let mut operations = Vec::new();
    let resources: Vec<_> = declaration.steps.iter().map(|s| &s.resource).collect();
    let primary = resources[0];
    for (index, step) in declaration.steps.iter().enumerate() {
        let index = index as u8;
        let resource = &step.resource;
        let operation_id = quote!(::noxide::stable_id(concat!(
            "mutation:",
            module_path!(),
            "::",
            stringify!(#name),
            ":",
            stringify!(#index)
        )));
        let target = if step.kind == "create" {
            quote!(::noxide::__private::Target::None)
        } else {
            quote!(::noxide::__private::Target::Signed)
        };
        let kind = match step.kind.to_string().as_str() {
            "create" => quote!(::noxide::__private::OperationKind::Create),
            "update" => quote!(::noxide::__private::OperationKind::Update),
            _ => quote!(::noxide::__private::OperationKind::Delete),
        };
        let mut assignments = Vec::new();
        let mut seen = BTreeSet::new();
        for (field, change) in &step.assignments {
            if !seen.insert(field.to_string()) {
                return Err(syn::Error::new(field.span(), "duplicate assignment"));
            }
            let hash = stable_id(&field.to_string());
            let value = match change {
                DeclaredChange::Set(expr) => {
                    let value = match expr {
                        syn::Expr::Path(path) if path.path.get_ident().is_some() => {
                            let ident = path.path.get_ident().unwrap();
                            let key = ident.to_string();
                            if key == "target" {
                                quote!(::noxide::__private::Value::SignedTarget)
                            } else if declared.contains(&key) {
                                quote!(::noxide::__private::Value::Input(#key.into()))
                            } else if let Some(previous) = created.get(&key) {
                                quote!(::noxide::__private::Value::Created(#previous))
                            } else {
                                return Err(syn::Error::new(
                                    ident.span(),
                                    "expected declared input, target, or earlier create",
                                ));
                            }
                        }
                        syn::Expr::Lit(lit) => match &lit.lit {
                            syn::Lit::Str(value) => {
                                quote!(::noxide::__private::Value::Constant(#value.into()))
                            }
                            syn::Lit::Int(_) | syn::Lit::Bool(_) => {
                                quote!(::noxide::__private::Value::Constant((#expr).to_string()))
                            }
                            _ => return Err(syn::Error::new(expr.span(), "unsupported constant")),
                        },
                        _ if integer_literal(expr) => {
                            quote!(::noxide::__private::Value::Constant((#expr).to_string()))
                        }
                        _ => {
                            return Err(syn::Error::new(
                                expr.span(),
                                "assignments require an input, constant, target, or earlier create",
                            ));
                        }
                    };
                    quote!(::noxide::__private::Change::Set(#value))
                }
                DeclaredChange::Adjustment {
                    increase,
                    by,
                    input,
                    message,
                } => {
                    let by = by.to_string();
                    let input = input.to_string();
                    if !declared.contains(&by) || !declared.contains(&input) {
                        return Err(syn::Error::new(
                            field.span(),
                            "guard requires declared inputs",
                        ));
                    }
                    let rejection = quote!(::noxide::__private::GuardRejection { input: #input.into(), message: #message.into() });
                    if *increase {
                        quote!(::noxide::__private::Change::Increase { by: #by.into(), rejection: #rejection })
                    } else {
                        quote!(::noxide::__private::Change::Decrease { by: #by.into(), rejection: #rejection })
                    }
                }
            };
            assignments.push(quote!(::noxide::__private::Assignment { field: <#resource as ::noxide::FieldSpec<#hash>>::KEY.into(), change: #value }));
        }
        let bind = if let Some(eligible) = &step.eligible {
            quote!(Some(::noxide::__private::Bind { field: <#resource as ::noxide::ResourceType>::definition().fields.into_iter().find(|f| matches!(f.kind, ::noxide::__private::FieldKind::Reference { .. })).expect("eligibility requires reference").name, eligible: <#eligible as ::noxide::QueryType>::operation().id }))
        } else {
            quote!(None)
        };
        let policy = policy_tokens(&declaration.policy, resource);
        operations.push(quote!(::noxide::__private::Operation { bind: #bind, scope: None, via: None, filter: Vec::new(), disclose: Vec::new(), list: None, id: #operation_id, resource: <#resource as ::noxide::ResourceType>::definition().id, kind: #kind, policy: #policy, visibility: None, fields: None }));
        steps.push(quote!(::noxide::__private::Step { operation: #operation_id, target: #target, assign: vec![#(#assignments),*] }));
        if let Some(step_name) = &step.name {
            let key = step_name.to_string();
            if key == "target" || declared.contains(&key) || !all_names.insert(key.clone()) {
                return Err(syn::Error::new(
                    step_name.span(),
                    "duplicate or reserved step name",
                ));
            }
            if step.kind == "create" {
                created.insert(key, index);
            }
        }
    }
    let eligibility_operations = declaration
        .steps
        .iter()
        .filter_map(|step| step.eligible.as_ref())
        .map(|query| quote!(<#query as ::noxide::QueryType>::operation()));
    let redirect = &declaration.redirect;
    let source_key = declaration.redirect_source.to_string();
    let source = if source_key == "target" {
        if declaration.redirect_reference.is_some() {
            return Err(syn::Error::new(
                declaration.redirect_source.span(),
                "reference navigation requires a step",
            ));
        }
        quote!(::noxide::__private::RedirectSource::Signed)
    } else {
        let index = declaration
            .steps
            .iter()
            .position(|s| {
                s.name
                    .as_ref()
                    .is_some_and(|name| name == &declaration.redirect_source)
            })
            .ok_or_else(|| {
                syn::Error::new(
                    declaration.redirect_source.span(),
                    "redirect requires target or named step",
                )
            })? as u8;
        if let Some(field) = &declaration.redirect_reference {
            let hash = stable_id(&field.to_string());
            let resource = &declaration.steps[index as usize].resource;
            quote!(::noxide::__private::RedirectSource::Reference { step: #index, field: <#resource as ::noxide::FieldSpec<#hash>>::KEY.into() })
        } else {
            quote!(::noxide::__private::RedirectSource::Step(#index))
        }
    };
    let revision = if declaration.identity {
        quote!(::noxide::__private::Revision::Identity)
    } else {
        quote!(::noxide::__private::Revision::Exact)
    };
    let version = declaration.version;
    let label = action_label(&name.to_string());
    let inspection_operation = if let Some(query) = &declaration.inspect {
        quote!(Some(<#query as ::noxide::QueryType>::operation()))
    } else {
        quote!(None)
    };
    let mut original = Tokens::new();
    let (original_type, inspection) = if let Some(query) = &declaration.inspect {
        let fields = &declaration.inspection_fields;
        let hashes: Vec<_> = fields.iter().map(|f| stable_id(&f.to_string())).collect();
        let resource = quote!(<#query as ::noxide::QueryType>::Resource);
        original = quote! {
            #vis struct #original_name { #(pub #fields: <#resource as ::noxide::FieldSpec<#hashes>>::Value),* }
            impl ::noxide::ActionInput for #original_name { fn from_fields(fields: &::noxide::Fields) -> Self { Self { #(#fields: <<#resource as ::noxide::FieldSpec<#hashes>>::Value as ::noxide::FieldValue>::decode(&fields[<#resource as ::noxide::FieldSpec<#hashes>>::KEY])),* } } }
        };
        (
            quote!(#original_name),
            quote!(Some(::noxide::__private::Inspection { operation: <#query as ::noxide::QueryType>::operation().id, fields: vec![#(<#resource as ::noxide::FieldSpec<#hashes>>::KEY.into()),*] })),
        )
    } else {
        (quote!(()), quote!(None))
    };
    Ok(quote! {
        #item
        #original
        #vis struct #input_name { #(pub #names: #types),* }
        #vis struct #controls_name { #(pub #names: ::noxide::ControlField<#types>),* }
        impl ::noxide::ActionInput for #input_name { fn from_fields(fields: &::noxide::Fields) -> Self { Self { #(#names: <#types as ::noxide::FieldValue>::decode(&fields[#keys])),* } } }
        impl #name { #(#[allow(non_upper_case_globals)] pub const #names: ::noxide::Field<Self, #types> = ::noxide::Field::new(#keys);)* }
        impl ::noxide::ActionType for #name {
            type Resource = #primary;
            type Input = #input_name;
            type Original = #original_type;
            type Controls = #controls_name;
            fn controls() -> Self::Controls { #controls_name { #(#names: ::noxide::ControlField::new(#keys)),* } }
            fn resources() -> Vec<::noxide::__private::Resource> { vec![#(<#resources as ::noxide::ResourceType>::definition()),*] }
            fn operations() -> Vec<::noxide::__private::Operation> { vec![#(#operations,)* #(#eligibility_operations),*] }
            fn inspection() -> Option<::noxide::__private::Operation> { #inspection_operation }
            fn definition() -> ::noxide::__private::Action { ::noxide::__private::Action { id: ::noxide::stable_id(concat!("action:", module_path!(), "::", stringify!(#name))), version: #version, name: #label.into(), layout: vec![], redirect: ::noxide::__private::Redirect { route: #redirect::id(), source: #source }, inspect: #inspection, inputs: vec![#(#schemas),*], revision: #revision, steps: vec![#(#steps),*] } }
        }
    })
}

fn integer_literal(expr: &syn::Expr) -> bool {
    matches!(
        expr,
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(_),
            ..
        })
    ) || matches!(expr, syn::Expr::Unary(syn::ExprUnary { op: syn::UnOp::Neg(_), expr, .. }) if matches!(&**expr, syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(_), .. })))
}

#[cfg(test)]
mod transaction_tests {
    use super::*;

    #[test]
    fn transaction_syntax_rejects_create_adjustments_and_extra_authority() {
        for source in [
            "inputs(q: i64 = 1..=10), transaction(create(Product, decrease(stock, by = q, reject(q, \"No\")))), allow = owner, redirect = show(target)",
            "inputs(q: i64 = 1..=10), transaction(update(Product, selected, set(stock = q))), allow = owner, redirect = show(target)",
            "inputs(q: i64 = 1..=10), transaction(delete(Product, target), update(Product, target, set(stock = q))), allow = owner, redirect = show(target)",
            "inputs(q: i64 = 1..=10), transaction(update(Product, target, set(stock = q + 1))), allow = owner, redirect = show(target)",
            "inputs(q: i64 = 1..=10), transaction(first = create(Note, set(order = later)), later = create(Order, set(quantity = q))), allow = owner, redirect = show(first)",
        ] {
            let result = syn::parse_str::<ActionDeclaration>(source).and_then(|declaration| {
                expand_declared_action(
                    declaration,
                    syn::parse_quote!(
                        struct Change;
                    ),
                )
            });
            assert!(result.is_err(), "{source}");
        }
    }
}
