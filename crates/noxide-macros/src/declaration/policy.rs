use crate::syntax::key;
use proc_macro2::TokenStream as Tokens;
use quote::quote;
use syn::{Expr, Ident, LitStr, Token, Type, parenthesized, parse::ParseStream};

#[derive(Clone)]
pub(crate) enum PolicyAtom {
    Public,
    Capability,
    Owner,
    PrincipalIs(Ident),
    Tenant,
    Service(LitStr),
    Role(LitStr, bool),
    ExistsRelated(Box<RelatedDeclaration>),
}

#[derive(Clone)]
pub(crate) struct RelatedDeclaration {
    resource: Type,
    reference: Ident,
    target: Option<Ident>,
    account: Ident,
    conditions: Vec<(Ident, Expr)>,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn policy(input: ParseStream<'_>) -> syn::Result<Vec<Vec<PolicyAtom>>> {
    let name: Ident = input.parse()?;
    match name.to_string().as_str() {
        "public" => Ok(vec![vec![PolicyAtom::Public]]),
        "capability" => Ok(vec![vec![PolicyAtom::Capability]]),
        "principal_is" => {
            let content;
            parenthesized!(content in input);
            let field: Ident = content.parse()?;
            if !content.is_empty() {
                return Err(content.error("expected one account field"));
            }
            Ok(vec![vec![PolicyAtom::PrincipalIs(field)]])
        }
        "owner" => Ok(vec![vec![PolicyAtom::Owner]]),
        "same_tenant" => Ok(vec![vec![PolicyAtom::Tenant]]),
        "service" => {
            let content;
            parenthesized!(content in input);
            let worker = key(content.parse()?)?;
            if !content.is_empty() {
                return Err(content.error("expected one worker identity"));
            }
            Ok(vec![vec![PolicyAtom::Service(worker)]])
        }
        "exists_related" => {
            let content;
            parenthesized!(content in input);
            Ok(vec![vec![PolicyAtom::ExistsRelated(Box::new(related(
                &content,
            )?))]])
        }
        "role" | "tenant_role" => {
            let content;
            parenthesized!(content in input);
            let role = key(content.parse()?)?;
            if !content.is_empty() {
                return Err(content.error("expected one role name"));
            }
            Ok(vec![vec![PolicyAtom::Role(role, name == "tenant_role")]])
        }
        "all" | "any" => {
            let content;
            parenthesized!(content in input);
            if content.is_empty() {
                return Err(content.error("policy groups cannot be empty"));
            }
            let conjunction = name == "all";
            let mut rules = if conjunction {
                vec![Vec::new()]
            } else {
                Vec::new()
            };
            while !content.is_empty() {
                let term = policy(&content)?;
                if term
                    .iter()
                    .flatten()
                    .any(|p| matches!(p, PolicyAtom::Public | PolicyAtom::Capability))
                {
                    return Err(syn::Error::new(
                        name.span(),
                        "public or capability cannot appear inside any or all",
                    ));
                }
                if conjunction {
                    let mut combined = Vec::new();
                    for left in &rules {
                        for right in &term {
                            if combined.len() == 8 || left.len() + right.len() > 4 {
                                return Err(syn::Error::new(
                                    name.span(),
                                    "policy limit: at most 8 alternatives of 4 predicates",
                                ));
                            }
                            let mut rule = left.clone();
                            rule.extend(right.clone());
                            combined.push(rule);
                        }
                    }
                    rules = combined;
                } else {
                    rules.extend(term);
                    if rules.len() > 8 {
                        return Err(syn::Error::new(name.span(), "policy alternative limit"));
                    }
                }
                if !content.is_empty() {
                    content.parse::<Token![,]>()?;
                }
            }
            Ok(rules)
        }
        _ => Err(syn::Error::new(
            name.span(),
            "expected owner, same_tenant, service, role, tenant_role, all, or any",
        )),
    }
    .and_then(|rules| {
        if rules
            .iter()
            .flatten()
            .filter(|p| matches!(p, PolicyAtom::ExistsRelated(_)))
            .count()
            > 2
        {
            Err(syn::Error::new(
                name.span(),
                "at most two membership predicates per operation",
            ))
        } else {
            Ok(rules)
        }
    })
}

fn related(input: ParseStream<'_>) -> syn::Result<RelatedDeclaration> {
    let resource = input.parse::<Type>()?;
    let mut reference = None;
    let mut target = None;
    let mut account = None;
    let mut conditions = None;
    while !input.is_empty() {
        input.parse::<Token![,]>()?;
        let option = input.parse::<Ident>()?;
        if option == "conditions" && conditions.is_none() {
            let content;
            parenthesized!(content in input);
            let mut predicates = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            while !content.is_empty() {
                let field = content.parse::<Ident>()?;
                content.parse::<Token![=]>()?;
                let value = content.parse::<Expr>()?;
                if predicates.len() == 4
                    || !seen.insert(field.to_string())
                    || !matches!(
                        &value,
                        Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Bool(_),
                            ..
                        }) | Expr::Path(_)
                    )
                {
                    return Err(content.error(
                        "conditions require at most four distinct Boolean/Choice literals",
                    ));
                }
                predicates.push((field, value));
                if !content.is_empty() {
                    content.parse::<Token![,]>()?;
                }
            }
            conditions = Some(predicates);
        } else {
            input.parse::<Token![=]>()?;
            if option == "reference" && reference.is_none() {
                reference = Some(input.parse()?);
            } else if option == "account" && account.is_none() {
                account = Some(input.parse()?);
            } else if option == "target" && target.is_none() {
                let kind = input.parse::<Ident>()?;
                let field = if kind == "self_record" {
                    None
                } else if kind == "reference" {
                    let content;
                    parenthesized!(content in input);
                    let field = content.parse()?;
                    if !content.is_empty() {
                        return Err(content.error("expected one protected reference"));
                    }
                    Some(field)
                } else {
                    return Err(syn::Error::new(
                        kind.span(),
                        "expected self_record or reference(field)",
                    ));
                };
                target = Some(field);
            } else {
                return Err(syn::Error::new(
                    option.span(),
                    "unknown or duplicate membership option",
                ));
            }
        }
    }
    Ok(RelatedDeclaration {
        resource,
        reference: reference.ok_or_else(|| input.error("membership reference is required"))?,
        target: target.ok_or_else(|| input.error("membership target is required"))?,
        account: account.ok_or_else(|| input.error("membership account is required"))?,
        conditions: conditions.unwrap_or_default(),
    })
}

/// Additional schema metadata required by membership predicates. It grants no
/// membership read/list operation. Action lowering uses this helper too.
pub(crate) fn resource_tokens(rules: &[Vec<PolicyAtom>]) -> Tokens {
    let resources = rules.iter().flatten().filter_map(|atom| match atom {
        PolicyAtom::ExistsRelated(related) => {
            let resource = &related.resource;
            Some(quote!(<#resource as ::noxide::ResourceType>::definition()))
        }
        _ => None,
    });
    quote!(vec![#(#resources),*])
}

pub(crate) fn policy_tokens(rules: &[Vec<PolicyAtom>], resource: &syn::Type) -> Tokens {
    let rules = rules.iter().map(|rule| {
        let predicates = rule.iter().map(|atom| match atom {
            PolicyAtom::Public => quote!(::noxide::__private::Predicate::Public),
            PolicyAtom::Capability => quote!(::noxide::__private::Predicate::Capability),
            PolicyAtom::PrincipalIs(field) => {
                let hash = crate::syntax::stable_id(&field.to_string());
                quote!({
                    fn check<T: ::noxide::FieldSpec<#hash, Value = ::noxide::AccountId>>() {}
                    check::<#resource>();
                    ::noxide::__private::Predicate::PrincipalIs { field: <#resource as ::noxide::FieldSpec<#hash>>::KEY.into() }
                })
            }
            PolicyAtom::Owner => quote!(::noxide::__private::Predicate::Owner),
            PolicyAtom::Tenant => quote!(::noxide::__private::Predicate::SameTenant),
            PolicyAtom::Service(worker) => quote!(::noxide::__private::Predicate::Service { worker: #worker.into() }),
            PolicyAtom::Role(name, tenant_scoped) => quote!(::noxide::__private::Predicate::Role { name: #name.into(), tenant_scoped: #tenant_scoped }),
            PolicyAtom::ExistsRelated(related) => related_tokens(related, resource),
        });
        quote!(vec![#(#predicates),*])
    });
    quote!(::noxide::__private::Policy {
        any: vec![#(#rules),*]
    })
}

fn related_tokens(related: &RelatedDeclaration, protected: &Type) -> Tokens {
    let membership = &related.resource;
    let reference = crate::syntax::stable_id(&related.reference.to_string());
    let account = crate::syntax::stable_id(&related.account.to_string());
    let target = if let Some(field) = &related.target {
        let hash = crate::syntax::stable_id(&field.to_string());
        quote!({
            const _: () = assert!(<<#protected as ::noxide::FieldSpec<#hash>>::Value as ::noxide::FieldValue>::REFERENCE, "membership target requires an immutable reference");
            fn check<T: ::noxide::FieldSpec<#reference, Value = <#protected as ::noxide::FieldSpec<#hash>>::Value>>() {}
            check::<#membership>();
            ::noxide::__private::membership::RelatedTarget::Reference { field: <#protected as ::noxide::FieldSpec<#hash>>::KEY.into() }
        })
    } else {
        quote!({
            fn check<T: ::noxide::FieldSpec<#reference, Value = ::noxide::Id<#protected>>>() {}
            check::<#membership>();
            ::noxide::__private::membership::RelatedTarget::SelfRecord
        })
    };
    let conditions = related.conditions.iter().map(|(field, value)| {
        let hash = crate::syntax::stable_id(&field.to_string());
        quote!({
            const _: () = assert!(<<#membership as ::noxide::FieldSpec<#hash>>::Value as ::noxide::FieldValue>::FILTERABLE, "membership conditions require Boolean/Choice");
            let value: &<#membership as ::noxide::FieldSpec<#hash>>::Value = &(#value);
            let encoded = ::noxide::FieldValue::encode(value);
            let literal = match <<#membership as ::noxide::FieldSpec<#hash>>::Value as ::noxide::FieldValue>::kind() {
                ::noxide::FieldKind::Boolean => ::noxide::__private::membership::MembershipLiteral::Boolean(encoded.parse().expect("canonical Boolean")),
                ::noxide::FieldKind::Choice { .. } => ::noxide::__private::membership::MembershipLiteral::Choice(encoded),
                _ => unreachable!("membership condition type"),
            };
            (<#membership as ::noxide::FieldSpec<#hash>>::KEY.into(), literal)
        })
    });
    quote!({
        fn check<T: ::noxide::FieldSpec<#account, Value = ::noxide::AccountId>>() {}
        check::<#membership>();
        ::noxide::__private::Predicate::ExistsRelated(::noxide::__private::membership::ExistsRelated {
            resource: <#membership as ::noxide::ResourceType>::KEY.into(),
            reference: <#membership as ::noxide::FieldSpec<#reference>>::KEY.into(),
            target: #target, account: <#membership as ::noxide::FieldSpec<#account>>::KEY.into(),
            conditions: ::std::collections::BTreeMap::from([#(#conditions),*]),
        })
    })
}

#[cfg(test)]
mod membership_tests {
    use super::*;
    use syn::parse::Parser;

    #[test]
    fn membership_declaration_rejects_unbounded_or_dynamic_shapes() {
        for source in [
            "exists_related(Member, reference = workspace, account = account)",
            "exists_related(Member, reference = workspace, target = input(workspace), account = account)",
            "exists_related(Member, reference = workspace, target = self_record, account = account, conditions(role = input(role)))",
            "exists_related(Member, reference = workspace, target = self_record, account = account, conditions(active = true, active = false))",
            "exists_related(Member, reference = workspace, target = self_record, account = account, conditions(a=true,b=true,c=true,d=true,e=true))",
            "all(exists_related(M, reference=r,target=self_record,account=a),exists_related(M, reference=r,target=self_record,account=a),exists_related(M, reference=r,target=self_record,account=a))",
        ] {
            assert!(policy.parse_str(source).is_err(), "{source}");
        }
        assert!(policy.parse_str("all(same_tenant, exists_related(M, reference=r,target=reference(workspace),account=a,conditions(role=Role::Admin)))").is_ok());
    }
}
