use crate::syntax::key;
use proc_macro2::TokenStream as Tokens;
use quote::quote;
use syn::{Ident, LitStr, Token, parenthesized, parse::ParseStream};

#[derive(Clone)]
pub(crate) enum PolicyAtom {
    Public,
    Capability,
    Owner,
    Tenant,
    Role(LitStr, bool),
}

pub(crate) fn policy(input: ParseStream<'_>) -> syn::Result<Vec<Vec<PolicyAtom>>> {
    let name: Ident = input.parse()?;
    match name.to_string().as_str() {
        "public" => Ok(vec![vec![PolicyAtom::Public]]),
        "capability" => Ok(vec![vec![PolicyAtom::Capability]]),
        "owner" => Ok(vec![vec![PolicyAtom::Owner]]),
        "same_tenant" => Ok(vec![vec![PolicyAtom::Tenant]]),
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
            "expected owner, same_tenant, role, tenant_role, all, or any",
        )),
    }
}

pub(crate) fn policy_tokens(rules: &[Vec<PolicyAtom>]) -> Tokens {
    let rules = rules.iter().map(|rule| {
        let predicates = rule.iter().map(|atom| match atom {
            PolicyAtom::Public => quote!(::noxide::__private::Predicate::Public),
            PolicyAtom::Capability => quote!(::noxide::__private::Predicate::Capability),
            PolicyAtom::Owner => quote!(::noxide::__private::Predicate::Owner),
            PolicyAtom::Tenant => quote!(::noxide::__private::Predicate::SameTenant),
            PolicyAtom::Role(name, tenant_scoped) => quote!(::noxide::__private::Predicate::Role { name: #name.into(), tenant_scoped: #tenant_scoped }),
        });
        quote!(vec![#(#predicates),*])
    });
    quote!(::noxide::__private::Policy {
        any: vec![#(#rules),*]
    })
}
