use crate::declaration::page::generic_argument;
use crate::syntax::{
    key, reject_generics, required_key, stable_id, text_type, validate_field_type,
};
use proc_macro2::TokenStream as Tokens;
use quote::quote;
use std::collections::BTreeSet;
use syn::{
    Data, DeriveInput, Expr, Fields, Ident, LitInt, LitStr, Token, parenthesized, spanned::Spanned,
};

pub(crate) fn expand_resource(input: DeriveInput) -> syn::Result<Tokens> {
    reject_generics(&input)?;
    let persistent_key = required_key(&input.attrs, "resource")?;
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(
            input.span(),
            "Resource requires a named struct",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new(
            data.fields.span(),
            "Resource requires named fields",
        ));
    };
    let mut definitions = Vec::new();
    let mut decoding = Vec::new();
    let mut specs = Vec::new();
    let mut handles = Vec::new();
    let mut keys = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let mut identity = false;
    let mut id_name = None;
    let mut accounts = 0;
    let mut references = 0;
    let mut gate = quote!(None);
    let mut gate_field = 0u32;
    let name = &input.ident;
    for field in &fields.named {
        let rust_name = field.ident.as_ref().expect("named field");
        let ty = &field.ty;
        let ids: Vec<_> = field
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("id"))
            .collect();
        if !ids.is_empty() {
            if identity || ids.len() != 1 || !matches!(ids[0].meta, syn::Meta::Path(_)) {
                return Err(syn::Error::new(
                    field.span(),
                    "Resource requires exactly one #[id] field",
                ));
            }
            if field.attrs.iter().any(|attr| attr.path().is_ident("field")) {
                return Err(syn::Error::new(
                    field.span(),
                    "the host-generated id cannot be a stored application field",
                ));
            }
            identity = true;
            id_name = Some(rust_name);
            decoding.push(quote!(#rust_name: ::noxide::Id::<Self>::new(record.id)));
            continue;
        }
        let parent = generic_argument(ty)
            .ok()
            .filter(|(kind, _)| *kind == "Id")
            .map(|(_, ty)| ty);
        if parent.is_some() {
            references += 1;
            if references > 1 {
                return Err(syn::Error::new(
                    ty.span(),
                    "at most one reference field per resource",
                ));
            }
        }
        if parent.is_none() {
            validate_field_type(ty, false)?;
        }
        let account = matches!(ty, syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "AccountId"));
        if account {
            accounts += 1;
            if accounts > 4 {
                return Err(syn::Error::new(
                    ty.span(),
                    "at most four account fields per resource",
                ));
            }
        }
        let mut scope = false;
        let mut initial = None;
        let mut visible = None;
        let mut create_when = None;
        let mut field_key = None;
        let mut label = None;
        let mut maximum = None;
        let mut min = None;
        let mut max = None;
        let attrs: Vec<_> = field
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("field"))
            .collect();
        if attrs.len() > 1 || (attrs.is_empty() && parent.is_none()) {
            return Err(syn::Error::new(
                field.span(),
                "stored fields require #[field(...)]",
            ));
        }
        if let Some(attr) = attrs.first() {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("scope") {
                    let value: Ident = meta.value()?.parse()?;
                    if scope || !account || value != "same_tenant" {
                        return Err(meta.error("account fields require scope = same_tenant"));
                    }
                    scope = true;
                    return Ok(());
                }
                if meta.path.is_ident("initial") {
                    if initial.is_some() {
                        return Err(meta.error("duplicate initial value"));
                    }
                    if quote!(#ty).to_string() != "bool" {
                        return Err(meta.error("initial requires a non-optional bool field"));
                    }
                    let value: syn::LitBool = meta.value()?.parse()?;
                    initial = Some(value);
                    return Ok(());
                }
                if meta.path.is_ident("visible") || meta.path.is_ident("create_when") {
                    let content;
                    parenthesized!(content in meta.input);
                    let name: Ident = content.parse()?;
                    content.parse::<Token![=]>()?;
                    let value: Expr = content.parse()?;
                    if !content.is_empty() {
                        return Err(content.error("expected one parent predicate"));
                    }
                    let slot = if meta.path.is_ident("visible") {
                        &mut visible
                    } else {
                        &mut create_when
                    };
                    if slot.replace((name, value)).is_some() {
                        return Err(meta.error("duplicate parent predicate"));
                    }
                } else if meta.path.is_ident("key") && field_key.is_none() {
                    field_key = Some(key(meta.value()?.parse()?)?);
                } else if meta.path.is_ident("label") && label.is_none() {
                    label = Some(meta.value()?.parse::<LitStr>()?);
                } else if meta.path.is_ident("max_bytes") && maximum.is_none() {
                    maximum = Some(meta.value()?.parse::<LitInt>()?);
                } else if meta.path.is_ident("min") && min.is_none() {
                    min = Some(meta.value()?.parse::<Expr>()?);
                } else if meta.path.is_ident("max") && max.is_none() {
                    max = Some(meta.value()?.parse::<Expr>()?);
                } else {
                    return Err(meta.error("unknown or duplicate field option"));
                }
                Ok(())
            })?;
        }
        if account && !scope {
            return Err(syn::Error::new(
                ty.span(),
                "AccountId requires scope = same_tenant",
            ));
        }
        let field_key = key(
            field_key.unwrap_or_else(|| LitStr::new(&rust_name.to_string(), rust_name.span()))
        )?;
        if !keys.insert(field_key.value()) {
            return Err(syn::Error::new(
                field_key.span(),
                "duplicate persistent field key",
            ));
        }
        if text_type(ty) && maximum.is_none() {
            return Err(syn::Error::new(
                ty.span(),
                "text fields require an explicit max_bytes bound",
            ));
        }
        let maximum = maximum.unwrap_or_else(|| LitInt::new("64", field.span()));
        let maximum_value = maximum.base10_parse::<u32>()?;
        if maximum_value == 0 || maximum_value > 4096 {
            return Err(syn::Error::new(
                maximum.span(),
                "max_bytes must be between 1 and 4096",
            ));
        }
        let label = label.unwrap_or_else(|| {
            let mut text = rust_name.to_string().replace('_', " ");
            if let Some(first) = text.get_mut(..1) {
                first.make_ascii_uppercase();
            }
            LitStr::new(&text, rust_name.span())
        });
        if label.value().is_empty()
            || label.value().len() > 128
            || label.value().chars().any(char::is_control)
        {
            return Err(syn::Error::new(
                label.span(),
                "labels must contain 1 to 128 bytes without control characters",
            ));
        }
        let bounds = if account {
            if min.is_some() || max.is_some() || visible.is_some() || create_when.is_some() {
                return Err(syn::Error::new(
                    ty.span(),
                    "account fields accept only scope and presentation options",
                ));
            }
            quote!(::noxide::FieldKind::Account {
                scope: ::noxide::__private::AccountScope::SameTenant
            })
        } else if let Some(parent) = parent {
            if min.is_some() || max.is_some() || initial.is_some() {
                return Err(syn::Error::new(
                    ty.span(),
                    "references cannot have initial values or numeric bounds",
                ));
            }
            match (visible, create_when) {
                (Some((vf, vv)), Some((wf, wv))) => {
                    gate_field = stable_id(&rust_name.to_string());
                    let vh = stable_id(&vf.to_string());
                    let wh = stable_id(&wf.to_string());
                    gate = quote!(Some(::noxide::__private::Gate {
                        field: #field_key.into(),
                        visible: ::noxide::__private::Visibility {
                            field: <#parent as ::noxide::FieldSpec<#vh>>::KEY.into(),
                            equals: ::noxide::FieldValue::encode(&#vv),
                        },
                        create_when: ::noxide::__private::Visibility {
                            field: <#parent as ::noxide::FieldSpec<#wh>>::KEY.into(),
                            equals: ::noxide::FieldValue::encode(&#wv),
                        },
                    }));
                }
                (None, None) => {}
                _ => {
                    return Err(syn::Error::new(
                        ty.span(),
                        "a gate requires both visible(...) and create_when(...)",
                    ));
                }
            }
            quote!(::noxide::FieldKind::Reference {
                resource: <#parent as ::noxide::ResourceType>::KEY.into(),
            })
        } else if visible.is_some() || create_when.is_some() {
            return Err(syn::Error::new(
                ty.span(),
                "gate predicates require Id<Resource>",
            ));
        } else if min.is_some() || max.is_some() {
            let lower = min.map_or_else(|| quote!(None), |v| quote!(Some(#v)));
            let upper = max.map_or_else(|| quote!(None), |v| quote!(Some(#v)));
            quote! {
                match <#ty as ::noxide::FieldValue>::kind() {
                    ::noxide::FieldKind::Integer { .. } => ::noxide::FieldKind::Integer { min: #lower, max: #upper },
                    _ => panic!("min/max bounds require an integer field"),
                }
            }
        } else {
            quote!(<#ty as ::noxide::FieldValue>::kind())
        };
        let initial = match initial {
            Some(value) => {
                let encoded = value.value.to_string();
                if encoded.len() > maximum_value as usize {
                    return Err(syn::Error::new(value.span(), "initial exceeds max_bytes"));
                }
                quote!(Some(#encoded.into()))
            }
            None => quote!(None),
        };
        definitions.push(quote! {
            ::noxide::__private::TextField {
                name: #field_key.into(), label: #label.into(), max_bytes: #maximum,
                initial: #initial, kind: { #bounds }, optional: <#ty as ::noxide::FieldValue>::OPTIONAL,
            }
        });
        decoding.push(quote! {
            #rust_name: <#ty as ::noxide::FieldValue>::decode(record.fields.get(#field_key).expect("host resource field"))
        });
        let hash = stable_id(&rust_name.to_string());
        if !hashes.insert(hash) {
            return Err(syn::Error::new(
                rust_name.span(),
                "field identifier collision",
            ));
        }
        specs.push(quote! {
            impl ::noxide::FieldSpec<#hash> for #name {
                type Value = #ty;
                const KEY: &'static str = #field_key;
            }
        });
        handles.push(quote! {
            #[allow(non_upper_case_globals)]
            pub const #rust_name: ::noxide::Field<Self, #ty> = ::noxide::Field::new(#field_key);
        });
    }
    if !identity {
        return Err(syn::Error::new(
            name.span(),
            "Resource requires one #[id] field",
        ));
    }
    if definitions.is_empty() || definitions.len() > 8 {
        return Err(syn::Error::new(
            name.span(),
            "Resource requires between 1 and 8 stored fields",
        ));
    }
    let id_name = id_name.expect("checked id");
    Ok(quote! {
        impl ::noxide::ResourceType for #name {
            const GATE_FIELD: u32 = #gate_field;
            fn record_id(&self) -> u64 { self.#id_name.get() }
            const KEY: &'static str = #persistent_key;
            fn definition() -> ::noxide::__private::Resource {
                ::noxide::__private::Resource {
                    id: ::noxide::stable_id(<Self as ::noxide::ResourceType>::KEY), name: <Self as ::noxide::ResourceType>::KEY.into(), fields: vec![#(#definitions),*], gate: #gate,
                }
            }
            fn from_record(record: ::noxide::__private::Record) -> Self {
                assert_eq!(record.resource, ::noxide::stable_id(<Self as ::noxide::ResourceType>::KEY), "host resource type");
                Self { #(#decoding),* }
            }
        }
        impl #name { #(#handles)* }
        #(#specs)*
    })
}
