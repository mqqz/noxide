use crate::syntax::{key, reject_generics};
use proc_macro2::TokenStream as Tokens;
use quote::quote;
use std::collections::BTreeSet;
use syn::{Data, DeriveInput, Fields, LitStr, spanned::Spanned};

pub(crate) fn expand_choice(input: DeriveInput) -> syn::Result<Tokens> {
    reject_generics(&input)?;
    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new(input.span(), "Choice requires an enum"));
    };
    if data.variants.is_empty() || data.variants.len() > 32 {
        return Err(syn::Error::new(
            input.span(),
            "Choice requires between 1 and 32 variants",
        ));
    }
    let mut keys = BTreeSet::new();
    let mut variants = Vec::new();
    let mut encoding = Vec::new();
    let mut decoding = Vec::new();
    let mut rendering = Vec::new();
    let enum_name = &input.ident;
    for variant in &data.variants {
        if variant.fields != Fields::Unit || variant.discriminant.is_some() {
            return Err(syn::Error::new(
                variant.span(),
                "Choice variants must be unit variants without discriminants",
            ));
        }
        let attrs: Vec<_> = variant
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("choice"))
            .collect();
        if attrs.len() != 1 {
            return Err(syn::Error::new(
                variant.span(),
                "each variant requires #[choice(key = \"stable_key\", label = \"Label\")]",
            ));
        }
        let mut variant_key = None;
        let mut label = None;
        attrs[0].parse_nested_meta(|meta| {
            if meta.path.is_ident("key") && variant_key.is_none() {
                variant_key = Some(key(meta.value()?.parse()?)?);
            } else if meta.path.is_ident("label") && label.is_none() {
                label = Some(meta.value()?.parse::<LitStr>()?);
            } else {
                return Err(meta.error("unknown or duplicate choice option"));
            }
            Ok(())
        })?;
        let variant_key =
            variant_key.ok_or_else(|| syn::Error::new(variant.span(), "missing choice key"))?;
        let label = label.ok_or_else(|| syn::Error::new(variant.span(), "missing choice label"))?;
        if !keys.insert(variant_key.value()) {
            return Err(syn::Error::new(variant_key.span(), "duplicate choice key"));
        }
        if label.value().is_empty()
            || label.value().len() > 128
            || label.value().chars().any(char::is_control)
        {
            return Err(syn::Error::new(label.span(), "invalid choice label"));
        }
        let name = &variant.ident;
        variants.push(
            quote!(::noxide::ChoiceVariant { key: #variant_key.into(), label: #label.into() }),
        );
        encoding.push(quote!(Self::#name => #variant_key.into()));
        decoding.push(quote!(#variant_key => Self::#name));
        rendering.push(quote!(#enum_name::#name => #label));
    }
    let name = &input.ident;
    Ok(quote! {
        impl ::noxide::SelectValue for #name {}
        impl ::noxide::Render for #name {
            fn render(self, fragment: &mut ::noxide::Fragment) {
                <&Self as ::noxide::Render>::render(&self, fragment);
            }
        }
        impl ::noxide::Render for &#name {
            fn render(self, fragment: &mut ::noxide::Fragment) {
                fragment.text(match self { #(#rendering),* });
            }
        }
        impl ::noxide::FieldValue for #name {
            const OPTIONAL: bool = false;
            fn kind() -> ::noxide::FieldKind {
                ::noxide::FieldKind::Choice { variants: vec![#(#variants),*] }
            }
            fn encode(&self) -> String { match self { #(#encoding),* } }
            fn decode(value: &str) -> Self {
                match value { #(#decoding,)* _ => panic!("host choice contract") }
            }
        }
    })
}
