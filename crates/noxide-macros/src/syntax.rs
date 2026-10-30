use noxide_protocol::identifier;
use syn::{Attribute, DeriveInput, LitStr, Type, spanned::Spanned};

pub(crate) fn key(value: LitStr) -> syn::Result<LitStr> {
    if identifier(&value.value()) {
        Ok(value)
    } else {
        Err(syn::Error::new(
            value.span(),
            "persistent keys must be lowercase ASCII identifiers of at most 32 bytes",
        ))
    }
}

pub(crate) fn stable_id(value: &str) -> u32 {
    value.bytes().fold(2_166_136_261_u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(16_777_619)
    })
}

pub(crate) fn reject_generics(input: &DeriveInput) -> syn::Result<()> {
    if input.generics.params.is_empty() && input.generics.where_clause.is_none() {
        Ok(())
    } else {
        Err(syn::Error::new(
            input.generics.span(),
            "application declarations cannot be generic",
        ))
    }
}

pub(crate) fn required_key(attrs: &[Attribute], attribute: &str) -> syn::Result<LitStr> {
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

pub(crate) fn text_type(ty: &Type) -> bool {
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

pub(crate) fn validate_field_type(ty: &Type, inside_option: bool) -> syn::Result<()> {
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
    if inside_option && segment.ident == "AccountId" {
        return Err(syn::Error::new(
            ty.span(),
            "account references must be required",
        ));
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
