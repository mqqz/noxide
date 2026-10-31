//! Asset file hashing runs during the selected build executor's compilation.
use noxide_protocol::assets::{MAX_ASSET_BYTES, valid_asset_name};
use proc_macro2::TokenStream;
use quote::quote;
use sha2::{Digest, Sha256};
use syn::{
    Ident, LitStr, Token,
    parse::{Parse, ParseStream},
};

pub(crate) struct Declaration {
    name: LitStr,
    media: Ident,
}
impl Parse for Declaration {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let name = input.parse()?;
        input.parse::<Token![,]>()?;
        let media = input.parse()?;
        if !input.is_empty() {
            return Err(input.error("expected logical name and MIME variant"));
        }
        Ok(Self { name, media })
    }
}
pub(crate) fn expand(declaration: Declaration, item: syn::ItemStruct) -> syn::Result<TokenStream> {
    let name = declaration.name;
    let media = declaration.media;
    if !valid_asset_name(&name.value()) {
        return Err(syn::Error::new(name.span(), "invalid logical asset name"));
    }
    if !["Png", "Jpeg", "Webp", "Woff2", "Css"].contains(&media.to_string().as_str()) {
        return Err(syn::Error::new(
            media.span(),
            "expected Png, Jpeg, Webp, Woff2 or Css",
        ));
    }
    if !matches!(item.fields, syn::Fields::Unit) || !item.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &item,
            "asset requires a nongeneric unit struct",
        ));
    }
    let directory = std::env::var_os("CARGO_MANIFEST_DIR")
        .ok_or_else(|| syn::Error::new(name.span(), "asset manifest directory unavailable"))?;
    let mut path = std::path::PathBuf::from(directory);
    path.push("public");
    let logical_name = name.value();
    for (index, component) in std::iter::once("public")
        .chain(logical_name.split('/'))
        .enumerate()
    {
        if index > 0 {
            path.push(component);
        }
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|_| syn::Error::new(name.span(), "asset input unavailable"))?;
        if meta.file_type().is_symlink() {
            return Err(syn::Error::new(name.span(), "linked asset input"));
        }
    }
    let meta = std::fs::metadata(&path)
        .map_err(|_| syn::Error::new(name.span(), "asset input unavailable"))?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_ASSET_BYTES as u64 {
        return Err(syn::Error::new(name.span(), "asset file limit"));
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_ASSET_BYTES as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| syn::Error::new(name.span(), "asset read failed"))?;
    if bytes.len() != meta.len() as usize {
        return Err(syn::Error::new(name.span(), "asset changed during read"));
    }
    let digest = format!("{:x}", Sha256::digest(bytes));
    let ident = &item.ident;
    let capability = match media.to_string().as_str() {
        "Css" => quote!(impl ::noxide::StylesheetAsset for #ident {}),
        "Woff2" => quote!(impl ::noxide::FontAsset for #ident {}),
        _ => quote!(impl ::noxide::ImageAsset for #ident {}),
    };
    Ok(quote! {
        #item
        #capability
        impl ::noxide::AssetType for #ident {
            fn declaration()->::noxide::AssetDeclaration { ::noxide::AssetDeclaration{name:#name.into(),digest:#digest.into(),media_type: ::noxide::AssetMediaType::#media} }
        }
    })
}
