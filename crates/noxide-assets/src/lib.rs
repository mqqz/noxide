//! Immutable public assets as the server holds them: already validated and
//! compiled at approval by `noxide-asset-admission`. The server verifies an
//! approved digest and parses no CSS, images or fonts.
#![cfg_attr(test, allow(clippy::too_many_lines))]
#![forbid(unsafe_code)]
pub static EMPTY: std::sync::LazyLock<AssetBundle> = std::sync::LazyLock::new(AssetBundle::default);
pub mod document;
use anyhow::{Result, ensure};
pub use noxide_protocol::assets::*;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug)]
pub struct PublicAsset {
    declaration: AssetDeclaration,
    bytes: Arc<[u8]>,
    served_digest: String,
    dimensions: Option<(u32, u32)>,
}
impl PublicAsset {
    /// `bytes` are the served form. Only asset admission and the compiled-pack
    /// loader, which verifies an approved digest, construct assets.
    pub fn new(
        declaration: AssetDeclaration,
        bytes: Vec<u8>,
        dimensions: Option<(u32, u32)>,
    ) -> Self {
        Self {
            served_digest: format!("{:x}", Sha256::digest(&bytes)),
            declaration,
            bytes: bytes.into(),
            dimensions,
        }
    }
    pub fn declaration(&self) -> &AssetDeclaration {
        &self.declaration
    }
    pub fn shared_bytes(&self) -> Arc<[u8]> {
        self.bytes.clone()
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn dimensions(&self) -> Option<(u32, u32)> {
        self.dimensions
    }
    pub fn path(&self) -> String {
        asset_path(&self.served_digest).expect("admitted digest")
    }
}
/// Manifest admission without trusting transported byte content.
pub fn validate_declarations(declarations: &[AssetDeclaration]) -> Result<()> {
    ensure!(declarations.len() <= MAX_ASSETS, "asset declaration count");
    let mut names = std::collections::BTreeSet::new();
    let mut digests = std::collections::BTreeSet::new();
    for d in declarations {
        ensure!(
            valid_asset_name(&d.name) && valid_digest(&d.digest),
            "asset name or digest"
        );
        ensure!(
            names.insert(&d.name) && digests.insert(&d.digest),
            "duplicate asset name or digest"
        );
    }
    Ok(())
}

const COMPILED_MAGIC: &[u8; 8] = b"NXCP\x01\0\0\0";

#[derive(Clone, Debug, Default)]
pub struct AssetBundle {
    names: BTreeMap<String, PublicAsset>,
    paths: BTreeMap<String, String>,
}
impl AssetBundle {
    /// Build from assets admission already validated.
    pub fn from_assets(assets: Vec<PublicAsset>) -> Result<Self> {
        let mut bundle = Self::default();
        ensure!(assets.len() <= MAX_ASSETS, "asset count limit");
        let mut total = 0usize;
        for asset in assets {
            total = total
                .checked_add(asset.bytes.len())
                .ok_or_else(|| anyhow::anyhow!("asset total overflow"))?;
            ensure!(total <= MAX_ASSET_TOTAL_BYTES, "compiled asset total limit");
            let name = asset.declaration.name.clone();
            // Sources that compile to identical bytes share one immutable URL.
            bundle.paths.insert(asset.path(), name.clone());
            ensure!(
                bundle.names.insert(name, asset).is_none(),
                "duplicate asset name"
            );
        }
        Ok(bundle)
    }
    /// Canonical compiled form, written at approval.
    pub fn to_compiled(&self) -> Result<Vec<u8>> {
        let mut out = COMPILED_MAGIC.to_vec();
        out.extend_from_slice(&u16::try_from(self.names.len())?.to_le_bytes());
        for asset in self.names.values() {
            let name = asset.declaration.name.as_bytes();
            out.extend_from_slice(&u16::try_from(name.len())?.to_le_bytes());
            out.extend_from_slice(name);
            let (width, height) = asset.dimensions.unwrap_or((0, 0));
            out.extend_from_slice(&width.to_le_bytes());
            out.extend_from_slice(&height.to_le_bytes());
            out.extend_from_slice(&u32::try_from(asset.bytes.len())?.to_le_bytes());
            out.extend_from_slice(&asset.bytes);
        }
        Ok(out)
    }
    /// Lowercase hex SHA-256 an operator approves for a compiled pack.
    pub fn compiled_digest(compiled: &[u8]) -> String {
        format!("{:x}", Sha256::digest(compiled))
    }
    /// Load a compiled pack whose digest was approved. The digest is checked
    /// before any field is read; only the framing is parsed, never the contents.
    pub fn from_compiled(
        declarations: &[AssetDeclaration],
        compiled: &[u8],
        approved_digest: &str,
    ) -> Result<Self> {
        ensure!(
            Self::compiled_digest(compiled) == approved_digest,
            "compiled assets do not match the approved digest"
        );
        validate_declarations(declarations)?;
        let take = |offset: &mut usize, length: usize| -> Result<&[u8]> {
            let end = offset
                .checked_add(length)
                .ok_or_else(|| anyhow::anyhow!("compiled asset length"))?;
            let bytes = compiled
                .get(*offset..end)
                .ok_or_else(|| anyhow::anyhow!("truncated compiled assets"))?;
            *offset = end;
            Ok(bytes)
        };
        let mut offset = 0;
        ensure!(
            take(&mut offset, COMPILED_MAGIC.len())? == COMPILED_MAGIC,
            "compiled asset header"
        );
        let count = u16::from_le_bytes(take(&mut offset, 2)?.try_into()?) as usize;
        ensure!(count == declarations.len(), "compiled asset count");
        let mut assets = Vec::with_capacity(count);
        for _ in 0..count {
            let length = u16::from_le_bytes(take(&mut offset, 2)?.try_into()?) as usize;
            let name = std::str::from_utf8(take(&mut offset, length)?)?;
            let declaration = declarations
                .iter()
                .find(|d| d.name == name)
                .ok_or_else(|| anyhow::anyhow!("undeclared compiled asset"))?
                .clone();
            let width = u32::from_le_bytes(take(&mut offset, 4)?.try_into()?);
            let height = u32::from_le_bytes(take(&mut offset, 4)?.try_into()?);
            let size = u32::from_le_bytes(take(&mut offset, 4)?.try_into()?) as usize;
            ensure!(
                (1..=MAX_ASSET_TOTAL_BYTES).contains(&size),
                "compiled asset size"
            );
            let bytes = take(&mut offset, size)?.to_vec();
            let dimensions = declaration.media_type.is_image().then_some((width, height));
            assets.push(PublicAsset::new(declaration, bytes, dimensions));
        }
        ensure!(offset == compiled.len(), "trailing compiled asset data");
        Self::from_assets(assets)
    }
    /// Recheck exact manifest binding at Application construction/restore.
    pub fn verify_declarations(&self, declarations: &[AssetDeclaration]) -> Result<()> {
        validate_declarations(declarations)?;
        ensure!(
            declarations.len() == self.names.len()
                && declarations
                    .iter()
                    .all(|d| self.get(&d.name).is_some_and(|a| a.declaration() == d)),
            "asset bundle contract mismatch"
        );
        Ok(())
    }
    pub fn get(&self, name: &str) -> Option<&PublicAsset> {
        self.names.get(name)
    }
    pub fn at_path(&self, path: &str) -> Option<&PublicAsset> {
        self.paths.get(path).and_then(|n| self.names.get(n))
    }
    pub fn declarations(&self) -> impl Iterator<Item = &AssetDeclaration> {
        self.names.values().map(|a| &a.declaration)
    }
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn declaration(name: &str, media_type: AssetMediaType, bytes: &[u8]) -> AssetDeclaration {
        AssetDeclaration {
            name: name.into(),
            media_type,
            digest: format!("{:x}", Sha256::digest(bytes)),
        }
    }
    #[test]
    fn compiled_round_trip_requires_the_approved_digest() {
        let css = declaration("site.css", AssetMediaType::Css, b"source");
        let bundle =
            AssetBundle::from_assets(vec![PublicAsset::new(css.clone(), b"p{}".to_vec(), None)])
                .unwrap();
        let compiled = bundle.to_compiled().unwrap();
        let digest = AssetBundle::compiled_digest(&compiled);
        let declarations = std::slice::from_ref(&css);
        let loaded = AssetBundle::from_compiled(declarations, &compiled, &digest).unwrap();
        loaded.verify_declarations(declarations).unwrap();
        assert_eq!(loaded.get("site.css").unwrap().bytes(), b"p{}");
        assert_eq!(
            loaded.get("site.css").unwrap().path(),
            bundle.get("site.css").unwrap().path()
        );
        assert!(AssetBundle::from_compiled(declarations, &compiled, "00").is_err());
        let mut tampered = compiled.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(AssetBundle::from_compiled(declarations, &tampered, &digest).is_err());
    }
    #[test]
    fn approved_digest_does_not_excuse_bad_framing() {
        let css = declaration("site.css", AssetMediaType::Css, b"source");
        for compiled in [
            b"".as_slice(),
            b"NXCP\x01\0\0\0",
            b"NXCP\x01\0\0\0\x01\0",
            b"NOPE\x01\0\0\0\0\0",
            b"NXCP\x01\0\0\0\x01\0\xff\xff",
        ] {
            let digest = AssetBundle::compiled_digest(compiled);
            assert!(
                AssetBundle::from_compiled(std::slice::from_ref(&css), compiled, &digest).is_err()
            );
        }
        let bundle =
            AssetBundle::from_assets(vec![PublicAsset::new(css, b"p{}".to_vec(), None)]).unwrap();
        let compiled = bundle.to_compiled().unwrap();
        let digest = AssetBundle::compiled_digest(&compiled);
        // A compiled entry must be declared by the approved manifest.
        assert!(AssetBundle::from_compiled(&[], &compiled, &digest).is_err());
    }
}
