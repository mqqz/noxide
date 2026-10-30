//! Public, immutable package assets. A declaration grants no filesystem access.
use serde::{Deserialize, Serialize};

pub const MAX_ASSETS: usize = 128;
pub const MAX_ASSET_NAME_BYTES: usize = 96;
pub const MAX_ASSET_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ASSET_TOTAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ASSET_PACK_BYTES: usize =
    MAX_ASSET_TOTAL_BYTES + MAX_ASSETS * (6 + MAX_ASSET_NAME_BYTES) + 10;
pub const MAX_IMAGE_PIXELS: u64 = 16_000_000;
pub const MAX_CSS_BYTES: usize = 65_536;
pub const ASSET_PATH_PREFIX: &str = "/_noxide/assets/";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetMediaType {
    Png,
    Jpeg,
    Webp,
    Woff2,
    Css,
}
impl AssetMediaType {
    pub fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
            Self::Woff2 => "font/woff2",
            Self::Css => "text/css; charset=utf-8",
        }
    }
    pub fn is_image(self) -> bool {
        matches!(self, Self::Png | Self::Jpeg | Self::Webp)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssetDeclaration {
    /// Relative package path; never a host path or a browser URL.
    pub name: String,
    /// Lowercase SHA-256 of the exact admitted source bytes.
    pub digest: String,
    pub media_type: AssetMediaType,
}

pub fn valid_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ASSET_NAME_BYTES
        && name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.starts_with('.')
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
        })
}
pub fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn asset_path(digest: &str) -> Option<String> {
    valid_digest(digest).then(|| format!("{ASSET_PATH_PREFIX}{digest}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_canonical_package_names_and_digests() {
        assert!(valid_asset_name("images/banner-2.webp"));
        assert_eq!(MAX_ASSET_NAME_BYTES, 96);
        for bytes in [95, 96, 97] {
            let name = format!("{}.css", "a".repeat(bytes - 4));
            assert_eq!(valid_asset_name(&name), bytes <= MAX_ASSET_NAME_BYTES);
        }
        for name in [
            "", "/x", "../x", "a/../x", "a//b", "a/./b", ".x", "a\\b", "x?q", "x#z", "x%2f",
        ] {
            assert!(!valid_asset_name(name), "{name}");
        }
        assert!(asset_path(&"a".repeat(64)).is_some());
        assert!(asset_path(&"A".repeat(64)).is_none());
    }
}
