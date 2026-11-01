//! Independent admission for immutable public package assets. Runs at approval;
//! the server only loads the compiled result. Parses hostile CSS and image headers,
//! so it never shares a process with host keys.
//!
//! No path here opens a file. Callers pass snapshotted bytes from the selected
//! build executor; hostile source trees must use the disposable build VM.
#![forbid(unsafe_code)]
mod css;
use anyhow::{Result, ensure};
use image::{ImageFormat, ImageReader, Limits};
use noxide_assets::*;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
};

#[derive(Clone, Debug)]
pub struct AssetInput {
    pub declaration: AssetDeclaration,
    pub bytes: Vec<u8>,
}

/// Atomically validate the complete bundle. No partially admitted state escapes.
pub fn admit(inputs: Vec<AssetInput>) -> Result<AssetBundle> {
    ensure!(inputs.len() <= MAX_ASSETS, "asset count limit");
    let mut paths = BTreeMap::new();
    let mut total = 0usize;
    let mut urls = BTreeMap::new();
    // Complete digest/MIME map first so CSS can only refer to declared entries.
    for input in &inputs {
        let d = &input.declaration;
        ensure!(
            valid_asset_name(&d.name) && valid_digest(&d.digest),
            "asset name or digest"
        );
        ensure!(
            !input.bytes.is_empty() && input.bytes.len() <= MAX_ASSET_BYTES,
            "asset size limit"
        );
        total = total
            .checked_add(input.bytes.len())
            .ok_or_else(|| anyhow::anyhow!("asset total overflow"))?;
        ensure!(total <= MAX_ASSET_TOTAL_BYTES, "asset total limit");
        ensure!(
            format!("{:x}", Sha256::digest(&input.bytes)) == d.digest,
            "asset digest mismatch"
        );
        ensure!(
            paths
                .insert(asset_path(&d.digest).unwrap(), d.name.clone())
                .is_none(),
            "duplicate asset digest"
        );
        ensure!(
            urls.insert(asset_path(&d.digest).unwrap(), d.media_type)
                .is_none(),
            "duplicate asset URL"
        );
    }
    let mut names = BTreeSet::new();
    let mut assets = Vec::with_capacity(inputs.len());
    for input in inputs {
        let d = input.declaration;
        ensure!(names.insert(d.name.clone()), "duplicate asset name");
        let dimensions = if d.media_type.is_image() {
            Some(image_dimensions(&input.bytes, d.media_type)?)
        } else {
            None
        };
        let bytes = match d.media_type {
            AssetMediaType::Css => css::validate(std::str::from_utf8(&input.bytes)?, &urls)?,
            AssetMediaType::Woff2 => {
                woff2(&input.bytes)?;
                input.bytes
            }
            _ => input.bytes,
        };
        assets.push(PublicAsset::new(d, bytes, dimensions));
    }
    AssetBundle::from_assets(assets)
}
/// Parse the canonical executor transport without opening archive paths.
/// Every transported entry must match exactly one approved declaration.
pub fn from_pack(declarations: &[AssetDeclaration], pack: &[u8]) -> Result<AssetBundle> {
    validate_declarations(declarations)?;
    ensure!(
        declarations.len() <= MAX_ASSETS && pack.len() <= MAX_ASSET_PACK_BYTES,
        "asset pack byte limit"
    );
    ensure!(
        pack.len() >= 10 && &pack[..8] == b"NXAS\x01\0\0\0",
        "asset pack header"
    );
    let count = u16::from_le_bytes(pack[8..10].try_into().unwrap()) as usize;
    ensure!(
        count <= MAX_ASSETS && count == declarations.len(),
        "asset pack declaration count"
    );
    let mut offset = 10usize;
    let mut inputs = Vec::with_capacity(count);
    let mut seen = std::collections::BTreeSet::new();
    let mut previous_name: Option<&str> = None;
    for _ in 0..count {
        let header = pack
            .get(offset..offset + 6)
            .ok_or_else(|| anyhow::anyhow!("truncated asset pack"))?;
        let name_len = u16::from_le_bytes(header[..2].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(header[2..6].try_into().unwrap()) as usize;
        ensure!(
            (1..=MAX_ASSET_NAME_BYTES).contains(&name_len) && (1..=MAX_ASSET_BYTES).contains(&size),
            "asset pack entry limit"
        );
        offset += 6;
        let name = std::str::from_utf8(
            pack.get(offset..offset + name_len)
                .ok_or_else(|| anyhow::anyhow!("truncated asset name"))?,
        )?;
        ensure!(
            valid_asset_name(name) && seen.insert(name),
            "unsafe or duplicate asset name"
        );
        ensure!(
            previous_name.is_none_or(|previous| previous < name),
            "noncanonical asset pack order"
        );
        previous_name = Some(name);
        offset += name_len;
        let declaration = declarations
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| anyhow::anyhow!("undeclared asset"))?
            .clone();
        let bytes = pack
            .get(offset..offset + size)
            .ok_or_else(|| anyhow::anyhow!("truncated asset bytes"))?
            .to_vec();
        offset += size;
        inputs.push(AssetInput { declaration, bytes });
    }
    ensure!(offset == pack.len(), "trailing asset pack data");
    admit(inputs)
}

fn image_dimensions(bytes: &[u8], kind: AssetMediaType) -> Result<(u32, u32)> {
    if kind == AssetMediaType::Webp {
        ensure!(
            bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP",
            "WebP container header"
        );
        let declared = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        ensure!(
            declared.checked_add(8) == Some(bytes.len()),
            "WebP container length"
        );
    }
    let format = match kind {
        AssetMediaType::Png => ImageFormat::Png,
        AssetMediaType::Jpeg => ImageFormat::Jpeg,
        AssetMediaType::Webp => ImageFormat::WebP,
        _ => unreachable!(),
    };
    ensure!(image::guess_format(bytes)? == format, "image MIME mismatch");
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_PIXELS as u32);
    limits.max_image_height = Some(MAX_IMAGE_PIXELS as u32);
    limits.max_alloc = Some(8 * 1024 * 1024);
    reader.limits(limits);
    let (width, height) = reader.into_dimensions()?;
    ensure!(
        width > 0
            && height > 0
            && u64::from(width)
                .checked_mul(u64::from(height))
                .is_some_and(|v| v <= MAX_IMAGE_PIXELS),
        "image pixel limit"
    );
    Ok((width, height))
}
fn woff2(bytes: &[u8]) -> Result<()> {
    // Fixed WOFF2 header validation only. Do not decompress attacker fonts on
    // the host. Browser font parsing remains a separate trust boundary.
    ensure!(bytes.len() >= 48 && &bytes[..4] == b"wOF2", "WOFF2 header");
    let u16_at = |i| u16::from_be_bytes([bytes[i], bytes[i + 1]]);
    let u32_at = |i| u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap());
    ensure!(
        [b"\0\x01\0\0".as_slice(), b"OTTO".as_slice()].contains(&&bytes[4..8]),
        "WOFF2 flavor"
    );
    ensure!(
        u32_at(8) as usize == bytes.len() && u16_at(12) > 0 && u16_at(12) <= 256 && u16_at(14) == 0,
        "WOFF2 header bounds"
    );
    ensure!(
        u32_at(16) >= 12
            && u32_at(16) <= 32 * 1024 * 1024
            && u32_at(20) > 0
            && u32_at(20) as usize <= bytes.len() - 48,
        "WOFF2 expansion bounds"
    );
    for (offset, length) in [(28, 32), (40, 44)] {
        let o = u32_at(offset) as usize;
        let n = u32_at(length) as usize;
        ensure!(
            (o == 0 && n == 0)
                || (o >= 48 && n > 0 && o.checked_add(n).is_some_and(|v| v <= bytes.len())),
            "WOFF2 metadata bounds"
        );
    }
    ensure!(u32_at(28) != 0 || u32_at(36) == 0, "WOFF2 metadata length");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(name: &str, kind: AssetMediaType, bytes: Vec<u8>) -> AssetInput {
        AssetInput {
            declaration: AssetDeclaration {
                name: name.into(),
                digest: format!("{:x}", Sha256::digest(&bytes)),
                media_type: kind,
            },
            bytes,
        }
    }
    #[test]
    fn names_share_one_bound_in_admission_pack_and_stylesheet_refs() {
        for bytes in [95, 96, 97] {
            let name = format!("{}.css", "a".repeat(bytes - 4));
            let input = input(&name, AssetMediaType::Css, b"p{color:red}".to_vec());
            let mut pack = b"NXAS\x01\0\0\0".to_vec();
            pack.extend_from_slice(&1u16.to_le_bytes());
            pack.extend_from_slice(&(name.len() as u16).to_le_bytes());
            pack.extend_from_slice(&(input.bytes.len() as u32).to_le_bytes());
            pack.extend_from_slice(name.as_bytes());
            pack.extend_from_slice(&input.bytes);
            let admitted = admit(vec![input.clone()]);
            assert_eq!(admitted.is_ok(), bytes <= MAX_ASSET_NAME_BYTES);
            assert_eq!(
                from_pack(std::slice::from_ref(&input.declaration), &pack).is_ok(),
                bytes <= MAX_ASSET_NAME_BYTES
            );
            if let Ok(bundle) = admitted {
                assert!(document::stylesheet(&name, &bundle).is_ok());
            }
        }
        let name = "a".repeat(97);
        assert!(
            document::stylesheet(&name, &AssetBundle::default())
                .unwrap_err()
                .to_string()
                .contains("stylesheet asset name")
        );
    }
    #[test]
    fn immutable_scoped_css_and_exact_lookup() {
        let bundle = admit(vec![input(
            "site.css",
            AssetMediaType::Css,
            b"p, .card > strong { color: #123; margin: 2rem auto }".to_vec(),
        )])
        .unwrap();
        let asset = bundle.get("site.css").unwrap();
        assert!(
            std::str::from_utf8(asset.bytes())
                .unwrap()
                .contains(".noxide-app p,.noxide-app .card > strong")
        );
        assert_eq!(
            bundle.at_path(&asset.path()).unwrap().bytes(),
            asset.bytes()
        );
        assert!(bundle.at_path(&(asset.path() + "?x")).is_none());
    }
    #[test]
    fn grammar_supports_static_layout_queries_and_bounded_animation() {
        for css in [
            "@media (min-width: 30rem) { .card { display: grid; grid-template-columns: 1fr 2fr; gap: 1rem } }",
            "@container panel (max-width: 20rem) { p:hover {color:red} }",
            "@keyframes nxa-fade { from {opacity:0} 100% {opacity:1} } .card {animation-name:nxa-fade;animation-duration:1s;animation-iteration-count:2}",
        ] {
            css::validate(css, &BTreeMap::new()).unwrap();
        }
    }
    #[test]
    fn deny_resource_indirection_unknown_and_malformed_css() {
        for css in [
            "@import '/x';",
            "x { background-image:url(https://evil/x) }",
            "x {background-image:u\\72l(//evil/x)}",
            "x {background-image:url(data:image/png,x)}",
            "x {background-image:image-set(url(/x) 1x)}",
            "x {color:var(--x)}",
            "x {width:attr(secret)}",
            "@font-face {font-family: x;src:local(x)}",
            "[value=secret] {color:red}",
            ":is(p) {color:red}",
            "@supports(display:grid){x{display:grid}}",
            "x{unknown:foo}",
            "x{color:red",
            "@media(min-width:1px){x{color:red}",
            "x{color: 'unterminated}",
            "x{color:red}/*",
            "x{animation-iteration-count:infinite}",
            "x{animation-duration:11s}",
            "x{position:fixed}",
            "x{color:red!important}",
            "p::before{color:red}",
            ". a{color:red}",
            "a > + b{color:red}",
            "p{color:rgb(1,2)}",
            "p{color:rgba(1,2,3,2)}",
            "p{width:1px 2px}",
            "p{padding:auto}",
        ] {
            assert!(css::validate(css, &BTreeMap::new()).is_err(), "{css}");
        }
    }
    #[test]
    fn css_urls_must_be_exact_declared_typed_digests() {
        let url = format!("{ASSET_PATH_PREFIX}{}", "a".repeat(64));
        let mut urls = BTreeMap::from([(url.clone(), AssetMediaType::Png)]);
        css::validate(&format!("p{{background-image:url('{url}')}}"), &urls).unwrap();
        assert!(css::validate(&format!("p{{background-image:url('{url}?x')}}"), &urls).is_err());
        assert!(
            css::validate(
                &format!("@font-face{{font-family:'nxa-face';src:url('{url}')}}"),
                &urls
            )
            .is_err()
        );
        assert!(css::validate(&format!("p{{background-image:url({url}"), &urls).is_err());
        urls.insert(url.clone(), AssetMediaType::Woff2);
        assert!(
            css::validate(
                &format!("@font-face{{font-family:'Arial';src:url('{url}')}}"),
                &urls
            )
            .is_err()
        );
        css::validate(
            &format!("@font-face{{font-family:'nxa-face';src:url('{url}')}}"),
            &urls,
        )
        .unwrap();
    }
    #[test]
    fn forged_names_hashes_duplicates_and_limits() {
        let css = b"p{color:red}".to_vec();
        let mut bad = input("../x", AssetMediaType::Css, css.clone());
        assert!(admit(vec![bad.clone()]).is_err());
        bad.declaration.name = "x".into();
        bad.declaration.digest = "0".repeat(64);
        assert!(admit(vec![bad]).is_err());
        let a = input("x", AssetMediaType::Css, css);
        assert!(admit(vec![a.clone(), a]).is_err());
        let a = input("x", AssetMediaType::Css, vec![b'x'; MAX_CSS_BYTES + 1]);
        assert!(admit(vec![a]).is_err());
        let a = input("x", AssetMediaType::Png, vec![0; MAX_ASSET_BYTES + 1]);
        assert!(admit(vec![a]).is_err());
        assert!(
            admit(
                (0..129)
                    .map(|i| input(
                        &format!("x{i}"),
                        AssetMediaType::Css,
                        format!("p{{margin:{i}px}}").into_bytes()
                    ))
                    .collect()
            )
            .is_err()
        );
    }
    #[test]
    fn malformed_metadata_and_mime_mismatch_fail() {
        for kind in [
            AssetMediaType::Png,
            AssetMediaType::Jpeg,
            AssetMediaType::Webp,
            AssetMediaType::Woff2,
        ] {
            for bytes in [vec![], vec![0; 48], b"\x89PNG\r\n\x1a\n".to_vec()] {
                assert!(admit(vec![input("x", kind, bytes)]).is_err());
            }
        }
    }
    #[test]
    fn valid_jpeg_and_webp_metadata_and_total_bound() {
        use image::ImageEncoder;
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
            .write_image(&[255, 0, 0], 1, 1, image::ExtendedColorType::Rgb8)
            .unwrap();
        let mut webp = Vec::new();
        image::codecs::webp::WebPEncoder::new_lossless(&mut webp)
            .write_image(&[255, 0, 0, 255], 1, 1, image::ExtendedColorType::Rgba8)
            .unwrap();
        let bundle = admit(vec![
            input("pixel.jpg", AssetMediaType::Jpeg, jpeg.clone()),
            input("pixel.webp", AssetMediaType::Webp, webp.clone()),
        ])
        .unwrap();
        for name in ["pixel.jpg", "pixel.webp"] {
            assert_eq!(bundle.get(name).unwrap().dimensions(), Some((1, 1)));
        }
        for (kind, bytes) in [(AssetMediaType::Jpeg, jpeg), (AssetMediaType::Webp, webp)] {
            for n in 0..bytes.len().min(30) {
                assert!(
                    admit(vec![input("truncated", kind, bytes[..n].to_vec())]).is_err(),
                    "{kind:?} prefix {n}"
                );
            }
        }
        let excessive = (0..5)
            .map(|i| {
                input(
                    &format!("font{i}"),
                    AssetMediaType::Woff2,
                    vec![i as u8; MAX_ASSET_BYTES],
                )
            })
            .collect();
        assert!(admit(excessive).unwrap_err().to_string().contains("total"));
    }
    #[test]
    fn image_dimensions_checked_without_full_decode() {
        use image::ImageEncoder;
        let mut png = Vec::new();
        image::codecs::png::PngEncoder::new(&mut png)
            .write_image(&[0, 0, 0, 0], 1, 1, image::ExtendedColorType::Rgba8)
            .unwrap();
        let a = admit(vec![input("pixel.png", AssetMediaType::Png, png.clone())]).unwrap();
        assert_eq!(a.get("pixel.png").unwrap().dimensions(), Some((1, 1)));
        assert!(admit(vec![input("pixel.jpg", AssetMediaType::Jpeg, png.clone())]).is_err());
        for n in 0..33 {
            assert!(
                admit(vec![input(
                    "pixel.png",
                    AssetMediaType::Png,
                    png[..n].to_vec()
                )])
                .is_err()
            );
        }
        for (w, h, accepted) in [
            (4000u32, 4000u32, true),
            (4001, 4000, false),
            (u32::MAX, u32::MAX, false),
            (0, 1, false),
        ] {
            let mut modified = png.clone();
            modified[16..20].copy_from_slice(&w.to_be_bytes());
            modified[20..24].copy_from_slice(&h.to_be_bytes());
            let mut crc = u32::MAX;
            for b in &modified[12..29] {
                crc ^= u32::from(*b);
                for _ in 0..8 {
                    crc = (crc >> 1) ^ ((0u32.wrapping_sub(crc & 1)) & 0xedb88320);
                }
            }
            modified[29..33].copy_from_slice(&(!crc).to_be_bytes());
            assert_eq!(
                admit(vec![input("large.png", AssetMediaType::Png, modified)]).is_ok(),
                accepted,
                "{w}x{h}"
            );
        }
    }
    #[test]
    fn pack_exact_declarations_truncation_and_duplicate_rejection() {
        let a = input("site.css", AssetMediaType::Css, b"p{color:red}".to_vec());
        let mut pack = b"NXAS\x01\0\0\0".to_vec();
        pack.extend_from_slice(&1u16.to_le_bytes());
        pack.extend_from_slice(&8u16.to_le_bytes());
        pack.extend_from_slice(&(a.bytes.len() as u32).to_le_bytes());
        pack.extend_from_slice(b"site.css");
        pack.extend_from_slice(&a.bytes);
        from_pack(std::slice::from_ref(&a.declaration), &pack).unwrap();
        for n in 0..pack.len() {
            assert!(from_pack(std::slice::from_ref(&a.declaration), &pack[..n]).is_err());
        }
        assert!(from_pack(&[], &pack).is_err());
        pack.push(0);
        assert!(from_pack(&[a.declaration], &pack).is_err());
    }
    #[test]
    fn tokens_rules_and_nesting_are_bounded() {
        assert!(css::validate(&"p{color:red}".repeat(513), &BTreeMap::new()).is_err());
        assert!(
            css::validate(
                &format!(
                    "{}p{{color:red}}{}",
                    "@media(min-width:1px){".repeat(9),
                    "}".repeat(9)
                ),
                &BTreeMap::new()
            )
            .is_err()
        );
        assert!(
            css::validate(
                &format!("p{{margin:{}}}", "0 ".repeat(17000)),
                &BTreeMap::new()
            )
            .is_err()
        );
    }
    #[test]
    fn isolated_pack_fixture() {
        let Ok(path) = std::env::var("NOXIDE_TEST_ISOLATED_ASSET_PACK") else {
            return;
        };
        let declarations =
            std::fs::read(std::env::var("NOXIDE_TEST_ISOLATED_ASSET_DECLARATIONS").unwrap())
                .unwrap();
        let declarations: Vec<AssetDeclaration> = serde_json::from_slice(&declarations).unwrap();
        let pack = std::fs::read(path).unwrap();
        let bundle = from_pack(&declarations, &pack).unwrap();
        assert_eq!(bundle.get("pixel.png").unwrap().dimensions(), Some((1, 1)));
        assert!(
            std::str::from_utf8(bundle.get("site.css").unwrap().bytes())
                .unwrap()
                .starts_with(".noxide-app p")
        );
        for d in &declarations {
            let a = bundle.get(&d.name).unwrap();
            assert_eq!(a.declaration(), d);
            assert_eq!(
                format!("{:x}", Sha256::digest(a.bytes())),
                a.path().strip_prefix(ASSET_PATH_PREFIX).unwrap()
            );
        }
    }
}
