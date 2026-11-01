use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Separately keyed token families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenDomain {
    Token,
    Cursor,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMaterial {
    key: [u8; 32],
    incarnation: String,
    #[serde(default)]
    edit_keys: Vec<EditKey>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditKey {
    id: u32,
    key: [u8; 32],
    signing: bool,
}

fn entropy<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
    Ok(bytes)
}

impl KeyMaterial {
    pub fn generate() -> Result<Self> {
        let mut keys = Self {
            key: entropy()?,
            incarnation: URL_SAFE_NO_PAD.encode(entropy::<32>()?),
            edit_keys: Vec::new(),
        };
        keys.rotate_edit_key()?;
        Ok(keys)
    }
    pub fn rotate_edit_key(&mut self) -> Result<()> {
        let id = self
            .edit_keys
            .iter()
            .map(|k| k.id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("edit key id exhausted"))?;
        let key = entropy()?;
        for old in &mut self.edit_keys {
            old.signing = false;
        }
        self.edit_keys.push(EditKey {
            id,
            key,
            signing: true,
        });
        Ok(())
    }
    pub fn incarnation(&self) -> &str {
        &self.incarnation
    }
    pub fn signing_edit_key(&self) -> Result<u32> {
        let mut ids = std::collections::BTreeSet::new();
        ensure!(
            self.edit_keys.iter().all(|k| ids.insert(k.id)),
            "duplicate edit key id"
        );
        let keys: Vec<_> = self.edit_keys.iter().filter(|k| k.signing).collect();
        ensure!(keys.len() == 1, "one signing edit key required");
        Ok(keys[0].id)
    }
    fn mac(&self, domain: &[u8], bytes: &[u8]) -> HmacSha256 {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.key).expect("fixed HMAC key length");
        mac.update(domain);
        mac.update(&[0]);
        mac.update(bytes);
        mac
    }
    fn cipher(&self, domain: TokenDomain) -> XChaCha20Poly1305 {
        // Domain-separated encryption keys; CSRF uses its own HMAC domain.
        let key = self
            .mac(
                match domain {
                    TokenDomain::Cursor => b"noxide/cursor/encryption/v1",
                    TokenDomain::Token => b"noxide/token/encryption/v2",
                },
                &[],
            )
            .finalize()
            .into_bytes();
        XChaCha20Poly1305::new(&key)
    }
    /// Version byte, independent random nonce, ciphertext and AEAD tag.
    pub fn seal(&self, domain: TokenDomain, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce: [u8; 24] = entropy()?;
        let ciphertext = self
            .cipher(domain)
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: b"noxide/token/v2",
                },
            )
            .map_err(|_| anyhow::anyhow!("token encryption failed"))?;
        let mut envelope = Vec::with_capacity(25 + ciphertext.len());
        envelope.push(2);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }
    pub fn open(&self, domain: TokenDomain, envelope: &[u8]) -> Result<Vec<u8>> {
        ensure!(envelope.len() >= 41 && envelope[0] == 2, "invalid token");
        self.cipher(domain)
            .decrypt(
                XNonce::from_slice(&envelope[1..25]),
                Payload {
                    msg: &envelope[25..],
                    aad: b"noxide/token/v2",
                },
            )
            .map_err(|_| anyhow::anyhow!("invalid token"))
    }
    pub fn csrf(&self, subject: &str) -> [u8; 32] {
        self.mac(b"noxide/csrf/v1", subject.as_bytes())
            .finalize()
            .into_bytes()
            .into()
    }
    pub fn edit_mac(&self, key_id: u32, resource: u32, id: u64, version: u64) -> Result<[u8; 32]> {
        let key = self
            .edit_keys
            .iter()
            .find(|k| k.id == key_id)
            .ok_or_else(|| anyhow::anyhow!("unknown edit key"))?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.key).expect("fixed HMAC key length");
        mac.update(b"noxide/edit/v1");
        mac.update(&[0]);
        mac.update(&resource.to_be_bytes());
        mac.update(&id.to_be_bytes());
        mac.update(&version.to_be_bytes());
        Ok(mac.finalize().into_bytes().into())
    }
}
