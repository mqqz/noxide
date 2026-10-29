use crate::database::{Param, Transaction};
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKeys {
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
pub(crate) const ANONYMOUS_TTL: i64 = 900;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TokenKind {
    Login,
    Session,
    Anonymous,
    AnonymousSubmission {
        contract: String,
        action: u32,
        version: u32,
        target: Option<RecordTarget>,
    },
    Submission {
        contract: String,
        action: u32,
        version: u32,
        target: Option<RecordTarget>,
    },
}

/// Private, authenticated scope. Guest-supplied record values never construct it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordTarget {
    pub resource: u32,
    pub id: u64,
    pub incarnation: String,
    pub revision: i64,
    pub route: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Token {
    pub kind: TokenKind,
    pub subject: String,
    pub nonce: String,
    pub issued: i64,
    pub expires: i64,
    pub incarnation: String,
}

pub(crate) fn random_id() -> Result<String> {
    let mut bytes = [0; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
pub(crate) fn record_id() -> Result<u64> {
    let mut bytes = [0; 8];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
    Ok((u64::from_le_bytes(bytes) & (i64::MAX as u64)).max(1))
}

impl HostKeys {
    pub(crate) fn incarnation(&self) -> &str {
        &self.incarnation
    }
    pub fn generate() -> Result<Self> {
        let mut key = [0; 32];
        OsRng
            .try_fill_bytes(&mut key)
            .map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
        let mut keys = Self {
            key,
            incarnation: random_id()?,
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
        let mut key = [0; 32];
        OsRng
            .try_fill_bytes(&mut key)
            .map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
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
    pub(crate) fn signing_edit_key(&self) -> Result<u32> {
        let mut ids = std::collections::BTreeSet::new();
        ensure!(
            self.edit_keys.iter().all(|k| ids.insert(k.id)),
            "duplicate edit key id"
        );
        let keys: Vec<_> = self.edit_keys.iter().filter(|k| k.signing).collect();
        ensure!(keys.len() == 1, "one signing edit key required");
        Ok(keys[0].id)
    }
    fn edit_mac(&self, key_id: u32, resource: u32, id: u64, version: u64) -> Result<HmacSha256> {
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
        Ok(mac)
    }
    pub(crate) fn edit_secret(
        &self,
        key_id: u32,
        resource: u32,
        id: u64,
        version: u64,
    ) -> Result<String> {
        ensure!(version > 0, "invalid capability version");
        Ok(format!(
            "nxc1.{key_id}.{version}.{}",
            URL_SAFE_NO_PAD.encode(
                self.edit_mac(key_id, resource, id, version)?
                    .finalize()
                    .into_bytes()
            )
        ))
    }
    pub(crate) fn verify_edit(
        &self,
        secret: &str,
        resource: u32,
        id: u64,
        version: i64,
    ) -> Result<()> {
        ensure!(secret.len() <= 128 && version > 0, "invalid edit secret");
        let parts: Vec<_> = secret.split('.').collect();
        ensure!(
            parts.len() == 4 && parts[0] == "nxc1",
            "invalid edit secret"
        );
        let key: u32 = parts[1].parse()?;
        let supplied: u64 = parts[2].parse()?;
        ensure!(supplied == version as u64, "revoked edit secret");
        self.edit_mac(key, resource, id, supplied)?
            .verify_slice(&URL_SAFE_NO_PAD.decode(parts[3])?)
            .map_err(|_| anyhow::anyhow!("invalid edit secret"))
    }
    pub(crate) fn anonymous(&self, cookie: &str, now: i64) -> Result<Token> {
        let token = self.verify(cookie, now)?;
        ensure!(
            token.kind == TokenKind::Anonymous
                && token.subject.is_empty()
                && token.expires - token.issued <= ANONYMOUS_TTL,
            "invalid anonymous cookie"
        );
        Ok(token)
    }
    fn mac(&self, domain: &[u8], bytes: &[u8]) -> HmacSha256 {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.key).expect("fixed HMAC key length");
        mac.update(domain);
        mac.update(&[0]);
        mac.update(bytes);
        mac
    }
    pub(crate) fn issue(
        &self,
        kind: TokenKind,
        subject: &str,
        now: i64,
        ttl: i64,
    ) -> Result<(Token, String)> {
        ensure!(
            (1..=86400).contains(&ttl) && subject.len() <= 128 && now >= 0,
            "invalid token scope"
        );
        let token = Token {
            kind,
            subject: subject.into(),
            nonce: random_id()?,
            issued: now,
            expires: now
                .checked_add(ttl)
                .ok_or_else(|| anyhow::anyhow!("clock overflow"))?,
            incarnation: self.incarnation.clone(),
        };
        let bytes = serde_json::to_vec(&token)?;
        // Use a domain-separated encryption key. CSRF authentication continues
        // to use the existing HMAC domains; token plaintext never leaves the host.
        let key = self
            .mac(b"noxide/token/encryption/v2", &[])
            .finalize()
            .into_bytes();
        let cipher = XChaCha20Poly1305::new(&key);
        let mut nonce = [0; 24];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &bytes,
                    aad: b"noxide/token/v2",
                },
            )
            .map_err(|_| anyhow::anyhow!("token encryption failed"))?;
        // Version, independent random encryption nonce, ciphertext and AEAD tag.
        let mut envelope = Vec::with_capacity(25 + ciphertext.len());
        envelope.push(2);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        let encoded = URL_SAFE_NO_PAD.encode(envelope);
        ensure!(encoded.len() <= 2048, "token limit");
        Ok((token, encoded))
    }
    pub(crate) fn verify(&self, encoded: &str, now: i64) -> Result<Token> {
        ensure!(encoded.len() <= 2048, "token limit");
        let envelope = URL_SAFE_NO_PAD.decode(encoded)?;
        ensure!(envelope.len() >= 41 && envelope[0] == 2, "invalid token");
        let key = self
            .mac(b"noxide/token/encryption/v2", &[])
            .finalize()
            .into_bytes();
        let cipher = XChaCha20Poly1305::new(&key);
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&envelope[1..25]),
                Payload {
                    msg: &envelope[25..],
                    aad: b"noxide/token/v2",
                },
            )
            .map_err(|_| anyhow::anyhow!("invalid token"))?;
        let token: Token = serde_json::from_slice(&plaintext)?;
        ensure!(
            token.incarnation == self.incarnation
                && token.issued >= 0
                && token.issued < token.expires
                && token.issued <= now
                && now < token.expires
                && token.expires - token.issued <= 86400,
            "expired token or authority"
        );
        Ok(token)
    }
    pub(crate) fn csrf(&self, subject: &str) -> String {
        URL_SAFE_NO_PAD.encode(
            self.mac(b"noxide/csrf/v1", subject.as_bytes())
                .finalize()
                .into_bytes(),
        )
    }
    pub(crate) fn verify_csrf(&self, subject: &str, value: &str) -> Result<()> {
        ensure!(value.len() <= 64, "csrf length");
        self.mac(b"noxide/csrf/v1", subject.as_bytes())
            .verify_slice(&URL_SAFE_NO_PAD.decode(value)?)
            .map_err(|_| anyhow::anyhow!("csrf mismatch"))
    }
}

pub(crate) fn now() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

/// A small wall-clock correction may delay expiry, but must never revive it.
/// Every caller uses the returned high-water time, including token verification.
pub(crate) const CLOCK_ROLLBACK_TOLERANCE: i64 = 60;

pub(crate) async fn observe_clock(tx: &mut Transaction, now: i64) -> Result<i64> {
    let rows = tx
        .fetch::<1>(
            "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await?;
    let previous: i64 = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("clock missing"))?[0]
        .parse()?;
    ensure!(now >= 0 && previous >= 0, "invalid clock");
    ensure!(
        previous.saturating_sub(now) <= CLOCK_ROLLBACK_TOLERANCE,
        "clock moved backwards beyond tolerance; use recover-clock with a fresh host key"
    );
    if now > previous {
        tx.execute(
            "UPDATE nx_clock SET observed=$1 WHERE singleton=1 AND observed<$1",
            &[Param::Number(now)],
        )
        .await?;
    }
    Ok(now.max(previous))
}

pub(crate) const CLOCK_CHECKPOINT_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60);
pub(crate) const CLOCK_CHECKPOINT_BEGIN_DEADLINE: std::time::Duration =
    std::time::Duration::from_millis(200);

pub(crate) async fn observe_clock_read(
    tx: &mut Transaction,
    now: i64,
    memory: &std::sync::atomic::AtomicI64,
) -> Result<i64> {
    use std::sync::atomic::Ordering;
    let rows = tx
        .fetch::<1>(
            "SELECT CAST(observed AS TEXT) FROM nx_clock WHERE singleton=1",
            &[],
        )
        .await?;
    let previous: i64 = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("clock missing"))?[0]
        .parse()?;
    ensure!(now >= 0 && previous >= 0, "invalid clock");
    let prior = memory.fetch_max(now, Ordering::Relaxed);
    let high = previous.max(prior);
    ensure!(
        high.saturating_sub(now) <= CLOCK_ROLLBACK_TOLERANCE,
        "clock moved backwards beyond tolerance; use recover-clock with a fresh host key"
    );
    Ok(now.max(high))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_envelopes_hide_clock_and_scope_and_reject_any_tampering() {
        let keys = HostKeys::generate().unwrap();
        let restored: HostKeys =
            serde_json::from_slice(&serde_json::to_vec(&keys).unwrap()).unwrap();
        for kind in [
            TokenKind::Login,
            TokenKind::Session,
            TokenKind::Submission {
                contract: "approved-contract".into(),
                action: 5,
                version: 3,
                target: Some(RecordTarget {
                    resource: 1,
                    id: 42,
                    incarnation: "record-incarnation".into(),
                    revision: 2,
                    route: 1,
                }),
            },
        ] {
            let (token, encoded) = keys
                .issue(kind.clone(), "private-subject", 1_800_000_000, 900)
                .unwrap();
            let envelope = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
            assert_eq!(envelope[0], 2);
            assert!(serde_json::from_slice::<serde_json::Value>(&envelope).is_err());
            for marker in [
                b"issued".as_slice(),
                b"expires",
                b"1800000000",
                b"private-subject",
                keys.incarnation.as_bytes(),
            ] {
                assert!(!envelope.windows(marker.len()).any(|part| part == marker));
            }
            let verified = restored.verify(&encoded, 1_800_000_001).unwrap();
            assert_eq!(verified.kind, kind);
            assert_eq!(verified.nonce, token.nonce);
            assert_eq!(verified.issued, token.issued);
            assert_eq!(verified.expires, token.expires);
            let (_, second) = keys
                .issue(kind, "private-subject", 1_800_000_000, 900)
                .unwrap();
            assert_ne!(
                &envelope[1..25],
                &URL_SAFE_NO_PAD.decode(second).unwrap()[1..25]
            );
            for i in 0..envelope.len() {
                let mut damaged = envelope.clone();
                damaged[i] ^= 1;
                assert!(
                    keys.verify(&URL_SAFE_NO_PAD.encode(damaged), 1_800_000_001)
                        .is_err(),
                    "offset {i}"
                );
            }
            for length in 0..envelope.len() {
                assert!(
                    keys.verify(&URL_SAFE_NO_PAD.encode(&envelope[..length]), 1_800_000_001)
                        .is_err()
                );
            }
            assert!(restored.verify(&encoded, 1_800_000_900).is_err());
            assert!(
                HostKeys::generate()
                    .unwrap()
                    .verify(&encoded, 1_800_000_001)
                    .is_err()
            );
        }
        let (_, encoded) = keys.issue(TokenKind::Login, "", 100, 900).unwrap();
        assert!(keys.verify(&format!("{encoded}.extra"), 100).is_err());
        assert!(keys.verify(&"A".repeat(2049), 100).is_err());
    }

    #[test]
    fn authenticated_expiry_subject_binding_and_incarnation() {
        let keys = HostKeys::generate().unwrap();
        let (_, signed) = keys.issue(TokenKind::Session, "alice", 100, 60).unwrap();
        assert_eq!(keys.verify(&signed, 159).unwrap().subject, "alice");
        assert!(keys.verify(&signed, 160).is_err());
        assert!(keys.verify(&signed, 99).is_err());
        assert!(HostKeys::generate().unwrap().verify(&signed, 100).is_err());
        let mut forged = signed.into_bytes();
        forged[5] = if forged[5] == b'A' { b'B' } else { b'A' };
        assert!(
            keys.verify(std::str::from_utf8(&forged).unwrap(), 100)
                .is_err()
        );
        assert!(keys.verify_csrf("alice", &keys.csrf("bob")).is_err());
    }
}

#[cfg(test)]
mod edit_tests {
    use super::*;
    #[test]
    fn edit_mac_is_domain_bound_and_old_versions_fail_under_every_key() {
        let mut keys = HostKeys {
            key: [8; 32],
            incarnation: "test".into(),
            edit_keys: vec![EditKey {
                id: 5,
                key: [7; 32],
                signing: true,
            }],
        };
        let old = keys.edit_secret(5, 3, 9, 1).unwrap();
        assert!(old == "nxc1.5.1.4fXgQvbcLyudujGVDF26-Anw47Dx4qtZ3UIBmv5Pr34");
        assert!(keys.verify_edit(&old, 3, 9, 1).is_ok());
        assert!(keys.verify_edit(&old, 4, 9, 1).is_err());
        assert!(keys.verify_edit(&old, 3, 10, 1).is_err());
        keys.rotate_edit_key().unwrap();
        assert_eq!(keys.signing_edit_key().unwrap(), 6);
        assert!(keys.verify_edit(&old, 3, 9, 1).is_ok());
        let newer = keys.edit_secret(6, 3, 9, 1).unwrap();
        for secret in [&old, &newer] {
            assert!(keys.verify_edit(secret, 3, 9, 2).is_err());
        }
        let rotated = keys.edit_secret(6, 3, 9, 2).unwrap();
        assert!(keys.verify_edit(&rotated, 3, 9, 2).is_ok());
        let mut bad = rotated.into_bytes();
        *bad.last_mut().unwrap() ^= 1;
        assert!(
            keys.verify_edit(std::str::from_utf8(&bad).unwrap(), 3, 9, 2)
                .is_err()
        );
        let legacy = serde_json::json!({"key":vec![8;32],"incarnation":"legacy"});
        let legacy: HostKeys = serde_json::from_value(legacy).unwrap();
        assert!(legacy.signing_edit_key().is_err());
    }
}
