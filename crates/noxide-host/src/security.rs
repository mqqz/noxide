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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TokenKind {
    Login,
    Session,
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
        Ok(Self {
            key,
            incarnation: random_id()?,
        })
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

pub(crate) async fn observe_clock(tx: &mut Transaction, now: i64) -> Result<()> {
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
    ensure!(now >= previous, "clock moved backwards; admission fenced");
    if now > previous {
        tx.execute(
            "UPDATE nx_clock SET observed=$1 WHERE singleton=1 AND observed<$1",
            &[Param::Number(now)],
        )
        .await?;
    }
    Ok(())
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
        // Reject the old readable HMAC envelope even with a valid old signature.
        let (token, _) = keys.issue(TokenKind::Login, "", 100, 900).unwrap();
        let body = serde_json::to_vec(&token).unwrap();
        let mac = keys.mac(b"noxide/token/v1", &body).finalize().into_bytes();
        let old = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(body),
            URL_SAFE_NO_PAD.encode(mac)
        );
        assert!(keys.verify(&old, 100).is_err());
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
