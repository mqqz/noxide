pub(crate) use crate::ids::{now, random_id, record_id};
#[cfg(test)]
pub(crate) use crate::lifecycle_clock::CLOCK_PERSIST_LAG;
pub(crate) use crate::lifecycle_clock::{
    CLOCK_CHECKPOINT_BEGIN_DEADLINE, observe_clock, observe_clock_bounded, observe_clock_read,
};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide_keys::{KeyMaterial, Keys, TokenDomain};
use serde::{Deserialize, Serialize};

/// Host keys, held locally or behind the key service. Everything here is token
/// and capability logic over key operations; no key bytes reach this crate.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostKeys(Keys);

/// Constant-time comparison, without trusting supplied MAC length.
fn verify_mac(expected: &[u8; 32], supplied: &[u8]) -> bool {
    supplied.len() == expected.len()
        && expected
            .iter()
            .zip(supplied)
            .fold(0, |difference, (a, b)| difference | (a ^ b))
            == 0
}

pub(crate) const ANONYMOUS_TTL: i64 = 900;
pub(crate) const MAX_TOKEN_BYTES: usize = 2048;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TokenKind {
    Cursor {
        scope: String,
        after: noxide_protocol::query::CursorKey,
    },
    Download {
        contract: String,
        read: u32,
        target: RecordTarget,
        field: String,
        blob: noxide_protocol::blobs::BlobRef,
    },
    Login,
    Session,
    Anonymous,
    Selection {
        contract: String,
        action: u32,
        binding: u32,
        name: String,
        query: u32,
        eligible: u32,
        targets: std::collections::BTreeMap<String, RecordTarget>,
    },
    AnonymousSubmission {
        contract: String,
        /// Web binding ID; zero is reserved for host edit-key rotation.
        action: u32,
        /// Web binding version, independent of the canonical action version.
        version: u32,
        targets: std::collections::BTreeMap<String, RecordTarget>,
    },
    Submission {
        contract: String,
        /// Web binding ID; zero is reserved for host edit-key rotation.
        action: u32,
        /// Web binding version, independent of the canonical action version.
        version: u32,
        targets: std::collections::BTreeMap<String, RecordTarget>,
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
    /// Issuing web route; absent for non-browser sealed identities.
    pub route: Option<u32>,
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

impl HostKeys {
    pub fn incarnation(&self) -> &str {
        self.0.incarnation()
    }
    pub fn generate() -> Result<Self> {
        Ok(Self(Keys::Local(KeyMaterial::generate()?)))
    }
    /// Operate through a running key service.
    pub fn remote(client: noxide_keys::KeyClient) -> Self {
        Self(Keys::Remote(client))
    }
    pub fn rotate_edit_key(&mut self) -> Result<()> {
        match &mut self.0 {
            Keys::Local(material) => material.rotate_edit_key(),
            Keys::Remote(_) => anyhow::bail!("rotate keys in the key file"),
        }
    }
    pub(crate) fn signing_edit_key(&self) -> Result<u32> {
        self.0.signing_edit_key()
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
            URL_SAFE_NO_PAD.encode(self.0.edit_mac(key_id, resource, id, version)?)
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
        ensure!(
            verify_mac(
                &self.0.edit_mac(key, resource, id, supplied)?,
                &URL_SAFE_NO_PAD.decode(parts[3])?
            ),
            "invalid edit secret"
        );
        Ok(())
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
            incarnation: self.incarnation().to_owned(),
        };
        let cursor = matches!(token.kind, TokenKind::Cursor { .. });
        let bytes = serde_json::to_vec(&token)?;
        let domain = if cursor {
            TokenDomain::Cursor
        } else {
            TokenDomain::Token
        };
        let envelope = self.0.seal(domain, &bytes)?;
        let encoded = URL_SAFE_NO_PAD.encode(envelope);
        ensure!(encoded.len() <= MAX_TOKEN_BYTES, "token limit");
        Ok((token, encoded))
    }
    pub(crate) fn verify(&self, encoded: &str, now: i64) -> Result<Token> {
        self.verify_domain(encoded, now, false, false)
    }
    pub(crate) fn verify_cursor(&self, encoded: &str, now: i64) -> Result<Token> {
        self.verify_domain(encoded, now, true, false)
    }
    /// Only selection proof verification defers expiry until after receipt lookup.
    pub(crate) fn verify_selection(&self, encoded: &str, now: i64) -> Result<Token> {
        let token = self.verify_domain(encoded, now, false, true)?;
        ensure!(
            matches!(token.kind, TokenKind::Selection { .. }),
            "not a selection proof"
        );
        Ok(token)
    }
    fn verify_domain(
        &self,
        encoded: &str,
        now: i64,
        cursor: bool,
        selection: bool,
    ) -> Result<Token> {
        ensure!(encoded.len() <= MAX_TOKEN_BYTES, "token limit");
        let envelope = URL_SAFE_NO_PAD.decode(encoded)?;
        let domain = if cursor {
            TokenDomain::Cursor
        } else {
            TokenDomain::Token
        };
        let plaintext = self.0.open(domain, &envelope)?;
        let token: Token = serde_json::from_slice(&plaintext)?;
        ensure!(
            token.incarnation == self.incarnation()
                && token.issued >= 0
                && token.issued < token.expires
                && token.issued <= now
                && (now < token.expires
                    || selection && matches!(token.kind, TokenKind::Selection { .. }))
                && token.expires - token.issued <= 86400,
            "expired token or authority"
        );
        Ok(token)
    }
    pub(crate) fn csrf(&self, subject: &str) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(self.0.csrf(subject)?))
    }
    pub(crate) fn verify_csrf(&self, subject: &str, value: &str) -> Result<()> {
        ensure!(value.len() <= 64, "csrf length");
        ensure!(
            verify_mac(&self.0.csrf(subject)?, &URL_SAFE_NO_PAD.decode(value)?),
            "csrf mismatch"
        );
        Ok(())
    }
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
                targets: std::collections::BTreeMap::from([(
                    "target".into(),
                    RecordTarget {
                        resource: 1,
                        id: 42,
                        incarnation: "record-incarnation".into(),
                        revision: 2,
                        route: Some(1),
                    },
                )]),
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
                keys.incarnation().as_bytes(),
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
        assert!(
            keys.verify_csrf("alice", &keys.csrf("bob").unwrap())
                .is_err()
        );
    }
}

#[cfg(test)]
mod edit_tests {
    use super::*;
    #[test]
    fn edit_mac_is_domain_bound_and_old_versions_fail_under_every_key() {
        let mut keys: HostKeys = serde_json::from_value(serde_json::json!({
            "key": vec![8; 32],
            "incarnation": "test",
            "edit_keys": [{"id": 5, "key": vec![7; 32], "signing": true}],
        }))
        .unwrap();
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

#[cfg(test)]
mod cursor_tests {
    use super::*;
    #[test]
    fn typed_cursor_wire_rejects_legacy_and_unknown_key_shapes() {
        for after in [
            serde_json::json!(42),
            serde_json::json!({"created":{"sequence":42,"record":7,"unchecked":true}}),
            serde_json::json!({"created":{"sequence":-1,"record":7}}),
            serde_json::json!({"scalar":{"value":{"integer":"42"},"record":7}}),
        ] {
            assert!(
                serde_json::from_value::<TokenKind>(serde_json::json!({
                    "cursor":{"scope":"approved-context", "after":after}
                }))
                .is_err()
            );
        }
        let keys = HostKeys::generate().unwrap();
        let kind = TokenKind::Cursor {
            scope: "scalar-context".into(),
            after: noxide_protocol::query::CursorKey::Scalar {
                value: noxide_protocol::query::CursorValue::Binary("عربي".into()),
                record: 9,
            },
        };
        let (_, encoded) = keys.issue(kind.clone(), "", 100, 900).unwrap();
        assert_eq!(keys.verify_cursor(&encoded, 100).unwrap().kind, kind);
    }
    #[test]
    fn cursor_tokens_are_opaque_expiring_and_domain_separated() {
        let keys = HostKeys::generate().unwrap();
        let kind = TokenKind::Cursor {
            scope: "approved-context".into(),
            after: noxide_protocol::query::CursorKey::Created {
                sequence: 42,
                record: 7,
            },
        };
        let (_, encoded) = keys.issue(kind.clone(), "", 100, 900).unwrap();
        assert!(!encoded.contains("approved-context"));
        assert_eq!(keys.verify_cursor(&encoded, 100).unwrap().kind, kind);
        assert!(keys.verify(&encoded, 100).is_err());
        assert!(keys.verify_cursor(&encoded, 1000).is_err());
        assert!(
            HostKeys::generate()
                .unwrap()
                .verify_cursor(&encoded, 100)
                .is_err()
        );
        let (_, submission) = keys.issue(TokenKind::Login, "", 100, 900).unwrap();
        assert!(keys.verify_cursor(&submission, 100).is_err());
        let mut bad = encoded.into_bytes();
        bad[30] = if bad[30] == b'A' { b'B' } else { b'A' };
        assert!(
            keys.verify_cursor(std::str::from_utf8(&bad).unwrap(), 100)
                .is_err()
        );
    }
}
