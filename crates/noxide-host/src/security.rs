use crate::database::{Param, Transaction};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
    },
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
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("fixed HMAC key length");
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
        let signature = self.mac(b"noxide/token/v1", &bytes).finalize().into_bytes();
        Ok((
            token,
            format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(bytes),
                URL_SAFE_NO_PAD.encode(signature)
            ),
        ))
    }
    pub(crate) fn verify(&self, signed: &str, now: i64) -> Result<Token> {
        ensure!(signed.len() <= 2048, "token limit");
        let (body, signature) = signed
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("invalid token"))?;
        let body = URL_SAFE_NO_PAD.decode(body)?;
        let signature = URL_SAFE_NO_PAD.decode(signature)?;
        self.mac(b"noxide/token/v1", &body)
            .verify_slice(&signature)
            .map_err(|_| anyhow::anyhow!("invalid token"))?;
        let token: Token = serde_json::from_slice(&body)?;
        ensure!(
            token.incarnation == self.incarnation
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
