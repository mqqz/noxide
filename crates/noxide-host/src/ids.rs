//! Host-generated identifiers and wall-clock seconds.
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};

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

pub(crate) fn now() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
