//! Opaque blob identities and hard ceilings. Identity alone grants no access.
//!
//! File bytes never use this wire format. Hosts independently authorize a
//! resource/field before resolving a blob, and a bound upload before attachment.
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_UPLOAD_BYTES: u64 = 10 * 1024 * 1024;
pub const MAX_APP_BLOB_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_APP_BLOB_OBJECTS: u32 = 65_536;
pub const MAX_LIVE_STAGES: u8 = 4;
pub const MAX_CONCURRENT_UPLOADS: u8 = 4;
pub const MAX_CONCURRENT_DOWNLOADS: u8 = 8;
pub const TRANSFER_BUFFER_BYTES: usize = 64 * 1024;
pub const STAGE_LIFETIME_MILLIS: i64 = 15 * 60 * 1000;
pub const DOWNLOAD_IDLE_MILLIS: u64 = 15 * 1000;
pub const TRANSFER_TOTAL_MILLIS: u64 = 120 * 1000;

macro_rules! opaque {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            /// Validates encoding only. This does not establish authority.
            pub fn parse(value: String) -> Result<Self, String> {
                let suffix = value.strip_prefix($prefix).ok_or("invalid blob token")?;
                if suffix.len() != 64
                    || !suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("invalid blob token".into());
                }
                Ok(Self(value))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = String;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}
opaque!(BlobRef, "b1_");
opaque!(UploadHandle, "u1_");

/// Deployment ceilings; operator policy may lower every field, never raise it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobLimits {
    pub file_bytes: u64,
    pub app_bytes: u64,
    pub objects: u32,
    pub live_stages: u8,
    pub uploads: u8,
    pub downloads: u8,
}
impl Default for BlobLimits {
    fn default() -> Self {
        Self {
            file_bytes: MAX_UPLOAD_BYTES,
            app_bytes: MAX_APP_BLOB_BYTES,
            objects: MAX_APP_BLOB_OBJECTS,
            live_stages: MAX_LIVE_STAGES,
            uploads: MAX_CONCURRENT_UPLOADS,
            downloads: MAX_CONCURRENT_DOWNLOADS,
        }
    }
}
impl BlobLimits {
    pub fn validate(self) -> Result<(), String> {
        if self.file_bytes == 0
            || self.file_bytes > MAX_UPLOAD_BYTES
            || self.app_bytes == 0
            || self.app_bytes > MAX_APP_BLOB_BYTES
            || self.file_bytes > self.app_bytes
            || self.objects == 0
            || self.objects > MAX_APP_BLOB_OBJECTS
            || self.live_stages == 0
            || self.live_stages > MAX_LIVE_STAGES
            || self.uploads == 0
            || self.uploads > MAX_CONCURRENT_UPLOADS
            || self.downloads == 0
            || self.downloads > MAX_CONCURRENT_DOWNLOADS
        {
            return Err("invalid blob limits".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens_are_distinct_canonical_and_redacted() {
        let blob = BlobRef::parse(format!("b1_{}", "a".repeat(64))).unwrap();
        let upload = UploadHandle::parse(format!("u1_{}", "b".repeat(64))).unwrap();
        assert!(UploadHandle::parse(blob.as_str().into()).is_err());
        assert!(BlobRef::parse(upload.as_str().into()).is_err());
        for bad in [
            "../x".into(),
            format!("b1_{}", "A".repeat(64)),
            format!("b1_{}", "a".repeat(63)),
            format!("b1_{}", "a".repeat(65)),
            format!("b1_{}", "0".repeat(63) + "/"),
        ] {
            assert!(BlobRef::parse(bad).is_err());
        }
        assert_eq!(format!("{blob:?}"), "BlobRef([redacted])");
        assert_eq!(
            serde_json::from_str::<BlobRef>(&serde_json::to_string(&blob).unwrap()).unwrap(),
            blob
        );
        assert!(serde_json::from_str::<BlobRef>("123").is_err());
    }
    #[test]
    fn operator_limits_only_lower_hard_ceilings() {
        let defaults = BlobLimits::default();
        defaults.validate().unwrap();
        let lower = BlobLimits {
            file_bytes: 2,
            app_bytes: 3,
            objects: 1,
            live_stages: 1,
            uploads: 1,
            downloads: 1,
        };
        lower.validate().unwrap();
        for bad in [
            BlobLimits {
                file_bytes: MAX_UPLOAD_BYTES + 1,
                ..defaults
            },
            BlobLimits {
                app_bytes: MAX_APP_BLOB_BYTES + 1,
                ..defaults
            },
            BlobLimits {
                objects: MAX_APP_BLOB_OBJECTS + 1,
                ..defaults
            },
            BlobLimits {
                objects: 0,
                ..defaults
            },
            BlobLimits {
                live_stages: 5,
                ..defaults
            },
            BlobLimits {
                uploads: 5,
                ..defaults
            },
            BlobLimits {
                downloads: 9,
                ..defaults
            },
            BlobLimits {
                file_bytes: 0,
                ..defaults
            },
            BlobLimits {
                app_bytes: 1,
                ..defaults
            },
            BlobLimits {
                downloads: 0,
                ..defaults
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }
}
