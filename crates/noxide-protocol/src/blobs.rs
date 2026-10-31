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
pub const MAX_UPLOAD_BINDINGS: usize = 16;
pub const MAX_ANONYMOUS_STAGES: u8 = 16;
pub const MAX_ANONYMOUS_BYTES: u64 = 160 * 1024 * 1024;
pub const MAX_CAPABILITY_BYTES: u64 = 40 * 1024 * 1024;
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
    pub fn intersection(self, other: Self) -> Result<Self, String> {
        self.validate()?;
        other.validate()?;
        let value = Self {
            file_bytes: self.file_bytes.min(other.file_bytes),
            app_bytes: self.app_bytes.min(other.app_bytes),
            objects: self.objects.min(other.objects),
            live_stages: self.live_stages.min(other.live_stages),
            uploads: self.uploads.min(other.uploads),
            downloads: self.downloads.min(other.downloads),
        };
        value.validate()?;
        Ok(value)
    }
}

/// Requested authority belongs to the manifest; operator ceilings intersect it.
/// Paths, keys, file bytes and store identity are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPolicy {
    pub limits: BlobLimits,
    pub anonymous: Option<AnonymousDeploymentQuota>,
    pub uploads: Vec<UploadBinding>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadBinding {
    pub id: u32,
    pub name: String,
    pub web_binding: u32,
    pub input: String,
    pub anonymous: Option<AnonymousCapabilityQuota>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnonymousDeploymentQuota {
    pub stages: u8,
    pub bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnonymousCapabilityQuota {
    pub stages: u8,
    pub bytes: u64,
}

/// Operator configuration, never guest authority. Anonymous staging is denied
/// unless both requested by the app and explicitly allowed by this policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobCeilings {
    pub limits: BlobLimits,
    pub anonymous: Option<AnonymousCeilings>,
}
impl Default for BlobCeilings {
    fn default() -> Self {
        Self {
            limits: BlobLimits::default(),
            anonymous: None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnonymousCeilings {
    pub deployment: AnonymousDeploymentQuota,
    pub capability: AnonymousCapabilityQuota,
}

impl AnonymousDeploymentQuota {
    pub fn validate(self) -> Result<(), String> {
        if self.stages == 0
            || self.stages > MAX_ANONYMOUS_STAGES
            || self.bytes == 0
            || self.bytes > MAX_ANONYMOUS_BYTES
        {
            return Err("invalid anonymous deployment quota".into());
        }
        Ok(())
    }
}
impl AnonymousCapabilityQuota {
    pub fn validate(self) -> Result<(), String> {
        if self.stages == 0
            || self.stages > MAX_LIVE_STAGES
            || self.bytes == 0
            || self.bytes > MAX_CAPABILITY_BYTES
        {
            return Err("invalid anonymous capability quota".into());
        }
        Ok(())
    }
}
impl BlobPolicy {
    /// Cross references, identifier grammar and field/action assignment checks
    /// remain independent host admission; this validates bounded quota shape.
    pub fn validate_limits(&self) -> Result<(), String> {
        self.limits.validate()?;
        if self.uploads.len() > MAX_UPLOAD_BINDINGS {
            return Err("upload binding limit".into());
        }
        if let Some(quota) = self.anonymous {
            quota.validate()?;
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut bindings = std::collections::BTreeSet::new();
        for upload in &self.uploads {
            if upload.id == 0
                || upload.web_binding == 0
                || !ids.insert(upload.id)
                || !bindings.insert(upload.web_binding)
            {
                return Err("duplicate or invalid upload binding".into());
            }
            if let Some(quota) = upload.anonymous {
                quota.validate()?;
                if self.anonymous.is_none() {
                    return Err("anonymous upload lacks deployment quota".into());
                }
            }
        }
        if self.anonymous.is_some() && !self.uploads.iter().any(|u| u.anonymous.is_some()) {
            return Err("unused anonymous deployment quota".into());
        }
        Ok(())
    }
    /// The returned SAME typed policy is the effective granted authority. Its
    /// canonical serialization participates in the deployment approval digest.
    pub fn effective(&self, operator: &BlobCeilings) -> Result<Self, String> {
        self.validate_limits()?;
        operator.limits.validate()?;
        if let Some(anonymous) = operator.anonymous {
            anonymous.deployment.validate()?;
            anonymous.capability.validate()?;
        }
        let mut effective = self.clone();
        effective.limits = self.limits.intersection(operator.limits)?;
        if let Some(requested) = self.anonymous {
            let granted = operator
                .anonymous
                .ok_or("anonymous uploads not approved by operator")?;
            effective.anonymous = Some(AnonymousDeploymentQuota {
                stages: requested.stages.min(granted.deployment.stages),
                bytes: requested.bytes.min(granted.deployment.bytes),
            });
            for upload in &mut effective.uploads {
                if let Some(requested) = upload.anonymous {
                    upload.anonymous = Some(AnonymousCapabilityQuota {
                        stages: requested.stages.min(granted.capability.stages),
                        bytes: requested.bytes.min(granted.capability.bytes),
                    });
                }
            }
        }
        effective.validate_limits()?;
        effective.uploads.sort_by_key(|u| u.id);
        Ok(effective)
    }
}

/// This requests a link to an independently authorized direct Read, not a URL
/// or a grant. The host resolves current provenance, projection and incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentDownload {
    pub read: u32,
    pub target: u64,
    pub field: String,
    pub text: String,
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

    fn policy() -> BlobPolicy {
        BlobPolicy {
            limits: BlobLimits::default(),
            anonymous: None,
            uploads: vec![UploadBinding {
                id: 1,
                name: "attachment".into(),
                web_binding: 2,
                input: "file".into(),
                anonymous: None,
            }],
        }
    }
    #[test]
    fn requested_policy_intersects_operator_limits_without_granting_anonymous() {
        let requested = policy();
        let operator = BlobCeilings {
            limits: BlobLimits {
                file_bytes: 10,
                app_bytes: 100,
                objects: 3,
                live_stages: 1,
                uploads: 1,
                downloads: 2,
            },
            anonymous: None,
        };
        let effective = requested.effective(&operator).unwrap();
        assert_eq!(effective.limits, operator.limits);
        assert_eq!(effective.uploads, requested.uploads);
        assert_eq!(effective.anonymous, None);
        assert_eq!(
            effective.effective(&BlobCeilings::default()).unwrap(),
            effective
        );
        let mut requested = requested;
        requested.anonymous = Some(AnonymousDeploymentQuota {
            stages: 16,
            bytes: MAX_ANONYMOUS_BYTES,
        });
        requested.uploads[0].anonymous = Some(AnonymousCapabilityQuota {
            stages: 4,
            bytes: MAX_CAPABILITY_BYTES,
        });
        assert!(requested.effective(&BlobCeilings::default()).is_err());
        let operator = BlobCeilings {
            limits: BlobLimits::default(),
            anonymous: Some(AnonymousCeilings {
                deployment: AnonymousDeploymentQuota {
                    stages: 2,
                    bytes: 1000,
                },
                capability: AnonymousCapabilityQuota {
                    stages: 1,
                    bytes: 500,
                },
            }),
        };
        let effective = requested.effective(&operator).unwrap();
        assert_eq!(
            effective.anonymous,
            Some(operator.anonymous.unwrap().deployment)
        );
        assert_eq!(
            effective.uploads[0].anonymous,
            Some(operator.anonymous.unwrap().capability)
        );
    }
    #[test]
    fn policy_rejects_anonymous_or_binding_ambiguities_and_oversized_quotas() {
        let mut requested = policy();
        requested.uploads.push(requested.uploads[0].clone());
        assert!(requested.validate_limits().is_err());
        let mut requested = policy();
        requested.anonymous = Some(AnonymousDeploymentQuota {
            stages: 16,
            bytes: MAX_ANONYMOUS_BYTES,
        });
        assert!(requested.validate_limits().is_err());
        let mut requested = policy();
        requested.uploads[0].anonymous = Some(AnonymousCapabilityQuota {
            stages: 4,
            bytes: MAX_CAPABILITY_BYTES,
        });
        assert!(requested.validate_limits().is_err());
        for quota in [
            AnonymousDeploymentQuota {
                stages: 17,
                bytes: 1,
            },
            AnonymousDeploymentQuota {
                stages: 0,
                bytes: 1,
            },
            AnonymousDeploymentQuota {
                stages: 1,
                bytes: MAX_ANONYMOUS_BYTES + 1,
            },
        ] {
            assert!(quota.validate().is_err());
        }
        for quota in [
            AnonymousCapabilityQuota {
                stages: 5,
                bytes: 1,
            },
            AnonymousCapabilityQuota {
                stages: 1,
                bytes: 0,
            },
            AnonymousCapabilityQuota {
                stages: 1,
                bytes: MAX_CAPABILITY_BYTES + 1,
            },
        ] {
            assert!(quota.validate().is_err());
        }
        let mut requested = policy();
        for id in 2..=17 {
            requested.uploads.push(UploadBinding {
                id,
                name: format!("upload{id}"),
                web_binding: id + 1,
                input: "file".into(),
                anonymous: None,
            });
        }
        assert!(requested.validate_limits().is_err());
    }
}
