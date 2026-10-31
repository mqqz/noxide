//! One deployment approval identity covering requested contract and effective
//! blob ceilings. Pure review helpers never open paths, keys or object stores.
use crate::{assets::AssetBundle, manifest};
use anyhow::{Result, ensure};
use noxide_protocol::{
    Manifest,
    blobs::{BlobCeilings, BlobPolicy},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobDeployment {
    pub directory: PathBuf,
    pub ceilings: BlobCeilings,
}

/// The constructor accepts one set of local deployment resources. It must
/// verify approval before opening a store and bind store identity before ready.
pub struct DeploymentResources {
    pub assets: AssetBundle,
    pub blobs: Option<BlobDeployment>,
}

pub struct DeploymentApproval {
    pub manifest_digest: [u8; 32],
    pub effective: Option<BlobPolicy>,
    pub digest: [u8; 32],
}

/// Requires an independently admitted manifest. During the wire10 checkpoint,
/// manifests with blobs still fail that admission until runtime enforcement is
/// complete. Operator paths are absent from this pure function's signature.
pub fn approval(
    manifest: &Manifest,
    ceilings: Option<&BlobCeilings>,
) -> Result<DeploymentApproval> {
    let manifest_digest = manifest::digest(manifest)?;
    let effective = match (&manifest.blobs, ceilings) {
        (None, None) => None,
        (None, Some(_)) => anyhow::bail!("blob configuration has no requested blob policy"),
        (Some(_), None) => {
            anyhow::bail!("blob policy requires explicit operator ceilings and store configuration")
        }
        (Some(policy), Some(ceilings)) => {
            Some(policy.effective(ceilings).map_err(anyhow::Error::msg)?)
        }
    };
    let digest = compose(manifest_digest, effective.as_ref())?;
    Ok(DeploymentApproval {
        manifest_digest,
        effective,
        digest,
    })
}
pub fn approval_digest(manifest: &Manifest, ceilings: Option<&BlobCeilings>) -> Result<[u8; 32]> {
    Ok(approval(manifest, ceilings)?.digest)
}

fn compose(requested: [u8; 32], effective: Option<&BlobPolicy>) -> Result<[u8; 32]> {
    let Some(effective) = effective else {
        return Ok(requested);
    };
    effective.validate_limits().map_err(anyhow::Error::msg)?;
    let mut effective = effective.clone();
    effective.uploads.sort_by_key(|upload| upload.id);
    let bytes = serde_json::to_vec(&effective)?;
    ensure!(
        bytes.len() <= noxide_protocol::MAX_MANIFEST_BYTES,
        "effective blob policy limit"
    );
    let mut digest = Sha256::new();
    digest.update(b"noxide/blob-deployment/v1\0");
    digest.update(requested);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxide_protocol::blobs::*;
    fn policy() -> BlobPolicy {
        BlobPolicy {
            limits: BlobLimits::default(),
            anonymous: None,
            uploads: vec![UploadBinding {
                id: 1,
                name: "file".into(),
                web_binding: 2,
                input: "attachment".into(),
                anonymous: None,
            }],
        }
    }
    #[test]
    fn no_blob_has_one_natural_identity_and_rejects_unused_store_configuration() {
        let manifest = crate::test_support::manifest();
        let expected = manifest::digest(&manifest).unwrap();
        let result = approval(&manifest, None).unwrap();
        assert_eq!(result.digest, expected);
        assert_eq!(result.manifest_digest, expected);
        assert!(result.effective.is_none());
        assert_eq!(approval_digest(&manifest, None).unwrap(), expected);
        assert!(approval(&manifest, Some(&BlobCeilings::default())).is_err());
    }
    #[test]
    fn composite_hash_binds_effective_quota_and_requested_contract() {
        let requested = [42; 32];
        let policy = policy();
        let original = compose(requested, Some(&policy)).unwrap();
        assert_ne!(original, requested);
        assert_ne!(compose([43; 32], Some(&policy)).unwrap(), original);
        let defaults = policy.limits;
        for limits in [
            BlobLimits {
                file_bytes: defaults.file_bytes - 1,
                ..defaults
            },
            BlobLimits {
                app_bytes: defaults.app_bytes - 1,
                ..defaults
            },
            BlobLimits {
                objects: defaults.objects - 1,
                ..defaults
            },
            BlobLimits {
                live_stages: defaults.live_stages - 1,
                ..defaults
            },
            BlobLimits {
                uploads: defaults.uploads - 1,
                ..defaults
            },
            BlobLimits {
                downloads: defaults.downloads - 1,
                ..defaults
            },
        ] {
            let changed = policy
                .effective(&BlobCeilings {
                    limits,
                    anonymous: None,
                })
                .unwrap();
            assert_ne!(compose(requested, Some(&changed)).unwrap(), original);
        }
    }
    #[test]
    fn anonymous_caps_bind_hash_but_upload_declaration_order_does_not() {
        let mut policy = policy();
        policy.anonymous = Some(AnonymousDeploymentQuota {
            stages: 16,
            bytes: MAX_ANONYMOUS_BYTES,
        });
        policy.uploads[0].anonymous = Some(AnonymousCapabilityQuota {
            stages: 4,
            bytes: MAX_CAPABILITY_BYTES,
        });
        policy.uploads.push(UploadBinding {
            id: 2,
            name: "other".into(),
            web_binding: 3,
            input: "other".into(),
            anonymous: None,
        });
        let original = compose([42; 32], Some(&policy)).unwrap();
        let mut reordered = policy.clone();
        reordered.uploads.reverse();
        assert_eq!(compose([42; 32], Some(&reordered)).unwrap(), original);
        let mut changes = Vec::new();
        let mut p = policy.clone();
        p.anonymous.as_mut().unwrap().bytes -= 1;
        changes.push(p);
        let mut p = policy.clone();
        p.anonymous.as_mut().unwrap().stages -= 1;
        changes.push(p);
        let mut p = policy.clone();
        p.uploads[0].anonymous.as_mut().unwrap().bytes -= 1;
        changes.push(p);
        let mut p = policy.clone();
        p.uploads[0].anonymous.as_mut().unwrap().stages -= 1;
        changes.push(p);
        for changed in changes {
            assert_ne!(compose([42; 32], Some(&changed)).unwrap(), original);
        }
    }
    #[test]
    fn paths_are_outside_effective_policy_and_composite_identity() {
        let a = BlobDeployment {
            directory: PathBuf::from("/must-not-open/a"),
            ceilings: BlobCeilings::default(),
        };
        let b = BlobDeployment {
            directory: PathBuf::from("/must-not-open/b"),
            ceilings: a.ceilings.clone(),
        };
        let requested = policy();
        let pa = requested.effective(&a.ceilings).unwrap();
        let pb = requested.effective(&b.ceilings).unwrap();
        assert_eq!(
            compose([42; 32], Some(&pa)).unwrap(),
            compose([42; 32], Some(&pb)).unwrap()
        );
        assert_ne!(
            serde_json::to_vec(&a).unwrap(),
            serde_json::to_vec(&b).unwrap()
        );
    }
}
