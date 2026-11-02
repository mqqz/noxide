//! Operator configuration for the blob directory.
use noxide_protocol::blobs::BlobCeilings;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobDeployment {
    pub directory: PathBuf,
    pub ceilings: BlobCeilings,
}
