//! The groups of state an `Application` holds.
use super::*;

/// What this deployment is: the admitted contract and the identities derived from it.
pub struct Identity {
    pub manifest: Arc<Manifest>,
    pub(crate) plans: BTreeMap<u32, Arc<crate::query_plan::ListPlan>>,
    pub(super) contract: String,
    pub(super) deployment: String,
    pub(super) generation: OnceLock<String>,
}

/// How this deployment appears over HTTP.
pub struct Web {
    pub presentation: crate::Presentation,
    pub assets: Arc<crate::assets::AssetBundle>,
    pub asset_responses: Arc<tokio::sync::Semaphore>,
    pub registration: auth::Registration,
}

/// The ceilings every request is admitted under.
pub struct RequestLimits {
    pub admission: AdmissionLimits,
    pub(super) database_statements: u16,
}

/// Optional features, each present only when the deployment approved it.
pub struct Services {
    pub blobs: Option<blobs::BlobRuntime>,
    pub(super) jobs: Option<job_worker::JobRuntime>,
    pub(super) effects: Option<effect_worker::EffectRuntime>,
}

/// Observed time and the maintenance that records it.
pub(super) struct Time {
    pub(super) observed: AtomicI64,
    pub(super) checkpointed: AtomicI64,
    pub(super) freshness: crate::lifecycle_clock::Freshness,
    pub(super) maintenance: Arc<tokio::sync::Semaphore>,
    pub(super) maintenance_running: std::sync::atomic::AtomicBool,
}
