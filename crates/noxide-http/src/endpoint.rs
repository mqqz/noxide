//! What a request is for, decided once from its method and path. Admission chooses a
//! class and deadline from this before any handler runs, so they cannot disagree.
use crate::{Application, limiter::RequestClass};
use noxide_protocol::{Operation, Route};
use std::time::Duration;

pub(super) enum Endpoint<'a> {
    Download,
    Asset,
    ClosedRegistration,
    Account,
    Registration,
    Stylesheet(&'a str),
    Login,
    Logout,
    Capability {
        resource: u32,
        id: u64,
    },
    Page {
        route: &'a Route,
        target: Option<u64>,
    },
    Action {
        id: u32,
        operation: &'a Operation,
    },
    NotFound,
}

impl<'a> Endpoint<'a> {
    pub(super) fn classify(app: &'a Application, is_get: bool, path: &str) -> Self {
        let presentation = app.presentation();
        if path == "/_noxide/download" {
            return Self::Download;
        }
        if path.starts_with(noxide_protocol::assets::ASSET_PATH_PREFIX) {
            return Self::Asset;
        }
        if path == presentation.registration_path {
            return if app.registration() == crate::Registration::Closed {
                Self::ClosedRegistration
            } else {
                Self::Registration
            };
        }
        if path == presentation.login_path {
            return Self::Login;
        }
        if is_get {
            if path == presentation.account_path {
                return Self::Account;
            }
            if path == presentation.stylesheet_path
                && let Some(css) = &presentation.stylesheet
            {
                return Self::Stylesheet(css);
            }
        }
        if let Some((resource, id)) = capability_path(path, presentation) {
            return Self::Capability { resource, id };
        }
        if path == presentation.logout_path {
            return Self::Logout;
        }
        if is_get {
            return app
                .manifest()
                .routes
                .iter()
                .find_map(|route| {
                    crate::render::match_path(route, path)
                        .map(|target| Self::Page { route, target })
                })
                .unwrap_or(Self::NotFound);
        }
        path.strip_prefix(&format!("{}/", presentation.action_path))
            .and_then(|id| id.parse().ok())
            .and_then(|id| {
                let action = crate::manifest::web_action(app.manifest(), id).ok()?;
                let operation =
                    crate::manifest::operation(app.manifest(), action.steps[0].operation).ok()?;
                Some(Self::Action { id, operation })
            })
            .unwrap_or(Self::NotFound)
    }

    pub(super) fn class(&self, is_get: bool) -> RequestClass {
        if is_get {
            return RequestClass::Get;
        }
        match self {
            Self::Login | Self::Registration | Self::ClosedRegistration => {
                RequestClass::PasswordHash
            }
            Self::Capability { .. } => RequestClass::AnonymousAction,
            Self::Action { operation, .. } if crate::manifest::anonymous_action(operation) => {
                RequestClass::AnonymousAction
            }
            _ => RequestClass::AuthenticatedAction,
        }
    }

    /// The deadline for this request, or `None` for the guest's wall time.
    pub(super) fn deadline(&self, class: RequestClass) -> Option<Duration> {
        if matches!(class, RequestClass::PasswordHash) {
            return Some(Duration::from_secs(3));
        }
        matches!(
            self,
            Self::Login | Self::Registration | Self::ClosedRegistration | Self::Logout
        )
        .then(|| Duration::from_secs(2))
    }
}

fn capability_path(path: &str, presentation: &crate::Presentation) -> Option<(u32, u64)> {
    let (resource, id) = path
        .strip_prefix(&format!("{}/", presentation.capability_path))?
        .split_once('/')?;
    let r: u32 = resource.parse().ok()?;
    let n: u64 = id.parse().ok()?;
    (r > 0 && n > 0 && n <= i64::MAX as u64 && r.to_string() == resource && n.to_string() == id)
        .then_some((r, n))
}
