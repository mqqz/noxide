//! Trusted deployment presentation; never supplied by a guest.
use anyhow::{Result, ensure};
use noxide_protocol::{Manifest, Route};
use serde::Deserialize;
use std::sync::LazyLock;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Presentation {
    pub session_cookie: String,
    pub login_cookie: String,
    pub anonymous_cookie: String,
    pub csrf_field: String,
    pub submission_field: String,
    pub capability_field: String,
    pub registration_path: String,
    /// Prefix without a trailing slash; resource and record IDs are appended.
    pub capability_path: String,
    pub login_path: String,
    pub account_path: String,
    pub logout_path: String,
    pub action_path: String,
    pub stylesheet_path: String,
    /// Local CSS in a deliberately URL-free subset. None means no stylesheet.
    pub stylesheet: Option<String>,
}
impl Default for Presentation {
    fn default() -> Self {
        Self {
            session_cookie: "session".into(),
            login_cookie: "login".into(),
            anonymous_cookie: "noxide_anon".into(),
            csrf_field: "_csrf".into(),
            submission_field: "_submission".into(),
            capability_field: "_capability".into(),
            registration_path: "/register".into(),
            capability_path: "/_noxide/capability".into(),
            login_path: "/login".into(),
            account_path: "/account".into(),
            logout_path: "/logout".into(),
            action_path: "/actions".into(),
            stylesheet_path: "/assets/site.css".into(),
            stylesheet: None,
        }
    }
}
pub(crate) static DEFAULT: LazyLock<Presentation> = LazyLock::new(Presentation::default);
impl Presentation {
    pub(crate) fn validate(&self, manifest: &Manifest) -> Result<()> {
        let cookies = [
            &self.session_cookie,
            &self.login_cookie,
            &self.anonymous_cookie,
        ];
        for (i, name) in cookies.iter().enumerate() {
            ensure!(
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
                "invalid cookie name"
            );
            ensure!(!cookies[..i].contains(name), "cookie names must differ");
        }
        let fields = [
            &self.csrf_field,
            &self.submission_field,
            &self.capability_field,
        ];
        for (i, name) in fields.iter().enumerate() {
            ensure!(
                !name.is_empty()
                    && name.len() <= 32
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
                "invalid host field name"
            );
            ensure!(!fields[..i].contains(name), "host field names must differ");
            ensure!(
                !["username", "password", "invite"].contains(&name.as_str())
                    && !manifest
                        .resources
                        .iter()
                        .any(|r| r.fields.iter().any(|f| &f.name == *name)),
                "host field overlaps application or authentication field"
            );
        }
        let paths: [&str; 7] = [
            &self.login_path,
            &self.account_path,
            &self.logout_path,
            &self.action_path,
            &self.stylesheet_path,
            &self.registration_path,
            &self.capability_path,
        ];
        for (i, path) in paths.iter().enumerate() {
            ensure!(
                path.len() <= 128
                    && path.starts_with('/')
                    && path.len() > 1
                    && path.split('/').skip(1).all(|s| !s.is_empty()
                        && s != "."
                        && s != ".."
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))),
                "invalid host endpoint path"
            );
            for other in &paths[..i] {
                ensure!(
                    !path.starts_with(&format!("{other}/"))
                        && !other.starts_with(&format!("{path}/"))
                        && path != other,
                    "host endpoints overlap"
                );
            }
            for route in &manifest.routes {
                if *path == self.capability_path {
                    let endpoint = format!("{path}/{{resource}}/{{id}}");
                    let left: Vec<_> = route.path.split('/').collect();
                    let right: Vec<_> = endpoint.split('/').collect();
                    let numeric = |v: &str| {
                        v.parse::<u64>()
                            .is_ok_and(|id| id > 0 && id <= i64::MAX as u64 && id.to_string() == v)
                    };
                    let overlap = left.len() == right.len()
                        && left.iter().zip(&right).all(|(a, b)| {
                            match (a.starts_with('{'), b.starts_with('{')) {
                                (true, true) => true,
                                (true, false) => numeric(b),
                                (false, true) => numeric(a),
                                (false, false) => a == b,
                            }
                        });
                    ensure!(!overlap, "capability endpoint overlaps application route");
                }
                ensure!(
                    crate::render::match_path(route, path).is_none(),
                    "host endpoint overlaps application route"
                );
                if *path == self.action_path {
                    ensure!(
                        path.split('/').skip(1).all(crate::manifest::identifier),
                        "invalid action path segment"
                    );
                    let action = Route {
                        params: Vec::new(),
                        path: format!("{path}/{{action}}"),
                        resource: Some(1),
                        ..route.clone()
                    };
                    ensure!(
                        !crate::render::paths_overlap(route, &action),
                        "action endpoint overlaps application route"
                    );
                }
            }
        }
        if let Some(css) = &self.stylesheet {
            // Exclude strings, escapes, comments, at-rules and functions. This
            // excludes every CSS resource-loading construct, including escaped
            // spellings. Ordinary selectors and literal declarations remain.
            ensure!(
                css.len() <= 65_536
                    && css.bytes().all(|b| b.is_ascii_alphanumeric()
                        || b.is_ascii_whitespace()
                        || b"{}:;.,#%-_+*>=".contains(&b)),
                "stylesheet must use URL-free literal CSS"
            );
            let mut open = false;
            for b in css.bytes() {
                match b {
                    b'{' => {
                        ensure!(!open, "nested CSS rule");
                        open = true;
                    }
                    b'}' => {
                        ensure!(open, "unmatched CSS rule");
                        open = false;
                    }
                    _ => {}
                }
            }
            ensure!(!open, "unclosed CSS rule");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_settings_reject_injection_and_endpoint_collisions() {
        let m = crate::test_support::manifest();
        Presentation::default().validate(&m).unwrap();
        for name in ["", "a;b", "a=b", "a\r\nX: y", "a b"] {
            let p = Presentation {
                session_cookie: name.into(),
                ..Presentation::default()
            };
            assert!(p.validate(&m).is_err(), "{name:?}");
        }
        for path in [
            "//evil", "/a/../b", "/x?y", "/x#y", "/x\"", "/", "/notes/1", "/login",
        ] {
            let p = Presentation {
                stylesheet_path: path.into(),
                ..Presentation::default()
            };
            assert!(p.validate(&m).is_err(), "{path:?}");
        }
        let p = Presentation {
            action_path: "/notes".into(),
            ..Presentation::default()
        };
        assert!(p.validate(&m).is_err());
        let p = Presentation {
            login_cookie: "session".into(),
            ..Presentation::default()
        };
        assert!(p.validate(&m).is_err());
        let mut custom = m;
        custom.routes[0].path = "/login".into();
        assert!(Presentation::default().validate(&custom).is_err());
        Presentation {
            login_path: "/signin".into(),
            ..Presentation::default()
        }
        .validate(&custom)
        .unwrap();
    }

    #[test]
    fn stylesheet_subset_has_no_resource_loading_syntax() {
        let m = crate::test_support::manifest();
        for css in [
            "body { color: #123; margin: 2rem auto } pre { white-space: pre-wrap }",
            "label:focus-visible { outline: 2px solid blue }",
        ] {
            Presentation {
                stylesheet: Some(css.into()),
                ..Presentation::default()
            }
            .validate(&m)
            .unwrap();
        }
        for css in [
            "x { background: url(https://evil/x) }",
            "@import 'https://evil/x';",
            "x { background: u\\72l(https://evil/x) }",
            "@font-face { src: url(/font) }",
            "x { cursor: image-set(url(/x) 1x), auto }",
            "/* comment */",
            "x{a:b",
            "x{y{a:b}}",
            "x { content: 'secret' }",
            "x { background: URL(/x) }",
            "@import/**/url(/x);",
        ] {
            let p = Presentation {
                stylesheet: Some(css.into()),
                ..Presentation::default()
            };
            assert!(p.validate(&m).is_err(), "{css:?}");
        }
        assert!(
            Presentation {
                stylesheet: Some("a".repeat(65_537)),
                ..Presentation::default()
            }
            .validate(&m)
            .is_err()
        );
    }
}

#[cfg(test)]
mod anonymous_cookie_tests {
    use super::*;
    #[test]
    fn session_and_login_cookies_cannot_use_the_fixed_anonymous_name() {
        let m = crate::test_support::manifest();
        for session in [false, true] {
            let mut p = Presentation::default();
            if session {
                p.session_cookie = "noxide_anon".into();
            } else {
                p.login_cookie = "noxide_anon".into();
            }
            assert!(p.validate(&m).is_err());
        }
        Presentation {
            session_cookie: "custom_session".into(),
            login_cookie: "custom_login".into(),
            ..Presentation::default()
        }
        .validate(&m)
        .unwrap();
    }
}

#[cfg(test)]
mod registration_endpoint_tests {
    use super::*;
    #[test]
    fn fixed_registration_path_cannot_shadow_host_or_application_endpoints() {
        let manifest = crate::test_support::manifest();
        for kind in 0..4 {
            let mut p = Presentation::default();
            match kind {
                0 => p.login_path = "/register".into(),
                1 => p.logout_path = "/register".into(),
                2 => p.action_path = "/register".into(),
                _ => p.stylesheet_path = "/register".into(),
            }
            assert!(p.validate(&manifest).is_err());
        }
        let mut m = manifest;
        m.routes.push(noxide_protocol::Route {
            params: Vec::new(),
            id: 3,
            path: "/register".into(),
            resource: None,
            operations: vec![],
            forms: vec![],
            access: noxide_protocol::Access::Authenticated,
        });
        crate::manifest::validate(&m).unwrap();
        assert!(Presentation::default().validate(&m).is_err());
    }
}

#[cfg(test)]
mod marker_tests {
    use super::*;

    #[test]
    fn configurable_markers_reject_injection_and_collisions() {
        let manifest = crate::test_support::manifest();
        for name in [
            "",
            "a b",
            "a\"b",
            "a=b",
            "x\r\ny",
            &"a".repeat(33),
            "username",
            "password",
            "invite",
            "body",
        ] {
            for kind in 0..3 {
                let mut p = Presentation::default();
                match kind {
                    0 => p.csrf_field = name.into(),
                    1 => p.submission_field = name.into(),
                    _ => p.capability_field = name.into(),
                }
                assert!(p.validate(&manifest).is_err(), "{name:?}");
            }
        }
        for kind in 0..3 {
            let mut p = Presentation::default();
            match kind {
                0 => p.csrf_field = p.submission_field.clone(),
                1 => p.submission_field = p.capability_field.clone(),
                _ => p.capability_field = p.csrf_field.clone(),
            }
            assert!(p.validate(&manifest).is_err());
        }
        for name in ["session", "login", "", "a;b", "a=b", "a b", &"x".repeat(65)] {
            let p = Presentation {
                anonymous_cookie: name.into(),
                ..Presentation::default()
            };
            assert!(p.validate(&manifest).is_err());
        }
        for path in [
            "//evil",
            "/x?y",
            "/x#y",
            "/x\"",
            "/a/../b",
            "/login",
            "/actions/nested",
            "/notes/1",
            "/",
        ] {
            for capability in [false, true] {
                let mut p = Presentation::default();
                if capability {
                    p.capability_path = path.into();
                } else {
                    p.registration_path = path.into();
                }
                assert!(p.validate(&manifest).is_err(), "{path:?}");
            }
        }
        let mut p = Presentation {
            anonymous_cookie: "guest".into(),
            registration_path: "/join".into(),
            capability_path: "/edit".into(),
            csrf_field: "check".into(),
            submission_field: "ticket".into(),
            capability_field: "key".into(),
            ..Presentation::default()
        };
        p.validate(&manifest).unwrap();
        // Historical defaults are available for reuse after all collisions move.
        p.session_cookie = "noxide_anon".into();
        p.login_path = "/register".into();
        p.validate(&manifest).unwrap();
        p.registration_path = "/edit/nested".into();
        assert!(p.validate(&manifest).is_err());
        let custom: Presentation = serde_json::from_str(
            r#"{
            "anonymous_cookie":"visitor", "registration_path":"/join",
            "capability_path":"/manage", "csrf_field":"check",
            "submission_field":"ticket", "capability_field":"edit_key"
        }"#,
        )
        .unwrap();
        custom.validate(&manifest).unwrap();
        assert_eq!(custom.anonymous_cookie, "visitor");
        assert_eq!(custom.registration_path, "/join");
        assert_eq!(custom.capability_path, "/manage");
        assert_eq!(custom.csrf_field, "check");
        assert_eq!(custom.submission_field, "ticket");
        assert_eq!(custom.capability_field, "edit_key");
        let defaults: Presentation = serde_json::from_str("{}").unwrap();
        assert_eq!(defaults.anonymous_cookie, "noxide_anon");
        assert_eq!(defaults.registration_path, "/register");
        assert_eq!(defaults.capability_path, "/_noxide/capability");
        assert_eq!(defaults.csrf_field, "_csrf");
        assert_eq!(defaults.submission_field, "_submission");
        assert!(serde_json::from_str::<Presentation>(r#"{"unknown_marker":"x"}"#).is_err());
    }
}
