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
    pub login_path: String,
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
            login_path: "/login".into(),
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
        for name in [&self.session_cookie, &self.login_cookie] {
            ensure!(
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
                "invalid cookie name"
            );
        }
        ensure!(
            self.session_cookie != self.login_cookie,
            "cookie names must differ"
        );
        let paths = [
            &self.login_path,
            &self.logout_path,
            &self.action_path,
            &self.stylesheet_path,
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
                ensure!(
                    crate::render::match_path(route, path).is_none(),
                    "host endpoint overlaps application route"
                );
                if i == 2 {
                    ensure!(
                        path.split('/').skip(1).all(crate::manifest::identifier),
                        "invalid action path segment"
                    );
                    let action = Route {
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
