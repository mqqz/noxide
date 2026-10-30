//! Safe rich document subtrees; no HTML, style, event, or URL escape hatch.
use crate::RouteRef;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ClassTokens(Vec<String>);
impl ClassTokens {
    pub fn new(tokens: Vec<String>) -> Result<Self, String> {
        if tokens.len() > 8
            || tokens.iter().any(|s| {
                s.is_empty()
                    || s.len() > 64
                    || s == "noxide-app"
                    || !s.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            })
        {
            return Err("invalid class tokens".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        if !tokens.iter().all(|s| seen.insert(s)) {
            return Err("duplicate class token".into());
        }
        Ok(Self(tokens))
    }
    pub fn tokens(&self) -> &[String] {
        &self.0
    }
}
impl<'de> Deserialize<'de> for ClassTokens {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Vec::<String>::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Element {
    Div,
    Section,
    Paragraph,
    Heading2,
    Strong,
    Emphasis,
    Table,
    Caption,
    TableHead,
    TableBody,
    Row,
    HeaderCell,
    Cell,
    Details,
    Summary,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PresentationNode {
    Text(String),
    Image {
        asset: String,
        alt: String,
        classes: ClassTokens,
    },
    Link {
        destination: RouteRef,
        text: String,
        classes: ClassTokens,
    },
    Element {
        element: Element,
        classes: ClassTokens,
        children: Vec<PresentationNode>,
    },
    Navigation {
        label: String,
        classes: ClassTokens,
        children: Vec<PresentationNode>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_classes_exclude_root_marker_and_injection() {
        assert!(ClassTokens::new(vec!["card".into(), "wide_2".into()]).is_ok());
        for tokens in [
            vec!["noxide-app".into()],
            vec!["x y".into()],
            vec!["x\"".into()],
            vec!["x".repeat(65)],
            vec!["x".into(); 9],
            vec!["a".into(), "a".into()],
        ] {
            assert!(ClassTokens::new(tokens).is_err());
        }
    }
}
