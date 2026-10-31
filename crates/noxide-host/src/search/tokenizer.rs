use std::{collections::BTreeSet, fmt};
use unicode_normalization::{
    UnicodeNormalization,
    char::{canonical_combining_class, decompose_compatible},
};
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

pub const MAX_QUERY_BYTES: usize = 4_096;
pub const MAX_QUERY_TOKENS: usize = 8;
pub const MAX_TOKEN_SCALARS: usize = 64;
pub(super) const MAX_QUERY_STAGE_BYTES: usize = 8_192;
pub(super) const MAX_NONSTARTERS: usize = 63;

// The exact Cargo pins are part of this identity, in addition to the Unicode
// table versions. No compatibility fallback/reinterpretation is provided.
pub const TOKENIZER_ID: &str = "noxide-token-and-v1;nfkc=0.1.25/unicode17.0.0;category=0.1.4/unicode17.0.0;lower=str-default/unicode17.0.0/rust1.98.0";
const VERIFIED_COMPILER: &str = env!(
    "NOXIDE_SEARCH_RUST_RELEASE",
    "register the search build guard before enabling this module"
);
const _: () = {
    assert!(
        std::char::UNICODE_VERSION.0 == 17
            && std::char::UNICODE_VERSION.1 == 0
            && std::char::UNICODE_VERSION.2 == 0
    );
    assert!(
        unicode_normalization::UNICODE_VERSION.0 == 17
            && unicode_normalization::UNICODE_VERSION.1 == 0
            && unicode_normalization::UNICODE_VERSION.2 == 0
    );
    assert!(
        unicode_properties::UNICODE_VERSION.0 == 17
            && unicode_properties::UNICODE_VERSION.1 == 0
            && unicode_properties::UNICODE_VERSION.2 == 0
    );
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedTokenizer,
    InputBytes,
    IntermediateBytes,
    CombiningSequence,
    TokenScalars,
    EmptyQuery,
    QueryTokens,
    IndexedFields,
    IndexedLimit,
    RecordTokens,
    PostingBytes,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::UnsupportedTokenizer => {
                "unsupported search tokenizer; explicit index rebuild required"
            }
            Self::InputBytes => "search input byte limit",
            Self::IntermediateBytes => "search normalization byte limit",
            Self::CombiningSequence => "search combining sequence limit",
            Self::TokenScalars => "search token scalar limit",
            Self::EmptyQuery => "search requires a token",
            Self::QueryTokens => "search query token limit",
            Self::IndexedFields => "search indexed field limit",
            Self::IndexedLimit => "invalid search indexed byte declaration",
            Self::RecordTokens => "search record distinct token limit",
            Self::PostingBytes => "search posting token byte limit",
        })
    }
}
impl std::error::Error for Error {}

pub fn require_tokenizer(identity: &str) -> Result<(), Error> {
    // Build-time guard and table assertions are deliberate fail-closed gates.
    if identity == TOKENIZER_ID && VERIFIED_COMPILER == "1.98.0" {
        Ok(())
    } else {
        Err(Error::UnsupportedTokenizer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalQuery {
    tokens: Vec<String>,
}
impl CanonicalQuery {
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }
    pub fn tokenizer(&self) -> &'static str {
        TOKENIZER_ID
    }
}

/// Query count applies to occurrences before deduplication. Canonical sorted
/// strings are the only query values later used for equality and cursor binding.
pub fn canonical_query(text: &str) -> Result<CanonicalQuery, Error> {
    if text.len() > MAX_QUERY_BYTES {
        return Err(Error::InputBytes);
    }
    let mut work = Stages::new(MAX_QUERY_STAGE_BYTES);
    let canonical = normalize(text, &mut work)?;
    let mut occurrences = 0usize;
    let mut tokens = BTreeSet::new();
    split(&canonical, |token| {
        occurrences += 1;
        if occurrences > MAX_QUERY_TOKENS {
            return Err(Error::QueryTokens);
        }
        tokens.insert(token.to_owned());
        Ok(())
    })?;
    if tokens.is_empty() {
        return Err(Error::EmptyQuery);
    }
    Ok(CanonicalQuery {
        tokens: tokens.into_iter().collect(),
    })
}

/// Each stage has its own aggregate budget, shared across all indexed fields.
/// An earlier stage cannot borrow capacity from a later one.
pub(super) struct Stages {
    decomposed: usize,
    first: usize,
    lowercase: usize,
    final_decomposed: usize,
    final_normalized: usize,
}
impl Stages {
    pub(super) fn new(bytes: usize) -> Self {
        Self {
            decomposed: bytes,
            first: bytes,
            lowercase: bytes,
            final_decomposed: bytes,
            final_normalized: bytes,
        }
    }
}
fn spend(remaining: &mut usize, bytes: usize) -> Result<(), Error> {
    *remaining = remaining
        .checked_sub(bytes)
        .ok_or(Error::IntermediateBytes)?;
    Ok(())
}
/// Preflight compatibility decomposition without invoking the reordering
/// iterator. This bounds its nonstarter buffer and canonical-ordering work.
fn preflight(text: &str, remaining: &mut usize) -> Result<(), Error> {
    let mut nonstarters = 0usize;
    for scalar in text.chars() {
        let mut failure = None;
        decompose_compatible(scalar, |part| {
            if failure.is_some() {
                return;
            }
            if let Err(error) = spend(remaining, part.len_utf8()) {
                failure = Some(error);
                return;
            }
            if canonical_combining_class(part) == 0 {
                nonstarters = 0;
            } else {
                nonstarters += 1;
                if nonstarters > MAX_NONSTARTERS {
                    failure = Some(Error::CombiningSequence);
                }
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
    }
    Ok(())
}
fn collect_bounded(
    scalars: impl Iterator<Item = char>,
    remaining: &mut usize,
) -> Result<String, Error> {
    let mut result = String::new();
    for scalar in scalars {
        spend(remaining, scalar.len_utf8())?;
        result.push(scalar);
    }
    Ok(result)
}
pub(super) fn normalize(text: &str, stages: &mut Stages) -> Result<String, Error> {
    preflight(text, &mut stages.decomposed)?;
    let first = collect_bounded(text.nfkc(), &mut stages.first)?;
    // Full-string casing is required: char::to_lowercase misses final sigma.
    // Unicode17 default lowercase has at most three output scalars per input
    // scalar. The first string is bounded before this finite expansion allocates.
    let lowercase = first.to_lowercase();
    spend(&mut stages.lowercase, lowercase.len())?;
    preflight(&lowercase, &mut stages.final_decomposed)?;
    collect_bounded(lowercase.nfkc(), &mut stages.final_normalized)
}

pub(super) fn split(
    text: &str,
    mut emit: impl FnMut(&str) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut start = None;
    let mut scalars = 0usize;
    for (offset, scalar) in text.char_indices() {
        let continues = match scalar.general_category_group() {
            GeneralCategoryGroup::Letter | GeneralCategoryGroup::Number => {
                if start.is_none() {
                    start = Some(offset);
                }
                true
            }
            GeneralCategoryGroup::Mark => start.is_some(),
            _ => false,
        };
        if continues {
            scalars += 1;
            if scalars > MAX_TOKEN_SCALARS {
                return Err(Error::TokenScalars);
            }
        } else {
            if let Some(begin) = start.take() {
                emit(&text[begin..offset])?;
            }
            scalars = 0;
        }
    }
    if let Some(begin) = start {
        emit(&text[begin..])?;
    }
    Ok(())
}
