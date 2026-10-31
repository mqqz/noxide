use super::tokenizer::{Error, Stages, TOKENIZER_ID, normalize, split};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_INDEXED_FIELDS: usize = 4;
pub const MAX_INDEXED_BYTES: usize = 16_384;
pub const MAX_RECORD_TOKENS: usize = 512;
pub const MAX_POSTINGS: usize = MAX_INDEXED_FIELDS * MAX_RECORD_TOKENS;
pub const MAX_POSTING_BYTES: usize = 32_768;
const MAX_RECORD_STAGE_BYTES: usize = 65_536;

/// Field ordinal is supplied by the sorted, approved index field declaration.
/// Token index addresses the single canonical string dictionary below.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldToken {
    pub field: u8,
    pub token: u16,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedRecord {
    tokens: Vec<String>,
    postings: Vec<FieldToken>,
    indexed_bytes: usize,
    posting_bytes: usize,
}
impl IndexedRecord {
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }
    pub fn postings(&self) -> &[FieldToken] {
        &self.postings
    }
    pub fn indexed_bytes(&self) -> usize {
        self.indexed_bytes
    }
    pub fn posting_bytes(&self) -> usize {
        self.posting_bytes
    }
    pub fn tokenizer(&self) -> &'static str {
        TOKENIZER_ID
    }
}

/// Values retain an ordinal even for an absent optional Text field. This leaf
/// cannot select fields, authorize reads, write postings or grant any capability.
/// Central admission must supply exactly its declared, sorted Text fields.
pub fn indexed_record(
    values: &[Option<&str>],
    admitted_bytes: usize,
    checkpoint: &mut impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<IndexedRecord> {
    checkpoint()?;
    if values.is_empty() || values.len() > MAX_INDEXED_FIELDS {
        return Err(Error::IndexedFields.into());
    }
    if admitted_bytes == 0 || admitted_bytes > MAX_INDEXED_BYTES {
        return Err(Error::IndexedLimit.into());
    }
    let indexed_bytes = values.iter().try_fold(0usize, |total, value| {
        total
            .checked_add(value.unwrap_or("").len())
            .ok_or(Error::InputBytes)
    })?;
    if indexed_bytes > admitted_bytes {
        return Err(Error::InputBytes.into());
    }
    let mut stages = Stages::new(MAX_RECORD_STAGE_BYTES);
    let mut dictionary = BTreeSet::new();
    let mut field_tokens = Vec::with_capacity(values.len());
    let mut posting_bytes = 0usize;
    for value in values {
        let canonical = normalize(value.unwrap_or(""), &mut stages, checkpoint)?;
        let mut unique = BTreeSet::new();
        split(&canonical, checkpoint, |token| {
            if !dictionary.contains(token) {
                if dictionary.len() == MAX_RECORD_TOKENS {
                    return Err(Error::RecordTokens);
                }
                dictionary.insert(token.to_owned());
            }
            if !unique.contains(token) {
                posting_bytes = posting_bytes
                    .checked_add(token.len())
                    .ok_or(Error::PostingBytes)?;
                if posting_bytes > MAX_POSTING_BYTES {
                    return Err(Error::PostingBytes);
                }
                unique.insert(token.to_owned());
            }
            Ok(())
        })?;
        field_tokens.push(unique);
    }
    checkpoint()?;
    let mut tokens = Vec::with_capacity(dictionary.len());
    for (index, token) in dictionary.into_iter().enumerate() {
        if index.is_multiple_of(64) {
            checkpoint()?;
        }
        tokens.push(token);
    }
    let mut ordinals = BTreeMap::new();
    for (index, token) in tokens.iter().enumerate() {
        if index.is_multiple_of(64) {
            checkpoint()?;
        }
        ordinals.insert(token.as_str(), index as u16);
    }
    let mut postings = Vec::new();
    for (field, unique) in field_tokens.into_iter().enumerate() {
        for token in unique {
            if postings.len().is_multiple_of(64) {
                checkpoint()?;
            }
            postings.push(FieldToken {
                field: field as u8,
                token: ordinals[token.as_str()],
            });
        }
    }
    debug_assert!(postings.len() <= MAX_POSTINGS);
    checkpoint()?;
    Ok(IndexedRecord {
        tokens,
        postings,
        indexed_bytes,
        posting_bytes,
    })
}
