//! Unregistered P09 pure values. This module grants no query or storage authority.
mod index;
mod postings;
mod tokenizer;

pub use index::{
    FieldToken, IndexedRecord, MAX_INDEXED_BYTES, MAX_INDEXED_FIELDS, MAX_POSTING_BYTES,
    MAX_POSTINGS, MAX_RECORD_TOKENS, indexed_record,
};
pub use postings::{MAX_PAYLOAD_BYTES, PreparedPostings};
pub use tokenizer::{
    CanonicalQuery, Error, MAX_QUERY_BYTES, MAX_QUERY_TOKENS, MAX_TOKEN_SCALARS, TOKENIZER_ID,
    canonical_query, require_tokenizer,
};

#[cfg(test)]
mod tests;
