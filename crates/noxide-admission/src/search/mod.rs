//! Pure search values. This module grants no query or storage authority.
mod index;
mod postings;
mod tokenizer;

#[cfg(any(test, feature = "test-support"))]
pub use index::{FieldToken, MAX_INDEXED_BYTES};
pub use index::{IndexedRecord, MAX_POSTING_BYTES, MAX_POSTINGS, indexed_record};
pub use postings::PreparedPostings;
#[cfg(any(test, feature = "test-support"))]
pub use tokenizer::{CanonicalQuery, Error, MAX_QUERY_BYTES, TOKENIZER_ID};
pub use tokenizer::{canonical_query, require_tokenizer};

#[cfg(test)]
mod tests;
