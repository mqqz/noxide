//! Bounded atomic-write payload, with common record metadata bound separately.
use super::{IndexedRecord, MAX_POSTING_BYTES, MAX_POSTINGS};
use anyhow::{Result, ensure};

// Each [field,"token"] contributes six framing bytes and one separator. Token
// scalars are Letter/Number/Mark, so no JSON quote, slash or control escaping is
// needed. The final array framing contributes one byte after separator accounting.
pub const MAX_PAYLOAD_BYTES: usize = MAX_POSTINGS * 7 + MAX_POSTING_BYTES + 1;
const _: () = assert!(MAX_PAYLOAD_BYTES <= 48 * 1024);

pub struct PreparedPostings {
    payload: String,
    count: usize,
}
impl PreparedPostings {
    /// The caller must pass its existing request or operator work checkpoint.
    /// There is no unchecked constructor. Serialization never opens a database.
    pub fn new(record: &IndexedRecord, mut checkpoint: impl FnMut() -> Result<()>) -> Result<Self> {
        checkpoint()?;
        ensure!(record.postings().len() <= MAX_POSTINGS, "posting count");
        let mut bytes = Vec::new();
        bytes.push(b'[');
        for (index, posting) in record.postings().iter().enumerate() {
            if index.is_multiple_of(64) {
                checkpoint()?;
            }
            let token = record
                .tokens()
                .get(usize::from(posting.token))
                .ok_or_else(|| anyhow::anyhow!("posting dictionary"))?;
            if index != 0 {
                bytes.push(b',');
            }
            serde_json::to_writer(&mut bytes, &(posting.field, token))?;
            ensure!(bytes.len() < MAX_PAYLOAD_BYTES, "posting payload bytes");
        }
        bytes.push(b']');
        ensure!(bytes.len() <= MAX_PAYLOAD_BYTES, "posting payload bytes");
        checkpoint()?;
        Ok(Self {
            payload: String::from_utf8(bytes)?,
            count: record.postings().len(),
        })
    }
    pub fn payload(&self) -> &str {
        &self.payload
    }
    pub fn count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::indexed_record;

    #[test]
    fn payload_has_explicit_fields_without_repeated_record_facts() {
        let record =
            indexed_record(&[Some("Rust العربية"), Some("Rust")], 100, &mut || Ok(())).unwrap();
        let prepared = PreparedPostings::new(&record, || Ok(())).unwrap();
        assert_eq!(
            prepared.payload(),
            r#"[[0,"rust"],[0,"العربية"],[1,"rust"]]"#
        );
        assert_eq!(prepared.count(), 3);
    }

    #[test]
    fn maximum_pair_cardinality_is_not_truncated_or_multiplied_by_facts() {
        let text = (0..512)
            .map(|i| format!("a{i:04}"))
            .collect::<Vec<_>>()
            .join(" ");
        let record = indexed_record(&[Some(text.as_str()); 4], 16_384, &mut || Ok(())).unwrap();
        let mut checkpoints = 0;
        let prepared = PreparedPostings::new(&record, || {
            checkpoints += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(prepared.count(), 2_048);
        // 2048 five-byte tokens, seven framing bytes per pair, one final byte.
        assert_eq!(prepared.payload().len(), 24_577);
        assert_eq!(checkpoints, 34);
        const { assert!(MAX_PAYLOAD_BYTES == 47_105) };
    }

    #[test]
    fn failed_work_checkpoint_returns_no_partial_payload() {
        let record = indexed_record(&[Some("a b")], 10, &mut || Ok(())).unwrap();
        let mut calls = 0;
        let result = PreparedPostings::new(&record, || {
            calls += 1;
            ensure!(calls < 2, "cancelled original owner");
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(calls, 2);
    }
}
