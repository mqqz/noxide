use super::*;

// Infallible pure fixture wrappers are test-only. Production callers must pass
// their real required request/operator checkpoint and retain its original error.
fn canonical_query(text: &str) -> Result<CanonicalQuery, Error> {
    super::canonical_query(text, &mut || Ok(()))
        .map_err(|error| *error.downcast_ref::<Error>().expect("tokenization error"))
}
fn indexed_record(values: &[Option<&str>], max_bytes: usize) -> Result<IndexedRecord, Error> {
    super::indexed_record(values, max_bytes, &mut || Ok(()))
        .map_err(|error| *error.downcast_ref::<Error>().expect("tokenization error"))
}

#[derive(Debug)]
struct Interrupted(usize);
impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original work owner interrupted")
    }
}
impl std::error::Error for Interrupted {}

#[test]
fn every_query_work_boundary_preserves_the_original_failure_without_a_result() {
    let text = format!("{}{} ΟΣ İ عربي", "a".repeat(64), ".".repeat(1024));
    let mut checkpoints = 0;
    let query = super::canonical_query(&text, &mut || {
        checkpoints += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        query.tokens(),
        [
            "a".repeat(64),
            "i\u{307}".into(),
            "ος".into(),
            "عربي".into()
        ]
    );
    assert!(checkpoints > 64);
    for stop in 1..=checkpoints {
        let mut calls = 0;
        let error = super::canonical_query(&text, &mut || {
            calls += 1;
            if calls == stop {
                return Err(Interrupted(stop).into());
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.downcast_ref::<Interrupted>().unwrap().0, stop);
        assert_eq!(calls, stop);
    }
    let error = super::canonical_query("", &mut || Err(Interrupted(0).into())).unwrap_err();
    assert_eq!(error.downcast_ref::<Interrupted>().unwrap().0, 0);
}

#[test]
fn every_index_work_boundary_preserves_the_original_failure_without_postings() {
    let text = (0..128)
        .map(|number| format!("word{number:03}"))
        .collect::<Vec<_>>()
        .join(" ");
    let values = [Some(text.as_str()); 4];
    let mut checkpoints = 0;
    let record = super::indexed_record(&values, MAX_INDEXED_BYTES, &mut || {
        checkpoints += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(record.tokens().len(), 128);
    assert_eq!(record.postings().len(), 512);
    assert!(checkpoints > 64);
    for stop in 1..=checkpoints {
        let mut calls = 0;
        let error = super::indexed_record(&values, MAX_INDEXED_BYTES, &mut || {
            calls += 1;
            if calls == stop {
                return Err(Interrupted(stop).into());
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.downcast_ref::<Interrupted>().unwrap().0, stop);
        assert_eq!(calls, stop);
    }
    let error = super::indexed_record(&[], 0, &mut || Err(Interrupted(0).into())).unwrap_err();
    assert_eq!(error.downcast_ref::<Interrupted>().unwrap().0, 0);
}

#[test]
fn unicode_vectors_have_handwritten_portable_results() {
    let cases: &[(&str, &[&str])] = &[
        ("HELLO world hello", &["hello", "world"]),
        ("The a and", &["a", "and", "the"]),
        ("running runs", &["running", "runs"]),
        ("resume résumé", &["resume", "résumé"]),
        ("سلام salaam", &["salaam", "سلام"]),
        ("ＦＯＯ ﬁle Ⅳ ①", &["1", "file", "foo", "iv"]),
        ("Cafe\u{301} CAFÉ", &["café"]),
        ("J\u{30c}", &["ǰ"]), // NFKC again after lowercase composes j+caron.
        ("Straße STRASSE ẞ", &["strasse", "straße", "ß"]),
        ("ΟΣ ΟΣΑ Σ ΣΑ", &["ος", "οσα", "σ", "σα"]),
        ("ΟΣ'Α", &["α", "οσ"]), // Apostrophe is case-ignorable before splitting.
        ("İ I ı", &["i", "i\u{307}", "ı"]),
        ("عَرَب عربي", &["عربي", "عَرَب"]),
        ("ﷲ، ﻻ", &["الله", "لا"]),
        ("١٢٣ 123", &["123", "١٢٣"]),
        ("Aالعربية42", &["aالعربية42"]),
        ("\u{301}X", &["x"]),
        ("A\u{301}", &["á"]),
        ("x\u{20dd}", &["x\u{20dd}"]),
        ("a\u{fe0f}", &["a\u{fe0f}"]),
        ("A\u{200d}B", &["a", "b"]),
        ("ΑAА", &["αaа"]), // Greek/Latin/Cyrillic remain distinct scripts.
    ];
    for (input, expected) in cases {
        let query = canonical_query(input).unwrap();
        assert_eq!(query.tokens(), *expected, "input {input:?}");
        assert_eq!(
            canonical_query(&expected.join(" ")).unwrap().tokens(),
            *expected
        );
    }
}

#[test]
fn tokenizer_identity_and_boundaries_fail_closed() {
    assert!(require_tokenizer(TOKENIZER_ID).is_ok());
    for wrong in ["", "noxide-token-and-v2", "unicode16", "rust1.99.0"] {
        assert_eq!(require_tokenizer(wrong), Err(Error::UnsupportedTokenizer));
    }
    for empty in ["", " \t\n", "😀👩\u{200d}💻", "\u{301}"] {
        assert_eq!(canonical_query(empty), Err(Error::EmptyQuery));
    }
    assert_eq!(
        canonical_query(&".".repeat(MAX_QUERY_BYTES + 1)),
        Err(Error::InputBytes)
    );
    assert_eq!(
        canonical_query(&"a".repeat(64)).unwrap().tokens()[0].len(),
        64
    );
    assert_eq!(canonical_query(&"a".repeat(65)), Err(Error::TokenScalars));
    assert_eq!(
        canonical_query(&"ع".repeat(64)).unwrap().tokens()[0]
            .chars()
            .count(),
        64
    );
    assert_eq!(canonical_query(&"ع".repeat(65)), Err(Error::TokenScalars));
    assert!(canonical_query(&"İ".repeat(32)).is_ok());
    assert_eq!(canonical_query(&"İ".repeat(33)), Err(Error::TokenScalars));
    assert_eq!(canonical_query("a a a a a a a a").unwrap().tokens(), ["a"]);
    assert_eq!(
        canonical_query("a a a a a a a a a"),
        Err(Error::QueryTokens)
    );
    assert_eq!(
        canonical_query("a b c d e f g h").unwrap().tokens().len(),
        8
    );
    assert_eq!(
        canonical_query("a b c d e f g h i"),
        Err(Error::QueryTokens)
    );
    assert_eq!(
        canonical_query(&"ﷺ".repeat(300)),
        Err(Error::IntermediateBytes)
    );
    assert!(canonical_query(&format!("a{}", "\u{301}".repeat(63))).is_ok());
    assert_eq!(
        canonical_query(&format!("a{}", "\u{301}".repeat(64))),
        Err(Error::CombiningSequence)
    );
    assert_eq!(
        canonical_query(&"\u{301}".repeat(64)),
        Err(Error::CombiningSequence)
    );
    assert_eq!(canonical_query(&"ﷲ".repeat(17)), Err(Error::TokenScalars));
}

#[test]
fn full_string_lowercase_has_the_pinned_finite_expansion_bound() {
    // This bound protects the one opaque full-context lowercase allocation.
    // Fixtures above independently specify context-sensitive semantic results.
    for code in 0..=0x10ffff {
        if let Some(scalar) = char::from_u32(code) {
            assert!(scalar.to_lowercase().count() <= 3);
        }
    }
}

#[test]
fn posting_dictionary_is_canonical_and_does_not_shift_absent_fields() {
    let record = indexed_record(&[Some("Z A A"), None, Some("A")], MAX_INDEXED_BYTES).unwrap();
    assert_eq!(record.tokens(), ["a", "z"]);
    assert_eq!(
        record.postings(),
        [
            FieldToken { field: 0, token: 0 },
            FieldToken { field: 0, token: 1 },
            FieldToken { field: 2, token: 0 }
        ]
    );
    assert_eq!(record.indexed_bytes(), 6);
    assert_eq!(record.posting_bytes(), 3);
    assert_eq!(record.tokenizer(), TOKENIZER_ID);
    let punctuation = ".".repeat(MAX_INDEXED_BYTES);
    let empty = indexed_record(&[Some(&punctuation)], MAX_INDEXED_BYTES).unwrap();
    assert!(empty.tokens().is_empty() && empty.postings().is_empty());
    assert!(
        indexed_record(&[None, None, None, None], MAX_INDEXED_BYTES)
            .unwrap()
            .tokens()
            .is_empty()
    );
}

#[test]
fn record_distinct_strings_and_field_postings_have_separate_ceilings() {
    let text = (0..512)
        .map(|i| format!("t{i:03}"))
        .collect::<Vec<_>>()
        .join(" ");
    let one = indexed_record(&[Some(&text)], MAX_INDEXED_BYTES).unwrap();
    assert_eq!(one.tokens().len(), 512);
    assert_eq!(one.postings().len(), 512);
    let four = indexed_record(&[Some(text.as_str()); 4], MAX_INDEXED_BYTES).unwrap();
    assert_eq!(four.tokens().len(), 512);
    assert_eq!(four.postings().len(), 2048);
    assert_eq!(four.posting_bytes(), 8192);
    assert_eq!(MAX_POSTINGS, 2048);
    assert_eq!(
        indexed_record(&[Some(&(text + " t512"))], MAX_INDEXED_BYTES),
        Err(Error::RecordTokens)
    );
}

#[test]
fn every_resource_work_bound_rejects_without_partial_index_values() {
    assert_eq!(
        indexed_record(&[], MAX_INDEXED_BYTES),
        Err(Error::IndexedFields)
    );
    assert_eq!(
        indexed_record(&[None; 5], MAX_INDEXED_BYTES),
        Err(Error::IndexedFields)
    );
    assert_eq!(indexed_record(&[None], 0), Err(Error::IndexedLimit));
    assert_eq!(
        indexed_record(&[None], MAX_INDEXED_BYTES + 1),
        Err(Error::IndexedLimit)
    );
    assert_eq!(indexed_record(&[Some("abcd")], 3), Err(Error::InputBytes));
    assert_eq!(
        indexed_record(
            &[Some(&".".repeat(MAX_INDEXED_BYTES + 1))],
            MAX_INDEXED_BYTES
        ),
        Err(Error::InputBytes)
    );
    assert_eq!(
        indexed_record(&[Some(&"ﷺ".repeat(2000))], MAX_INDEXED_BYTES),
        Err(Error::IntermediateBytes)
    );
    // ﷲ normalizes to four Arabic letters (eight UTF8 bytes). Fifteen
    // ligatures plus three ASCII digits make a 63-scalar/123-byte token.
    // 270 such distinct tokens fit the raw input cap but exceed32KiB postings.
    let expanded = (0..270)
        .map(|i| format!("{}{i:03}", "ﷲ".repeat(15)))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(expanded.len() < MAX_INDEXED_BYTES);
    assert_eq!(
        indexed_record(&[Some(&expanded)], MAX_INDEXED_BYTES),
        Err(Error::PostingBytes)
    );
    // The intermediate budget is shared; it is not reset for another field.
    let expanded = "ﷺ".repeat(1000);
    assert_eq!(
        indexed_record(&[Some(&expanded), Some(&expanded)], MAX_INDEXED_BYTES),
        Err(Error::IntermediateBytes)
    );
}
