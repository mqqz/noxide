use super::*;

const BOUNDARY: &str = "---------------------------1726374890273647";
fn boundary() -> Boundary {
    Boundary::content_type(&format!("multipart/form-data; boundary={BOUNDARY}")).unwrap()
}
fn spec(optional: bool, limit: u64) -> PrefixSpec {
    PrefixSpec::new(
        vec![
            ScalarPart {
                name: "_csrf".into(),
                max_bytes: 4096,
                required: true,
            },
            ScalarPart {
                name: "_submission".into(),
                max_bytes: 4096,
                required: true,
            },
            ScalarPart {
                name: "_upload".into(),
                max_bytes: 4096,
                required: true,
            },
            ScalarPart {
                name: "title".into(),
                max_bytes: FIELD_BYTES,
                required: true,
            },
            ScalarPart {
                name: "enabled".into(),
                max_bytes: 5,
                required: false,
            },
            ScalarPart {
                name: "attachment".into(),
                max_bytes: 67,
                required: false,
            },
        ],
        "_file".into(),
        optional,
        limit,
    )
    .unwrap()
}
fn prefix(filename: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in [
        ("_csrf", "csrf-proof"),
        ("_submission", "submission-proof"),
        ("_upload", "upload-ticket"),
        ("title", "عنوان\r\nwith blank\r\n\r\nline"),
    ] {
        out.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"_file\"; filename=\"{filename}\"\r\nContent-Type: text/html\r\n\r\n").as_bytes());
    out
}
fn ending() -> Vec<u8> {
    format!("\r\n--{BOUNDARY}--\r\n").into_bytes()
}
fn ready(prefix: &[u8], optional: bool, limit: u64) -> ReadyPrefix {
    let mut decoder = PrefixDecoder::new(boundary(), spec(optional, limit));
    let progress = decoder.push(prefix).unwrap();
    assert_eq!(progress.consumed, prefix.len());
    decoder.finish().unwrap();
    progress.ready.unwrap()
}

#[test]
fn prefix_stops_exactly_before_file_bytes_for_every_split() {
    let prefix = prefix("page.html");
    let payload = [
        prefix.as_slice(),
        b"<script>arbitrary hostile bytes</script>",
        ending().as_slice(),
    ]
    .concat();
    for split in 0..=payload.len() {
        let mut decoder = PrefixDecoder::new(boundary(), spec(false, 100));
        let first = decoder.push(&payload[..split]).unwrap();
        let (ready, consumed) = if let Some(ready) = first.ready {
            (ready, first.consumed)
        } else {
            let second = decoder.push(&payload[split..]).unwrap();
            (second.ready.unwrap(), split + second.consumed)
        };
        assert_eq!(consumed, prefix.len());
        assert_eq!(ready.values["_csrf"], "csrf-proof");
        assert_eq!(ready.values["title"], "عنوان\r\nwith blank\r\n\r\nline");
        assert_eq!(ready.filename.as_ref().unwrap().as_str(), "page.html");
        // Authentication/quota would run here; no sink exists during prefix.
        let mut body = ready.into_body();
        let mut bytes = Vec::new();
        body.push(&payload[consumed..], |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
        assert_eq!(body.finish().unwrap(), bytes.len() as u64);
        assert_eq!(bytes, b"<script>arbitrary hostile bytes</script>");
    }
}

#[test]
fn one_byte_stream_and_all_boundary_splits_preserve_binary_bytes() {
    let expected = (0..=255u8)
        .chain(b"\r\n--not-the-boundary\r\n--".iter().copied())
        .collect::<Vec<_>>();
    let full = [expected.as_slice(), ending().as_slice()].concat();
    for size in 1..=100 {
        let mut decoder = PrefixDecoder::new(boundary(), spec(false, 1000));
        let mut completed = None;
        for chunk in prefix("binary.bin").chunks(size) {
            let progress = decoder.push(chunk).unwrap();
            if progress.ready.is_some() {
                completed = progress.ready;
            }
        }
        let mut body = completed.unwrap().into_body();
        let mut out = Vec::new();
        for chunk in full.chunks(size) {
            body.push(chunk, |bytes| {
                out.extend_from_slice(bytes);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(body.finish().unwrap(), expected.len() as u64);
        assert_eq!(out, expected);
    }
}

#[test]
fn delimiter_matcher_fallback_emits_exact_prefix_without_duplicates() {
    for length in 0..=10 {
        for mask in 0..(1usize << length) {
            let mut input = (0..length)
                .map(|i| if mask & (1 << i) == 0 { b'a' } else { b'b' })
                .collect::<Vec<_>>();
            input.extend_from_slice(b"ababac");
            let first = input.windows(6).position(|w| w == b"ababac").unwrap();
            let mut matcher = Matcher::new(b"ababac".to_vec());
            let mut out = Vec::new();
            for byte in input {
                if matcher
                    .byte(byte, |data| {
                        out.extend_from_slice(data);
                        Ok(())
                    })
                    .unwrap()
                {
                    break;
                }
            }
            let expected = (0..length)
                .map(|i| if mask & (1 << i) == 0 { b'a' } else { b'b' })
                .take(first)
                .collect::<Vec<_>>();
            assert_eq!(out, expected);
        }
    }
}

#[test]
fn maximum_file_and_buffer_bounds_are_enforced_before_sink() {
    let mut body = ready(&prefix("max.bin"), false, MAX_UPLOAD_BYTES).into_body();
    let chunk = vec![b'x'; TRANSFER_BUFFER_BYTES];
    let mut written = 0;
    for _ in 0..MAX_UPLOAD_BYTES / TRANSFER_BUFFER_BYTES as u64 {
        body.push(&chunk, |bytes| {
            assert!(bytes.len() <= TRANSFER_BUFFER_BYTES);
            written += bytes.len();
            Ok(())
        })
        .unwrap();
    }
    body.push(&ending(), |bytes| {
        written += bytes.len();
        Ok(())
    })
    .unwrap();
    assert_eq!(body.finish().unwrap(), MAX_UPLOAD_BYTES);
    assert_eq!(written as u64, MAX_UPLOAD_BYTES);
    let mut body = ready(&prefix("tiny.bin"), false, 3).into_body();
    let mut written = 0;
    assert!(
        body.push(b"four", |bytes| {
            written += bytes.len();
            Ok(())
        })
        .is_err()
    );
    assert_eq!(written, 0);
    assert!(body.push(&ending(), |_| Ok(())).is_err());
    assert!(body.finish().is_err());
    let mut body = ready(&prefix("large.bin"), false, MAX_UPLOAD_BYTES).into_body();
    assert!(
        body.push(&vec![0; TRANSFER_BUFFER_BYTES + 1], |_| Ok(()))
            .is_err()
    );
}

#[test]
fn missing_filename_is_not_optional_absence_and_empty_selection_carries_no_bytes() {
    assert!(
        PrefixDecoder::new(boundary(), spec(false, 10))
            .push(&prefix(""))
            .is_err()
    );
    let ready = ready(&prefix(""), true, 10);
    assert!(ready.filename.is_none());
    let mut body = ready.into_body();
    body.push(&ending(), |_| panic!("no-file cannot emit bytes"))
        .unwrap();
    assert_eq!(body.finish().unwrap(), 0);
    let mut body = super::tests::ready(&prefix(""), true, 10).into_body();
    assert!(body.push(b"x", |_| Ok(())).is_err());
    let malformed = String::from_utf8(prefix("x"))
        .unwrap()
        .replace("; filename=\"x\"", "");
    assert!(
        PrefixDecoder::new(boundary(), spec(true, 10))
            .push(malformed.as_bytes())
            .is_err()
    );
}

#[test]
fn boundary_media_type_and_parameter_ambiguities_fail_closed() {
    for bad in [
        "text/plain; boundary=x",
        "multipart/form-data",
        "multipart/form-data; boundary=",
        "multipart/form-data; boundary=x; boundary=y",
        "multipart/form-data; boundary=\"unterminated",
        "multipart/form-data; boundary=x\r\nInjected:yes",
        "multipart/form-data; boundary=a b",
        "multipart/form-data; charset=utf-8; boundary=x",
    ] {
        assert!(Boundary::content_type(bad).is_err(), "{bad:?}");
    }
    assert!(
        Boundary::content_type(&format!("multipart/form-data; boundary={}", "a".repeat(71)))
            .is_err()
    );
    Boundary::content_type(&format!(
        "Multipart/Form-Data; boundary=\"{}\"",
        "a".repeat(70)
    ))
    .unwrap();
}

#[test]
fn prefix_reordering_duplicates_unknown_parts_and_headers_are_denied() {
    let normal = String::from_utf8(prefix("x.bin")).unwrap();
    for bad in [
        normal.replacen("name=\"_csrf\"", "name=\"_submission\"", 1),
        normal.replacen("name=\"title\"", "name=\"unknown\"", 1),
        normal.replacen(
            "Content-Disposition:",
            "Content-Transfer-Encoding: base64\r\nContent-Disposition:",
            1,
        ),
        normal.replace(
            "Content-Type: text/html",
            "Content-Type: text/html\r\nContent-Type: text/plain",
        ),
        normal.replace(
            "name=\"_file\"; filename=\"x.bin\"",
            "name=\"_file\"; filename*=utf-8''x",
        ),
        normal.replacen("name=\"_csrf\"", "name=\"_csrf\"; filename=\"evil\"", 1),
        normal.replacen(
            "\r\n\r\ncsrf-proof",
            "\r\nContent-Type: text/plain\r\n\r\ncsrf-proof",
            1,
        ),
        normal.replace("\r\n", "\n"),
    ] {
        let mut parser = PrefixDecoder::new(boundary(), spec(false, 10));
        assert!(parser.push(bad.as_bytes()).is_err());
        assert!(parser.push(&[]).is_err());
    }
}

#[test]
fn scalar_header_total_and_schema_limits_are_bounded() {
    let normal = String::from_utf8(prefix("x.bin")).unwrap();
    let long = normal.replacen("csrf-proof", &"x".repeat(4097), 1);
    assert!(
        PrefixDecoder::new(boundary(), spec(false, 10))
            .push(long.as_bytes())
            .is_err()
    );
    let header = normal.replacen(
        "Content-Disposition:",
        &format!("X-Unknown:{}\r\nContent-Disposition:", "x".repeat(1024)),
        1,
    );
    assert!(
        PrefixDecoder::new(boundary(), spec(false, 10))
            .push(header.as_bytes())
            .is_err()
    );
    let filename = normal.replace("x.bin", &"x".repeat(256));
    assert!(
        PrefixDecoder::new(boundary(), spec(false, 10))
            .push(filename.as_bytes())
            .is_err()
    );
    assert!(PrefixSpec::new(vec![], "_file".into(), false, 10).is_err());
    assert!(
        PrefixDecoder::new(boundary(), spec(false, 10))
            .push(&vec![0; TRANSFER_BUFFER_BYTES + 1])
            .is_err()
    );
    assert!(
        PrefixDecoder::new(boundary(), spec(false, 10))
            .finish()
            .is_err()
    );
}

#[test]
fn extra_parts_epilogues_truncation_and_failed_sinks_cannot_finalize() {
    for suffix in [b"\r\n--not-matching--\r\n".to_vec(),ending()[..ending().len()-1].to_vec(),
        [ending().as_slice(),b"epilogue"].concat(),format!("\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"extra\"\r\n\r\nx\r\n--{BOUNDARY}--\r\n").into_bytes()] {
        let mut body=ready(&prefix("x"),false,1000).into_body();let result=body.push(&[b"data".as_slice(),suffix.as_slice()].concat(),|_|Ok(()));
        assert!(result.is_err() || body.finish().is_err());
    }
    let mut body = ready(&prefix("x"), false, 100).into_body();
    assert!(
        body.push(b"data", |_| anyhow::bail!("disk failure"))
            .is_err()
    );
    assert!(body.push(&ending(), |_| Ok(())).is_err());
    assert!(body.finish().is_err());
}

#[test]
fn quoted_filename_semicolons_and_escapes_never_become_active_mime_or_paths() {
    let ready = ready(&prefix("a;\\\"b.html"), false, 10);
    assert_eq!(ready.filename.unwrap().as_str(), "a__b.html");
    let bad = prefix("a\\qb.html");
    assert!(
        PrefixDecoder::new(boundary(), spec(false, 10))
            .push(&bad)
            .is_err()
    );
}
