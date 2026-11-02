// Reviewer scratch: append inside an http.rs cfg(test) module or use qualified names.
// Source-only at 17aa8fe; not compiled or executed by R.
#[test]
fn reviewer_max_admitted_scalar_cursor_survives_http_query_transport() {
    use noxide_protocol::{
        ListOrder, ListSettings,
        query::{CursorKey, CursorValue, Direction, SortMode},
    };
    let mut manifest = crate::test_support::manifest();
    manifest.resources[0].fields[0].max_bytes = 512;
    manifest.resources[0].fields[0].immutable = true;
    manifest.actions[0].inputs[0].max_bytes = 512;
    manifest.operations[0].list = Some(ListSettings {
        page_size: 1,
        order: ListOrder::Field {
            field: "body".into(),
            direction: Direction::Ascending,
            mode: SortMode::Immutable,
        },
        preview: None,
    });
    crate::manifest::validate(&manifest).unwrap();
    let keys = crate::HostKeys::generate().unwrap();
    let (_, cursor) = keys
        .issue(
            crate::security::TokenKind::Cursor {
                scope: "s".repeat(43),
                after: CursorKey::Scalar {
                    value: CursorValue::Binary("a".repeat(512)),
                    record: 1,
                },
            },
            "",
            1_793_440_000,
            900,
        )
        .unwrap();
    let raw = format!("cursor={cursor}");
    eprintln!(
        "REVIEWER admitted scalar512 cursor_bytes={} raw_query_bytes={}",
        cursor.len(),
        raw.len()
    );
    assert!(cursor.len() <= 2048);
    assert!(raw.len() > 1024);
    let (parsed, params) = crate::parse_query(&manifest, &manifest.routes[0], Some(&raw))
        .expect("host-issued next-page cursor must pass the real HTTP query parser");
    assert_eq!(parsed, Some(cursor));
    assert!(params.is_empty());
}

#[test]
fn escaped_maximum_scalar_cursor_keeps_the_existing_token_limit() {
    use noxide_protocol::query::{CursorKey, CursorValue};
    let manifest = crate::test_support::manifest();
    let keys = crate::HostKeys::generate().unwrap();
    let (_, cursor) = keys
        .issue(
            crate::security::TokenKind::Cursor {
                scope: "s".repeat(43),
                after: CursorKey::Scalar {
                    value: CursorValue::Binary("\\\"".repeat(256)),
                    record: i64::MAX as u64,
                },
            },
            "",
            i64::MAX - 900,
            900,
        )
        .unwrap();
    assert!(cursor.len() > 1024 && cursor.len() <= crate::security::MAX_TOKEN_BYTES);
    keys.verify_cursor(&cursor, i64::MAX - 900).unwrap();
    let (parsed, params) = crate::parse_query(
        &manifest,
        &manifest.routes[0],
        Some(&format!("cursor={cursor}")),
    )
    .unwrap();
    assert_eq!(parsed, Some(cursor));
    assert!(params.is_empty());
}

#[test]
fn opaque_cursor_allowance_cannot_expand_ordinary_query_inputs() {
    use noxide_protocol::query::CursorKey;
    let manifest = crate::test_support::manifest();
    let route = &manifest.routes[0];
    let keys = crate::HostKeys::generate().unwrap();
    let (_, cursor) = keys
        .issue(
            crate::security::TokenKind::Cursor {
                scope: "s".repeat(43),
                after: CursorKey::Created {
                    sequence: 1,
                    record: 1,
                },
            },
            "",
            100,
            900,
        )
        .unwrap();
    let boundary = "&".repeat(1024);
    crate::parse_query(&manifest, route, Some(&boundary)).unwrap();
    crate::parse_query(
        &manifest,
        route,
        Some(&format!("cursor={cursor}&{boundary}")),
    )
    .unwrap();
    for raw in [
        "&".repeat(1025),
        format!("cursor={cursor}&{}", "&".repeat(1025)),
    ] {
        let error = crate::parse_query(&manifest, route, Some(&raw)).unwrap_err();
        assert!(error.to_string().contains("query string limit"));
    }
    for raw in [
        format!("cursor={cursor}&cursor={cursor}"),
        format!("cursor={}", "a".repeat(2049)),
        format!("cursor={cursor}&unknown=value"),
    ] {
        assert!(crate::parse_query(&manifest, route, Some(&raw)).is_err());
    }
}
