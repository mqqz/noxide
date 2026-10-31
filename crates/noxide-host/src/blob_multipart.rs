//! Deliberately bounded native-form multipart grammar (RFC 7578 / RFC 2046).
//! Prefix decoding stops EXACTLY before the first file byte. The HTTP adapter
//! must authenticate these values and commit quota/slot reservation before it
//! calls into_body or polls more body data. This parser grants no authority.
use crate::blob_transport::AttachmentName;
use anyhow::{Context, Result, ensure};
use noxide_protocol::blobs::{MAX_UPLOAD_BYTES, TRANSFER_BUFFER_BYTES};
use std::collections::{BTreeMap, BTreeSet};

const PREFIX_BYTES: usize = 65_536;
const HEADER_BYTES: usize = 1_024;
const FIELD_BYTES: usize = 32_768;
const MAX_FIELDS: usize = 39; // three host controls, 32 inputs, four target handles

#[derive(Clone)]
pub(crate) struct Boundary(Vec<u8>);
impl Boundary {
    /// Native browsers use token boundaries. Also accept one quoted token;
    /// no escapes, extra parameters, whitespace within, or ambiguous duplicates.
    pub(crate) fn content_type(value: &str) -> Result<Self> {
        ensure!(value.len() <= 256, "multipart content type limit");
        let mut parts = value.split(';');
        ensure!(
            parts
                .next()
                .is_some_and(|s| s.trim().eq_ignore_ascii_case("multipart/form-data")),
            "invalid multipart media type"
        );
        let parameter = parts.next().context("missing multipart boundary")?.trim();
        ensure!(parts.next().is_none(), "unknown multipart parameter");
        let (name, value) = parameter
            .split_once('=')
            .context("missing multipart boundary")?;
        ensure!(
            name.eq_ignore_ascii_case("boundary"),
            "unknown multipart parameter"
        );
        let value = if value.starts_with('"') {
            value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .context("invalid quoted boundary")?
        } else {
            value
        };
        ensure!(
            !value.is_empty()
                && value.len() <= 70
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "invalid multipart boundary"
        );
        Ok(Self(value.as_bytes().to_vec()))
    }
    fn initial(&self) -> Vec<u8> {
        [b"--".as_slice(), self.0.as_slice(), b"\r\n"].concat()
    }
    fn next(&self) -> Vec<u8> {
        [b"\r\n--".as_slice(), self.0.as_slice(), b"\r\n"].concat()
    }
    fn file_end(&self) -> Vec<u8> {
        [b"\r\n--".as_slice(), self.0.as_slice()].concat()
    }
}

pub(crate) struct ScalarPart {
    pub(crate) name: String,
    pub(crate) max_bytes: usize,
    pub(crate) required: bool,
}
pub(crate) struct PrefixSpec {
    fields: Vec<ScalarPart>,
    file: String,
    optional: bool,
    limit: u64,
}
impl PrefixSpec {
    pub(crate) fn new(
        fields: Vec<ScalarPart>,
        file: String,
        optional: bool,
        limit: u64,
    ) -> Result<Self> {
        ensure!(
            (3..=MAX_FIELDS).contains(&fields.len()) && (1..=MAX_UPLOAD_BYTES).contains(&limit),
            "invalid multipart schema"
        );
        let mut seen = BTreeSet::new();
        for field in &fields {
            ensure!(
                part_name(&field.name)
                    && (1..=FIELD_BYTES).contains(&field.max_bytes)
                    && seen.insert(field.name.as_str()),
                "invalid multipart scalar schema"
            );
        }
        for (field, expected) in fields.iter().zip(["_csrf", "_submission", "_upload"]) {
            ensure!(
                field.name == expected && field.required,
                "invalid multipart security prefix"
            );
        }
        ensure!(
            part_name(&file) && !seen.contains(file.as_str()),
            "invalid multipart file schema"
        );
        Ok(Self {
            fields,
            file,
            optional,
            limit,
        })
    }
}
fn part_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

enum PrefixPhase {
    Initial(usize),
    Headers,
    Scalar(usize, Vec<u8>, Matcher),
    Ready,
    Poisoned,
}
pub(crate) struct PrefixDecoder {
    boundary: Boundary,
    spec: PrefixSpec,
    phase: PrefixPhase,
    headers: Vec<u8>,
    values: BTreeMap<String, String>,
    field: usize,
    total: usize,
}
pub(crate) struct PrefixProgress {
    pub(crate) consumed: usize,
    pub(crate) ready: Option<ReadyPrefix>,
}
pub(crate) struct ReadyPrefix {
    pub(crate) values: BTreeMap<String, String>,
    pub(crate) filename: Option<AttachmentName>,
    boundary: Boundary,
    limit: u64,
}
impl ReadyPrefix {
    /// The caller must first validate origin/CSRF/submission/ticket/schema and
    /// resolve replay/commit reservation. Even an already buffered input chunk
    /// must stay unconsumed until that succeeds. Optional no-file has limit0.
    pub(crate) fn into_body(self) -> FileDecoder {
        FileDecoder::new(&self.boundary, self.limit)
    }
}
impl PrefixDecoder {
    pub(crate) fn new(boundary: Boundary, spec: PrefixSpec) -> Self {
        Self {
            boundary,
            spec,
            phase: PrefixPhase::Initial(0),
            headers: Vec::new(),
            values: BTreeMap::new(),
            field: 0,
            total: 0,
        }
    }
    pub(crate) fn push(&mut self, input: &[u8]) -> Result<PrefixProgress> {
        let result = self.push_inner(input);
        if result.is_err() {
            self.phase = PrefixPhase::Poisoned;
        }
        result
    }
    fn push_inner(&mut self, input: &[u8]) -> Result<PrefixProgress> {
        ensure!(
            input.len() <= TRANSFER_BUFFER_BYTES,
            "multipart input buffer limit"
        );
        ensure!(
            !matches!(self.phase, PrefixPhase::Ready | PrefixPhase::Poisoned),
            "multipart prefix is closed"
        );
        let initial = self.boundary.initial();
        for (index, byte) in input.iter().copied().enumerate() {
            self.total = self
                .total
                .checked_add(1)
                .context("multipart prefix overflow")?;
            ensure!(self.total <= PREFIX_BYTES, "multipart prefix limit");
            match &mut self.phase {
                PrefixPhase::Initial(cursor) => {
                    ensure!(
                        initial.get(*cursor) == Some(&byte),
                        "invalid initial multipart delimiter"
                    );
                    *cursor += 1;
                    if *cursor == initial.len() {
                        self.phase = PrefixPhase::Headers;
                    }
                }
                PrefixPhase::Headers => {
                    ensure!(self.headers.len() < HEADER_BYTES, "multipart header limit");
                    self.headers.push(byte);
                    if self.headers.ends_with(b"\r\n\r\n") {
                        let headers = parse_headers(&self.headers[..self.headers.len() - 4])?;
                        self.headers.clear();
                        if headers.name == self.spec.file {
                            ensure!(
                                self.spec.fields[self.field..].iter().all(|f| !f.required),
                                "missing multipart prefix field"
                            );
                            let raw = headers.filename.context("file part lacks filename")?;
                            ensure!(
                                !raw.is_empty() || self.spec.optional,
                                "required upload missing"
                            );
                            let filename = if raw.is_empty() {
                                None
                            } else {
                                Some(AttachmentName::normalize(&raw)?)
                            };
                            let limit = if filename.is_some() {
                                self.spec.limit
                            } else {
                                0
                            };
                            self.phase = PrefixPhase::Ready;
                            return Ok(PrefixProgress {
                                consumed: index + 1,
                                ready: Some(ReadyPrefix {
                                    values: std::mem::take(&mut self.values),
                                    filename,
                                    boundary: self.boundary.clone(),
                                    limit,
                                }),
                            });
                        }
                        ensure!(
                            headers.filename.is_none() && !headers.content_type,
                            "file or media header in scalar prefix"
                        );
                        let next = self.spec.fields[self.field..]
                            .iter()
                            .position(|f| f.name == headers.name)
                            .map(|i| self.field + i)
                            .context("unknown, duplicate or reordered multipart field")?;
                        ensure!(
                            self.spec.fields[self.field..next]
                                .iter()
                                .all(|f| !f.required),
                            "missing required multipart prefix"
                        );
                        self.field = next + 1;
                        self.phase = PrefixPhase::Scalar(
                            next,
                            Vec::new(),
                            Matcher::new(self.boundary.next()),
                        );
                    }
                }
                PrefixPhase::Scalar(field, value, matcher) => {
                    let maximum = self.spec.fields[*field].max_bytes;
                    let ended = matcher.byte(byte, |bytes| {
                        ensure!(
                            value
                                .len()
                                .checked_add(bytes.len())
                                .is_some_and(|n| n <= maximum),
                            "multipart scalar limit"
                        );
                        value.extend_from_slice(bytes);
                        Ok(())
                    })?;
                    if ended {
                        let name = self.spec.fields[*field].name.clone();
                        let value = String::from_utf8(std::mem::take(value))
                            .context("multipart scalar is not UTF-8")?;
                        self.values.insert(name, value);
                        self.phase = PrefixPhase::Headers;
                    }
                }
                PrefixPhase::Ready | PrefixPhase::Poisoned => unreachable!(),
            }
        }
        Ok(PrefixProgress {
            consumed: input.len(),
            ready: None,
        })
    }
    pub(crate) fn finish(&self) -> Result<()> {
        ensure!(
            matches!(self.phase, PrefixPhase::Ready),
            "truncated multipart prefix"
        );
        Ok(())
    }
}

struct PartHeaders {
    name: String,
    filename: Option<String>,
    content_type: bool,
}
fn parse_headers(bytes: &[u8]) -> Result<PartHeaders> {
    let text = std::str::from_utf8(bytes).context("invalid multipart header encoding")?;
    let mut disposition = None;
    let mut content_type = false;
    for line in text.split("\r\n") {
        ensure!(
            !line.is_empty() && !line.bytes().any(|b| b < 32 || b == 127),
            "invalid multipart header line"
        );
        let (name, value) = line.split_once(':').context("invalid multipart header")?;
        let value = value.trim_matches(' ');
        if name.eq_ignore_ascii_case("content-disposition") {
            ensure!(disposition.is_none(), "duplicate multipart disposition");
            disposition = Some(disposition_value(value)?);
        } else if name.eq_ignore_ascii_case("content-type") {
            ensure!(
                !content_type
                    && !value.is_empty()
                    && value.len() <= 128
                    && value.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                "invalid multipart media hint"
            );
            content_type = true;
        } else {
            anyhow::bail!("unknown multipart header");
        }
    }
    let (name, filename) = disposition.context("missing multipart disposition")?;
    ensure!(
        filename.is_some() || !content_type,
        "scalar multipart media hint denied"
    );
    Ok(PartHeaders {
        name,
        filename,
        content_type,
    })
}
fn disposition_value(value: &str) -> Result<(String, Option<String>)> {
    let (kind, rest) = value.split_once(';').context("missing multipart name")?;
    ensure!(
        kind.eq_ignore_ascii_case("form-data"),
        "invalid multipart disposition"
    );
    let mut bytes = rest.as_bytes();
    let (name, value) = attribute(&mut bytes)?;
    ensure!(
        name == "name" && part_name(&value),
        "invalid multipart field name"
    );
    let field = value;
    let filename = if bytes.is_empty() {
        None
    } else {
        ensure!(bytes[0] == b';', "invalid multipart disposition suffix");
        bytes = &bytes[1..];
        let (name, value) = attribute(&mut bytes)?;
        ensure!(
            name == "filename" && value.len() <= 255 && bytes.is_empty(),
            "unknown multipart disposition attribute"
        );
        Some(value)
    };
    Ok((field, filename))
}
fn attribute<'a>(input: &mut &'a [u8]) -> Result<(&'a str, String)> {
    while input.first() == Some(&b' ') {
        *input = &input[1..];
    }
    let equals = input
        .iter()
        .position(|b| *b == b'=')
        .context("invalid multipart attribute")?;
    let name = std::str::from_utf8(&input[..equals])?;
    ensure!(
        name.bytes().all(|b| b.is_ascii_alphabetic()),
        "invalid multipart attribute name"
    );
    *input = &input[equals + 1..];
    ensure!(
        input.first() == Some(&b'"'),
        "multipart attribute must be quoted"
    );
    *input = &input[1..];
    let mut out = Vec::new();
    let mut closed = false;
    while let Some(byte) = input.first().copied() {
        *input = &input[1..];
        if byte == b'"' {
            closed = true;
            break;
        }
        let byte = if byte == b'\\' {
            let escaped = input
                .first()
                .copied()
                .context("truncated multipart quoted escape")?;
            ensure!(
                matches!(escaped, b'\\' | b'"'),
                "unknown multipart quoted escape"
            );
            *input = &input[1..];
            escaped
        } else {
            byte
        };
        ensure!(
            byte >= 32 && byte != 127 && out.len() < 255,
            "multipart attribute limit"
        );
        out.push(byte);
    }
    ensure!(closed, "unclosed multipart attribute");
    Ok((
        name,
        String::from_utf8(out).context("invalid multipart attribute encoding")?,
    ))
}

/// Linear-time streaming delimiter matching; retains at most delimiter.len()
/// bytes implicitly as a prefix index. No scanning/copying a growing file buffer.
struct Matcher {
    delimiter: Vec<u8>,
    failure: Vec<usize>,
    matched: usize,
}
impl Matcher {
    fn new(delimiter: Vec<u8>) -> Self {
        let mut failure = vec![0; delimiter.len()];
        let mut matched = 0;
        for index in 1..delimiter.len() {
            while matched > 0 && delimiter[index] != delimiter[matched] {
                matched = failure[matched - 1];
            }
            if delimiter[index] == delimiter[matched] {
                matched += 1;
            }
            failure[index] = matched;
        }
        Self {
            delimiter,
            failure,
            matched: 0,
        }
    }
    fn byte(&mut self, byte: u8, mut emit: impl FnMut(&[u8]) -> Result<()>) -> Result<bool> {
        while self.matched > 0 && self.delimiter[self.matched] != byte {
            let fallback = self.failure[self.matched - 1];
            let release = self.matched - fallback;
            emit(&self.delimiter[..release])?;
            self.matched = fallback;
        }
        if self.delimiter[self.matched] == byte {
            self.matched += 1;
            if self.matched == self.delimiter.len() {
                self.matched = 0;
                return Ok(true);
            }
        } else {
            emit(&[byte])?;
        }
        Ok(false)
    }
}
#[derive(Clone, Copy)]
enum FilePhase {
    Data,
    Closing(usize),
    Done,
    Poisoned,
}
pub(crate) struct FileDecoder {
    matcher: Matcher,
    phase: FilePhase,
    limit: u64,
    accepted: u64,
    buffer: Box<[u8; TRANSFER_BUFFER_BYTES]>,
}
impl FileDecoder {
    fn new(boundary: &Boundary, limit: u64) -> Self {
        Self {
            matcher: Matcher::new(boundary.file_end()),
            phase: FilePhase::Data,
            limit,
            accepted: 0,
            buffer: Box::new([0; TRANSFER_BUFFER_BYTES]),
        }
    }
    /// One reusable output buffer, at most64KiB. Sink failure poisons this body.
    pub(crate) fn push(
        &mut self,
        input: &[u8],
        mut sink: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let result = self.push_inner(input, &mut sink);
        if result.is_err() {
            self.phase = FilePhase::Poisoned;
        }
        result
    }
    fn push_inner(
        &mut self,
        input: &[u8],
        sink: &mut impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            input.len() <= TRANSFER_BUFFER_BYTES,
            "multipart file input buffer limit"
        );
        ensure!(
            !matches!(self.phase, FilePhase::Poisoned),
            "multipart file is poisoned"
        );
        let buffer = &mut self.buffer;
        let mut count = 0;
        let limit = self.limit;
        let accepted = &mut self.accepted;
        let mut flush = |bytes: &[u8]| -> Result<()> {
            let total = accepted
                .checked_add(bytes.len() as u64)
                .context("multipart file overflow")?;
            ensure!(total <= limit, "multipart file byte limit");
            sink(bytes)?;
            *accepted = total;
            Ok(())
        };
        for byte in input.iter().copied() {
            match self.phase {
                FilePhase::Data => {
                    let ended = self.matcher.byte(byte, |bytes| {
                        for byte in bytes {
                            buffer[count] = *byte;
                            count += 1;
                            if count == buffer.len() {
                                flush(&buffer[..])?;
                                count = 0;
                            }
                        }
                        Ok(())
                    })?;
                    if ended {
                        self.phase = FilePhase::Closing(0);
                    }
                }
                FilePhase::Closing(cursor) => {
                    const CLOSING: &[u8] = b"--\r\n";
                    ensure!(
                        CLOSING.get(cursor) == Some(&byte),
                        "unexpected part or multipart closing suffix"
                    );
                    self.phase = if cursor + 1 == CLOSING.len() {
                        FilePhase::Done
                    } else {
                        FilePhase::Closing(cursor + 1)
                    };
                }
                FilePhase::Done => anyhow::bail!("multipart epilogue or extra part denied"),
                FilePhase::Poisoned => unreachable!(),
            }
        }
        if count > 0 {
            flush(&buffer[..count])?;
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<u64> {
        ensure!(
            matches!(self.phase, FilePhase::Done),
            "truncated multipart file"
        );
        Ok(self.accepted)
    }
}

#[cfg(test)]
#[path = "blob_multipart_tests.rs"]
mod tests;
