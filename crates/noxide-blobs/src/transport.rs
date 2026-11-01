//! Attachment response values and bounded monotonic transfer accounting.
//! This module grants no read authority and is not registered as an HTTP handler.
use anyhow::{Context, Result, ensure};
use noxide_protocol::blobs::{
    DOWNLOAD_IDLE_MILLIS, MAX_UPLOAD_BYTES, TRANSFER_BUFFER_BYTES, TRANSFER_TOTAL_MILLIS,
};
use std::time::{Duration, Instant};

pub const CONTENT_TYPE: &str = "application/octet-stream";
pub const CACHE_CONTROL: &str = "no-store";
pub const NOSNIFF: &str = "nosniff";
pub const CSP: &str = "default-src 'none'; sandbox";
const MAX_RAW_FILENAME_BYTES: usize = 255;
const MAX_FILENAME_BYTES: usize = 80;

/// A display label only; it must never be passed to any filesystem API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentName(String);
impl AttachmentName {
    pub fn normalize(input: &str) -> Result<Self> {
        ensure!(
            input.len() <= MAX_RAW_FILENAME_BYTES,
            "upload filename limit"
        );
        let basename = input.rsplit(['/', '\\']).next().unwrap_or("");
        let label = basename
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .take(MAX_FILENAME_BYTES)
            .collect::<String>();
        let label = label.trim_matches(['.', '_', '-']);
        Ok(Self(if label.is_empty() {
            "download.bin".into()
        } else {
            label.into()
        }))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Contains only ASCII letters, digits, dot, underscore and hyphen inside a
    /// quoted filename. No untrusted quote, separator, Unicode or header byte.
    pub fn disposition(&self) -> String {
        format!("attachment; filename=\"{}\"", self.0)
    }
}

/// Transport adapters must actually enforce these deadlines while waiting for
/// body/network progress, including when no further body poll occurs. Merely
/// checking on the next poll is insufficient to release a stalled stream.
pub struct TransferBudget {
    total: Instant,
    idle: Instant,
    remaining: u64,
}
impl TransferBudget {
    pub fn new(now: Instant, request_deadline: Instant, bytes: u64) -> Result<Self> {
        ensure!(bytes <= MAX_UPLOAD_BYTES, "download byte limit");
        let total = request_deadline.min(
            now.checked_add(Duration::from_millis(TRANSFER_TOTAL_MILLIS))
                .context("blob transfer deadline overflow")?,
        );
        let idle = total.min(
            now.checked_add(Duration::from_millis(DOWNLOAD_IDLE_MILLIS))
                .context("blob idle deadline overflow")?,
        );
        ensure!(now < total, "blob transfer deadline");
        Ok(Self {
            total,
            idle,
            remaining: bytes,
        })
    }
    pub fn deadline(&self) -> Instant {
        self.total.min(self.idle)
    }
    pub fn check(&self, now: Instant) -> Result<()> {
        ensure!(
            now < self.deadline(),
            "blob transfer idle or total deadline"
        );
        Ok(())
    }
    /// Called after nonempty progress, never for empty polls or keepalives.
    /// This is exact byte accounting, not permission to send bytes before auth.
    pub fn progress(&mut self, now: Instant, bytes: usize) -> Result<()> {
        self.check(now)?;
        ensure!(
            bytes > 0 && bytes <= TRANSFER_BUFFER_BYTES,
            "blob transfer buffer limit"
        );
        self.remaining = self
            .remaining
            .checked_sub(bytes as u64)
            .context("blob transfer length exceeded")?;
        self.idle = self.total.min(
            now.checked_add(Duration::from_millis(DOWNLOAD_IDLE_MILLIS))
                .context("blob idle deadline overflow")?,
        );
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.remaining == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filenames_are_labels_and_cannot_inject_headers_or_paths() {
        for (input, expected) in [
            ("../../secret.txt", "secret.txt"),
            ("C:\\fakepath\\a.svg", "a.svg"),
            ("/", "download.bin"),
            ("..", "download.bin"),
            ("a\r\nX-Header: evil.html", "a__X-Header__evil.html"),
            ("a\";filename=x.html", "a__filename_x.html"),
            ("\0", "download.bin"),
            ("📦.bin", "bin"),
        ] {
            let name = AttachmentName::normalize(input).unwrap();
            assert_eq!(name.as_str(), expected);
            assert_eq!(
                name.disposition(),
                format!("attachment; filename=\"{expected}\"")
            );
        }
        assert_eq!(
            AttachmentName::normalize(&"a".repeat(255))
                .unwrap()
                .as_str()
                .len(),
            80
        );
        assert!(AttachmentName::normalize(&"a".repeat(256)).is_err());
        assert_eq!(CONTENT_TYPE, "application/octet-stream");
        assert_eq!(CACHE_CONTROL, "no-store");
        assert_eq!(NOSNIFF, "nosniff");
        assert_eq!(CSP, "default-src 'none'; sandbox");
    }
    #[test]
    fn exact_length_buffer_and_idle_deadlines_are_enforced() {
        let now = Instant::now();
        let mut budget = TransferBudget::new(now, now + Duration::from_secs(200), 65537).unwrap();
        assert_eq!(budget.deadline(), now + Duration::from_secs(15));
        assert!(budget.progress(now, 0).is_err());
        assert!(budget.progress(now, 65537).is_err());
        budget
            .progress(now + Duration::from_secs(14), 65536)
            .unwrap();
        assert_eq!(budget.deadline(), now + Duration::from_secs(29));
        assert!(!budget.complete());
        assert!(budget.progress(now + Duration::from_secs(29), 1).is_err());
        budget.progress(now + Duration::from_secs(28), 1).unwrap();
        assert!(budget.complete());
        assert!(budget.progress(now + Duration::from_secs(28), 1).is_err());
    }
    #[test]
    fn progress_never_extends_total_or_outer_request_deadline() {
        let now = Instant::now();
        let mut budget =
            TransferBudget::new(now, now + Duration::from_secs(200), MAX_UPLOAD_BYTES).unwrap();
        for seconds in (14..120).step_by(14) {
            budget
                .progress(now + Duration::from_secs(seconds), 1)
                .unwrap();
        }
        assert_eq!(budget.deadline(), now + Duration::from_secs(120));
        assert!(budget.check(now + Duration::from_secs(120)).is_err());
        let short = TransferBudget::new(now, now + Duration::from_secs(2), 0).unwrap();
        assert_eq!(short.deadline(), now + Duration::from_secs(2));
        assert!(short.complete());
        assert!(TransferBudget::new(now, now, 1).is_err());
        assert!(
            TransferBudget::new(now, now + Duration::from_secs(1), MAX_UPLOAD_BYTES + 1).is_err()
        );
    }
}
