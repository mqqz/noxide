//! Pure metadata transitions. Persist each candidate with its quota delta and
//! expected generation in ONE database transaction; these methods do not lock,
//! commit, authorize a principal, or recover an uncertain semantic receipt.
use crate::blob_store::{DurableObject, ObjectKey};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{
    blobs::{
        BlobLimits, BlobRef, MAX_LIVE_STAGES, MAX_UPLOAD_BYTES, STAGE_LIFETIME_MILLIS, UploadHandle,
    },
    time::{Duration, Timestamp},
};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Commitment(String);
impl Commitment {
    pub(crate) fn parse(value: String) -> Result<Self> {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid blob binding"
        );
        Ok(Self(value))
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Commitment([redacted])")
    }
}

/// Host-created commitments after origin/CSRF/ticket/canonical input checks.
/// Subject counts account or anonymous form capability, never circuit identity.
/// Context commits deployment, session/capability and web binding. `input`
/// identifies the NAMED UploadHandle input, never canonical scalar/selection
/// values: the existing serialized semantic receipt claim owns those values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UploadBinding {
    pub(crate) slot: Commitment,
    pub(crate) subject: Commitment,
    pub(crate) context: Commitment,
    pub(crate) input: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Association {
    pub(crate) resource: i64,
    pub(crate) id: i64,
    pub(crate) incarnation: String,
    pub(crate) field: String,
}
impl Association {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.resource > 0
                && self.id > 0
                && !self.incarnation.is_empty()
                && self.incarnation.len() <= 64
                && self
                    .incarnation
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                && !self.field.is_empty()
                && self.field.len() <= 64
                && self
                    .field
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid blob association"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Uploading,
    Staged,
    Attached,
    Unreferenced,
    Deleting,
    Deleted,
}

/// Monotonic database fencing generation, never reused after a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Generation(i64);
impl Generation {
    pub(crate) fn parse(value: i64) -> Result<Self> {
        ensure!(value > 0, "invalid blob generation");
        Ok(Self(value))
    }
    pub(crate) fn value(self) -> i64 {
        self.0
    }
    fn next(self) -> Result<Self> {
        Self::parse(self.0.checked_add(1).context("blob generation exhausted")?)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Metadata {
    pub(crate) blob: BlobRef,
    pub(crate) handle: UploadHandle,
    pub(crate) key: ObjectKey,
    pub(crate) binding: UploadBinding,
    pub(crate) state: State,
    pub(crate) generation: Generation,
    pub(crate) expires: Timestamp,
    pub(crate) reserved: u64,
    pub(crate) bytes: u64,
    pub(crate) digest: Option<[u8; 32]>,
    pub(crate) association: Option<Association>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Quota {
    pub(crate) reserved: u64,
    pub(crate) used: u64,
    pub(crate) objects: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QuotaDelta {
    reserved: i64,
    used: i64,
    objects: i64,
}
impl Quota {
    pub(crate) fn apply(self, delta: QuotaDelta, limits: BlobLimits) -> Result<Self> {
        limits.validate().map_err(anyhow::Error::msg)?;
        fn add(value: u64, delta: i64) -> Result<u64> {
            value
                .checked_add_signed(delta)
                .context("blob quota underflow or overflow")
        }
        let next = Self {
            reserved: add(self.reserved, delta.reserved)?,
            used: add(self.used, delta.used)?,
            objects: add(self.objects, delta.objects)?,
        };
        let before = self
            .reserved
            .checked_add(self.used)
            .context("blob quota overflow")?;
        let after = next
            .reserved
            .checked_add(next.used)
            .context("blob quota overflow")?;
        ensure!(
            before <= i64::MAX as u64
                && after <= i64::MAX as u64
                && self.objects <= i64::MAX as u64
                && next.objects <= i64::MAX as u64,
            "blob quota exceeds database representation"
        );
        // Lowering operator limits stops new reservations, not cleanup of
        // already charged objects. Conversion/final deletion may reduce an
        // existing overage without requiring it to disappear in one batch.
        ensure!(
            (after <= limits.app_bytes || after <= before)
                && (next.objects <= u64::from(limits.objects) || next.objects <= self.objects)
                && (delta.objects <= 0
                    || (after <= limits.app_bytes && next.objects <= u64::from(limits.objects))),
            "blob app quota exceeded"
        );
        Ok(next)
    }
}

/// Read while the app counter is write-locked. An anonymous capability supplies
/// explicitly lower per-cap limits; accounts retain the default 4 live stages.
pub(crate) struct SubjectUsage {
    pub(crate) live_stages: u64,
    pub(crate) held_bytes: u64,
    pub(crate) stage_limit: u8,
    pub(crate) byte_limit: u64,
}

/// Candidate plus expected old generation. Applying it is conditional in SQL;
/// a rollback discards it and leaves the original Staged row reusable.
pub(crate) struct Transition {
    pub(crate) expected: Generation,
    pub(crate) next: Metadata,
    pub(crate) quota: QuotaDelta,
}

/// A committed GC claim is required before calling the store's deletion API.
/// This token must not be dispatched to an I/O worker until claim commit is known.
#[derive(Clone, Debug)]
pub(crate) struct GcClaim {
    key: ObjectKey,
    generation: Generation,
}
impl GcClaim {
    pub(crate) fn key(&self) -> &ObjectKey {
        &self.key
    }
    pub(crate) fn generation(&self) -> Generation {
        self.generation
    }
}

impl Metadata {
    pub(crate) fn reserve(
        blob: BlobRef,
        pending_handle: UploadHandle,
        key: ObjectKey,
        binding: UploadBinding,
        now: Timestamp,
        bytes: u64,
        limits: BlobLimits,
        subject: SubjectUsage,
        quota: Quota,
    ) -> Result<(Self, Quota)> {
        limits.validate().map_err(anyhow::Error::msg)?;
        ensure!(
            (1..=limits.file_bytes).contains(&bytes),
            "invalid blob reservation"
        );
        ensure!(
            subject.stage_limit > 0
                && subject.stage_limit <= limits.live_stages
                && subject.stage_limit <= MAX_LIVE_STAGES
                && subject.live_stages < u64::from(subject.stage_limit)
                && subject.byte_limit > 0
                && subject.byte_limit <= MAX_UPLOAD_BYTES * u64::from(MAX_LIVE_STAGES)
                && subject
                    .held_bytes
                    .checked_add(bytes)
                    .is_some_and(|n| n <= subject.byte_limit),
            "blob subject quota exceeded"
        );
        let next_quota = quota.apply(
            QuotaDelta {
                reserved: bytes as i64,
                used: 0,
                objects: 1,
            },
            limits,
        )?;
        let expires = now.checked_add(Duration::from_millis(STAGE_LIFETIME_MILLIS)?)?;
        Ok((
            Self {
                blob,
                // Private Uploading identity is never returned to a guest or
                // accepted by attach. Stage publication replaces it with the
                // canonical object/digest-bound handle exactly once.
                handle: pending_handle,
                key,
                binding,
                state: State::Uploading,
                generation: Generation(1),
                expires,
                reserved: bytes,
                bytes: 0,
                digest: None,
                association: None,
            },
            next_quota,
        ))
    }

    fn candidate(
        &self,
        expected: Generation,
        state: State,
        quota: QuotaDelta,
    ) -> Result<Transition> {
        ensure!(self.generation == expected, "stale blob generation");
        let mut next = self.clone();
        next.generation = expected.next()?;
        next.state = state;
        Ok(Transition {
            expected,
            next,
            quota,
        })
    }
    fn fresh(&self, now: Timestamp, binding: &UploadBinding) -> Result<()> {
        ensure!(
            &self.binding == binding && now < self.expires,
            "foreign or expired upload handle"
        );
        Ok(())
    }
    pub(crate) fn stage(
        &self,
        expected: Generation,
        object: DurableObject,
        now: Timestamp,
        binding: &UploadBinding,
    ) -> Result<Transition> {
        self.fresh(now, binding)?;
        ensure!(
            self.state == State::Uploading
                && self.reserved <= MAX_UPLOAD_BYTES
                && self.bytes == 0
                && self.digest.is_none()
                && self.association.is_none()
                && object.key() == &self.key
                && object.bytes() <= self.reserved,
            "invalid staged object"
        );
        let mut transition = self.candidate(
            expected,
            State::Staged,
            QuotaDelta {
                reserved: -i64::try_from(self.reserved).context("blob reservation overflow")?,
                used: i64::try_from(object.bytes()).context("blob size overflow")?,
                objects: 0,
            },
        )?;
        transition.next.reserved = 0;
        transition.next.bytes = object.bytes();
        transition.next.digest = Some(object.sha256());
        transition.next.handle = self.finalized_handle(&object)?;
        Ok(transition)
    }
    fn finalized_handle(&self, object: &DurableObject) -> Result<UploadHandle> {
        self.expected_handle(object.bytes(), object.sha256())
    }
    pub(crate) fn expected_handle(&self, bytes: u64, sha256: [u8; 32]) -> Result<UploadHandle> {
        let mut digest = Sha256::new();
        digest.update(b"noxide/finalized-upload/v1\0");
        digest.update(self.binding.slot.as_str().as_bytes());
        digest.update(self.key.as_str().as_bytes());
        digest.update(self.blob.as_str().as_bytes());
        digest.update(bytes.to_be_bytes());
        digest.update(sha256);
        let bytes = digest.finalize();
        let mut token = String::from("u1_");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            token.push(HEX[(byte >> 4) as usize] as char);
            token.push(HEX[(byte & 15) as usize] as char);
        }
        UploadHandle::parse(token).map_err(anyhow::Error::msg)
    }
    pub(crate) fn attach(
        &self,
        expected: Generation,
        now: Timestamp,
        binding: &UploadBinding,
        handle: &UploadHandle,
        association: Association,
    ) -> Result<Transition> {
        self.fresh(now, binding)?;
        association.validate()?;
        ensure!(
            self.state == State::Staged
                && self.association.is_none()
                && &self.handle == handle
                && self.digest.is_some(),
            "upload handle is not attachable"
        );
        let mut transition = self.candidate(
            expected,
            State::Attached,
            QuotaDelta {
                reserved: 0,
                used: 0,
                objects: 0,
            },
        )?;
        transition.next.association = Some(association);
        Ok(transition)
    }
    /// The owning resource deletion and this transition share the receipt tx.
    pub(crate) fn unreference(
        &self,
        expected: Generation,
        association: &Association,
    ) -> Result<Transition> {
        ensure!(
            self.state == State::Attached && self.association.as_ref() == Some(association),
            "blob association does not match"
        );
        self.candidate(
            expected,
            State::Unreferenced,
            QuotaDelta {
                reserved: 0,
                used: 0,
                objects: 0,
            },
        )
    }
    /// Uploading rows are deliberately excluded. A stopped worker/startup
    /// reconciler must fence their completion before a separate abandon path.
    pub(crate) fn claim(
        &self,
        expected: Generation,
        now: Timestamp,
    ) -> Result<(Transition, GcClaim)> {
        ensure!(
            self.state == State::Unreferenced
                || (self.state == State::Staged && now >= self.expires),
            "blob is not collectable"
        );
        let transition = self.candidate(
            expected,
            State::Deleting,
            QuotaDelta {
                reserved: 0,
                used: 0,
                objects: 0,
            },
        )?;
        let claim = GcClaim {
            key: self.key.clone(),
            generation: transition.next.generation,
        };
        Ok((transition, claim))
    }
    /// A known stopped worker permits cleanup of failed uploads immediately;
    /// successful but unpublished completion must first reach stage expiry.
    /// Startup recovery needs a separate process-fence proof from exclusive
    /// store ownership; it must never fabricate a completed worker witness.
    pub(crate) fn claim_stopped_upload(
        &self,
        expected: Generation,
        now: Timestamp,
        stopped: &crate::blob_io::StoppedIo,
    ) -> Result<(Transition, GcClaim)> {
        ensure!(
            self.state == State::Uploading
                && stopped.key() == &self.key
                && stopped.generation() == self.generation
                && (stopped.failed_or_cancelled() || now >= self.expires),
            "upload worker is not collectable"
        );
        let transition = self.candidate(
            expected,
            State::Deleting,
            QuotaDelta {
                reserved: 0,
                used: 0,
                objects: 0,
            },
        )?;
        let claim = GcClaim {
            key: self.key.clone(),
            generation: transition.next.generation,
        };
        Ok((transition, claim))
    }
    /// Call only after idempotent unlink AND directory fsync succeeded.
    pub(crate) fn deleted(&self, claim: &GcClaim) -> Result<Transition> {
        ensure!(
            self.state == State::Deleting
                && self.key == claim.key
                && self.generation == claim.generation,
            "stale blob GC claim"
        );
        let mut transition = self.candidate(
            claim.generation,
            State::Deleted,
            QuotaDelta {
                reserved: -i64::try_from(self.reserved).context("blob reservation overflow")?,
                used: -i64::try_from(self.bytes).context("blob size overflow")?,
                objects: -1,
            },
        )?;
        transition.next.reserved = 0;
        transition.next.bytes = 0;
        Ok(transition)
    }
}

#[cfg(test)]
#[path = "blob_state_tests.rs"]
mod tests;
