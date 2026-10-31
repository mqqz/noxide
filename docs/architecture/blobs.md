# Blob storage

P08 is **disabled**, not an available application capability. Wire version 10
includes opaque types and the requested policy; host admission rejects blob
manifests. Durable store, multipart parsing, state and approval helpers have leaf
tests. Native schema verification is separately reviewed. Metadata SQL, pairing
and inspection interfaces compile, but their provider/commit/FS integration is
unfinished. Explicit SDK declarations lower to this same contract; they grant no
authority. Runtime upload/download dispatch, transactional attachment, GC and
operator activation remain unfinished.

The feature contract is [F4 in the handover](handover-2026-10-31.md#f4-blob-storage-and-delivery).
All application bytes are hostile. They will be downloaded as attachments with
`application/octet-stream`, never interpreted as assets, HTML, SVG or inline
previews. No uploaded bytes enter Wasm, ordinary JSON or Document IR buffers.

## Implemented foundation

`noxide-protocol/src/blobs.rs` distinguishes a `BlobRef` from an `UploadHandle`.
Each encodes a random host identity, with a distinct prefix and canonical lowercase
hex encoding; parsing establishes no authority. Debug output redacts tokens.
Host object keys are separate identities and never supplied by a guest as paths.

The hard ceilings are 10 MiB per file, 1 GiB per application, 65,536 physical
objects, four live stages per subject, four concurrent uploads and eight
concurrent downloads. Operator limits may lower these ceilings. The object count
includes Uploading, Staged, Attached, Unreferenced and Deleting, including uncertain
physical work. Empty files consume object quota. Bytes and object count are
released only after acknowledged durable deletion. Reducing an operator quota
stops new reservations while allowing existing overages to be cleaned gradually.

`blob_store.rs` opens an absolute operator path by directory descriptors, refusing
symlink components. The root and internal directories must have mode 0700 and
belong to the effective host user. Files must be owned, regular and singly linked.
Staging uses create-new, mode 0600, no-follow operations. Finalization seals the
file to mode 0400, fsyncs its data, renames within one filesystem without replacing
an existing object, and fsyncs both directories. Only then can it return the
private durable-object token needed for a Staged candidate.

A persistent random store identity and a distinct pair identity must be bound to
the database during activation. A nonblocking exclusive flock prevents simultaneous owners of the
same store. Descriptors, uploads and scans retain this lease. Store access assumes
a healthy operator-managed local filesystem and trusted host account. Another
process with that same account's authority can tamper with private files; this is
not a sandbox against the operator. Directory-relative I/O prevents guest paths
and symlinks from redirecting an operation.

Downloads can capture an immutable descriptor after checking expected length,
ownership, file type, link count and mode. Missing or inconsistent objects fail.
A descriptor already captured remains readable after unlink; a new open fails.
Actual authorization is intentionally absent from the store and must precede
opening through the shared current resource/field read authority.

All data operations check a supplied monotonic deadline and cancellation flag
between chunks of at most 64 KiB, and after finalization syscalls. Lifecycle
timestamps come from the existing durable clock, never this I/O deadline.
Native fsync/read/write calls cannot be forcibly interrupted by a Tokio timeout.
`blob_io.rs` acquires a bounded worker permit before enqueueing, without a waiting
admission queue, and keeps the permit inside the worker until actual exit.
Timed-out or abandoned work quarantines its capacity until completion. A late
successful syscall cannot publish a successful worker result after cancellation.
No destructor performs filesystem cleanup. Failed/incomplete files remain
unclaimable and must be reconciled under fenced metadata ownership.

The pure `blob_state.rs` transitions preserve the sequence
`Uploading -> Staged -> Attached -> Unreferenced -> Deleting -> Deleted`.
Reservations count the full upload ceiling before receiving bytes. Staged
publication converts the reservation to actual used bytes exactly once;
attachment does not charge again. A handle is bound to subject, stable invocation
slot, deployment/session/form context and the named UploadHandle input. Scalar
and selected-review inputs belong to the serialized action receipt claim, not
the immutable file slot. After an authoritatively aborted action the same form
scope and original nonce may reuse that file while correcting other inputs.
Committed or unknown invocations cannot be rebound to different canonical input.
Expiry is exactly 15 minutes from the attempt's typed lifecycle timestamp.
Attachment produces a conditional candidate rather than mutating the original,
so transaction rollback leaves Staged reusable. Generation checks fence every
transition. Failed-upload cleanup requires a matching stopped-worker proof;
successful unpublished work must expire first. Startup process-fence recovery is
not yet implemented and must not fabricate a completed-worker proof.

Directory enumeration retains a scanner between batches and reads at most 64
entries per batch. It rejects malformed names and nonregular entries rather than
following or recursively deleting them. The root permits only its fixed private
store names and refuses an unrelated existing directory. A bounded inspection
plan distinguishes known reservation recovery from completely unknown objects;
the latter always require operator reconciliation. Plans omit filenames, content
and credentials, and are host/operator-only data, never deletion or read grants.
Durable observations, automatic recovery execution and SQL GC claims remain to
be integrated.

`blob_transport.rs` normalizes bounded filenames to at most 80 safe ASCII bytes
and constructs attachment-only header values. Its monotonic transfer accounting
enforces exact remaining bytes, 64 KiB chunks, 15-second idle and 120-second total
ceilings, clamped to the existing request deadline. Empty polls cannot renew idle
time. The eventual transport must enforce timers even when the client stops
polling; a budget object alone cannot wake or cancel a stalled HTTP connection.

## Required integration

The approved browser flow is one NoJS multipart POST to an existing web action.
A GET issues a stateless form/deployment/session-or-anonymous-capability ticket
without database writes. The host validates origin, CSRF, submission identity,
ticket and bounded scalar prefix before reserving quota and reading the final
one-file part. Reused stage and new file are mutually exclusive. Unknown parts,
headers and ordering fail closed. One upload input attaches to exactly one create
field; scalar one-input-to-many assignment does not apply. There is at most one
upload input/binding per action and web binding, and at most 16 bindings per app.
The existing eight-field resource limit is unchanged. Explicit File controls
follow all submitted prefix controls in native DOM order.

`Manifest.blobs` contains the requested ceilings, upload bindings and anonymous
opt-in. Anonymous staging additionally requires explicit operator ceilings, at
most 16 live stages/160 MiB per deployment and four/40 MiB per capability, within
the shared application limits. These defaults are bounds, not capacity claims.
The build manifest digest covers this requested authority. A blob deployment's
single approval token additionally covers the canonical effective policy after
operator intersection; declaration order does not change that token. Paths and
secrets are excluded. Changed effective authority invalidates old submissions,
tickets, receipts and queued work. `contract-hash` remains a build digest;
`deployment-hash` is the read-only deployment approval calculation. Activation
must verify the one approval before opening the configured store.

Before accepting file bytes, a replay must resolve its stable slot and committed
receipt. The first finalized object fixes its handle, identity and digest. Retry
cannot replace those bytes, create a fresh stage, or substitute an equivalent new
handle. Committed receipt recovery precedes stage expiry checks; new execution
requires current authority and time. Streaming consumes the remaining overall
HTTP deadline rather than starting a fresh action budget afterward.
The existing 60-second connection ceiling clamps the 120-second transfer ceiling;
the final action retains its stricter two-second phase cap. A single private
request scope must retain the outer deadline and actual provider-statement meter
through classification, staging, execution, navigation and cleanup. Metadata
leaves currently expose an explicit caller counter for preparation only; runtime
integration must delegate to the shared transaction-owned meter. No new upload
allowance or independently reset budget is authorized.

SQL must atomically lock/count quota, publish Staged with the correct generation,
attach the owning resource/field and receipt together, and mark resource deletion
Unreferenced in that same transaction. Unknown commit acknowledgements go through
authoritative receipt recovery before cleanup. Fenced GC commits its claim before
unlink, deletes outside the transaction, then conditionally finalizes metadata.
Every normal file creation must follow a durably committed Uploading reservation.
Unknown acknowledgement is recovered before file creation. Retained reservation
and claimed-deletion metadata permits fenced normal crash recovery. A completely
unknown object is evidence of an ambiguous restore or lost metadata, even after
a grace interval: retain and quarantine/account it in bounded batches, block new
uploads on mismatch/overage, and require explicit operator reconciliation. Never
delete it merely because its store marker matches or it appears old.

Downloads must use the canonical current read policy, active membership,
projection, visibility, parent gate, expiry, grant scope and record incarnation.
Initially only independent direct Read provenance is accepted. A BlobRef, edit
capability, cursor, mutation grant or child-list grant cannot substitute for it;
Follow requires separately proven source provenance and is not inferred.
Capture the file descriptor in the short read transaction and release transaction
and database permits before streaming. Require no-store, nosniff, restrictive
CSP, a host-normalized attachment filename, no Range, 64 KiB transfer chunks,
15-second idle and 120-second total limits, plus bounded stream concurrency.
Revocation stops new streams; bytes already delivered cannot be recalled.

## Backup and restore contract

These are requirements for the unfinished operator integration, not a shipped
backup command. One designated host manages this local object store even when
metadata uses PostgreSQL. Multi-host shared object storage is outside this scope.

An operator backup must fence uploads, finalization, attachment and GC, drain or
quarantine native work, and pair a consistent metadata snapshot with its immutable
objects and store identity. Preserve private modes and ownership. Copying only the
database or only the objects is not a complete backup. Restore must verify the
store identity, each referenced object's type, mode, link count, length and stored
digest before serving. Missing objects cannot become successful downloads.
Resume the existing lifecycle clock and reconcile incomplete rows and orphan
files in bounded batches before clearing the maintenance fence. Do not reset
quota counters or delete unknown-commit objects to obtain readiness.

First bind commits a pending database pair before writing a synced private
filesystem pair marker, then acknowledges the same pair in the database. No
readiness or GC precedes both. A missing/new database refuses any already-paired
store, including an empty one. A paired database refuses a missing/mismatched
marker. A matching pending bind resumes only after authoritative database outcome
recovery and a bounded empty-store proof under the held lease. No mismatch cleanup
is automatic. Matching markers do not certify that database and filesystem
snapshots were captured together; equal-time backup/restore validation remains
required.

## Leaf verification

Run the committed standalone harness with new evidence output and a dedicated
compiler lane:

```sh
python3 tools/test_blob_leaves.py \
  --output /path/to/fresh/evidence \
  --target /path/to/dedicated/cargo-target
```

It includes the actual leaf sources without registering them, verifies that the
entire resolved dependency identity/version/checksum closure is a subset of the
workspace lock, and runs tests offline with two compiler jobs and one test thread.
The accepted frozen foundation had 35 passing tests: exact file/buffer limits, immutable
round trips, no-follow/special-file/hardlink/mode negatives, create/rename
collisions, finalization fault points, retained descriptors/leases, bounded scans,
quota and object counts, corrupt metadata arithmetic, expiry, foreign handle
binding, rollback reuse, association/GC generations, worker cancellation,
stuck-worker capacity, panic, filename/header injection and monotonic idle,
total and outer-deadline accounting.
Later pure/parser/native leaf filters have their own exact logs and source
checkpoints; do not add their counts to provider proof. This does not prove
metadata transactions, pairing commit order, quotas, HTTP, NoJS browser behavior,
packaged SDK lowering or an enabled P08 capability. Shared request accounting,
unknown-COMMIT recovery and provider-capacity fixes are prerequisites. Those gates
and independent review remain required.
