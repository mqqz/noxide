# Blob storage

Noxide stores uploads in one host's private immutable local store, including
when metadata uses PostgreSQL. Applications receive opaque `UploadHandle` and
`BlobRef` values. File bytes stay outside Wasm, ordinary JSON and Document IR.
A blob declaration requires explicit deployment resources and approval; it grants
no guest filesystem or network access.

The [security principles](../../README.md#security-principles) and
[runtime security contract](runtime.md#security-contract) apply. Application code
and uploaded content remain hostile. This implementation is not an audited
security or transport-anonymity certification.

## Declare and approve

A resource stores a `BlobRef` or `Option<BlobRef>`. An explicit action declares one
`UploadHandle` input and assigns it to one compatible Blob field in a Create step.
The SDK's `.file()` control and `download::<ReadQuery>(record, field, text)` helper
lower to the same protocol shapes. An `UploadHandle` input declares the 10 MiB host
maximum unless `file: UploadHandle = bytes(N)` narrows it; admission requires the
declared size to fit the policy's `file_bytes`. See the complete
[explicit SDK fixture](../../tools/fixtures/blob-app/src/lib.rs) and its
[production HTTP harness](../../tools/test_blob_http.py).

One `Manifest.blobs: Option<BlobPolicy>` declares limits and upload bindings. Each
binding names its web binding and upload input. At most 16 bindings are admitted;
each action and web binding has at most one upload input, used exactly once.
Blob literals, initial values, updates, scalar expressions and comparisons are
rejected. Only host canonicalization supplies an unassigned optional Blob field's
empty value. A submitted absent file requires both optional input and optional
destination, with no previously reserved slot for that form nonce.

The constructor's final argument is one `DeploymentResources` value:

```rust
DeploymentResources {
    assets,
    blobs: Some(BlobDeployment { directory, ceilings }),
}
```

Applications without blob policy pass `blobs: None`. Unused blob configuration
and policy without explicit operator ceilings/store configuration are rejected.
There is no compatibility overload for the former asset-only argument.

The CLI uses the existing `approved_contract` field and approval path. For a blob
deployment, `noxide deployment-hash CONFIG.json` reports `manifest_digest`,
requested/effective blob policy, and `deployment_digest`; the latter is the value
approved for activation. It reads configuration and declarations without opening
keys, a database, assets or the store. `contract-hash` remains the requested build
contract digest. The one domain-separated deployment digest covers that manifest
and the canonical effective policy, excluding paths and secrets. Verify approval
before opening the store. Changing requested or effective authority invalidates
old submissions and download tickets.

A `blobs` configuration entry is explicit, for example:

```json
{
  "directory": "objects",
  "ceilings": {
    "limits": {
      "file_bytes": 10485760,
      "app_bytes": 1073741824,
      "objects": 65536,
      "live_stages": 4,
      "uploads": 4,
      "downloads": 8
    },
    "anonymous": null
  }
}
```

Paths are relative to the configuration file. The directory must be a private
local store with no symlink components. The framework does not adopt an unrelated
operator directory.

## Upload and replay

An ordinary NoJS form submits one multipart POST to its existing action endpoint.
The host renders security controls, selected targets and scalar fields before the
sole final file control. The bounded parser rejects unknown/reordered parts,
headers, duplicate controls and additional files. Origin, session or anonymous
capability, CSRF, submission scope, upload ticket and scalar prefix are checked
before any file bytes are consumed by the file decoder or written to storage.

The prefix and upload-bound core attempt lock the existing paired metadata row
before receipt probe/claim, then stage rows. This ordering serializes an in-flight
no-file commit against a competing file reservation. No placeholder receipt or
second executor is used. Upload/download transport runs outside those transactions.

A slot binds deployment, original verified form nonce, principal/session or
anonymous capability, web binding and named upload input. The account stage quota
is shared across its sessions; the separate context still seals the originating
session. The first finalized file fixes its handle and cannot be replaced.

After a known rejection/rollback, corrected scalar or reviewed target input can
reuse the same form nonce and file. Scalar identity belongs to the existing
semantic receipt, not a permanent hash on the stage. Committed or unknown outcomes
must recover that receipt first. Original canonical input is preserved; a changed
input cannot become a second commit. A committed optional no-file submission also
replays through its receipt without inventing a slot. An existing slot cannot be
discarded by forging an empty URL-encoded upload input.

Quota is reserved and durably acknowledged before file creation. The hard maxima
are 10 MiB/file, 1 GiB/application, 65,536 live objects, four live stages/account or
anonymous capability, four upload workers and eight download streams. Empty files
consume object quota. Operator ceilings can only lower limits. Anonymous staging
requires both explicit binding capability limits and deployment limits: at most
four stages/40 MiB per capability and 16 stages/160 MiB per deployment, within the
shared limits. No circuit identity is stored.

Stages expire after 15 minutes of the existing durable lifecycle clock's UTC
milliseconds. Credential seconds remain separate. Reservation, publication,
attachment, reads and GC consume a fresh committed heartbeat and fixed attempt
time; raw credential observations never advance blob lifecycle time. Blob-only
applications also require freshness. Stale maintenance makes new temporal work
unavailable; known receipt recovery still precedes stage expiry/freshness checks.

Files use create-new/no-follow staging, mode 0600, then seal to 0400, data fsync,
same-filesystem no-replace rename and directory fsync before becoming Staged.
The state sequence is:

```text
Uploading -> Staged -> Attached -> Unreferenced -> Deleting -> Deleted
```

Publication converts reserved bytes to actual usage once. Attachment locks the
stage, verifies a durable immutable descriptor, resolves canonical proposed-row
policy and associates one stable storage resource/record incarnation/field in the
same transaction as every resource outcome and receipt. Rollback leaves Staged
reusable. A reservation lease covers cancellation before native dispatch.

## Authorized downloads

A link requires successful direct Read provenance for the exact operation,
record/incarnation and projected Blob field. A Blob ID, list/cursor, edit,
mutation or Follow grant cannot mint it. The endpoint verifies the sealed ticket,
current session and current canonical read authority, visibility, gate,
membership and expiry through the shared `ReadContext`.

The host captures and integrity-checks an immutable no-follow descriptor inside
the short read transaction, then releases the transaction/database admission
before streaming. Missing or inconsistent bytes fail closed. The response uses
`application/octet-stream`, attachment disposition with a normalized ASCII
filename, `nosniff`, `no-store` and restrictive CSP. Ranges and inline previews are
unsupported. Uploaded HTML/SVG never becomes application HTML or a packaged asset.

Transfers use 64 KiB chunks, 15-second idle and 120-second total ceilings, clamped
to the original 60-second HTTP outer deadline. A watchdog also expires a body that
is never polled. Stream admission remains held until completion/timeout and the
actual native worker's exit. Revocation stops newly authorized streams; an
already captured stream can finish, and already-sent bytes cannot be recalled.

The original private request root retains its actual 256-statement ceiling across
classification, prefix, publication, action, navigation and cleanup. The action's
logical 16-call and query's 4,096-call budgets are unchanged. Named metadata/action
phases retain their existing caps; no transfer resets the outer deadline or meter.
Kernel I/O can outlive cancellation: its bounded worker permit stays quarantined
until physical exit, with no destructor filesystem cleanup or late publication.

## Pairing, cleanup and recovery

One designated process retains an exclusive store flock. The root has a strict
layout; descriptors/scanners retain that lease. First activation commits a pending
database pair, writes and fsyncs its filesystem marker, then acknowledges the
same pair in the database before readiness. A new database refuses an already
paired store; a paired database refuses missing/wrong markers. Matching pending
state resumes only through authoritative recovery and the empty-store checks.
Pair identity is not a certificate of snapshot-time consistency.

Activation and serving maintenance reconcile bounded pages: 16 inventory/metadata
items and at most four physical deletions per pass, within the ordinary root
budgets. New uploads wait for initial inventory completion. Known incomplete
reservations recover under stopped-worker or exclusive prior-process proof.
Resource deletion detaches exactly its expected nonempty fields in the same
resource/receipt transaction; extra, missing or mismatched associations roll back.

GC commits a generation-fenced Deleting claim, releases its transaction, unlinks
and fsyncs through bounded native work, then commits the matching quota release.
Attachment cannot claim Deleting objects. Proof for either possible generation
survives cancellation between claim commit and native dispatch. Uncertain commits
are resolved through authoritative state/receipts before physical cleanup.
Deleted metadata tombstones retain identity; pagination does not rescan an
unbounded history in one request.

Completely unknown files are retained, accounted in `nx_blob_orphans`, and block
new uploads. Missing referenced objects and physical mismatches also fence new
uploads. Neither age nor a matching pair marker authorizes deleting unknown
bytes. This increment provides no automatic unknown-object adoption/deletion or
backup command; operator reconciliation must preserve uncertain data.

Storage version 12 deliberately refuses version-11 databases without resetting
or silently migrating them. Use a new development database and new unpaired
store, or a separately reviewed explicit migration. See
[metadata storage](blob-storage-schema.md) for native schema and migration guards.

A backup must fence/drain writes and GC and pair metadata, immutable objects and
private store markers/identity, preserving permissions and verifying referenced
length/digest before serving. Copying only one side is incomplete and is refused
with a pair identity mismatch. The operator procedure is in
[running applications](../running-applications.md#back-up-and-restore);
full-program acceptance belongs to P14. Current runtime/provider evidence is
recorded in the implementation ledger, separately from those later gates.
