# Expiring paste

Publish escaped plain text and one public attachment without an account or
JavaScript. A paste is immediately public for one hour. The host returns its
existing ownership handover with an edit secret; that secret permits early
deletion and does not make the paste private. Keep it somewhere private.
Attachments are downloads only, with no inline preview or caller-selected MIME.

The anonymous create is one resource mutation. It attaches an opaque
`UploadHandle` to an immutable `BlobRef`, records host transaction time and sets
expiry to that same time plus 3,600 seconds. The host supplies the initial
`published = true` field. Browser inputs contain only title, body and file;
publication state, timestamps, expiry, storage paths and blob identities are not
caller inputs. The title must contain a non-whitespace character. A rejected
title can be corrected on the same staged-file form. Publication, attachment,
cleanup-job capture, synthetic-effect capture and the semantic receipt commit
together. Receipt replay returns the same handover without new captures.

Public List, direct Read and download authorization all apply the resource's
host-enforced expiry. The public list projects titles and lifecycle timestamps;
only a successful public direct Read can issue an attachment download link.
Uploaded HTML/SVG remains attachment bytes; the host serves it as an octet-stream
attachment with restrictive headers. Expiry blocks newly authorized downloads;
it does not recall previously downloaded bytes or an already admitted stream.

The product UI distinguishes visibility from deletion. At the logical cutoff,
ordinary reads and downloads stop even when the record and attachment still
exist. The sealed one-shot cleanup job is due at the same expression as the
stored expiry. Its distinct, input-free `paste_cleanup` action uses an approved
Service + SameTenant maintenance Read and Delete, checks elapsed expiry, then
deletes the row. It never impersonates the anonymous creator. There is no browser
binding for this service action. An indexed creation-order maintenance List and
sixty-second recurring expiry-repair selection provide eventual repair, with
host-persisted cutoffs/frontiers and at most twenty emitted jobs per bounded
batch. Resource deletion detaches its blob transactionally; bounded host blob
maintenance removes the bytes and releases quota later. Delayed or revoked jobs
can delay physical cleanup indefinitely.

The source action also declares one fixed `published` synthetic event for the
logical `synthetic_events` endpoint, with secret-slot identity
`synthetic_events_token`. Its complete payload disclosure is the literal event
name, newly created paste ID and transaction timestamp. Text, title, file bytes,
blob/upload handles, edit secrets, user identities and secret values are absent.
The guest declares no URL, socket, secret bytes, mail, payment or inbound event.
No application code sends a request or receives a remote response body.

Outbound delivery is denied until an operator supplies and approves the exact
endpoint, tenant, Tor transport and secret slot. This emission is mandatory:
publication fails closed when its endpoint or secret grant is missing/revoked.
The host captures the approved immutable destination and payload transactionally;
it does not create a destination-free fallback event. A deployment must approve
blob, cleanup-job and effect authority before accepting publication.

Build this trusted example:

```sh
noxide build --app examples/expiring-paste --name expiring_paste --framework . --output NEW_BUNDLE
```

Use the disposable build VM with `--isolated` for untrusted application code or
dependencies. The example lockfile is a mechanical copy of the reservations
example lock with only the root package name replaced; central build validation
must verify it. No root workspace or shared dependency locks are changed.

Configure a new runtime with the built manifest/component and a private local
blob directory. Its explicit requested ceilings are:

| Limit | Requested ceiling |
| --- | --- |
| File | 1 MiB |
| Application bytes / objects | 16 MiB / 64 |
| Live stages / upload workers / downloads | 2 / 1 / 2 |
| Anonymous deployment stages / bytes | 4 / 4 MiB |
| Anonymous capability stages / bytes | 2 / 2 MiB |

Operator ceilings can lower these limits. Anonymous staging requires both
`BlobPolicy.anonymous` and the binding's explicit capability quota plus operator
anonymous ceilings; a Blob field alone grants no upload authority. Staging stays
at the host's existing fifteen-minute lifetime. The object store is private,
local and exclusively leased by one designated host, including with PostgreSQL.
A stage is bound to its original anonymous form/session scope and cannot become
a global bearer upload or a reusable attachment.

Grant worker `paste_cleanup` only the manifest's numeric `Cleanup paste` action
ID in tenant `""`, the unpartitioned tenant. It does not mean all tenants. Use
lower pending/concurrency limits where appropriate. For the effect, explicitly
bind `synthetic_events` in tenant `""` to an operator-approved canonical HTTPS
DNS host, port and exact path, a numeric loopback Tor SOCKS proxy, and a private
host file for `synthetic_events_token`. Secret files contain the exact token
without an added newline. Nothing in this example grants a production endpoint
by default. Do not use a real provider merely to test the example.

Run `noxide deployment-hash RUNTIME.json`, review requested/effective blob, job
and effect authority and disclosures, and install its `deployment_digest` as
`approved_contract`. A manifest-only hash does not approve deployment resources.
Initialize a fresh database/store, then run `noxide schema indexes RUNTIME.json`.
The [blob](../../docs/architecture/blobs.md),
[job operations](../../docs/architecture/jobs-operations.md) and
[effect operations](../../docs/architecture/effects-operations.md) guides describe
the operator configuration and bounded lifecycle.

Effects run later through the host's approved HTTPS POST transport using Tor
remote RESOLVE, checked numeric CONNECT and TLS, without direct fallback.
Delivery is at least once: the receiver must deduplicate the stable
`Idempotency-Key` across retries and operator retry rounds. The capture survives
paste expiry/deletion; deleting a public paste cannot retract a previously
captured or delivered event. Revocation stops future admitted delivery attempts
and cannot retract packets already admitted to the network.

Run the NoJS source harness with a trusted built CLI and a new output directory:

```sh
python tools/test_expiring_paste.py --bundle NEW_BUNDLE --host-cli HOST_CLI --output NEW_OUTPUT
python tools/test_expiring_paste.py --bundle NEW_BUNDLE --host-cli HOST_CLI --output NEW_PG_OUTPUT --postgres DISPOSABLE_LOOPBACK_DATABASE_URL
```

The harness explicitly approves the fixed synthetic `hooks.example.com` identity
and a private fixture token, then uses a loopback-only SOCKS server that rejects
all RESOLVE/CONNECT requests. That fixture has no outgoing socket or DNS lookup.
It proves capture/retry state without delivering an event or contacting a real
provider. It checks multipart ticket/CSRF prefixes, rejected-stage correction,
foreign/reused handle denial, anonymous handover/replay, public visibility,
escaping and safe attachment headers. Keep its output private: handover HTML and
runtime keys belong to the disposable fixture. Blob-aware operator commands run
only after serving releases the exclusive store lease.

Add `--await-expiry` for the optional real one-hour lifecycle lane. It revokes
cleanup before the cutoff, observes the durable host watermark, refreshes a
download ticket near expiry, and verifies that expired rows disappear while
attachments remain attached. It then isolates reconciled one-shot deletion with
`jobs worker-once`, proves a cancelled one-shot is recovered by recurring repair,
and waits for physical blob GC/quota release. Polls test committed state
predicates; no timestamp is rewritten and the production lifetime is unchanged.
A fast deterministic clock test and actual synthetic 2xx delivery require the
parent host test process, its test-only clock/CA fixtures and this built SDK
bundle. The external CLI harness adds no production clock, CA or mock bypass.

For backup, stop admission and drain serving, uploads, jobs, delivery and GC.
Pair a consistent database snapshot with the immutable object store, private
pair markers/identity, keys and host-only secret files, retaining permissions.
Preserve uncertain files and verify referenced lengths/digests before serving.
A database-only or object-only copy is incomplete. Before resuming copied
storage, use the reviewed runtime fork/recovery procedure to rotate the shared
job/effect epoch, pause retained work and reconcile it under current approval.
A pairing/directory audit can refuse a copied or relocated store; retain that
copy and use reviewed recovery rather than editing identities or bypassing the
audit. Never automatically replay retained effects after restore. Complete
backup/restore execution remains a parent integration gate.

The SDK test in `crates/noxide/tests/expiring_paste.rs` checks exact declarations;
the simple and explicit fixture sources are for central equivalence checks and
JSON baseline generation. P11 and combined P13 acceptance, actual provider work
budgets, packaged builds and browser-engine tests require separate evidence.
Source checks do not establish audited security, transport anonymity or deployment
readiness. Application code and uploaded content remain hostile, and explicit
deployment infrastructure grants no additional guest authority.
