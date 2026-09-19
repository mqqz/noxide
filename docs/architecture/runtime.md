# HTTP and application runtime

Noxide applications describe pages and request permitted effects. The trusted
host controls browser output, authentication, authorization, persistence, and
execution. Application source and all application dependencies are untrusted
during both compilation and execution.

The first architectural milestone is a private-notes application with a complete
transactional form flow on **both SQLite and PostgreSQL**. A preceding rendering
spike tests the execution and output boundaries.

## Trust and authority

The trusted computing base includes the Noxide host and its dependencies,
Wasmtime, the build isolation platform, database engine, operating system, and
operator-approved deployment policy. Treat application declarations and templates
as untrusted, along with dependencies and all build outputs. Guest arguments and
ordinary stored content remain untrusted too. Ownership, tenant membership, and
roles are authoritative only through protected host-managed fields and update paths.

Every application operation requires:

```text
deployment permits the operation
AND this request/action grants the operation on these targets
AND principal/resource policy permits it
```

Guest logic can further restrict this result. It cannot expand it. V1 checks
ownership and tenant boundaries and supports roles within an explicit scope.
Missing or invalid authorization facts deny access. Richer native policy and
repository extensions are deferred beyond M1.

| Authority fact | Authoritative source and permitted updates |
| --- | --- |
| Principal and auth epoch | Host authentication/session subsystem; guest application values cannot update them |
| Resource owner/tenant | Protected database fields set by approved host operations; ordinary field updates exclude them |
| Roles and membership | Host-managed security records; changes require separately approved actions |
| Deployment permissions | Operator-approved policy revision, bound to admitted application contracts |

Before M1, specify whether a revocation takes effect at transaction serialization
or must prevent every later commit after its acknowledgement. The latter requires
additional ordering; a policy read by itself does not establish it.

A declaration in an application bundle requests authority; it does not approve
it. The deployment policy must constrain approved resources, operations, policy
rules, and action contracts. Installation and upgrades must not silently widen
those permissions.

Grants apply to reads as well as writes. A request to delete note 42 cannot delete
note 43 merely because the principal owns both. A read route has no application
mutation grant. Compound actions must declare their bounded effects. Framework
session maintenance and security bookkeeping use separate host-owned interfaces.

These boundaries cannot establish that a malicious application is honest about
data it is legitimately allowed to read or display. All dependencies in one
guest share that guest's granted authority. A host-issued form proves its action
binding; guest-authored text around it is not proof of the user's informed intent.
Microarchitectural side channels and physical memory erasure are not established
by fresh-instance semantics.

## Execution boundary

Wasmtime is the primary application execution boundary. Guests receive a small,
explicit import surface. Ordinary WASI, generic HTTP clients, raw SQL, filesystem
and process access, ambient environment variables, and raw response construction
are absent. Wasm isolation depends on the host imports it provides.
([Wasmtime security model](https://docs.wasmtime.dev/security.html))

| Shared host state | Fresh for every execution attempt |
| --- | --- |
| Engine and compiled component | Store and component instance |
| Immutable linker definitions | Linear memory, globals, tables, resource handles |
| Approved route/asset/policy registries | Identity view, grants, budgets, request buffers |
| Database connection pools | Transaction, host request state, render buffers |

A retry creates a new attempt with a new Store and instance. A completed receipt
can be recovered without executing the application. No guest-created resource
handle survives its Store; durable identifiers are untrusted references whose
use is reauthorized. Cross-request persistence exists only through explicit host
capabilities. M1 needs application records and host sessions; generic cache,
storage, and job capabilities can follow later.

Limits are installed before instantiation. Imports check the host execution phase:
initializers can neither inspect request secrets nor perform application effects.
Request capabilities become usable only for handler execution. Initialization,
component cleanup, and host work remain bounded. Disable application effects again
when the handler returns, before any guest post-return cleanup.

Compiled code can be reused without retaining guest state. Pooling is an optional
optimization after tests verify fresh-state behavior for the selected Wasmtime
configuration; it does not authorize dirty instance or request-context reuse.
([Store lifetime](https://docs.rs/wasmtime/48.0.2/wasmtime/struct.Store.html),
[fast instantiation](https://docs.wasmtime.dev/examples-fast-instantiation.html))

## Boundary protocol and rendering

The following contracts define semantics. Rust and WIT definitions remain open.

| Contract | Contents and authority |
| --- | --- |
| RequestView | Registered route/action, bounded typed input, permitted context; no raw cookies or host credentials |
| RequestGrant | Host resource bound to one attempt, principal scope, allowed operations/targets, and budgets |
| ResourceDefinition | Field schemas, bounds, protected fields, operations, and authorization declarations subject to deployment approval |
| ActionDefinition | ID/version, input schema, target/effect derivation, policy, allowed outcomes, and limits |
| DocumentIR | Versioned elements, element-specific attributes, text, typed references, and form intents |
| ResponseIntent | Page, local redirect, not-found page, or declared semantic action outcome |
| SubmissionToken | Authenticated subject/action/target/version binding, database incarnation, nonce, issue/expiry time, and key identity |
| ActionReceipt | Submission identity, canonical input/target digests, minimal semantic outcome, and retention metadata |

Guest templates produce Document IR. The host validates it, resolves references,
augments forms, applies response policy, and serializes HTML. Text values are
escaped by context; there is no guest escape function that confers trust.

The IR has a finite vocabulary with element-specific attributes. It contains no
raw HTML, arbitrary tag or attribute names, inline event handlers, script,
iframe, generic style attributes, or generic URL strings. RouteRef, AssetRef, and
fragment references resolve through host registries. IDs and references never
confer authority by themselves. Redirects use the same route policy.

The validator checks HTML content models and parsing contexts as well as balanced
structure, attributes, reference permissions, nesting, node counts, text bytes,
form controls, and final serialized size. Escaping text alone does not establish
the behavior of the browser's parsed document. M0 should start with the smallest
element vocabulary needed by its fixture; M1 adds the notes form.

Forms declare registered actions. The host checks availability and input schema,
resolves targets, fixes permitted encoding and method, and inserts CSRF and
submission fields. The guest cannot supply or override framework field names.
Constructing a form never gives the rendering request mutation authority.

The host chooses HTTP status, content type, security headers, cookies, cache policy,
and redirect representation. A guest cannot emit header maps. Private responses
must not enter shared caches. M1 responses are fully buffered and bounded before
commit; live guest page streaming and compatibility HTML are out of scope.

Static styles and assets require host admission. Style identifiers resolve to
approved classes. The trusted asset pipeline parses CSS and rejects disallowed
resource references, including imports, fonts, images, cursors, and image sets.
Asset types also need explicit policy; local HTML or SVG can contain active
content. The initial notes fixture can use framework-owned CSS and no uploaded
assets. Arbitrary application CSS support is not a prerequisite for M1.
CSP provides an additional browser constraint.
([CSS URLs](https://www.w3.org/TR/css-values-4/#urls),
[Content Security Policy](https://www.w3.org/TR/CSP3/))

A flat instruction representation with bounded string/value tables is the proposed
wire shape. The SDK may expose a tree API. The transport must bound allocation
before component argument/result lifting creates host collections, including host
import arguments and exported results. Test nested lists, strings, transcoding,
and malicious encoded lengths. Validating an already allocated large list is too
late. The exact WIT world and transport are an M0 gate.

## Data, sessions, and action scope

Applications declare data operations. The host interprets an approved finite
operation set; generated typed guest repositories provide ergonomics. M1 has no
application native adapters, raw SQL, user-defined SQL functions, or arbitrary
migration execution. Schema changes use approved host-managed operations.

For the notes fixture, the proposed model has a host-generated NoteId, protected
owner identity, and bounded body text. CreateNote grants at most one creation for
the authenticated owner. Ownership comes from the host principal, never a form
field. Owner-scoped ListNotes and ReadNote expose only the data needed by their
route. The action contract must state which mutation fields are fixed by validated
input and which, if any, the guest may choose; this cannot be implicit.

Policy checks and writes use a transactionally coherent view. Shared conformance
fixtures cover target predicates, nullability, integer ranges, ordering, and
string/collation semantics across providers. Query plans also need work bounds:
returning ten rows does not imply that only ten rows were scanned.

The host owns login, credential verification, sessions, auth epochs, cookies,
CSRF, and keys. Credentials never enter the guest. Authentication and security
pages exclude guest content and styles. Any guest-visible application session
values occupy a separate namespace and cannot change identity or roles.

Inventory every persistent host effect before exposing it. Application-visible
session changes and flash state must participate in the action transaction or
remain unavailable in M1; the same restriction applies to cache publication.
The host separately governs session lifecycle and security accounting, including
quota charges. Identify which of these effects persist after a failed attempt.
Fresh Stores do not roll back host state already published.

## Transactional action lifecycle

1. Bound connection, headers, body, and parsing work; apply global admission.
2. Validate authority/origin, authenticate, verify CSRF and the submission token,
   check subject/auth epoch, database incarnation, and expiry, and canonicalize
   typed input under its declared contract version.
3. Enter the submission protocol. A completed receipt returns a permitted semantic
   outcome without re-executing the action. Recovery checks identity and disclosure
   policy; it does not require the original target still to exist.
4. For a new attempt, begin a transaction and claim the submission atomically.
   A database uniqueness constraint arbitrates competing claims.
5. Resolve authoritative facts and derive request grants in that transaction.
6. Instantiate a fresh guest under limits, initialize without authority, enable
   its grants, and execute the handler.
7. Obtain bounded output, validate the entire intent/IR, resolve references, and
   serialize the complete response into a bounded host buffer.
8. Store the minimal semantic receipt and commit it with the application writes.
9. After a known successful commit, release guest/transaction resources and send
   the response under separate transmission limits.

Any failure before commit begins aborts the attempt and discards output. Database
cleanup must confirm rollback or discard an unusable connection. After commit
has been requested, cancellation or connection loss may leave the result unknown.
Recovery uses the authoritative submission protocol; it cannot interpret a stale
replica's missing row as permission to execute again.

Every transactional action requires replay protection. Reusing a token with the
same canonical validated input recovers its outcome. Reusing it with different
input fails. Canonical encoding is versioned and bounded, with explicit treatment
of repeated fields, defaults, ordering, Unicode, and invalid values. Form byte
order alone does not determine input identity. A token authenticates its immutable
scope; the accepted input digest is recorded atomically with execution.

Mutation and submission claim share one transaction with the completed receipt
and any declared outbox entry. The guarantee is at most one committed
transactional execution per valid submission. Rolled-back attempts may repeat.
The receipt stores outcome references, never a private rendered page or secrets.
Receipt recovery rechecks disclosure policy, and destination routes authorize
their own reads. External delivery would require an outbox contract and separate
delivery guarantees; M1 does not need an external delivery subsystem.

Automatic retries are bounded and restricted to specifically classified,
definitely aborted conflicts. Each retry repeats authorization and guest execution
with a fresh transaction, Store, and grants, retaining the same submission/input.
The original request retains its wall-time and work budgets across retries, with
a separate cap on total attempts.
Pin the admitted bundle/contract for these attempts; a deployment must not change
the executing code midway through a retry. Policy revocation can stop further
attempts. Unknown commit outcomes enter recovery instead of this retry path.

## SQLite and PostgreSQL

Both providers must implement the same semantic protocol and pass the same
hostile acceptance suite on real databases, including independent connections
and host processes. Provider SQL, locking, and error classification can differ.

Proposed baseline: SQLite WAL with explicit write admission and `BEGIN IMMEDIATE`;
PostgreSQL `SERIALIZABLE` for transactional actions. These are implementation
proposals requiring contention and failure tests. SQLite permits one active
writer, so guest execution and rendering consume part of the write-lock budget.
([SQLite isolation](https://www.sqlite.org/isolation.html))

The adapter must distinguish an active transaction from an aborted one. For
example, SQLite can leave a transaction active after a failed commit. PostgreSQL
serialization retries must repeat the entire transaction logic. Do not classify
all database errors or uniqueness conflicts as retryable.
([SQLite transaction errors](https://www.sqlite.org/lang_transaction.html),
[PostgreSQL retry rules](https://www.postgresql.org/docs/current/mvcc-serialization-failure-handling.html))

Receipt retention depends on the token's expiry and key lifecycle. Cleanup must
account for trusted time, clock rollback/skew, in-flight attempts, and restart.
Deletion of a receipt must never make its token executable again. Deployment
changes must define whether an old action version remains supported for execution,
supports recovery only, or is rejected; new code cannot silently reinterpret it.

The proposed durability baseline is SQLite WAL with `synchronous=FULL`, and
PostgreSQL with `fsync=on`, `full_page_writes=on`, and `synchronous_commit=on`.
Verify effective settings when establishing provider connections, and document
storage/flush assumptions. WAL with SQLite `synchronous=NORMAL` and asynchronous
PostgreSQL commit can lose acknowledged transactions after a system crash.
([SQLite synchronous settings](https://www.sqlite.org/pragma.html#pragma_synchronous),
[PostgreSQL WAL settings](https://www.postgresql.org/docs/current/runtime-config-wal.html))

M1's durability claim is scoped to a single authoritative database preserving its
acknowledged history. Restoring an older database while accepting previously issued
tokens can resurrect actions: this follows from losing their receipts while
retaining token validity. On restore, database fork, or lossy failover, fence
requests and change the accepted database incarnation/key epoch outside the
restored state before serving traffic. Invalidate affected authentication sessions
as well as old forms. Recovery cannot reconstruct receipts removed by restore.
Cross-provider atomic actions and transparent failover are outside M1.
([PostgreSQL point-in-time recovery](https://www.postgresql.org/docs/current/continuous-archiving.html))

## Resource and cancellation policy

Bound guest CPU and wall time, aggregate linear memory, memory/table/instance
counts, host calls, query work/results, input parsing, IR lifting/validation,
rendering, output bytes, and compilation. Configure per-request limits together
with process-wide concurrency, queues, connection limits, and memory admission.
Numerical defaults remain an implementation gate; earlier illustrative budgets
are not selected defaults.

Wasmtime's ResourceLimiter does not account for all runtime or host allocations.
Fuel and epoch interruption do not cancel a blocked host function. Host operations
need deadlines, cancellation, and confirmed cleanup of transactions/resources.
Unsupported features that bypass the selected controls must be rejected at
admission; guest threads/shared memory are not needed for M1.
([ResourceLimiter](https://docs.rs/wasmtime/48.0.2/wasmtime/trait.ResourceLimiter.html),
[execution interruption](https://docs.rs/wasmtime/48.0.2/wasmtime/struct.Config.html#method.epoch_interruption))

High-latency browser transfer and short database transaction deadlines are separate
phases. A slow client cannot retain a live guest or write transaction. Disconnects
before commit cancel work; disconnects during commit enter outcome recovery.

Logs contain bounded host-defined events. Application text, note contents,
credentials, tokens, cookies, and raw request identifiers are not default log
fields. Guest logging is a separately budgeted capability, not ambient stdout.

## Build and deployment boundary

M1 uses an **existing disposable Linux VM runner**, locally or remotely, with a
fixed build contract. The concrete runner and image recipe remain open. A
framework-managed cross-platform builder is deferred.

Cargo build scripts and procedural macros execute native code during compilation.
Targeting Wasm does not contain them.
([Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html),
[procedural macros](https://doc.rust-lang.org/reference/procedural-macros.html))

The build contract requires:

- A trusted acquisition step prepares pinned toolchain and dependency inputs
  without executing application code. Credentials used there never enter the VM.
- Explicitly selected source and dependency inputs are read-only. The build gets
  fresh writable scratch, bounded CPU/memory/disk/time, and no developer, CI, or
  deployment secrets, host sockets, or unrelated mounts.
- Network is denied by the isolation platform throughout application execution.
  Cargo offline mode alone does not enforce this boundary.
- Metadata discovery, macros, build scripts, hooks, asset tools, and editor-driven
  project builds execute inside the same boundary. No shared writable build cache
  can carry an application's changes into another build.
- Extraction bounds total bytes and file counts and rejects path escape, symlinks,
  hard links, and special files. Reject unsupported output types. Treat logs and terminal
  control sequences as untrusted too. Destroy the disposable build state.

The deployment bundle contains portable component bytes, versioned declarations,
and permitted static assets. A trusted admission step independently checks import
and feature policy, declarations against deployment permissions, asset policy,
schema compatibility, and compilation budgets. Builder assertions confer no trust.
Bind the exact component, definitions, assets, schema/contract versions, and
external policy revision to one immutable admitted deployment identity. Execute
those admitted bytes, with no path replacement between validation and use.

The serving host never runs Cargo or application native code. It accepts no
builder-supplied Wasmtime AOT/native cache. Any such cache is produced and controlled
by the trusted runtime for its exact engine configuration; deserializing untrusted
native artifacts can execute arbitrary code.
([Wasmtime deserialization contract](https://docs.rs/wasmtime/48.0.2/wasmtime/struct.Module.html#method.deserialize))

## Implementation boundaries and open gates

Proposed crate layout: retain `noxide` for guest-facing APIs, `noxide-macros` for
guest ergonomics, and `noxide-cli` for commands; introduce internal `noxide-host`
and `noxide-protocol` crates as needed. Provider and transport dependency types
must not enter guest APIs. Tokio/Hyper and a custom Component Model WIT world are
candidates, not selected dependencies. Do not implement a custom HTTP parser.

Before code depends on them, resolve:

- Compatible stable Rust, Wasmtime, binding-generator, HTTP, and database-driver
  versions, supported features, and current advisories. The Wasmtime API links
  here use 48.0.2 as research evidence. Dependency approval remains open.
- The external VM runner/image and supported host setup.
- Bounded component transport, IR version/vocabulary, and declaration grammar.
- Host login/account provisioning, session/key/auth-epoch lifecycle, and tested
  cookie/origin behavior for the supported onion/local browser deployment.
- Listener and proxy trust, shutdown, privacy logging, numeric budgets, provider
  error protocol, token codec/time/GC, and action-version rollout policy.

The [milestone plan](runtime-milestones.md) assigns these gates to the first stage
that needs them. Reopening an agreed boundary requires an explicit design change;
implementation inconvenience does not create an escape hatch.

Primary sources linked above were checked on 2026-09-19. The design does not claim
that the scaffold implements these properties or that the proposed configuration
has passed a security audit.
