# HTTP and application runtime

Noxide applications describe pages and request permitted effects. The trusted
host controls browser output, authentication, authorization, persistence, and
execution. Application source and all application dependencies are untrusted
during both compilation and execution.

The first architectural milestone is a private-notes application with a complete
transactional form flow on both SQLite and PostgreSQL. A preceding rendering
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

Revocation takes effect at transaction serialization. An overlapping authorized
transaction may serialize before a revocation even if its acknowledgement arrives
later. Every retry re-reads authoritative policy. A stronger acknowledgement fence
would require a separately specified ordering protocol.

Application declarations request authority. Approval comes from deployment
policy, which must constrain resources, operations, policy rules, and action
contracts. Installation and upgrades must preserve those constraints unless the
operator explicitly approves wider permissions.

Grants apply to reads as well as writes. A request to delete note 42 cannot delete
note 43 merely because the principal owns both. Read routes have no application
mutation grants; compound actions must declare their bounded effects. Separate
host-owned interfaces handle framework session maintenance and security
bookkeeping.

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
| Database connection configuration | Dedicated connection, transaction, host state, render buffers |

A retry creates a new attempt with a new Store and instance. A completed receipt
can be recovered without executing the application. No guest-created resource
handle survives its Store; durable identifiers are untrusted references whose
use is reauthorized. Cross-request persistence exists only through explicit host
capabilities. M1 needs application records and host sessions; generic cache,
storage, and job capabilities can follow later.

Limits are installed before instantiation. Imports check the host execution phase:
initializers can neither inspect request secrets nor perform application effects.
Request capabilities become usable only for handler execution. Initialization,
component cleanup, and host work remain bounded. This implementation rejects
canonical post-return hooks, asynchronous canonical functions, and resource
intrinsics at admission. Wasmtime 48 performs post-return processing during calls;
excluding hooks keeps application effects out of cleanup entirely.

Compiled code can be reused without retaining guest state. Pooling is an optional
optimization after tests verify fresh-state behavior for the selected Wasmtime
configuration; it does not authorize dirty instance or request-context reuse.
([Store lifetime](https://docs.rs/wasmtime/48.0.2/wasmtime/struct.Store.html),
[fast instantiation](https://docs.wasmtime.dev/examples-fast-instantiation.html))

## Boundary protocol and rendering

The Rust contracts live in `noxide-protocol`. The SDK's
`crates/noxide/wit/application.wit` defines the versioned import world. Request
grants stay inside the host; guests cannot select them through resource handles.

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
iframe, generic style attributes, or generic URL strings. The current IR supports
RouteRef links and framework-owned styles; AssetRef and fragment references are
future work. Every ID and reference still requires authorization, including
redirect destinations, which use the same route policy.

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
Because local HTML or SVG can contain active content, the asset policy must cover
file types as well as resource references. M1 can use framework-owned CSS without
uploaded assets or support for arbitrary application CSS.
CSP provides an additional browser constraint.
([CSS URLs](https://www.w3.org/TR/css-values-4/#urls),
[Content Security Policy](https://www.w3.org/TR/CSP3/))

A flat, bounded JSON instruction sequence is transported using fixed scalar calls.
The guest exports `handle: () -> ()`. Imports read request/result chunks as u64,
invoke a declared operation by numeric ID/target, and emit at most eight bytes per
call. No guest-sized string, list, or collection is lifted across the component
boundary. The host checks byte budgets before appending output, then decodes the
bounded message with Serde's recursion guard and validates the document's structure.

## Data, sessions, and action scope

Applications declare data operations. The host interprets an approved finite
operation set; the guest SDK supplies list/read/create helpers. M1 has no
application native adapters, raw SQL, user-defined SQL functions, or arbitrary
migration execution. Schema changes use approved host-managed operations.

For the notes fixture, the model has a host-generated NoteId, protected
owner identity, and bounded body text. CreateNote permits one creation per action,
with ownership set from the authenticated host principal. Form fields cannot
select an owner. Owner-scoped ListNotes and ReadNote expose only the data their
route needs. Validated input fixes every ordinary field; the guest can neither
substitute values nor choose the tenant or generated ID. Resource schemas are
persisted at activation and must match on subsequent requests. Schema migration
requires a separate trusted operation.

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
For host-managed session lifecycle and security accounting, specify which effects
persist after failure, including quota charges. A fresh Store cannot undo host
state already published.

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

Before commit begins, a failure aborts the attempt: discard output and confirm
rollback, or discard the connection if rollback cannot be confirmed.
Once commit has been requested, cancellation or connection loss can leave its
outcome unknown. Recovery must use the authoritative submission protocol. A
missing row on a stale replica cannot authorize another execution.

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
definitely aborted conflicts. Each attempt repeats authorization and guest
execution with a fresh transaction, Store, and grants while retaining the original
submission and input. Retries share the request's wall-time and work budgets, and
the total number of attempts is capped. Pin the admitted bundle and contract
throughout: a deployment must not replace code midway through a retry.
Revocation can stop further attempts. Unknown commit outcomes require recovery.

## SQLite and PostgreSQL

Both providers must implement the same semantic protocol and pass the same
hostile acceptance suite on real databases, including independent connections
and host processes. Provider SQL, locking, and error classification can differ.

The adapters use SQLite WAL with `BEGIN IMMEDIATE` and PostgreSQL `SERIALIZABLE`.
Every transaction owns a dedicated connection, including read routes and host
security bookkeeping; unresolved connections are discarded. SQLite permits one active
writer, so guest execution and rendering consume part of the write-lock budget.
([SQLite isolation](https://www.sqlite.org/isolation.html))

Track whether a transaction remains active after an error. SQLite can leave it
active after a failed commit; a PostgreSQL serialization retry must repeat the
entire transaction. Do not treat every database error or uniqueness conflict as
retryable.
([SQLite transaction errors](https://www.sqlite.org/lang_transaction.html),
[PostgreSQL retry rules](https://www.postgresql.org/docs/current/mvcc-serialization-failure-handling.html))

Deleting a receipt must never make its token executable again. Set retention from
the token's expiry and key lifecycle, accounting for clock rollback/skew, trusted
time, in-flight attempts, and restart. Deployment changes must define whether an
old action version remains supported for execution, supports recovery only, or is
rejected; new code cannot silently reinterpret it.

The enforced durability baseline is SQLite WAL with `synchronous=FULL`, and
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
The selected defaults are:

| Budget | Limit |
| --- | --- |
| Portable component | 2 MiB, 4,096 defined functions, 500,000 operators |
| Component expansion before compilation | 1,024 core/component instances including the root; 8 MiB expanded component bytes; 32 lexical component levels including the root |
| Guest memory / table allocation | 64 MiB aggregate; four memories/tables, 4,096 elements per table, eight instances |
| Request execution | 10 million fuel, two seconds, at most three fresh attempts |
| Host calls / repository invocations | 32,768 / 16, cumulative across retries |
| Input / repository result / IR | 32 KiB / 64 KiB / 64 KiB |
| Document | 1,024 nodes, depth 32, eight forms, 256 KiB serialized output |
| Repository list | Three records, cursor bound to the request; stored fields guarded at 20,000 bytes before transfer |
| Persistent records | 10,000 per resource and owner |
| HTTP admission | 64 connections; 16 active application requests; two password workers |
| HTTP parsing and transfer | 64 headers, 32 KiB header buffer, 64 KiB encoded form body, 30-second header/body phases, 60-second connection lifetime |
| Database work | Request deadline; PostgreSQL 1.5-second statement and 250 ms lock timeouts; SQLite progress interruption and 250 ms busy timeout |
| Cleanup | 500 ms for the entire explicit rollback, including SQLite handle acquisition |

Before creating a Wasmtime engine or compiling, admission summarizes each component
definition and charges its full transitive cost at every instantiation. Outer
aliases and component export aliases preserve that cost; repeated references are
charged separately. The byte estimate includes each component's complete encoded
body, including nested definitions, and is deliberately conservative. Each
definition must fit these bounds, including unused definitions. Component-valued
imports and component-valued instance-export aliases are rejected because their
instantiation costs depend on supplied values. Ordinary host-function imports
remain supported. This bounds the instantiation graph without expanding it in the
admission checker; Store limits and request deadlines only apply after compilation.

These bounds cover protocol buffers and declared work, not every allocator inside
the compiler, database, or operating system. Apply a service memory/process limit
and storage quotas appropriate to the trusted deployment. The VM has its own
enforced resource envelope, described in the runnable guide.

Wasmtime's ResourceLimiter covers only some runtime and host allocations, and
neither fuel nor epoch interruption cancels a blocked host function. Give host
operations their own deadlines and cancellation, then confirm transaction and
resource cleanup.
Unsupported features that bypass the selected controls must be rejected at
admission; guest threads/shared memory are not needed for M1.
([ResourceLimiter](https://docs.rs/wasmtime/48.0.2/wasmtime/trait.ResourceLimiter.html),
[execution interruption](https://docs.rs/wasmtime/48.0.2/wasmtime/struct.Config.html#method.epoch_interruption))

Release the guest and write transaction before transferring a response to a slow
browser. Database execution and browser transfer have separate deadlines. Cancel
work when a disconnect is observed before commit. If the HTTP engine observes it
after commit, the client must use submission recovery to resolve the uncertain
outcome.

Logs contain bounded host-defined events. Application text, note contents,
credentials, tokens, cookies, and raw request identifiers are not default log
fields. Guest logging is a separately budgeted capability, not ambient stdout.

## Build and deployment boundary

The initial runner is QEMU with TCG and a freshly generated initramfs. The tested
recipe has two virtual CPUs, 6 GiB RAM, a 2 GiB scratch tmpfs, no NIC or disks, no
host shares, and a 600-second deadline. QEMU's seccomp sandbox is enabled; native
build code runs as an unprivileged guest user. See [the runnable recipe](../running-applications.md).
A framework-managed cross-platform builder remains deferred.

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

## Selected implementation and verification

The workspace separates `noxide` (guest SDK and packaged WIT), `noxide-protocol` (semantic types),
`noxide-host` (trusted runtime), and `noxide-cli` (operator tools). Template macros
remain future work. The guest API does not expose transport/provider dependencies.

The tested configuration uses Rust 1.98.0, Wasmtime 48.0.2 with Cranelift and its
component/async runtime, wit-bindgen 0.46.0, wit-component 0.254.0 for wrapping,
Tokio 1.53.1, Hyper 1.11.1, Axum 0.8.9, and SQLx 0.8.6 with only PostgreSQL/SQLite
backends. No WASI implementation is linked. Current Wasmtime advisories through
the August 2026 fixes are patched in this release; SQLx's protocol truncation fix
is included. Recheck advisories on dependency changes.
([Wasmtime advisories](https://rustsec.org/packages/wasmtime.html),
[SQLx fix](https://rustsec.org/advisories/RUSTSEC-2024-0363.html))

Tokens use HMAC-SHA256, 256-bit random nonces, explicit token domains, authenticated
expiry, and a host-key incarnation. Sessions last one hour; login/form challenges
last 15 minutes. Canonical input is a sorted map of exact UTF-8 field values with
form newlines normalized to LF. Duplicate fields and malformed percent/UTF-8
encodings are rejected; Unicode normalization is not implicit. Receipts store
only canonical input digests and Created/RouteRef outcomes. Collection is bounded
and obeys a persisted clock high-water mark and expiry grace period.

The encoded HTTP form budget accounts for CRLF and percent-encoding expansion.
Canonical input has a separate 32 KiB limit. To avoid treating writer-lock waits
as clock rollback, sample request time after transaction acquisition and admission.
Authorized read pages omit declared forms denied by policy; undeclared forms
remain invalid.

Deployment identity includes the component bytes and approved manifest digest.
Activation precedes request acceptance but follows listener preparation; failed
preparation cannot retire a working deployment. A changed identity retires old
tokens. Code rollback creates a fresh generation. Restoring lost database history
also requires new keys supplied outside the restored state.

Firefox's no-JavaScript flow is exercised against SQLite/local and
PostgreSQL/test-onion origins. Referrer-Policy is `same-origin`: `no-referrer`
makes navigation POST Origin opaque, which conflicts with strict Origin checks.
Cross-origin referrers remain suppressed.
([Fetch Origin processing](https://fetch.spec.whatwg.org/#append-a-request-origin-header),
[same-origin policy](https://w3c.github.io/webappsec-referrer-policy/#referrer-policy-same-origin))

The suites cover hostile output/imports, fresh memory/globals/tables, initialization,
resource limits, bounded stored values and SQL, rollback, concurrent duplicate
claims, role-revocation ordering, authentication epochs, known-aborted retries,
lost commit acknowledgements, process crashes, expired-token collection, schema and
deployment fencing, and browser privacy boundaries. Build scripts and procedural
macros are tested inside fresh VMs against filesystem, network, host-socket, and
cross-build canaries; a native build loop must hit the VM deadline.

On the tested host, the locked notes VM build took 153.8 seconds with a measured
peak QEMU RSS of 3.61 GiB. The hostile runtime concurrency fixture peaked at
82.3 MiB process RSS and completed cleanup in about 59 ms. These measurements
describe the acceptance runs and do not establish throughput guarantees.
Test commands and operational limits are in
[Running an application](../running-applications.md).

The implementation has not undergone an external security audit or hardware
power-loss certification.

Primary sources above were checked on 2026-09-19.
