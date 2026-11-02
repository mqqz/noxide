# Architecture layers

The explicit SDK works without `#[app]`, CRUD shorthand, or inferred queries; see
the [explicit examples](../sdk-lowering.md).

| Crate | Responsibility |
| --- | --- |
| `noxide-protocol` | Canonical schemas, policies, operations, actions, web bindings, routes, requests, results and Document IR |
| `noxide-sql`, `noxide-sql-macros` | SQL text composed only from literals, checked identifiers, numbers and other `Sql` values |
| `noxide-assets` | Compiled public assets and their document rendering; parses no CSS, images or fonts |
| `noxide-asset-admission` | Asset pack validation and compilation; never linked by the server |
| `noxide-admission` | Pure manifest admission, policy and query planning, SQL generation, identity values and computed scalars |
| `noxide-render` | Document IR to bytes, with its budget passed in |
| `noxide-host-calls` | The storage calls a guest may make, as a trait with no runtime behind it |
| `noxide-guest` | The worker wire protocol and the server's worker pool; links no guest runtime |
| `noxide-sandbox` | The Wasmtime boundary and complete guest import surface, behind `HostCalls`; compiles and loads guest code |
| `noxide-keys` | Host key material and the key service protocol; callers never receive key bytes |
| `noxide-confine` | Landlock and seccomp policy for deployed processes |
| `noxide-test-support` | Test fixtures; a dev-dependency only |
| `noxide-store` | Transactions, schema activation, storage layout, every SQL statement, the request lifecycle and durable time; the only crate that links a database driver |
| `noxide-effects` | Effect approval, capture, the outbox and operator commands; opens no outbound socket |
| `noxide-effect-delivery` | The delivery worker, Tor SOCKS client and TLS transport; only `noxide-cli` depends on it |
| `noxide-blobs` | The blob directory, blob metadata, upload authority, pairing and bounded maintenance |
| `noxide-jobs` | Job queue storage, recurrence, selection validation and operator commands; runs no guest code |
| `noxide-authority` | Accounts, roles, tokens, admission limits and per-attempt request authority |
| `noxide-repository` | Record reads and writes, policy filtering, search and aggregates for one request attempt; runs no guest code |
| `noxide-host` | Application orchestration and job execution; links no HTTP server |
| `noxide-http` | Routing, forms, cookies, headers and listeners over the application |
| `noxide` | Typed resources, queries, actions, forms and pages; WIT bindings and guest entry points |
| `noxide-macros` | Explicit declaration expansion and optional convenience lowering |
| `noxide-cli` | Operator build, dependency, approval, lifecycle, schema and role commands |

`tools/check_layers.py` runs in CI. It fails if a crate gains a restricted dependency
such as `sqlx`, `rustls`, `wasmtime` or `image`, if a pure crate depends on an
impure one, if a feature crate depends on the host, sandbox, renderer, `axum` or `hyper`,
if a deployed binary enables a `test-support` feature, or if a crate outside its allowed
list compiles a policy filter. `tools/check_binaries.py` checks the
symbols of each deployed binary, because `noxide-cli` builds them all.

Feature crates hold storage and bookkeeping; the host keeps what binds the guest,
authorization and request budgets. When a feature crate runs maintenance, the host
supplies its fence through a narrow trait such as `ReconcileHost`, and every transaction
calls it first. In `noxide-http`, every request gets its class, deadline and handler from
one `Endpoint` classification, so admission cannot disagree with routing.

### SQL boundary

All statement text lives in `noxide-store`. `Transaction::execute` and `fetch` are
private to that crate; a `test-support` feature, which no deployed binary enables,
opens them for fixtures. Other crates run a named `Statement<P, C>` from
`noxide_store::statements`, or one of a few store methods. Only the store can
construct a `Statement`, and the compiler checks its parameter and column counts.

Filtered reads of application records go through `Transaction::scan_records`, which
requires an `AuthorizedFilter`. That filter has no constructor taking SQL: it comes
from compiling a policy for a principal. The store keeps further restrictions in
their own parentheses, so a restriction narrows the filter but cannot widen it.

These checks stop mistakes. They do not stop a compromised or careless host crate:

- Rust has no friend crates, so `noxide-admission` must expose the filter
  constructors. `tools/check_layers.py` limits which crates call them, by text search.
- A caller can compile the wrong policy for an operation. The type proves that a
  policy was compiled, not that it was the right one.
- `RecordScan` columns, restrictions and order, and the arguments to
  `records_by_ids`, `posting_candidates`, `postings_matching_all` and
  `membership_witnesses`, are still `Sql` built above the store. That text comes from
  the `sql!` macro and never from runtime strings.
- `records_by_ids` and `record_by_id` apply no filter. Their callers must authorize
  each row in Rust, and the compiler does not check that they do.
- Statement parameters are `Param` values, so the compiler checks how many there
  are but not their types or meaning.

## Deployed processes

`noxide serve` is a supervisor that holds no keys and handles no requests. It
validates and compiles assets, then runs:

| Process | Holds | Can reach after startup | Links none of |
| --- | --- | --- | --- |
| `noxide-server` | Database connections, blob store, listener | Database files or loopback database port, blob directory, its key service | `rustls`, SOCKS, `cssparser`, `image` |
| `noxide-keyd` | Host key material | Its one socket | Network, database, Wasmtime, Tokio |
| `noxide-guest` | One compiled guest | Its one socket | Keys, database, HTTP, TLS |
| `noxide-effects-worker` | Effect secret paths, database connections | Database, secret files, loopback Tor proxy port | Host keys, HTTP server, login |

The server and worker start on one thread, bind and activate, then confine
themselves before any serving thread exists. Direct deployments run these binaries
themselves and should use a separate user for each.

This limits what follows a host compromise; it does not replace the guest boundary.
A compromised server can still use the keys through its service while it runs, read
and write everything in its database, and run job actions: jobs still run in the
server process. Landlock port rules name no address, so loopback-only database and
proxy connections rest on the checks in `Database::postgres` and `TorProxy::loopback`.

The SDK and host use the canonical protocol. Macro implementation follows
`convenience -> explicit declaration parser/expander -> generated SDK code and
canonical manifest`. Declaration modules never import convenience modules.
Registration assembles existing declarations; there is no general compiler IR or
second authorization system. Generated declarations remain in their original
application scopes, preserving `module_path!()` identities.

The SDK's private `typed` modules organize resources, queries and request
arguments, action execution and field errors, forms, and pages. Root re-exports,
including generated-code paths through `noxide::__private`, remain the public
interface. Type opacity prevents common mistakes; it cannot authorize a guest.
The host independently rejects forged manifests and undeclared or out-of-scope
runtime operations.

Form layout generation uses action inputs, independently of resource fields. The host owns CSRF, input canonicalization,
writable-field checks, approved action binding, credential issuance, escaping,
headers and final Document IR validation. Navigation presentation is separate from
host authorization of the destination and credential handover.

### Guest workers

Guest code runs in `noxide-guest` processes. The server links no Wasmtime, which
`tools/check_binaries.py` enforces; in-process guests exist only for tests, behind
`test-support`. The server stays the authority: it checks storage access on every call,
counts calls, limits each message, enforces the deadline and validates the output
itself. A worker that breaks the protocol is killed and never reused.

**Compile once.** A compile process (`noxide-guest --compile`) confines itself, then
admits and compiles the component, and exits. This is the component's admission check.
The broker holds the compiled artifact in memory and sends it to each new worker, which
loads it in under a millisecond, so a new account costs no compile. Nothing is written
to disk. Loading is the one `unsafe` block in `noxide-sandbox`, because Wasmtime runs
those bytes as machine code; `tools/check_layers.py` holds it to that one block and one
caller. A compiler bug triggered by a hostile component could make an artifact hostile,
so a worker confines itself before it loads one.

**Isolation.** Each request gets a new worker, used once, so a guest that escapes
Wasmtime sees no other request. `guest_worker_requests` can raise that. A worker then
still serves only one account or service identity, and anonymous submissions and
capability requests stay single-use; anonymous page reads share one.

**Limits on a compromised worker.** Before running guest code a worker sets hard limits
on address space, CPU time, open files, file size and locked memory, makes itself
undumpable, and applies Landlock and seccomp with no filesystem, threads, new sockets
or signals. The server kills a worker that misses its deadline.

**The broker.** A confined server cannot start processes, so `noxide-guest --broker`
starts the compile process and workers, and passes each worker's socket back. It runs no
guest code and never reads worker messages. It can run only its own binary and the
dynamic linker, and read system libraries. If it dies the server stops with an error, so
that a supervisor restarts both.

What this does not do:

- With `guest_worker_requests` above one, an escaped guest can read that worker's later
  requests, and corrupt their responses. For anonymous page reads, that includes the URLs
  other visitors request.
- The kernel limits are per process and coarse. The CPU limit covers a worker's whole
  life, about 33 seconds at the defaults, and grows with `guest_worker_requests`, so an
  escaped guest can spin until then. A worker can hold up to its 2 GiB address space, plus memfds it creates
  and unmaps, up to its 32 files at the guest memory limit each. Many workers add up: a
  hard total needs a cgroup, which is an operator's choice.
- Landlock and seccomp reduce a kernel attack surface; they do not remove it. An escape
  from Wasmtime followed by a kernel exploit is outside this boundary.
- A burst of new accounts can still outrun worker starts. A request that finds none
  ready waits, and fails as busy at its deadline. With stubbed storage and a 162 KiB
  release-built application on one machine, new accounts ran at about 2100 per second,
  and each worker used about 8 MiB. Through the whole server, one worker per request cost
  under 10% of throughput against reusing workers, on SQLite and on PostgreSQL.

## Mutation and navigation lifecycle

`application/action.rs` owns private invocation contexts and target grants, the
common admission envelope and retry budget, and the core action attempt: receipt
claim, target authorization, revision checks, authorized inspection, guest decision, step execution, destination capture and anonymous edit
handover issuance. It returns a presentation-free outcome: a pending commit,
matching receipt replay, or a settled unavailable, conflict, guest rejection or
guard rejection. Missing, reincarnated and unauthorized targets share one
unavailable outcome with no cause. `ActionCore` projects execution fields from the
approved canonical action and declares eligible target reads. It has no route or
redirect dependency. A separate optional navigation plan comes from verified web
binding admission.

`application/action/targets.rs` owns typed selection-handle verification, opaque
canonical input certificates, per-alias target authorization and NoJS picker
completion. The picker invokes the existing bounded query path under a declared
binding grant. Its compute projection stays host-only; independently declared
inspection is the only target data delivered to guest validation. Physical row
caching never shares eligibility or mutation authority between aliases.

`application/submission.rs` is the web form binding. It uses common invocation
admission and owns browser proof verification, input handling, response mapping,
the commit loop and recovery. Its preparation function maps settled outcomes to forms
and asks `application/navigation.rs` to prepare a pending commit or replay response
inside the open transaction. The core receipt-write helper runs after response
preparation, retaining the order: prepare response, write receipt, check deadline,
commit. The WASM admission permit remains held through preparation and receipt
persistence. The step executor in `repository.rs` authorizes every step against
current transaction state and derives its outcome. Mutations, handover issuance
and the receipt persist atomically.

`application/navigation.rs` retains `SemanticReceipt`, `Prepared`, transactional
destination capture, response preparation and bounded post-commit destination
resolution. Delivery waits for confirmed commitment or a verified committed
receipt. An unknown commit outcome uses receipt recovery, never an assumed success
or a fresh mutation. See [Core action and bindings](transactions.md#core-action-and-bindings)
for the boundary and requirements for any future binding.

After commitment, parent navigation checks the captured parent incarnation and
fresh read authority within its budget. It cannot rerun mutation handlers or turn
a committed mutation into a failed-write response. Denied or unavailable navigation
uses the prepared fallback, including anonymous credential handover/recovery.
Ordinary redirects retain their separate behavior. Route access alone does not
prove that a particular record is readable; a child edit grant does not grant
parent reads. Direct reads, list filtering and parent checks retain shared host
policy semantics with distinct request contexts.

## Extension rule

A convenience may generate or rearrange existing declarations. New authority
requires explicit protocol representation, independent host validation and runtime
enforcement, bounded work and adversarial tests. A typed macro name or capability
declaration cannot bypass deployment policy or request scope. Host calls,
database work, retries, rendering and cleanup retain their limits; fuel cannot
cancel blocked host work.

Local compilation is for trusted applications and dependencies. Untrusted build
inputs require the disposable VM. Guests have no ambient filesystem, network,
process or secret access. Browser output and anonymity defaults remain governed
by the [runtime security contract](runtime.md#security-contract). These are
requirements and implementation boundaries, not proof of audited security or
transport anonymity.

See [declarative queries](queries.md) for the staged query design and compatibility contract.

See [declared action transactions](transactions.md) for the transaction contract and implementation boundaries.
