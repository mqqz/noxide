# Architecture layers

The explicit SDK works without `#[app]`, CRUD shorthand, or inferred queries; see
the [explicit examples](../sdk-lowering.md).

| Crate | Responsibility |
| --- | --- |
| `noxide-protocol` | Canonical schemas, policies, operations, actions, web bindings, routes, requests, results and Document IR |
| `noxide-sql`, `noxide-sql-macros` | SQL text composed only from literals, checked identifiers, numbers and other `Sql` values |
| `noxide-assets` | Compiled public assets and their document rendering; parses no CSS, images or fonts |
| `noxide-asset-admission` | Asset pack validation and compilation; never linked by the server |
| `noxide-admission` | Pure manifest admission, policy and query planning, SQL generation and identity values |
| `noxide-render` | Document IR to bytes, with its budget passed in |
| `noxide-sandbox` | The Wasmtime boundary and complete guest import surface, behind `HostCalls` |
| `noxide-keys` | Host key material and the key service protocol; callers never receive key bytes |
| `noxide-confine` | Landlock and seccomp policy for deployed processes |
| `noxide-test-support` | Test fixtures; a dev-dependency only |
| `noxide-host` | Authentication, authorization, persistence, jobs, effects, blobs, application orchestration and HTTP |
| `noxide` | Typed resources, queries, actions, forms and pages; WIT bindings and guest entry points |
| `noxide-macros` | Explicit declaration expansion and optional convenience lowering |
| `noxide-cli` | Operator build, dependency, approval, lifecycle, schema and role commands |

`tools/check_layers.py` runs in CI. It fails if a crate gains a restricted dependency
such as `sqlx`, `rustls`, `wasmtime` or `image`, if a pure crate depends on an
impure one, if a deployed binary enables a `test-support` feature, or if a module
inside `noxide-host` depends on a higher layer. `tools/check_binaries.py` checks the
symbols of each deployed binary, because `noxide-cli` builds them all.

`noxide-host` still contains the store, repository, blobs, jobs and effects as
modules, separated by that lint and not by the compiler. `Transaction` accepts only
`Sql`, so runtime strings cannot become statement text anywhere, but statements are
not yet confined to one crate.

## Deployed processes

`noxide serve` is a supervisor that holds no keys and handles no requests. It
validates and compiles assets, then runs:

| Process | Holds | Can reach after startup | Links none of |
| --- | --- | --- | --- |
| `noxide-server` | Guest runtime, database connections, blob store, listener | Database files or loopback database port, blob directory, its key service | `rustls`, SOCKS, `cssparser`, `image` |
| `noxide-keyd` | Host key material | Its one socket | Network, database, Wasmtime, Tokio |
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
