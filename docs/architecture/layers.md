# Architecture layers

Noxide retains five workspace crates. The explicit SDK works without `#[app]`,
CRUD shorthand, or inferred queries; see the [explicit examples](../sdk-lowering.md).

| Crate | Responsibility |
| --- | --- |
| `noxide-protocol` | Canonical schemas, policies, operations, actions, routes, requests, results and Document IR |
| `noxide-host` | Independent admission, authentication, authorization, bounded persistence and execution, receipts, rendering and navigation |
| `noxide` | Typed resources, queries, actions, forms and pages; WIT bindings and guest entry points |
| `noxide-macros` | Explicit declaration expansion and optional convenience lowering |
| `noxide-cli` | Operator build, dependency, approval, lifecycle, schema and role commands |

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

`application/action.rs` owns a core action attempt: identity resolution inside the
write transaction, receipt claim, target authorization, revision checks, authorized
inspection, guest decision, step execution, destination capture and anonymous edit
handover issuance. It returns a presentation-free outcome: a pending commit,
matching receipt replay, or a settled unavailable, conflict, guest rejection or
guard rejection. Missing, reincarnated and unauthorized targets share one
unavailable outcome with no cause. `ActionCore` projects execution fields from the
approved action; it carries the navigation source and destination resource. The
destination route ID is retained as an opaque receipt identity to preserve receipt
serialization. It carries no form presentation.

`application/submission.rs` is the web form binding. It owns admission, input
canonicalization and digesting, the shared retry budget, response mapping, the
commit loop and recovery. Its preparation function maps settled outcomes to forms
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

See the [inbox feasibility exercise](inbox-spike.md) for a concrete limit of the
existing authority model.

The [refactor validation record](refactor-validation.md) lists executed commands
and checks that still require CI infrastructure.

See [declarative queries](queries.md) for the staged query design and compatibility contract.

See [declared action transactions](transactions.md) for the transaction contract and implementation boundaries.
