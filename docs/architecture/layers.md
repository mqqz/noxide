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

Form layout generation is convenience. The host owns CSRF, input canonicalization,
writable-field checks, approved action binding, credential issuance, escaping,
headers and final Document IR validation. Navigation presentation is separate from
host authorization of the destination and credential handover.

## Mutation and navigation lifecycle

`application/submission.rs` binds the current principal and approved action,
canonicalizes input, checks target and relationships, and executes mutation and
receipt persistence atomically. `application/navigation.rs` owns the existing
`SemanticReceipt`, `SemanticOutcome`, `Prepared`, response preparation and
post-commit destination resolution. Required response preparation happens before
commit; delivery waits for confirmed commitment or a verified committed receipt.
An unknown commit outcome uses receipt recovery, never an assumed success or a
fresh mutation.

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
