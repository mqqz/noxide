# Declarative queries

This is the implementation plan for a small approved query vocabulary, starting
at main `9917660`. Increments 0–2 record compatibility, compile list plans and add descending order; later
increments below are planned behavior until their implementation and validation land.

Any approved query has a statically known shape, bounded execution, independently
enforced authorization, and predictable performance. Developers declare intent;
the host owns execution. The [security contract](runtime.md#security-contract)
remains mandatory, including hostile guests, host authorization, safe browser
output, request budgets and anonymity defaults.

## Conditions and authority

Three condition kinds remain separate:

- Authorization is `Policy`, interpreted only by `policy.rs`: who may access a
  record, including account-reference principal policies.
- Visibility is `Operation.visibility`: which records exist for a public
  audience. It applies to reads and lists and is checked again on returned rows.
- Selection is the planned list-only `Operation.filter`: which accessible
  records appear in a list. It cannot widen policy or make an excluded record
  unreadable through an approved read. A sold item can disappear from an
  available-items list while remaining readable on its record page.

Every scan composes `(policy) AND visibility AND parent AND selection`. A compiled
list plan grants nothing: execution reads authority and visibility from the
approved operation and rechecks `policy::allowed` on stored rows. Classification
of policy atoms belongs in `policy.rs`. Values come only from approved literals
or host-validated request parameters; `Query<Q>::fetch()` takes no arguments.
Index existence never grants permission to filter a field.

New protocol fields must default and omit their empty values so existing
serialized contracts and approval digests stay unchanged. Derived indexes do not
change table layout and do not warrant a `STORAGE_VERSION` bump.

## Two existing execution paths

Policies without `principal_is` use one SQL policy disjunction. Ordered scans
transfer at most three rows per batch, enforce a strict serialized byte prefix,
recheck row policy, and look ahead for continuation.

Any policy containing `principal_is` uses the existing account merge path. Each
rule scans ordered `(created_seq, id)` candidates. A rule with at most one identity
atom (`owner` or `principal_is`) and no parent scope is exact: its ordered composite
index supports `page_size + 1` candidates. A residual rule scans its first identity
atom with limit `min(256 / rules, 64)`. Candidates are deduplicated by creation
sequence, loaded and independently authorized, parent-checked, and appended within
the byte prefix. A conservative boundary preserves continuation when a residual
scan reaches its bound, even if the page is short or empty.

Descending order, filters, parameters and previews must work in both paths. Do
not extend merge execution to other policies without the conditional design in
increment 7. No additional execution engine or host-managed index table is planned.

The host compiles an immutable plan map at manifest load. A plan retains only
operation ID, parent field, scan strategy, selection, order and limit. It does not
copy policy, resource, visibility or projection. `policy.rs` classifies exact and
residual scans independently of the current principal and constructs their scan
policies. Execution still takes authority from the approved operation.

## Disclosure semantics

A public filter on a field outside the projection is an approved information
disclosure, recorded in the manifest. A literal equality reveals, for every
visible record, whether that field equals the literal. A parameter on a Boolean
or Choice field lets callers try every value and effectively reveals the field's
value for every visible record.

The planned `disclose(field)` approves only that filter-based inference, not
reading the field. Every unprojected public filter must have exactly this approval.
Private owner, tenant, role and `principal_is` lists need no disclosure declaration:
the same policy already authorizes reading the complete record.

## Structure, measurements and bounds

Admission of derived index requirements will prove that an index-compatible
access path exists. It cannot promise a particular planner decision or latency.
`query-metrics` measures index visits on stated datasets; the existing inbox
benchmark uses 100,000 unrelated records and checks 21 visits per exact scan for
a 20-record page. Measurements are evidence, not general performance guarantees.
The request deadline is the actual execution bound.

All existing database-call, per-list row and byte limits remain. Host calls,
database work, retries, rendering and cleanup share bounded request execution;
fuel cannot cancel blocked host work. New limits supplement these bounds.
Residual-policy lists may return short or empty pages with a continuation; filters
must retain this behavior and cannot turn a bounded scan into a false end.

## Cursor binding

Cursor scope uses canonical serialization of the approved list `Operation` and,
once introduced, canonical parameter values sorted by name. It also binds the
contract digest, deployment identity, route, target, parent incarnation and current
account identity. Cursors cannot cross accounts, parent scopes, parameter values,
orders or changed operations, and do not survive deployments. No separate query
identity hash is needed; index-name hashes only name derived indexes.

## Increments

Each increment has its own branch/PR, preserves compatibility goldens and leaves
main releasable. New admission rules require forged-manifest negative tests;
SQLite and PostgreSQL validation and documentation accompany behavior changes.

| Increment | Scope |
| --- | --- |
| 0 | This design note; exact manifest bytes, approval digest and cursor-scope fixtures |
| 1 | Compile admitted list plans; move scan classification into policy; split existing execution paths without changing behavior |
| 2 | Creation-descending keyset pagination in both paths, using backward scans of existing indexes |
| 3 | At most four canonical Boolean/Choice literal equality filters; explicit public inference disclosure; SQL and stored-row checks |
| 4 | Deduplicated derived equality-prefix indexes, at most eight per resource; operator reconciliation before activation, no request-path creation |
| 5 | Explicit required route parameters, host schema validation before database work, canonical links and cursor binding |
| 6 | At most four bounded lists, at most one paginated list, page-size sum at most 40; previews, invocation and aggregate byte budgets |
| 7, conditional | Generalize the existing merge strategy only if increment 4 measurements show material single-path multi-rule regressions; write the design first |

Derived indexes depend on operations, so deployment reconciliation must create
missing indexes and remove obsolete ones even without a schema migration.
Activation verifies requirements and refuses missing indexes with an operator
command. PostgreSQL concurrent creation must run outside migration transactions.

Parameters are declared, never inferred. The strict URL parser admits only
`cursor` and declared required canonical values, with bounded length and no
duplicate keys. Invalid inputs receive the same not-found result as unknown
routes without inspecting data or logging values. Typed link parameters never
bypass target validation.

Previews share request budgets with the paginated list. They ignore cursors,
report truncation on row, byte or residual bounds, and can link to an equivalent
full list with canonical parameters. Guest cooperation cannot enforce any budget.

## Deferred

| Feature | Precondition |
| --- | --- |
| Query refinements (`refine(Base)`) | Repeated boilerplate in real apps; SDK-only resolution cannot widen policy, visibility, projection or budgets |
| Integer ranges | Demand; range column last before creation sequence |
| Optional parameters | A strategy that avoids multiplying index shapes |
| Account-field filters | Account-ID parameter disclosure analysis and demonstrated need |
| Mutable-field ordering | Weaker documented semantics or snapshots |
| Independent pagination of several lists | One signed page-state token |
| Counts, OR filters, joins | Demonstrated need |
| Arbitrary SQL | Never |

Guest query builders, host prefetch, host-rendered facets and multiple cursor
states are outside this plan. Local tests do not establish deployment readiness,
audited security or transport anonymity.
