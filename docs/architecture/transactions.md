# Declared action transactions

Status: implemented: protocol admission, host step execution, transactional
receipts, action-input forms, SDK lowering and the shop example. Provider and
failure tests are implementation evidence, not an independent security audit or
proof of transport anonymity. The
[runtime security contract](runtime.md#security-contract) applies throughout.

An action declares typed inputs and a bounded, straight-line transaction of
individually authorized mutation steps. The guest validates input and returns a
decision; the host executes every step, writes the receipt and commits, without
resuming the guest. Ordinary CRUD actions are one-step transactions. There is one
mutation, authorization, rollback, receipt and budget path.

This replaces the single `Action.operation`, `Action.fields` and `Action.bind`
model and the guest mutation callback. The code is pre-release: contracts,
approval digests and development databases change; no compatibility path exists.

## Lifecycle

1. The host validates the submission, claims the receipt, resolves the signed
   target under the revision rule below, and builds `RequestView` (canonical
   input and declared inspection) inside the write transaction.
2. The guest runs with no storage imports. `invoke`, `follow-source` and `follow`
   during an action request are execution failures. The guest returns exactly one
   decision: `Execute` or `Rejected { field_errors, message }`.
3. On `Execute`, the host runs all steps in order, derives every outcome itself,
   prepares the response, writes the receipt and commits. The guest is not resumed.

Guest validation against authorized inspection is correct: inspection comes from
the same transaction the steps run in. Declared guards are needed for conditions
on execution-time state that the guest cannot inspect, such as a counter's value
after a concurrent commit or a value changed by an earlier step.

Keeping the guest inside the write transaction preserves the existing locking
approach. Additional steps lengthen lock duration, especially for SQLite's single
writer, so all steps share the existing request deadline and work budgets.

## Core action and bindings

The host separates three parts of an action:

- The core owns authorized inputs and target, inspection, mutation steps, step
  outcomes, captured navigation source and receipt replay semantics.
- The web form binding owns form presentation, CSRF and submission credentials,
  response mapping, conflict and rejection forms, recovery and handover delivery.
- The response expresses success, validation errors and an optional destination.

Protocol 12 retains the split between canonical `Action` execution declarations and
`WebBinding` presentation. Routes carry binding IDs; bindings reference action IDs.
Several bindings can present the same action. A canonical action can have no web
binding, route or redirect; a headless-only manifest may have zero routes.
The existing action syntax generates both declarations.
`ActionType` owns inputs and execution; `WebActionType` adds controls and navigation.
Explicit headless SDK declarations register an `Action` through
`ApplicationDefinition::action` and need no `WebActionType` implementation.

`application/action.rs::attempt_action` accepts a transaction and an opaque,
host-created invocation context. Browser admission authenticates the cookie,
verifies CSRF, the signed submission and binding/version, and seals the target
identity. It does not reauthorize the target before receipt recovery. Private
context and target-grant fields prevent an adapter from supplying a principal or
turning a raw record ID into authority. Service admission verifies authoritative
persisted job, grant, fence and runtime state in the execution transaction; see
[durable jobs](jobs.md). It never synthesizes browser credentials.

Each Page target explicitly declares eligible reads. Its web grant also
requires a matching read operation on the issuing route; current policy is checked
inside the execution transaction. SDK registration lowers the existing page
bindings into that explicit read list without inventing policies. Edit credentials
retain mutation authority only: guest inspection still requires its declared
read operation. No route, redirect or browser credential is required by `ActionCore`.

The receipt claim cryptographically binds invocation kind, deployment generation,
contract, user/tenant or anonymous subject, session, canonical action/version,
web binding/version, canonical inputs, sealed target identity and replay nonce.
Mutable roles are excluded from identity. Recovery precedes target policy and
revision reevaluation; rejected attempts roll back their claim. Every step
outcome, incarnation and anonymous handover remains in the semantic receipt.

The common invocation admission envelope holds request and database permits and
preserves anonymous-write limits. Its execution budget retains one deadline,
fuel, host-call and database-call allowance across retries. The WASM permit stays
held through result preparation and receipt persistence. Web preparation captures
navigation and handover before receipt write, deadline check and commit. A
headless execution has no navigation source and requires bounded non-rendering
result preparation before the same write/check/commit sequence. The production
job adapter uses this path with a stable invocation identity across retries; its
changing claim fence is an execution precondition.

Semantic receipt version 3 represents named navigation sources and target maps.
Framework storage is version 14 and the wire contract is version 12. Earlier
stores and contracts are deliberately incompatible. Explicitly create a new
disposable development store, with its paired blob store, or arrange a separately
reviewed migration. Rebuild and reapprove application contracts; old signed forms
are invalidated. Resolve outstanding submissions under their original deployment
when recovery is required. There is no compatibility executor or automatic
operator-database reset. Contract changes pause captured jobs for explicit
reconciliation; [job operations](jobs-operations.md) describes the controls.

## Protocol shape

```rust
pub struct Action {
    pub id: u32,
    pub version: u32,
    pub name: String,
    pub targets: Vec<ActionTarget>,  // at most four named target declarations
    pub inputs: Vec<Input>,           // action-level schema, unique names
    pub steps: Vec<Step>,             // 1..=4 steps, at most 2 creates
}
pub struct WebBinding {
    pub id: u32,
    pub version: u32,
    pub action: u32,
    pub layout: Vec<FormInstruction>,
    pub redirect: Redirect,
}
pub struct Input { pub name: String, pub label: String, pub kind: FieldKind, pub optional: bool, pub max_bytes: u32 }
pub struct Step { pub operation: u32, pub target: Target, pub assign: Vec<Assignment> }
pub enum Target { None, Named(String) } // None for create; approved alias otherwise
pub struct Assignment { pub field: String, pub change: Change }
pub enum Change {
    Set(Value),
    Decrease { by: String, rejection: GuardRejection },
    Increase { by: String, rejection: GuardRejection },
}
pub enum Value { Input(String), Constant(String), Target(String), Created(u8) }
pub struct GuardRejection { pub input: String, pub message: String }
pub enum Revision { Exact, Identity }
```

`Redirect` keeps its route plus a source: the signed target, a step's record, or
a reference field on a step's record (today's `Redirect::Reference`).

`ResponseIntent` becomes guest-facing only. Routes may return `Page`, `NotFound`
or `Redirect`; actions may return `Execute` or `Rejected`. The host rejects any
other variant for the request kind. `Created`, `Updated` and `Deleted` stop being
guest-produced; they become host receipt types.

## Inputs

Each input is defined once, with its own type, bounds, optionality and canonical
encoding, using the existing `FieldKind` vocabulary. `Input.max_bytes` carries
the byte bound, matching the existing resource field schema; `FieldKind::Text` does not
carry that bound. `initial` values and reference kinds are not valid inputs.
Account inputs and `Set` assignments to account fields are allowed only on creates,
with the existing host-enforced active-account and tenant-scope binding checks.
Canonicalization and the input digest use the action's input schema, not a
resource's fields. One input may be consumed by
several assignments; the form contains it once. For example, `quantity` is
both the stock decrement and the order's stored quantity.

Every assignment checks that the input's domain fits its destination: the same
kind; integer `min..=max` within the field's bounds; text `max_bytes` no greater
than the field's; choice variants a subset; optional only into optional fields.

An adjustment amount (`by`) must be a required integer input with `min >= 1`.
Its `max` must not exceed the field's span, computed as `i128` to avoid overflow.
Applications should set it to the permitted business quantity, not the span.
Every declared input must be used.

## Admission rules

Admission in `manifest.rs` rejects the manifest unless all of these hold:

- There are 1–4 steps and at most 2 creates. A delete is the only step.
- Each step's operation is a create, update or delete on the step's resource,
  with `Target::None` for create and `Target::Named` otherwise. Every named
  use addresses its declared target resource; web bindings require matching issuing routes.
- Each field is assigned at most once per step. A create assigns every writable
  stored field, including its reference. An update assigns a nonempty subset of
  ordinary fields. No step assigns owner, tenant, ID, incarnation, revision,
  account fields on update, or a reference field on update. Fields with initial
  values cannot be assigned on create; authorized updates may change them.
- `Value::Input` names a declared input whose domain fits (see Inputs).
  `Value::Constant` is valid for the field's schema. `Value::Target(name)` and
  `Value::Created(n)` assign only reference fields of the matching target
  resource. `Created(n)` requires `n` to be an earlier create step.
- `Decrease`/`Increase` appear only in update steps targeting a named alias; create
  assignments use `Set`. They assign an integer field declaring both `min` and
  `max`. Their `by` input satisfies the Inputs rule. The rejection's `input` is
  declared.
- `revision` is no weaker than the implied requirement (see Revision rules).
- An action with more than one step contains no public or capability operation.
  This keeps one anonymous ownership handover per action in this increment.
- Each target declares its own revision, compute projection and optional guest inspection.
- Reference eligibility lives on the referencing create operation as a field-keyed map. Each `Target`/`Created` reference assignment keeps
  the existing source create policy, gate and target existence checks.

Admission checks structure only. It does not estimate database cost.

## Revision rules

Identity means the same record ID and incarnation as the signed token. Exact also
means the revision recorded in the token.

For each alias, the implied requirement is `Exact` if any step updates it with
`Set`, or deletes it. Otherwise it is `Identity`. Applications declare each target's `revision`;
SDK lowering defaults to `Exact`. Admission rejects a declared `Identity` when
`Exact` is implied, so declarations can only strengthen.

Declare `Exact` when the user's decision depends on the version they saw. For
example, an order created on a product page must declare `Exact` if the customer
agreed to a price shown there. A stock guard protects inventory, not the accepted
price. The order and stock example below uses `Identity` only because it stores no
price and the stock count is guarded.

The pre-execution check in `attempt_action()` applies the action's declared
requirement independently per alias, deduplicating physical identity without
sharing authority. A stale `Exact` page target produces the existing 409 conflict
form; multiple/selected targets receive a safe reload prompt. Reference
eligibility no longer compares revisions; identity plus current eligibility,
gate and create policy inside the transaction is the binding requirement.

## Execution semantics

The executor in `repository.rs` keeps per-request transaction state. For each
step in order:

1. Resolve the target. For `Signed`, reload the row in this transaction. Only the
   first load compares against the token; later steps observe earlier writes.
   A missing row or changed incarnation fails the transaction as unavailable.
2. Check the step operation's policy against the current row, or the principal
   for creates. Denial is unavailable. A policy affected by an earlier step sees
   the earlier step's write.
3. Compute new field values: inputs, constants, the signed reference, or the ID
   created by step `n`.
4. For each adjustment, read the current integer from the row loaded in step 1.
   Then apply checked arithmetic and require the result within the field's
   `[min, max]`. Overflow or bounds failure produces the step's declared
   `GuardRejection`. Guards run only after authorization succeeds.
5. Write conditionally on resource, ID, incarnation and the revision read in
   step 1; increment the revision once per step. Zero affected rows means a
   concurrent change: treat it as an internal retryable conflict, never success
   or a business rejection.
6. Record the step outcome: kind, resource, ID and incarnation.

SQLite's `BEGIN IMMEDIATE` excludes other writers for the transaction. PostgreSQL
`SERIALIZABLE` turns a concurrent committed write into `40001`, already classified
as retryable in `database.rs`. Creates keep quota, account-binding and
initial-value handling. Deletes keep the referenced-child rejection.

Each step charges one repository invocation from the existing budget of 16. Its
SQL is fixed by step kind and schema and draws on the shared deadline and
database-call budget.

## Failure responses

| Failure | Response |
| --- | --- |
| Target missing, changed incarnation, or policy denial at any step | Unavailable (404), indistinguishable across these causes |
| Stale revision where `Exact` applies | Existing 409 conflict form |
| Guest `Rejected` | Existing 422 form, original token |
| Guard failure after authorization | 422 with the declared message on the declared input |
| Retryable database error | Fresh bounded retry; retryable failure when exhausted |
| Trap, deadline, budget, invalid guest decision, other database error | Generic execution failure |

Every failure rolls back all mutations and the receipt claim. No response reveals
the failing step index, undeclared values, or database diagnostics. A guard's
message is contract content: approving the action approves showing it to anyone
authorized to perform that step.

## Receipts and replay

The receipt stores every step outcome (at most four), the navigation source, the
captured destination identity, and any anonymous edit handover. Navigation uses
`redirect`; it does not limit which results survive recovery. Post-commit
destination authorization runs during first delivery and recovery, as today; a
stored destination never bypasses it.

- The receipt and all mutations commit atomically at one commit point.
- Receipt identity binds the session subject, the action ID and version, the
  submission contract (manifest digest and generation), and the canonical input
  digest. The token binds the signed target identity. Different input means a
  different canonical digest, not different HTTP bytes.
- Each submission yields at most one committed mutation set and one durable
  successful receipt. Aborted attempts may run guest code and partial work more
  than once; all of it rolls back.
- Successes replay without execution. Rejections commit nothing, so later
  submissions with the same token are evaluated against current state.
- An uncertain commit outcome goes to receipt recovery before any new execution.
  A missing receipt is conclusive only once the original transaction is known to
  have finished and the recovery read is authoritative.

The manifest digest hashes the complete serialized manifest, so inputs,
assignments, constants, step order, guards, revision requirements, inspection,
and redirect bindings are all part of approval and submission-contract identity.

## SDK shape

```rust
#[action(
    inputs(quantity: i64 = 1..=10, body: String = 2000),
    revision = identity,
    transaction(
        update(Product, target, decrease(stock, by = quantity,
               reject(quantity, "Not enough stock"))),
        order = create(Order, set(quantity = quantity, product = target), eligible = ReadProduct),
        create(OrderNote, set(body = body, order = order), eligible = ReadOrder),
    ),
    allow = owner,
    redirect = show_order(order),
)]
struct PlaceOrder;
```

`eligible = Query` is available for exactly one reference field. Multiple fields
use `eligible(field = ReadQuery, other = OtherReadQuery)`. Explicit SDK
`TargetDeclarations` provides `page`, `selected`, `reference` and `inspect` methods;
`targets = declarations_fn` in a transaction macro lowers to the same protocol.
See [references](references.md#named-targets-and-the-nojs-picker) for handle and
projection authority.
`redirect = page(target)` names the signed target; `page(order)` names a step,
and `reference(order.product, page)` names a reference on a step.

A handler is `fn(Submission<A>) -> Result<Execute<A>, ActionError<A>>`.
`Submission::execute()` returns the decision. Without a handler, the action
executes directly. `crud!` and single-operation `#[action]` lower to one-step
transactions with inputs derived from their listed fields.

## Implementation stages

1. Protocol and admission: introduce the types above and remove
   `Action.operation`, `fields` and `bind`. Split guest and host response types.
   Rewrite action validation in `manifest.rs` and keep the workspace compiling.
2. Executor and lifecycle: add the step executor in `repository.rs` and forbid
   action-time storage imports in `runtime.rs`. Change `submission.rs` to run the
   guest decision, execute, receipt and commit. Update `application.rs` target,
   revision and conflict checks, and the `navigation.rs` receipts and recovery.
3. Forms and rendering: generate form fields, recovery and conflict forms from
   action inputs.
4. SDK and macros: add input declarations, `transaction(...)`, the
   `Execute`-returning handler, and one-step lowering for `crud!`. Migrate all
   examples.
5. Multi-step behavior: add `Created(n)` and adjustments with guard rejections,
   plus the new `examples/shop` (product stock, order, first order note).
6. Documentation: update `runtime.md` (action lifecycle, rejection and replay),
   `references.md` (binding), `layers.md`, `application-api.md`, and
   `sdk-lowering.md`, then change this document's status.

## Acceptance tests

- Two distinct valid orders compete for the last unit on SQLite and PostgreSQL.
  At most one commits. Under the supported retry policy, and without unrelated
  failures, one succeeds and the other receives the declared stock rejection.
- Concurrent submissions with one token converge on one committed mutation set
  and replay its stored outcome.
- Failure at each step, guest rejection, trap and deadline leave no mutation and
  no receipt.
- A policy denial at any step matches a missing target. A guard on an
  unauthorized record never produces its rejection.
- Two `Signed` steps succeed without self-conflict. A later step's policy sees
  the earlier step's write.
- A stale `Exact` edit form returns 409 after a concurrent adjustment; an
  `Identity` order form survives concurrent orders. Declaring `Identity` where
  `Exact` is implied is rejected.
- Adjustments cover overflow, both bounds, and spans near `i64::MIN`/`i64::MAX`.
  Zero, negative and out-of-range amounts fail canonicalization.
- One input feeds two assignments and appears once in the form and digest.
- Admission rejects forward `Created`, duplicate or protected assignments,
  invalid input domains, adjustments in create steps, adjustment of an unbounded
  or non-integer field, more
  than four steps or two creates, delete with other steps, wrong reference types,
  undeclared or unused inputs, and multi-step public or capability operations.
- Action-time `invoke`, `follow-source` and `follow` fail.
- Changing any input, assignment, constant, step order, guard, revision, inspection
  or redirect binding changes the approval digest and invalidates old tokens.
- Receipt recovery replays the outcome and handover after a lost commit
  acknowledgement, and post-commit navigation still checks destination authority.

## Deferred

Transfers (selected second target, authority over both records, exact numeric
representation and debit/credit invariants), user-selected targets, deletes
combined with other steps, updates to records created in the same transaction,
conditional steps, more than one anonymous handover, and moving guest execution
out of the write transaction.
