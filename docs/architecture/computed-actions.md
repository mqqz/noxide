# Computed action values

Protocol 8 extends the existing host transaction executor with typed literals,
inputs, sealed targets, earlier created IDs, approved field projections, the
principal account on create, and durable transaction time. Integer addition,
subtraction, and multiplication are checked. Timestamp addition requires a bounded
duration. Each action admits at most 64 expression nodes, depth eight, and eight
guard nodes. Division, floating point, arbitrary functions, loops, and dynamic SQL
are unavailable.

A named target's compute projection names an eligible read and its fields.
`SnapshotField` reads the fixed initial transaction snapshot. Its required
`reviewed` flag is an explicit source-review dependency: `true` requires that
named target to use `Exact` revision. A flag of `false` keeps its declared revision
mode. Guest inspection is a separate approved subset and requires exact review.
An adjustment's bounded success/failure disclosure does not grant guest numeric
inspection. `manifest::action_disclosures` reports source, destination, read
operation, review marker, and declared rejection information from the contract.

`CurrentField` is guard-only and must name the current step's target. The host
checks the mutation policy and the projection's current read authority before
reading it. Each step evaluates its guards and all right-hand sides before any
assignment. Assignment order does not affect contract identity or behavior;
mutation-step order does. Every physical write compares the current revision,
while initial exact review is checked once per physical target. Aliases retain
separate authority checks.

Create preflight checks only decidable principal prerequisites. After resolving
initial values, immutable references (including earlier `Created` rows), and
active same-tenant account bindings, the host evaluates the operation policy
against the complete proposed row. `PrincipalIs(account_field)` is supported on
Create as well as Read and List. Update and Delete do not gain this predicate.
Protected fields remain host-owned and account/reference fields remain immutable.

A guard can bind its message to a declared input or reject the action without a
field. Rejections and arithmetic failures roll back every earlier step and the
receipt claim. No stored secret value is included in arithmetic failure messages.
The canonical receipt still commits with the mutations, and retries use the same
executor and common request budget.

Actions that use transaction time acquire it after committed-receipt recovery.
The existing core has already admitted and fenced its transaction; the narrow
clock helper adds one charged durable clock read and fixes that time for the
attempt. A stale clock rejects new temporal work without preventing recovery of
committed work. Storage remains version 11 and receipt encoding remains version 3.
Old protocol manifests require regeneration and explicit contract reapproval;
there is no compatibility executor or database deletion.

The reservations example demonstrates reviewed price/currency copying, checked
minor-unit totals, stock adjustment, proposed order creation, and cancellation
using the stored order quantity. Its headless expiry declaration does not enable
a production service adapter.
