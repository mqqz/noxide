# Typed references

A resource may have one required, immutable `Id<T>` reference. The host binds it
from a signed page target. A reference declares integrity, not read authority.
The [runtime security contract](runtime.md#security-contract) applies throughout.

Three decisions remain separate:

| Decision | Question | When checked |
| --- | --- | --- |
| Binding eligibility | May this action link the new record to this target? | Submission, in the write transaction |
| Gate | Does target state hide the source or block its creation? | Public source reads/lists and source creation |
| Follow | May this request read the target and these fields? | Every follow execution |

An order remains visible when its product becomes unavailable. Reading an order
does not authorize reading the product. A forum reply can instead declare a gate:
thread publication controls public reply visibility, and locking blocks new
replies without revoking existing edit or delete authority. Private operations
retain their own policies even when the thread is hidden.

## Integrity and binding

References are required, have no initial value, and cannot be form controls,
submitted fields, update fields, selection filters or disclosures. Every create
action explicitly declares `bind(field = target, eligible = Query)`. The eligible
operation must be a non-follow target read on every route carrying that form.
The route must address the reference target resource.

The signed target's identity, revision and incarnation are checked inside the
write transaction, together with source create policy, the eligible read's full
policy/visibility/gate semantics, and both source gate conditions. Losing
eligibility later does not affect the source. Committed receipt recovery precedes
new-execution checks and never reruns eligibility or creation gates.

The target must exist. Deleting it while any record references it is rejected,
including records the caller cannot read. Anyone permitted to create a referencing
record can therefore block target deletion. SQLite writer serialization and
PostgreSQL serializable transactions prevent a racing create and target delete
from both committing. Migrations reject orphans, adding a reference to an existing
resource, and changing a reference target.

Each reference has a schema-managed `nx_r_<storage:x>_<field>` index over resource,
reference value and creation sequence. Gated references also have owner and tenant
variants. Query index reconciliation continues to own only `nx_q_*` indexes.

## Gates and scope

A gate names the resource's reference field and two Boolean/Choice predicates on
its target: `visible` and `create_when`. The target cannot itself have a gate.
A missing target hides public source reads and lists. `create_when` applies only
to creation. Binding eligibility remains independent of the gate.

A list's explicit protocol `scope` restricts that reference to the page target;
its filters narrow the authorized result. Gated lists must be scoped by the gate
field. SDK lowering supplies this scope when omitted, while the host independently
validates the emitted field. Ungated references allow unscoped collection lists.
Cursor scope includes the scoped target's incarnation. Preview destinations must
agree on scope as well as policy, visibility and selection.

## Follow

`via(Source.field)` declares a one-hop read from records returned by a non-follow
read or list. The source projection must include the reference, and every route
using the follow must include its source. `follow_many(&records)` accepts that
query's typed output. Ordinary reads cannot invoke follow operations by ID.

Per-request host provenance maps source operation, resource and ID to the stored
reference. Only records actually returned enter the map: lookahead, pagination,
preview truncation and byte limits cannot supply hidden sources. Guest reference
changes have no effect. Follow output creates no further provenance.

A follow runs once, accepts at most 20 source identities, batches distinct targets
with indexed primary-key reads, and applies its own policy, visibility, gate and
projection. The positional result preserves duplicates and order; missing and
authorization-denied targets both return `None`. It returns the complete result or
a controlled failure. Database calls, serialized bytes, invocation count and the
request deadline share existing request budgets. Provenance is capped at 56
entries, covering the route's 40 list records plus bounded reads.

## Redirects and recovery

`redirect = reference(field, page)` names an unparameterized page with one target
read. Inside the mutation transaction, the host captures the reference target's
resource, ID and incarnation before deletion removes the source. The semantic
receipt retains that destination. After commit and during recovery, current route
and read authorization determine navigation. A denied, missing or replaced target
falls back to mutation success; it cannot undo a committed write. Source edit
credentials never grant target read authority. Anonymous credential handover
precedes navigation.

## Deferred until an application needs them

- Reference selection from URL parameters and folding scope into filters.
- A second binding source and multiple references per resource.
- Cross-thread gated lists and gates on private operations.
- Mutable references and deletion behavior other than rejection.
- Multi-hop follows.

This track intentionally replaces old contracts, approval digests, cursor scopes
and storage formats. Development databases must be recreated. Local validation is
not proof of audited security, deployment acceptance or transport anonymity.
