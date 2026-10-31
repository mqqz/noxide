# Typed references

A resource may have up to four required, immutable `Id<T>` references. The host
binds each field from an approved named target or an earlier create step. A reference declares
integrity, not read authority.
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
submitted inputs, update fields, selection filters or disclosures. A referencing
create operation declares binding eligibility; the action assigns its reference
with `Target(name)` or `Created(n)`. The latter names an earlier create step of the
matching resource. Admission rejects forward references and references to other
resources. Updates to newly created records remain deferred.

The explicit single-operation SDK syntax `bind(field = target, eligible = Query)`
lowers to operation eligibility and a `Set(Target("target"))` assignment. A multi-step
create uses `create(Order, set(product = target, quantity = quantity),
eligible = ReadProduct)`, or assigns a named earlier create instead of `target`.
With multiple references, write `eligible(product = ReadProduct, contact = ReadContact)`;
every declared reference needs its own eligible non-follow Read operation. The
wire operation stores a field-keyed map, with duplicate fields rejected before
canonical sorting. The single-reference shorthand lowers to that same map.
Page targets use explicitly declared eligible reads intersected with the issuing
route's reads. An edit credential supplies mutation authority and cannot authorize
inspection.

Binding checks identity and incarnation, current eligibility, source create policy
and both gate predicates inside the transaction. It does not compare the reference
target's revision. Each named target's declared `Exact` or `Identity` requirement applies
separately before execution. Losing eligibility later does
not affect the source. Receipt recovery precedes new execution checks and never
reruns eligibility or creation gates.

The target must exist. Deleting it while any record references it is rejected,
including records the caller cannot read. Anyone permitted to create a referencing
record can therefore block target deletion. SQLite writer serialization and
PostgreSQL serializable transactions prevent a racing create and target delete
from both committing. Migrations reject orphans, adding a reference to an existing
resource, and changing a reference target.

Each reference has a schema-managed `nx_r_<storage:x>_<field>` index over resource,
reference value and creation sequence. Gated references also have owner and tenant
variants. Query index reconciliation continues to own only `nx_q_*` indexes.

## Named targets and the NoJS picker

An action declares at most four existing targets. A target comes from its signed
page, an opaque user-selected handle, or one immutable reference from a page or
selected target. Reference-derived sources cannot themselves be derived. Source
names are resolved as a graph; declaration order has no meaning. Named target
maps and field eligibility maps are canonicalized, while mutation step order
remains semantic.

Selected and derived targets name one eligible Read and an explicit host compute
projection. A derived source projection must contain its reference field. Guest
inspection is separate, uses an explicit private Read and projection, and requires
Exact review. Compute-only fields and handle bytes do not enter guest inputs.
Aliases of one physical record share loading and revision checks; each alias still
passes its own eligibility, projection and mutation policies. Conflicting Exact
seals produce a conflict only after every alias is authorized.

The host renders a native HTML select from an authorized bounded List result,
filtered by the selected target's eligible Read. Its label fields must be an
explicit subset of the compute projection. Results share the route's database,
byte and deadline budgets; the picker exposes at most twenty candidates per
query. The current picker uses the query's first bounded page. Applications can
use a narrower declared query when that page is insufficient.

Each encrypted handle binds deployment, contract, user/tenant or anonymous
session, binding, action, target name, selection and eligible operations, record
incarnation and a ten-minute expiry. Raw IDs confer no authority. Submit verifies
that scope before receipt lookup, then rechecks current eligible Read, projection,
incarnation, reference and revision inside the existing write transaction. Query
filters choose candidates when issuing the handle; the explicit eligible Read is
the execution authority. Public picker queries do not revoke independently
approved private target reads.

Receipt identity includes decoded target identities rather than randomized token
bytes. Identity targets ignore review revision in that identity; Exact targets
retain it. Equivalent or expired handles can recover a committed receipt, with no
fresh write or current target-authority requirement. Expired handles cannot begin
a new execution. Role changes are excluded from receipt identity.

The [catalog-links example](../../examples/catalog-links/src/lib.rs) selects a
contact, derives its project through an immutable reference, and creates a ticket
with both references using the existing executor.

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

A single-step `redirect = reference(field, page)`, or multi-step
`redirect = reference(step.field, page)`, names an unparameterized page with one
target read. Inside the mutation transaction, the host captures the reference target's
resource, ID and incarnation before deletion removes the source. The semantic
receipt retains that destination. After commit and during recovery, current route
and read authorization determine navigation. A denied, missing or replaced target
falls back to mutation success; it cannot undo a committed write. Source edit
credentials never grant target read authority. Anonymous credential handover
precedes navigation.

## Deferred until an application needs them

- Reference selection from URL parameters and folding scope into filters.
- Cross-thread gated lists and gates on private operations.
- Mutable references and deletion behavior other than rejection.
- Multi-hop follows.

This track intentionally replaces old contracts, approval digests, cursor scopes
and storage formats. Rebuild and reapprove development contracts when changing protocol versions; do
not delete databases. Local validation is
not proof of audited security, deployment acceptance or transport anonymity.
