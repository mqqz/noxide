# Resource authority migrations

Resource gate, expiry field and horizon, and explicitly declared membership
uniqueness are part of the stored application schema fingerprint. Unique tuple
declaration order does not change that fingerprint. Existing storage format 11
is unchanged; this is an application contract transition, not a framework reset.

Changing this metadata requires a reviewed migration against the approved target
bundle. The operation below adopts only that resource's target `gate`, `expiry`
and `unique` values. It cannot rename resources, change fields, replace catalog
identities, or alter protected owner/tenant data.

```json
{"op":"change_resource_authority","resource":"membership"}
```

`rename_field` updates local gate, expiry and unique tuple field names along with
the field. Other metadata changes still require explicit operations; the complete
normalized result must equal the approved target. A reduced expiry horizon does
not rewrite existing timestamps or reinterpret the durable clock. Ordinary
expiry semantics and assignment admission use the shared runtime authority layer.

Run the existing schema check before schema apply. Both exercise the real
provider DDL and row validation. Check rolls back rows, catalog, indexes, history
and deployment generation. Apply commits them together or rolls them all back.
No automatic duplicate deletion, reference repair, or operator database reset is
performed. A failed uniqueness activation preserves historical data, including
raw malformed bytes. Resolve data conflicts through separately approved data
changes, then rehearse again.

Explicit unique tuples receive native `nx_m_*` unique indexes on resource,
canonical reference and canonical account. These keys deliberately omit status,
owner and tenant; revocation or expiry does not release the tuple. Resources
without a unique declaration retain legal historical duplicates. Required query,
account and multiple-reference indexes retain their existing namespaces.

Activation reads rows in pages of at most 64 candidates and 60 KiB returned data,
with a 32 KiB per-row cap, and rejects duplicate JSON keys, nonstring
values, unknown/missing fields and noncanonical scalars before extracting tuples.
Whitespace and object key ordering do not change a canonical tuple. Native index
creation detects historical duplicates without retaining all tuples in host
memory. Source validation precedes migration rewrites; validation itself does not
rewrite object formatting. Startup checks required index definitions, including uniqueness, key
order and resource predicate; a matching name alone is insufficient. Missing,
spoofed or obsolete membership indexes fail closed. The existing operator
`schema indexes` command reconciles them under the schema maintenance lock and
rolls back if canonical preflight or native uniqueness fails.

Ordinary requests keep the bounded schema digest/catalog and deployment
generation fence; they do not scan raw rows or inspect index catalogs on GET.
Only framework operator maintenance changes DDL, under the operator lock, and
schema apply rotates generation. Database/schema administrators remain trusted;
out-of-band DDL by an administrator is outside the guest authority model.
Startup retains its original two-second deadline, and operator schema work
retains its original sixty-second deadline. A large or slow database that cannot
finish validation within that envelope fails closed; these limits are not raised
by declaring uniqueness.

This layer does not grant membership-management authority. Public unavailable
responses, mutation conflict receipts, witness invalidation, and all-path expiry
enforcement are runtime integration gates, tested separately from schema DDL.
