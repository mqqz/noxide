# Blob metadata storage

The blob runtime uses this provider-portable metadata layout for uploads,
transactional attachment, pairing and fenced cleanup. See [blob storage](blobs.md)
for the complete authority and transfer contract.
The framework storage version is 12. Existing version-11 databases are refused
without changing their data; the framework does not reset or migrate them silently.
Use a separately configured empty development database, or implement and review
an explicit migration. Preserve the old database and any corresponding object
snapshot. Never point a new empty database at a previously paired object store.

Four framework tables contain store counters/identity and durable pending/paired
state, per-subject counters,
immutable blob lifecycle/association metadata, and fenced orphan observations.
No bytes or filesystem paths enter these tables. Text primary keys explicitly
reject NULL on both providers. Ten named indexes cover bounded stage/expiry/claim/
owner scans and native uniqueness of blob references, handles, object keys and
attached resource fields. Initialization checks primary keys and the actual index
definitions, including uniqueness, column order and partial predicates. Existing
index names alone do not establish correctness. Activation must repeat the two
bounded blob catalog checks before binding the store; ordinary reads do not scan
catalogs. The runtime metadata adapter enforces counter/state consistency and pairing;
an empty table layout alone does not prove those runtime invariants.

Generic application migrations refuse removing or renaming resources containing
Blob fields, removing/renaming existing Blob fields, converting or changing their
kind, or initializing an existing record's attachment from a literal ID. They
must first implement atomic association maintenance. Adding a new resource remains
possible through the ordinary declared schema path. Record deletion uses the
transactional detachment path, followed by deferred physical deletion; that
runtime path is implemented by the shared action executor and blob maintenance.

## Store pairing

`nx_blob_store` requires a canonical opaque pair_id and
pair_state (pending/paired), without defaults. A fresh bind durably commits its
pending row before writing/syncing the private filesystem pairing marker, then
acknowledges paired in the database before readiness. Mismatch or missing metadata
never silently adopts a previously paired store, even if it is empty. A pending
bind with populated object directories fails closed. A matching pair does not
prove snapshot-time consistency: completely unknown objects are quarantined and
accounted, not automatically deleted after a grace period. Normal crash cleanup
requires the authoritative preexisting Uploading/reservation or deletion claim.

Native layout tests on SQLite and PostgreSQL accept pending/paired and reject an
unknown state and a missing pair ID. The PostgreSQL layout verifier takes only the
quoted namespace from the catalog and pins each table from the host declaration,
so a required index name on an unrelated compatible table is rejected.
