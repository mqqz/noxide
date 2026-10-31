# Blob metadata storage preparation

This schema is P08 preparation, not enabled uploads or downloads. Blob declarations
still fail host admission until their complete runtime is integrated and reviewed.
The framework storage version is 12. Existing version-11 databases are refused
without changing their data; the framework does not reset or migrate them silently.
Use a separately configured empty development database, or implement and review
an explicit migration. Preserve the old database and any corresponding object
snapshot. Never point a new empty database at a previously paired object store.

Four framework tables contain store counters/identity, per-subject counters,
immutable blob lifecycle/association metadata, and fenced orphan observations.
No bytes or filesystem paths enter these tables. Text primary keys explicitly
reject NULL on both providers. Ten named indexes cover bounded stage/expiry/claim/
owner scans and native uniqueness of blob references, handles, object keys and
attached resource fields. Initialization checks primary keys and the actual index
definitions, including uniqueness, column order and partial predicates. Existing
index names alone do not establish correctness. Activation must repeat the two
bounded blob catalog checks before binding the store; ordinary reads do not scan
catalogs. Counter/state consistency and pairing are enforced by the forthcoming
metadata adapter, not established by an empty table layout.

Generic application migrations refuse removing or renaming resources containing
Blob fields, removing/renaming existing Blob fields, converting or changing their
kind, or initializing an existing record's attachment from a literal ID. They
must first implement atomic association maintenance. Adding a new resource remains
possible through the ordinary declared schema path. Record deletion uses the
transactional detachment path, followed by deferred physical deletion; that
runtime path is not enabled by this schema preparation.

Coordinator owns the schema and storage-version allocation. Requested route is
Sol/high; effective token/credit usage is unavailable. The isolated worktree is
`/tmp/noxide-p08-schema`, based on B's `a2a97d7` (which includes integrated
`fd000f4`). Ordinary transaction lifecycle repair belongs separately to D; this
patch changes neither cancellation nor COMMIT classification.

Executed checks with Rust 1.98.0, CARGO_BUILD_JOBS=2, CARGO_INCREMENTAL=0,
CARGO_TARGET_DIR=/home/mo/code/noxide/target/p08-schema:

- `cargo test -p noxide-host --lib database::blob_layout::tests --locked --offline --no-run`:
  compile exit0; schema-build-final.log.
- Same test selector with `-- --include-ignored --test-threads=1 --nocapture` and
  disposable NOXIDE_TEST_POSTGRES: exit0, both providers passed/zero ignored;
  schema-providers-initial.log. The fixture verifies six missing/spoofed index
  cases, missing primary key, four native uniqueness violations, and old-version
  refusal preserving the version and row. The fixture-created PG database is
  dropped only on success; no other database is inspected or dropped.
- `cargo test -p noxide-host --lib schema::tests::blob_associations_cannot_be_reinterpreted_by_schema_migrations --locked --offline -- --exact --test-threads=1`:
  exit0, one test passed; schema-migration-guards.log.

Logs are under target/capability-evidence/p08. Independent review, full integrated
suites, store-pairing recovery, quota races, real streaming/GC and consistent
backup/restore remain open. No operator database mutation or external delivery
was performed.
