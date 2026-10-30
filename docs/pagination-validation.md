# Creation pagination validation

The SQLite and opt-in PostgreSQL suites cover numeric creation ordering,
transactional counter rollback and exhaustion, immutable metadata, parent
visibility, strict serialized-byte prefixes, token domain separation, cursor
context binding, and deployment changes. PostgreSQL explicitly exercises counter
lock timeouts and stale-snapshot serialization failures. Ordering expressions
qualify `nx_records.created_seq` so PostgreSQL cannot sort the text projection
instead of the numeric storage column.

The relationship suite inspects SQLite and PostgreSQL plans for resource-owner,
resource-tenant, parent-owner, and parent-tenant continuations. It requires ordered
index access without a separate sort. PostgreSQL additionally checks a generic
prepared parent plan. On small fixtures PostgreSQL may choose a global creation, owner, or
tenant index and filter the JSON parent expression rather than use the available
parent-specific composite index. JSON visibility predicates remain residual
filters; these checks do not promise constant work for sparse visibility or
arbitrary policy combinations. Existing statement and request deadlines apply.

## Local contention measurements

These are short development measurements from 2026-10-29 on a disposable local
PostgreSQL cluster and SQLite WAL database. They are evidence of contention and
bounded failure behavior, not production capacity estimates. Concurrent tasks
start without client backoff. Each task attempts 20 database-only creations or
10 complete form/submission workflows. A failure count includes rejected or busy
attempts; latency percentiles include successful submissions only.

Database-only creation inserts alternate between two resource IDs and include
transaction setup, counter allocation, insertion, and commit. They do not execute
a guest or application authorization. The isolated results were:

| Backend | Concurrency | Committed / attempted | Throughput / sec | p95 transaction |
| --- | ---: | ---: | ---: | ---: |
| SQLite | 1 | 20 / 20 | 1402 | 0.82 ms |
| SQLite | 4 | 80 / 80 | 1642 | 3.63 ms |
| SQLite | 16 | 318 / 320 | 1133 | 8.65 ms |
| PostgreSQL | 1 | 20 / 20 | 285 | 3.61 ms |
| PostgreSQL | 4 | 20 / 80 | 231 | 5.06 ms |
| PostgreSQL | 16 | 49 / 320 | 219 | 14.81 ms |

The complete workflow uses the trusted test component and distinct authenticated
principals, with replies distributed across two parent scopes. It includes real
host authorization, form credentials, guest execution, response rendering,
receipt persistence, and commit. Workflow throughput includes fetching forms;
submission latency starts after the form has been fetched. Test-only timing
records the maximum interval from allocation returning to commit returning,
including remaining guest execution and rendering. It excludes allocation SQL and
lock acquisition time, so it is an observed post-allocation hold interval rather
than an exact database lock duration.

| Backend | Concurrency | Committed / attempted | Workflow / sec | Submit p95 | Max post-allocation hold |
| --- | ---: | ---: | ---: | ---: | ---: |
| SQLite | 1 | 10 / 10 | 195 | 2.54 ms | 0.42 ms |
| SQLite | 4 | 40 / 40 | 229 | 6.26 ms | 0.96 ms |
| SQLite | 16 | 140 / 160 | 262 | 71.00 ms | 1.13 ms |
| PostgreSQL | 1 | 10 / 10 | 65 | 7.97 ms | 0.85 ms |
| PostgreSQL | 4 | 30 / 40 | 85 | 25.69 ms | 2.20 ms |
| PostgreSQL | 16 | 77 / 160 | 70 | 78.10 ms | 2.77 ms |

PostgreSQL serializable conflicts are substantial under immediate competing
writes. Keep creation transactions short and retain bounded failures; these
measurements do not justify changing to per-resource allocation or relaxing
isolation. Test-component timings do not bound arbitrary application guest work,
which continues to use the configured execution and rendering limits.

Run the manual benchmarks separately from regression suites for comparable
measurements:

```sh
cargo test -p noxide-host --lib creation_contention_benchmark -- --ignored --nocapture --test-threads=1
cargo test -p noxide-host --lib full_creation_benchmark -- --ignored --nocapture --test-threads=1
```

Both commands include PostgreSQL tests and require `NOXIDE_TEST_POSTGRES` pointing
to a disposable local cluster with `CREATE DATABASE` permission. Use a backend
name prefix in the test filter to run one backend only. Benchmark databases live
in temporary directories or uniquely named PostgreSQL databases; dispose of the
cluster after collecting evidence.

## Compiled list compatibility

Increment 1 keeps the two existing execution paths and cursor contract. Local
validation on 2026-10-30 ran the workspace suite with ignored PostgreSQL tests
(excluding crash-worker and browser entry points), the instrumented SQLite host
suite, and the real private-inbox HTTP/component fixture. The exact serialized
contracts and cursor-scope fixtures remained unchanged. The inbox measurement
still checks 21 index visits per exact scan on its 100,000-unrelated-record
fixture; this is a dataset measurement, not a latency or arbitrary-policy bound.

Increment 2 adds descending account pagination and descending parent-scoped byte
prefix/live-insertion cases on SQLite and PostgreSQL. Ordered parent owner/tenant
plan checks exercise both directions, including PostgreSQL generic prepared
plans. On the same inbox dataset, descending exact scans also measured 21 visits
on each backend. The updated newest-first inbox and the existing forum HTTP
fixtures passed locally. The original inbox source is retained beside its golden
manifest so the compatibility producer stays fixed despite the deliberate example
order change.

## Literal filter baseline

Before derived indexes, the increment 3 instrumented fixture measured 210 index
visits on both SQLite and PostgreSQL to return 21 owner candidates from 1,000
caller records with one in ten matching `archived = false`. The fixture also has
one matching unauthorized record. These are baseline measurements, not asserted
performance limits. The separate unfiltered inbox fixture retains its 100,000
unrelated records and 21-visit assertion. Filter regressions cover both orders,
exact and residual account policies, read/list authorization equivalence, public
projection/disclosure, parent visibility and records changing selection between
pages. Workspace tests with PostgreSQL and the instrumented SQLite suite passed
locally on 2026-10-30; SDK positive/negative and compatibility producers passed.

## Derived filter indexes

On 2026-10-30, the filtered fixture extended the baseline to 1,000 caller records
(one in ten matching) plus 100,000 unrelated records. Owner exact scans measured
21 visits on SQLite and PostgreSQL with derived indexes, compared with the earlier
210-visit baseline without them. Both-direction SQLite plans and PostgreSQL generic
prepared plans require derived owner, account and account-plus-tenant indexes with
no sort; public parent selection also checks its derived index in both orders.
Missing-index refusal, idempotent reconciliation, removal without schema migration,
and the ninth-shape admission rejection have regressions. Existing contracts add
no derived indexes.

The separate single-path `any(owner, role("moderator"))` filtered benchmark on this
dataset measured 100,021 visits for an ungranted moderator and 21 for a granted
moderator on **both** databases. It uses one SQL policy disjunction, not the account
merge path. The ungranted case is a material sparse-authorization cost: an available
ordered index does not imply bounded index visits. This evidence supports the
conditional increment 7 design discussion after the first six increments; no new
merge policy classification is introduced here. Request deadlines remain the bound.

The broad PostgreSQL suite exhausted the disposable cluster's default predicate
lock capacity. The successful rerun uses 512 connections,
`max_pred_locks_per_transaction=512`, and `max_locks_per_transaction=256`.
These are local test-cluster settings, not production sizing recommendations.
