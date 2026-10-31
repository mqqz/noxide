# Durable jobs

The P10 integration runs declared background actions through the existing action
executor. It includes operator approval, durable queues, recurring selection and
worker shutdown. P10 scoped acceptance passed at `85ef201`; the
[implementation ledger](implementation-ledger.md#p10-closure-at85ef201) records
exact-source evidence and earlier preparation history.

## Authority and capture

`JobContract` declares workers, transactional schedules and fixed-interval recurring
schedules. Each worker action names a fixed action and exact target aliases, with a
resource and eligible Read operation for each alias. Host admission checks target
relationships, scalar expression domains and disclosures. It rejects cycles in the
schedule-call graph. Worker actions have no web binding and can update or delete;
service creation requiring a user owner is outside this increment.

Service identity is distinct from a user account. A service receives its approved
worker name, tenant and action subset without browser credentials, ownership,
roles or edit secrets. A service target or derived one-hop Reference target still
requires its own current eligible Read. The normal action policies run at execution.
Expired-row maintenance requires approved operation metadata. Guests cannot grant
that authority with a job payload or bypass host authentication, budgets or safe
rendering. Jobs grant no filesystem, network, process or host-secret access.

The operator configuration intersects the declaration without changing its target
rules. The stored grant binds the persisted `nx_deployment.generation`, tenant,
worker/action subset, positive version, approved contract and runtime epoch. Runtime
and grant rows are locked during execution; cached configuration cannot authorize a
commit. Revocation retains the grant row and earlier receipts.

Transactional scheduling shares the source action's mutation and receipt transaction.
The host evaluates admitted scalar sources once, canonicalizes inputs and resolves
Created or existing targets there. Capture stores immutable resource IDs,
incarnations and revision rules. Picker tokens, cookies, submission tokens,
passwords and edit secrets never become job arguments.

The job ID derives from deployment generation, originating invocation and effect
ordinal. Contract, epoch, grant version, destination action/version, canonical input
and all target seals enter the invocation digest. Claim fences never change this
identity. A repeated origin/ordinal with different capture fails closed. The receipt
nonce is the job ID, its subject binds deployment/tenant/worker, and its input field
contains the invocation digest.

## Claims, receipts and execution

The queue progresses through Pending, Running and Succeeded. A known retry returns
to Pending; terminal results include Rejected and Dead. Authority changes pause
unresolved work for operator reconciliation.

`QueueContext` borrows a transaction and its remaining logical database-call budget.
It creates no request root, deadline or executor and never commits its caller's
transaction. Enqueue is idempotent for an identical capture and serializes quota
admission with insertion. Pending, Running and Paused rows count against app and
tenant limits, including retained earlier generations.

A worker claims one eligible job in a short transaction and commits before entering
the action executor. Tenant rotation makes claims fair within the app. PostgreSQL
claims skip execution-locked rows rather than wait while holding the queue lock.
Running rows continue to consume concurrency capacity after lease expiry; an expired
lease permits fenced recovery and never proves that an older transaction stopped.
The lease lasts 30 seconds, and the admitted action deadline must be shorter.

The production adapter uses `lock_execution_with_time` in its execution transaction.
It locks runtime, current grant and claimed job rows, then checks the bound semantic
receipt. A complete receipt is validated with the existing core decoder before
fresh lifecycle time is sampled. This ordering permits receipt recovery even when
new temporal execution is unavailable. Malformed, incomplete or mismatched receipts
fail closed.

Without a recoverable receipt, the same locked transaction samples fresh durable
lifecycle time, verifies lease/fence and current authority, and produces the private
`VerifiedJob` proof. The adapter constructs a service invocation from that proof and
runs the common action core. Mutations, every semantic outcome, the complete receipt
and queue success commit together. Headless receipts cannot carry browser navigation
or anonymous handover state.

Only a confirmed abort permits transient retry handling. The core distinguishes an
acknowledged rollback from an ambiguous provider error. After a known abort, a fresh
short transaction locks the same authority/job rows and checks the receipt before
recording backoff or rejection. An uncertain COMMIT or cleanup leaves the job Running
for authoritative recovery. The worker never marks failure from a raw error.

At most five attempts fit within 24 hours of due/first eligibility. Future scheduling
does not consume that window before the job becomes eligible. Retry delays are one
minute, five minutes, thirty minutes and two hours, with deterministic additive
jitter of zero to ten percent. The exact 24-hour boundary is terminal. Business and
current-authority rejection do not automatically retry.

## Work limits and lifecycle

The default pending ceiling is 1,000/app and 1,000/tenant; the operator may lower both,
with the tenant ceiling no greater than the app ceiling. Worker concurrency is at
most two/app and may be lowered. Locked runtime state enforces these ceilings.
Captures are limited to 16 KiB and scheduling to 30 days ahead. Validated rejection
metadata has a separate 24 KiB serialized ceiling.

A production worker carries one request root, original deadline, actual statement
meter and remaining logical calls across claim and invocation. Durable time and the
claim consume that same 16-call allowance. Execution preserves the existing fuel,
host-call and memory limits; actual provider statements remain capped at 256 or the
operator's lower request ceiling. Internal retries cannot replenish these budgets.

Worker/request and database permits are separate from interactive requests and the
reserved clock maintenance lane. An app-bound worker slot cannot be inherited by
another app. Claim cleanup and later database admission share the original deadline;
at most two held slots bound waiting. Wasm uses the existing shared admission limit.

The service starts at most two loops, polling once per second and coalescing missed
polls. Shutdown stops new work, joins those loops and closes the dedicated job
request registry. That registry waits for physical provider stop using original
admitted deadlines. Unconfirmed cleanup retains capacity and fails closed. Once
closed, the registry stays closed: restarting this service requires a new activated
`Application` instance.

## Recurring selection

Recurring schedules use fixed intervals between 60 seconds and 30 days. Missed ticks
coalesce. A schedule may be target-free or select exactly one approved target through
the existing indexed query adapter. Fanout is capped at 20 occurrences per batch and
also consumes the existing queue and request budgets.

The selection subset is deliberately narrow: creation ascending/descending order,
fixed Boolean/Choice literal filters, and exactly one policy conjunction containing
the matching Service predicate and SameTenant. Scoped/via/preview lists, search,
ranges and aggregate queries are excluded. Every candidate passes the List policy
and an independent current eligible Read before the common adapter seals its target.

A scan persists a lifecycle cutoff, creation-sequence cutoff and canonical internal
frontier of at most 4 KiB. The creation cutoff enters the native indexed frontier
before its bounded LIMIT. Current attempt time governs authorization and expiry
visibility. Expiry repair additionally requires maintenance-approved List, Read and mutation
operations and an expiry no later than the fixed scan cutoff.

Partial scans retain their cutoffs across later ticks. The selector reserves work
for each possible enqueue and cursor finalization before reading another candidate.
It may return fewer than 20 rows, or zero with an incomplete frontier. Cursor progress
and emitted jobs commit together. A completed scan clears its continuation and
coalesces the next interval.

When a resumed scan cannot afford a candidate and returns an unchanged frontier,
`defer_recurrence` advances only its version and next work time by one second. It
preserves cursor and cutoffs, allowing another due tenant to run without claiming
row progress or completing the occurrence. The deferral uses the already reserved
finalization call and statement. An initial budget stop persists the selector's
canonical start frontier with no row position.

Ordinary occurrence keys include the scan cutoff and target incarnation. Expiry
repair deduplicates by schedule, scope, target identity/incarnation, expiry value and
contract across later repair scans. Grant version changes do not reset these keys.

## Storage and acceptance

Wire 12 and storage 14 register the integrated contract. The authoritative fixed DDL
and audits live in `database/jobs_layout.rs`; the earlier leaf SQL packet is obsolete.
Startup audits provider-native types, nullability, keys, foreign namespaces, byte/JSON
bounds and required B-tree indexes. Incompatible operator storage fails with an
explicit migration/new-store message; the host does not silently reset it.

Startup installs runtime/grant state in the same maintenance transaction as its
first durable lifecycle tick. Contract changes pause old captures. Explicit
reconciliation checks current approval, canonical input and fresh target eligibility
before creating a protected link to a new job identity. The [operations guide](jobs-operations.md)
covers commands, clock recovery and restore fencing.

The complete serial host suite passed 601 tests at the accepted source, including
both providers; independent source review and focused crash/budget/clock gates
are recorded in the ledger. This is scoped P10 acceptance. Final proof-application
and combined browser/package/build-VM gates remain P12–P14; no security audit or
deployment readiness is claimed. P11 outbox delivery remains unfinished.
