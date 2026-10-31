# Durable jobs

This is the P10 leaf integration contract. The protocol module and host queue
remain unregistered on the dependency SHA. No production worker, scheduling
capability, migration, SDK integration or acceptance is claimed by this packet.
Native compilation and provider execution are unrun while P09 owns the gate.

## Authority and identity

`jobs::JobContract` declares workers, transactional schedules and operator recurring
schedules. Each `WorkerAction` names a fixed action and exact target aliases with
resource and eligible Read operations. A `Schedule` names its originating action,
ordinal 0 or 1, fixed worker/action, typed scalar `Value` sources, target sources
and due-time expression. Maps reject duplicate keys. Independent host admission
checks the call graph is acyclic, aliases/resources agree, workers have no web
bindings, and service actions update/delete only. Existing computation admission
must check expression domains and explicit disclosures; leaf admission requires
callbacks to that existing implementation.

Central integration adds `TargetSource::Service { eligible }`, the distinct
`Principal::Service`, `Predicate::Service { worker }`, and approved operation
maintenance metadata. A worker may also use an existing one-hop Reference target.
Every alias retains its independent eligible Read; enqueue verifies any derived
relationship and execution checks it again. Service identities inherit no user,
owner, account, role, browser session or edit-capability authority. Current policy
and tenant checks remain in the existing executor. Maintenance access to expired
rows is an explicit operation approval, never a flag supplied by a job.

An operator installs a `Grant` containing `JobScope { deployment, tenant }`, the
approved `Worker` intersection, positive version, contract and runtime epoch.
Deployment is the persisted `nx_deployment.generation`, not a display name. A grant
row is retained on revocation so committed receipts remain recoverable. Updates,
revocation and epoch rotation conflict with execution's authoritative row locks.
A captured grant alone grants nothing.

`CapturedJob::capture` accepts the admitted Schedule, verified originating
invocation identity, current Grant, action version, evaluated due time, fixed
attempt time, canonical Fields and sealed targets. The common adapter must verify
that the schedule belongs to its current source action and resolve Created and
existing targets inside that originating transaction. Evaluate scalar expressions
once from its snapshots and transaction time. Never persist picker tokens,
submission tokens, cookies, passwords, edit secrets or guest-asserted identities.
Each `SealedTarget` has resource, positive ID, incarnation and revision.

Job IDs derive from deployment, originating invocation and effect ordinal. Input,
contract, epoch, grant version, action/version and all target seals enter the
stable invocation digest. The changing claim fence is excluded. The receipt nonce
is the job ID; subject is the domain-separated deployment/tenant/worker identity;
`nx_receipts.input` is the invocation digest, matching the existing executor.
Changing a capture under an existing origin/ordinal fails closed.

## Queue API and transactions

`QueueContext<'a>` borrows `tx: &'a mut Transaction` and `calls: &'a mut u32` from
existing request/execution ownership. It creates no transaction, timer, request
root or executor and never commits a caller transaction. One bounded public queue
command charges one existing logical database call; every internal statement
charges the existing root's actual statement meter and deadline. CPU work checks
the current RequestScope or the transaction's existing operator checkpoint.

The methods are:

- `enqueue(&CapturedJob, Timestamp, tenant_limit: u16) -> Result<bool>`;
- `claim(deployment: &str, Timestamp) -> Result<Option<Claim>>`;
- `lock_execution(&Claim, Timestamp, receipt_decoder) -> Result<Execution>`;
- `succeed(&VerifiedJob, receipt_decoder) -> Result<()>`;
- `fail(&Claim, Timestamp, Failure, receipt_decoder) -> Result<FailureResult>`;
- `begin_recurrence(&JobScope, &RecurringSchedule, Timestamp)` returns an optional
  `RecurrenceBatch`; `emit_recurrence` appends one bounded occurrence; and
  `finish_recurrence(batch, Option<&str>)` stores the internal continuation.

`receipt_decoder` has type `impl Fn(&str) -> anyhow::Result<()>`. Production must
supply the existing semantic receipt decoder, including version/outcome validation.
A malformed, incomplete or mismatched receipt is unavailable; it is never proof
of an abort. `Execution` is Ready(VerifiedJob), Recovered(String), Paused or Dead.
`Failure` is Transient or Rejected. A rejection is terminal. FailureResult carries
Retrying(Timestamp), Rejected, Dead, Paused or a validated Recovered(String).

Enqueue shares the action mutation/receipt transaction. Its queue lock serializes
quota admission and insertion. App and per-tenant pending ceilings are 1,000 or a
lower operator tenant limit; Pending, Running and Paused count. Historical terminal
rows do not enter the bounded active scan (at most 1,001 candidates). Payloads are
at most 16 KiB; due dates are at most 30 days ahead. Duplicate enqueue succeeds
without consuming another quota slot, including when the queue is full.

Claims commit in a short host-owned work transaction before execution. A separate
queue lock preserves tenant rotation without serializing all action transactions.
All Running rows consume the two/app concurrency ceiling, including expired
leases. An expired Running row can itself be recovered under a new monotonic
fence; expiry does not release an old execution's capacity or prove termination.
Leases last 30 seconds. The existing action work deadline must be shorter.

Execution locks runtime, authoritative grant and claimed job rows, then probes the
bound receipt before any reexecution. PostgreSQL runtime/grant locks are shared;
SQLite's existing write transaction provides serialization. Restores/revocations
take conflicting locks. Acquiring the job lock serializes with a previous execution
transaction; the old fence cannot later commit. Only this admission creates
VerifiedJob. Its immutable accessors expose deployment, tenant, worker,
grant_version, action `(u32,u32)`, canonical input, sealed targets, receipt nonce,
receipt subject, invocation digest, runtime epoch, fence and lease timestamp.

C's adapter constructs the service principal only from VerifiedJob, then invokes
the existing action executor. It persists the complete semantic receipt and calls
`succeed` before committing mutations, receipt and completion together. Headless
result validation precedes commit. A failure after an uncertain commit goes to a
fresh fenced transaction's receipt probe before retry or terminal marking. The
queue never classifies an uncertain COMMIT from its error alone.

Attempts are at most five within 24 hours from due/first eligibility, not enqueue.
Retry delays are 1 minute, 5 minutes, 30 minutes and 2 hours with deterministic
additive jitter between zero and 10 percent. Retry beyond the remaining window is
Dead. Business/authorization rejection is terminal. Contract, grant or epoch
changes pause work. Central activation/restore must atomically pause old pending
work, rotate the authoritative runtime epoch when required, and preserve old
receipts/grants. Operator reconciliation cancels or explicitly reenqueues with a
linked new identity; it must not silently resume old captured jobs.

## Recurring selection

Fixed intervals are between 60 seconds and 30 days. Recurring schedules are a
separate approved operator capability, with a ceiling of 20 occurrences per tick.
They do not extend the action's two-schedule limit. Query selection uses the
existing service-authorized indexed query adapter and fixed literal filters.

Persist a lifecycle cutoff, a creation-sequence cutoff and the internal query
frontier. A resumed scan retains both cutoffs across missed ticks. Query SQL must
apply `created_seq <= batch.cutoff_seq()` and any approved maintenance expiry
condition at `batch.cutoff()`. This is a host-owned bound operator runtime
parameter; guests cannot provide it. Current authorization still applies to every
candidate, and temporal eligibility never widens ordinary guest query authority.
The internal frontier must be canonical and at most 4 KiB; browser cursors or other
expiring credentials cannot be persisted as it.

`RecurrenceBatch` exposes cutoff(), cutoff_seq(), cursor(), remaining() and scope().
The selector must stop before exhausting the existing logical/actual budgets and
persist an advanced continuation. Twenty is a ceiling, not a new budget: smaller
batches resume next interval. Emission consumes fanout work even for a duplicate.
Cursor progress and emitted jobs commit atomically. Completed scans coalesce missed
intervals instead of replaying every historical tick.

Ordinary occurrence keys include the fixed scan cutoff and target incarnation.
Expiry repair keys instead include schedule, scope, target identity/incarnation,
expiry value and contract, deduplicating that expiry across later repair scans.
`nx_job_occurrences` records this relationship atomically with enqueue.

## Central integration packet

The fixed table/index packet is `crates/noxide-host/src/jobs/schema.sql`. C owns
storage14 registration, provider-native byte/JSON/SQLite integer-affinity checks,
fixed-layout audits, activation and migrations. Leaf SQL is not schema activation.
The queue uses separate runtime and queue rows, retained grant rows, active jobs,
tenant rotation, persisted recurring cursors and occurrence deduplication. No
operator database reset, migration, deletion or restore was performed.

C also owns wire12/root exports, optional Manifest.jobs omission when absent,
canonical hashing of every authority field, SDK explicit declarations, maintenance
policy/selection integration, action effect evaluation and the service adapter.
The runtime remains unavailable until those paths and operator approval are real.
Measure the worst permitted two enqueues plus four mutations, recovery and service
completion under the original logical16/actual256 root; no allowance was raised.

Source fixtures cover SQLite and retained disposable PostgreSQL queue transitions,
duplicate capture, tenant rotation, concurrency ceiling, stale fence, bounded
retry, lost commit acknowledgement, malformed/mismatched receipts, revocation,
resumed cutoff/cursor and expiry repair deduplication. These fixtures use a narrow
fixture receipt decoder only; executor/normal-policy integration needs C's real
adapter tests. All compilation and provider tests remain unrun in this preparation
packet. Rustfmt parsed/formatted the owned Rust leaves successfully.
