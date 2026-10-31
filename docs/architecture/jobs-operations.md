# Operating durable jobs

The integrated P10 worker executes declared actions through the existing host action
executor. Each service has an explicit worker identity, tenant and approved action
subset. It receives no user account, browser credentials, edit secret, filesystem or
network authority. P10 acceptance remains open; consult the
[implementation ledger](implementation-ledger.md#p10-integrated-runtime-evidence-and-remaining-corrections)
for current evidence and remaining gates.

## Deployment approval

Add operator choices to the runtime configuration before approving the deployment:

```json
{
  "jobs": {
    "grants": [
      { "worker": "repair", "tenant": "alpha", "actions": [2] }
    ],
    "limits": {
      "pending_per_app": 1000,
      "pending_per_tenant": 100,
      "worker_concurrency": 2
    }
  }
}
```

Use names and action IDs from the admitted manifest. A grant must contain a nonempty
subset of that worker's declared actions. Target resources and eligible-read rules
come unchanged from the declaration. The empty tenant string selects the
unpartitioned tenant; it never selects all tenants.

Omitting `limits` selects the framework defaults shown above, except the default
per-tenant ceiling is 1,000. Pending ceilings must be positive and at most 1,000;
the tenant ceiling cannot exceed the app ceiling. Concurrency must be one or two.
Pending, Running and Paused work all count against queue quotas. Retained paused
captures continue to count after a deployment change until explicitly resolved.

`deployment::approval` is a pure calculation. Its digest covers the manifest,
effective blob policy when present, and canonical effective job grants and limits.
Job declarations require explicit job deployment configuration. The jobs CLI reads
config/manifest and verifies approval before opening keys, stores or the database.
Startup installs runtime and grant state in the same maintenance transaction as its
first durable lifecycle tick. Repeating an unchanged generation and approval preserves existing
revocation and restore pauses.

## Local operator commands

Commands use the selected runtime configuration:

```sh
noxide jobs inspect /srv/app/runtime.json
noxide jobs inspect /srv/app/runtime.json LAST_JOB_ID
noxide jobs revoke /srv/app/runtime.json alpha repair
noxide jobs grant /srv/app/runtime.json alpha repair
noxide jobs cancel /srv/app/runtime.json JOB_ID
noxide jobs reconcile /srv/app/runtime.json JOB_ID
noxide jobs worker-once /srv/app/runtime.json
```

For an unpartitioned deployment, pass `''` as the tenant argument to `grant` or
`revoke`. These commands are trusted local controls and are not HTTP routes.

Inspection returns at most 100 records in ID order. Pass the last returned ID for the
next page. Listings include retained deployment generations and contain job identity,
tenant, worker/action, state, attempt count and due/eligible timestamps. Inputs,
target seals, receipts, rejection details and secrets are omitted.

`revoke` waits for the current runtime/grant locks, revokes the selected grant and
pauses its Pending/Running captures. The tenant's recurring scans pause as well.
Committed actions remain committed. Restarting the same approved configuration
preserves revocation.

`grant` selects only a worker/tenant already present in the approved configuration.
It installs a new grant version and explicitly resumes that worker's current approved
recurring schedules, resetting their scan frontier and coalescing a current tick.
The JSON result reports `recurring_resumed`. Earlier captured jobs stay paused;
expiry-repair occurrence keys remain stable across grant versions.

`cancel` settles a Pending, Running, Paused or Dead job as Rejected without executing
it. `reconcile` accepts a Paused, Dead or Rejected capture, including one from an
older deployment generation. It checks the current approved action, canonical input
and every fresh eligible target read. If permitted, one transaction settles the old
job and enqueues a linked job under the current generation, contract, epoch and grant
version. It returns the replacement ID. A changed target or policy can deny
reconciliation; the old capture never regains execution authority.

`worker-once` makes one bounded claim and invokes the same executor as the background
service. Its output is one fixed label: `idle`, `completed`, `recovered`,
`business_rejected`, `unavailable`, `paused`, `dead` or `retrying`. It adds no authority
and does not include the action result or rejection contents.

## Execution, retries and shutdown

Claims use a 30-second lease and an increasing fence. The action deadline must be
shorter. Execution locks current runtime, grant and job state, then checks the bound
semantic receipt before sampling fresh lifecycle time. A validated receipt can
recover a committed result without executing again. Mutations, complete receipt and
queue success commit together.

An unknown commit or cleanup outcome leaves the job Running for locked receipt
recovery. Lease expiry alone cannot prove an earlier transaction stopped. A known
abort permits fenced backoff: one minute, five minutes, thirty minutes and two hours,
with zero to ten percent additive jitter. At most five attempts fit within 24 hours
of due/first eligibility. Future due time delays the start of that window. Business
or authority rejection is terminal.

The service polls once per second with at most two worker slots. Dedicated request,
database and provider-lifecycle capacity keeps jobs separate from interactive work
and clock maintenance. Claim and execution retain one request root and deadline,
including the original 16 logical calls, actual statement ceiling, fuel and host-call
limits. Shutdown stops new work and waits for admitted providers to stop. Unconfirmed
cleanup retains capacity. A stopped service closes its job registry permanently;
starting it again requires a new activated `Application` instance.

Recurring intervals are at least 60 seconds. Selection supports the approved
creation-order, fixed Boolean/Choice-filter subset under Service + SameTenant, with
an independent eligible Read for each target. Fanout 20 is a ceiling within existing
budgets. Partial scans keep their creation/lifecycle cutoffs and internal cursor.
A budget-stalled resumed scan defers work by one second while preserving that state,
so another due tenant can proceed. Missed intervals coalesce rather than replay each
historical tick.

## Clock recovery and copied storage

The existing clock recovery command requires serving to be stopped and a configured
fresh host key:

```sh
noxide recover-clock /srv/app/runtime.json
```

Recovery preserves the lifecycle watermark, rotates the job runtime epoch, revokes
active grants and pauses Pending/Running jobs. Credential time recovery does not
revive observed expiry or authorize replay of old captures. Reconcile or cancel
retained jobs under current approval after recovery.

Before starting workers on restored or copied storage, fence the retained runtime:

```sh
noxide jobs fork /srv/app/runtime.json
```

`fork` rotates the runtime epoch, revokes grants and pauses unresolved current-runtime
jobs and recurring schedules in one transaction. Restarting the same configuration
preserves this pause. Explicitly grant the required services, then reconcile or
cancel retained jobs. Full backup/restore acceptance remains a P13 gate.

Storage 14 requires an explicit reviewed migration or a new empty database when the
existing format differs. Jobs commands do not silently migrate or delete operator
storage. The current implementation and focused tests do not establish an independent
security audit or transport anonymity. P10 final integration/review gates and future
P11 outbox delivery remain separate acceptance work.
