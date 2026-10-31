# Operating durable jobs

Workers execute declared actions through the host's existing action executor.
Each worker is an application service identity with an explicit tenant and an
operator-approved subset of declared actions. It receives no user account,
browser session, password, edit secret, filesystem or network authority.

Add a `jobs` section to the deployment configuration before approving it:

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

Replace the worker and action with names and IDs in the admitted application
contract. The empty tenant string selects the unpartitioned tenant; it is never
a wildcard. Target resource and eligible-read rules come from the declaration.
The configuration cannot replace those rules or add undeclared actions.
Pending limits may only decrease from 1000, and concurrency may only decrease
from two. Paused work continues to count against queue limits.

The canonical approval summary includes tenant grants, permitted actions and
effective limits. Changing any of them requires deployment approval. Validation
precedes opening the database, host keys and resource stores. Startup installs
the approved state in the same maintenance transaction as its first durable
lifecycle heartbeat.

## Inspection and explicit changes

Commands take the deployment's runtime configuration:

```sh
noxide jobs inspect /srv/app/runtime.json
noxide jobs inspect /srv/app/runtime.json JOB_ID
noxide jobs revoke /srv/app/runtime.json alpha repair
noxide jobs grant /srv/app/runtime.json alpha repair
noxide jobs cancel /srv/app/runtime.json JOB_ID
noxide jobs reconcile /srv/app/runtime.json JOB_ID
noxide jobs worker-once /srv/app/runtime.json
```

Inspection returns at most 100 records in ID order. Pass the last returned ID to
read the next page. The listing includes retained generations so paused jobs
from an earlier approved contract can be reconciled or cancelled. Results include identity, captured deployment generation, tenant, worker, action, state,
attempt count and due/eligible timestamps. Inputs, sealed target identities,
receipts, rejection details and secrets are omitted.

Revocation waits for the authoritative runtime/grant locks and pauses pending
and running captures. It cannot undo an action that already committed. Restarting
with the same approved configuration preserves the revoked grant. `grant`
explicitly installs a new grant version within the approved configuration; it
does not resume captures made under the previous version. It explicitly resumes
current declared recurring schedules for that worker, tenant and approved action
subset, with a fresh cursor and a coalesced current tick. Existing expiry-repair
occurrence keys remain stable; a new grant version does not replay old captures.

`cancel` settles an unresolved job without executing it. `reconcile` rechecks the
current approved action, canonical input and every eligible target read. If
authorized, it atomically settles the previous job and enqueues a linked job with
a new identity. Its input and target seals are bound to the new contract and
grant version. Reconciliation can reject records whose current state or policy
no longer permits the action. It never resumes the old invocation identity.

`worker-once` makes one bounded claim and calls the same executor used by the
background workers. It prints only a fixed outcome label. It is useful for
supervised operation and diagnosis, and grants no additional authority.

## Recovery and shutdown

A job claim has a 30-second lease and an increasing fence. The execution
transaction checks the current runtime epoch, grant, claim, lease and fence,
then commits action mutations, the semantic receipt and queue completion
together. Lease expiry does not prove an older transaction has stopped.

An unknown commit outcome leaves the job Running. A later attempt locks the row
and checks its bound semantic receipt before executing. Retryable known aborts
use delays of one minute, five minutes, thirty minutes and two hours, with
bounded jitter and at most five attempts in 24 hours from first eligibility.
Business rejection is terminal.

Workers poll at most once per second and use at most two slots per application.
Their request and database capacity is separate from clock maintenance and
interactive requests. Shutdown stops new claims and waits for existing executor
work and provider cleanup; a timeout never releases capacity as evidence of a
stopped transaction. Recurring schedules have a minimum 60-second interval and
coalesce missed ticks. Their persisted cursor and immutable scan cutoff survive
partial scans, and their maximum fanout remains subject to request and queue
budgets.

After restoring or copying a database, fence its previous runtime before
starting workers:

```sh
noxide jobs fork /srv/app/runtime.json
```

This rotates the runtime epoch, revokes grants and pauses unresolved jobs and
recurring schedules in one transaction. Restarting the same configuration
preserves that pause. Review the retained work, explicitly grant the required
services, and reconcile or cancel individual jobs. Full backup/restore
acceptance remains part of the P13 integration gate.

These are host enforcement requirements and operational behavior, not evidence
of an independent security audit or transport anonymity. Full P10 acceptance
also requires integrated action, selector, provider, lifecycle and operator tests.
