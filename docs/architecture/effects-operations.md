# Operating approved effects

The host provides an approved HTTPS POST outbox through Tor. Effects are not yet
certified for deployment; no production delivery or live Tor request is
authorized by the local fixtures. See the [effect contract](effects.md)
for declaration and disclosure rules.

## Deployment approval

The manifest names endpoints, optional secret slots and fixed payload mappings.
Operator configuration supplies the exact destination for each approved tenant:

```json
{
  "effects": {
    "tor_proxy": "127.0.0.1:9050",
    "grants": [
      {
        "endpoint": "events",
        "tenant": "team",
        "host": "receiver.org",
        "port": 443,
        "path": "/events"
      }
    ],
    "secrets": [
      { "slot": "delivery_token", "path": "secrets/delivery-token" }
    ],
    "limits": {
      "pending_per_app": 1000,
      "pending_per_tenant": 100,
      "worker_concurrency": 2
    }
  }
}
```

This example requires the declared `events` endpoint to name `delivery_token`.
An endpoint without a secret slot needs no corresponding secret resource. Unknown
endpoints, duplicate tenant/endpoint pairs, missing slots and unused secret
resources are rejected. The empty tenant selects the unpartitioned tenant; it
does not select every tenant.

The protocol is fixed to HTTPS POST JSON. Hostnames must be canonical ASCII DNS
names; IP literals, reserved/local suffixes, URL credentials, query strings,
fragments, escapes and normalized paths are rejected. The proxy must be an
explicit numeric loopback socket. It must support remote SOCKS RESOLVE. The host
validates the returned globally routable numeric address and uses numeric CONNECT
while retaining the approved hostname for TLS, SNI and Host. There is no system
DNS lookup, redirect following or direct fallback.

Approval is a pure calculation covering endpoint/tenant bindings, host/port/path,
Tor proxy, declared secret-slot identities, payload schemas and disclosure
expressions, and lowered limits. Secret values and host paths are excluded from
approval output. The CLI verifies approval before opening keys, stores or the
database. Declarations require explicit effect configuration.

Secret paths resolve relative to the configuration directory. Send-time reads
require a private, process-owned regular file with one link, no symlink path
components and at most 2,048 bytes. Its contents must be the exact permitted bearer
token; newlines are not stripped. Values never enter guest reads, outbox bodies,
inspection output or logs.

The CLI derives delivery ownership from the existing host-key parent directory;
there is no additional runtime-directory configuration field. That directory must
be private, owned and free of symlink components. The database binds a stable
store identity to its checked directory identity. Another directory is refused.
Activation prepares the lock file without claiming it, so inspection and
revocation remain available while a worker delivers. Delivery runs only in
`noxide-effects-worker` or `worker-once`; each requires the exclusive flock. The
serving process never delivers and links no outbound transport. `noxide serve` starts
the worker for you. It holds no host keys and writes no deployment state; it waits for
the serving process to activate.

On PostgreSQL, run the worker under its own role. `noxide effects worker-grants ROLE`
prints the grants; they exclude accounts, records, sessions, blobs and jobs. SQLite
has no roles, so a worker on SQLite can read the whole database file, including
sessions. Use PostgreSQL where that separation matters.

## Local operator commands

```sh
noxide effects inspect /srv/app/runtime.json
noxide effects inspect /srv/app/runtime.json LAST_EFFECT_ID
noxide effects revoke /srv/app/runtime.json team events
noxide effects grant /srv/app/runtime.json team events
noxide effects revoke-secret /srv/app/runtime.json delivery_token
noxide effects grant-secret /srv/app/runtime.json delivery_token
noxide effects cancel /srv/app/runtime.json EFFECT_ID
noxide effects resume /srv/app/runtime.json EFFECT_ID
noxide effects retry /srv/app/runtime.json EFFECT_ID
noxide effects worker-once /srv/app/runtime.json
```

Pass `''` as the tenant for an unpartitioned deployment. These commands are
trusted local controls and have no HTTP or guest entry point. Inspection returns
at most 100 rows in ID order, including retained generations. It exposes identity,
tenant, endpoint, state, attempt count, retry round and eligibility time. Payloads,
secret values, secret paths and response bodies are omitted.

`revoke` and `revoke-secret` pause future work under the same runtime locks used by
attempt admission. `grant` and `grant-secret` can restore only current approved
choices. Their version changes pause queued captures and never silently resume
them. Revocation cannot retract packets already admitted to the network.

`resume` rechecks a paused capture against the current source action version,
exact declaration/disclosure digest, tenant, destination and secret-slot binding.
It retains the automatic attempt count and retry window. `retry` explicitly
starts a new bounded round for Dead or Paused work. Both preserve the original
body and receiver key, install current authority, and advance the claim fence.
Changed disclosures or destinations require a new originating action; these
commands never rewrite the captured payload. Dead-to-Pending retries must fit the
current app and tenant quotas. Paused work already occupies quota.

`cancel` stops future attempts. A known 2xx observation may still settle that same
current-epoch fence as Delivered: cancellation cannot undo receiver success. An
older epoch or superseded fence cannot finalize a newer round.

`worker-once` uses the same owner, transport, admission and persistence path as the
background worker. It refuses concurrent delivery ownership, so stop the worker first.

## Attempts, recovery and shutdown

Source mutations, jobs, immutable captures and the semantic receipt commit in
one transaction. Receipt replay enqueues nothing new. Delivery runs later in
separate claim, preflight and finalization transactions; no database transaction
contains network I/O or secret-file reads. An uncertain commit is checked through
durable fenced state before any later POST.

Each delivery has one 30-second Root shared by all phases, 16 logical database
calls and at most 256 actual statements. Connect is bounded to ten seconds, and
the transport receives the original work deadline minus a two-second finalization
reserve. The source action keeps its existing fuel and request deadline. Two
physical delivery slots have a separate registry/database lane from jobs and the
clock. Lease expiry, including a forward wall-clock jump, never proves that an
old socket or native file worker stopped.

Pending, Running and Paused rows count against app and tenant quotas, each at
most 1,000; concurrency is one or two. Omitted limits default to 1,000/1,000/two.
Tenant scheduling is fair. A 60-second durable lease fences row updates, while
the exclusive owner and retained physical slots bound actual live work. A lease
that expires before preflight admits a send returns the row to Pending
(`lease_expired`) under its already-charged attempt; after admission, expiry
pauses the row because the send may have left. A claim writes the queue
sequence row only when it takes a row, so idle polls are read-only and do not
conflict with another worker's preflight. If preflight fails before any send,
the claim is returned to Pending with its attempt refunded
(`preflight_unavailable`); lease expiry remains the fallback.

Automatic retries allow five attempts within 24 hours of first eligibility.
The window check uses the fixed durable lifecycle timestamp of the preflight
transaction. Its commit admits the request; the original monotonic Root bounds
the following I/O. This is not a physical wall-clock packet cutoff.
Backoff is one minute, five minutes, thirty minutes and two hours, with bounded
deterministic jitter and numeric Retry-After bounded by the remaining window.
429, 5xx and ambiguous transport failures retry; redirects and other 4xx are
terminal. Validated 2xx is Delivered even if bounded response discard fails.
Responses are discarded within 16 KiB and never become guest data.

Attempts are at least once. A receiver can commit before its reply is lost;
receivers must deduplicate the stable `Idempotency-Key`. Runtime epochs, lease
fences and deliberate retry rounds do not change that key.

Shutdown stops polling, waits for admitted deliveries and drains provider/file
work before releasing ownership. An unconfirmed physical stop retains capacity
and its flock. A service registry is closed after shutdown; starting another
service requires a new App. The clock stops after worker/provider drain.

Clock recovery and restore/fork share `nx_job_runtime` with jobs. Their same
transaction rotates or retires the required epoch, pauses captured effects and
revokes grants. Unchanged-approval restart preserves that pause. Explicit current
grants plus per-capture reconciliation are required before further sends; old
effects are never automatically replayed from a restored database. Remote effects
survive database rollback. A restored copy refuses to activate under another
owner directory until `noxide jobs fork` adopts it, pausing every capture and
revoking grants in the same transaction; see the
[backup and restore procedure](../running-applications.md#back-up-and-restore).
