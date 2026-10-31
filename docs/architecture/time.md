# Lifecycle time

Status: P06 clock integration implemented, awaiting independent review and final
acceptance evidence. Resource expiry declarations/enforcement remain P07 work.

`noxide-protocol/src/time.rs` defines distinct `Timestamp` and `Duration` types.
Both store nonnegative signed 64-bit whole milliseconds. A timestamp is UTC since
the Unix epoch; a duration carries no epoch. Named constructors check seconds to
milliseconds multiplication and arithmetic overflow. Duration conversion rejects
sub-millisecond precision; trusted host wall sampling floors its sub-millisecond
fraction. Feature admission must impose its own duration horizon. Existing
credential timestamps, signatures, TTLs and rollback tolerance retain seconds.
Execution deadlines and heartbeat freshness use monotonic `Instant`, never UTC.

Storage version 11 extends the existing `nx_clock` row with `lifecycle_ms` and
`lifecycle_version`. The database admits one active deployment through the
`nx_deployment` singleton and generation fence; the watermark belongs to that
deployment's database. Activating a replacement deployment retains this history.
It must not select an older watermark. Independent active deployments need
independent databases under the existing deployment contract.

A version 10 database is rejected with an explicit migration requirement. No
automatic conversion or reset is implemented. Use a new empty disposable or
development database for version 11; preserve operator data and arrange a reviewed
migration before upgrading an existing deployment. Rejection leaves its old
clock and records unchanged.

A bounded maintenance transaction, fenced against the current generation,
reuses `security::observe_clock_read` and `security::observe_clock`. Checked named
conversion keeps their seconds separate from lifecycle milliseconds. The returned
credential maximum can include process-local credential read history; it never
advances lifecycle time. Maintenance alone advances lifecycle to
`max(previous durable lifecycle_ms, sampled trusted host wall milliseconds)` and
increments the durable version, even when time is unchanged. Compare-and-swap
checks both old fields; serialization conflicts require a new bounded maintenance
attempt. `tick` returns evidence only after a confirmed commit. An unknown outcome
provides no freshness evidence; another successful tick can establish progress.

Before serving temporal operations each process must complete a durable startup
tick. It then ticks about once per second using reserved capacity, independent
of application request and worker permits. Activation shares one two-second
monotonic deadline across validation, schema/deployment binding, tick and commit.
The one existing server maintenance service then uses a 200ms nonresetting
deadline for admission, connection, fencing, tick, commit and awaited cleanup.
A dedicated one-slot maintenance semaphore has no queue. Each tick has a private
work connection outside request/session/Wasm lanes; PostgreSQL additionally has
one private control connection under that same slot. There is no shared pool to
exhaust. The last 50ms of the original 200ms budget is reserved for cleanup. The
provider execution deadline uses the preceding 150ms; this does not enlarge the
maintenance budget. SQLite maintenance connections use a zero busy
wait; a failed BEGIN waits for the SQLx worker close acknowledgement before
returning. Ordinary request connections retain their existing busy timeout.
PostgreSQL takes the clock row with `FOR UPDATE NOWAIT`, uses a 1ms lock timeout
for other locks, and updates statement timeouts from the remaining work budget.
Maintenance timeouts use session settings on the private connection so they
survive COMMIT. Post-COMMIT advisory unlock refreshes that setting from, and is
bounded by, the same original work deadline; it receives no fresh timeout.
Ordinary request settings and their 500ms gate-cleanup default remain unchanged.
This reserves host admission and
connection capacity; external database locks or server-wide connection exhaustion can still
prevent progress, bounded by the deadline. Missed intervals skip backlog. Unavailable
capacity, failed startup, stale progress or inconsistent durable state make
temporal operations unavailable. They do not become guest policy rejections.

The process-local `Freshness` guard expires five monotonic seconds after observed
progress. Repeated reads of the same version update neither the progress time
nor its lease. Production processes publish only their own confirmed maintenance
ticks. The tested optional independent heartbeat observer is not enabled in the
production service. Its separate read-only transaction is timed before BEGIN;
an old request snapshot cannot renew freshness.
A response taking five seconds cannot establish freshness. After a stale period,
the first unseen version is only a baseline because it might already be old;
a subsequent greater version proves a commit after the previous snapshot. Its
freshness deadline is anchored to that previous read's start, not the current
read's start or delivery time. The conservative bound must still be within five
seconds when consumed; otherwise the read establishes only the next baseline.
A newly confirmed own tick also restores freshness. Observations cannot bypass the
required own startup tick. Out-of-order observations fail closed.

After the normal host deployment fence, every temporal transaction captures one
`AttemptTime` from the durable row and retains it throughout that attempt. Reads
never sample wall time or update durable state or freshness. A newer attempt gets
a new snapshot. A transaction snapshot older than already observed process
progress is unavailable and can be retried under its existing deadline. This
conservative rule prevents a GET from observing unpersisted expiry and later
reviving the row after restart. Forward wall jumps can expire resources early;
operator wall accuracy is assumed, not externally certified.

Clock recovery and key rotation must preserve both lifecycle columns. Recovery
may reset the credential seconds observation under the existing fresh-key rule;
it cannot reset lifecycle time, reuse a prior process's freshness lease, resume
jobs, or undo previously observed expiry. The future jobs/effects package must
pause durable queues at recovery and require explicit operator resumption; P06
does not add placeholder queue tables or enable workers.

The clock tests initialize the production schema and use real provider
transactions/security code, with fake wall/monotonic points only in tests. They
cover units and arithmetic, durable watermarks, backward clocks, restarts, fixed
attempt values, read-only requests, version exhaustion, credential recovery,
freshness, startup unknown commits, saturated request lanes, maintenance capacity
loss, cancellation and service drain. The service remains active through HTTP
request drain, then receives a stop signal and joins. An in-flight tick retains
its permit and single-service owner through provider cleanup. Dropping/canceling
serve signals stop and detaches this already bounded owner; it does not abort its
provider work. A canceled startup transfers its owned permit to one bounded
cleanup task under the original deadline.
Only one service may own an application at a time. Retired generations cannot
tick or obtain temporal attempt time.

PostgreSQL cleanup cancels only its host-created work connection, drains/rolls
back that connection and observes its backend identity disappear before releasing
capacity. The driver exposes no public secret-bearing cancel token. The host
captures the PID and backend start time plus a fresh unguessable application name,
keeps the work socket owned through cancel, and checks tag/start/database/user
in qualified catalog queries. This is a narrowly scoped check, not an atomic
PID/secret cancellation primitive. A provider crash or operator kill/PID recycle
between the identity check and cancellation is a residual trusted-provider
assumption; guests have no path to supply identities or manage DB sessions.

Unacknowledged cleanup permanently quarantines the slot and temporal readiness;
late commits, old leases and peer observations cannot clear that state. Cleanup
has no retry queue or deadline reset. HTTP shutdown reports an error if it cannot
confirm drain in its bounded wait; it does not silently release an unknown owner.
A fresh host process/application is required to recover quarantined capacity;
its startup still retains the durable lifecycle watermark and requires its own
confirmed tick. This is fail-closed handling of uncertainty, not proof that an
unresponsive provider has physically stopped. Provider cleanup and PID-scope
assumptions remain explicit independent-review requirements.

The internal temporal-attempt accessor is ready for later consumers; no current
resource path declares expiry. Independent review and exact final integrated-SHA
provider/load/recovery evidence remain acceptance requirements. P07 must enforce
resource expiry on every ordinary
read/list/follow/search/aggregate/inspection/download/mutation path. Expiry does
not release inventory or delete records, and receipt replay does not rerun
original temporal guards. Current delivery authorization still applies.
