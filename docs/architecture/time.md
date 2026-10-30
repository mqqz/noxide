# Lifecycle time

Status: P06 leaf implementation, awaiting root/schema/startup/maintenance integration
and independent review. No resource expiry capability is enabled by this slice.

`noxide-protocol/src/time.rs` defines distinct `Timestamp` and `Duration` types.
Both store nonnegative signed 64-bit whole milliseconds. A timestamp is UTC since
the Unix epoch; a duration carries no epoch. Named constructors check seconds to
milliseconds multiplication and arithmetic overflow. Duration conversion rejects
sub-millisecond precision; trusted host wall sampling floors its sub-millisecond
fraction. Feature admission must impose its own duration horizon. Existing
credential timestamps, signatures, TTLs and rollback tolerance retain seconds.
Execution deadlines and heartbeat freshness use monotonic `Instant`, never UTC.

The lifecycle clock extends the existing `nx_clock` row with `lifecycle_ms` and
`lifecycle_version`. The database admits one active deployment through the
`nx_deployment` singleton and generation fence; the watermark belongs to that
deployment's database. Activating a replacement deployment retains this history.
It must not select an older watermark. Independent active deployments need
independent databases under the existing deployment contract.

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
of application request and worker permits. The tick transaction and permit wait
share a short monotonic deadline; missed intervals skip backlog. Unavailable
capacity, failed startup, stale progress or inconsistent durable state make
temporal operations unavailable. They do not become guest policy rejections.

The process-local `Freshness` guard expires five monotonic seconds after observed
progress. Repeated reads of the same version update neither the progress time
nor its lease. Optional heartbeat observations use a separate bounded read-only
transaction, timed before BEGIN; an old request snapshot cannot renew freshness.
A response taking five seconds cannot establish freshness. After a stale period,
the first unseen version is only a baseline because it might already be old;
a subsequent greater version within five seconds proves progress. A newly
confirmed own tick also restores freshness. Observations cannot bypass the
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

The leaf tests use the real database transaction/security code with test-only
schema columns and fake wall samples. They cover units and arithmetic, durable
watermarks, backward clocks, restarts, fixed attempt values, read-only requests,
version exhaustion, real credential recovery and freshness transitions. Temporary
verification module declarations do not prove production integration. Production
schema migration, startup fail-closed behavior, reserved maintenance under load,
multi-process/provider contention, cancellation and exact integrated-SHA tests
remain integration gates. P07 must enforce resource expiry on every ordinary
read/list/follow/search/aggregate/inspection/download/mutation path. Expiry does
not release inventory or delete records, and receipt replay does not rerun
original temporal guards. Current delivery authorization still applies.
