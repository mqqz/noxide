# Ordinary database lifecycle

Ordinary Application requests carry one private host-created scope before admission
waits or session classification. The scope fixes an outer monotonic deadline and
an ordinary phase deadline (the existing two-second request or three-second
password phase, clamped to the connection's original sixty-second deadline).
Classification, endpoint work, retries and post-commit navigation share that root.
A nested ordinary API may narrow its deadline; it cannot restart it. Buffered form
reading uses the same work deadline instead of its previous fresh thirty seconds.
Future explicitly approved transfer phases may use the immutable outer bound;
this does not enable uploads or grant authority.

Fifty milliseconds of the existing phase is reserved for cleanup. Connection,
setup, BEGIN, provider statements, COMMIT and advisory unlock use the remaining
work deadline. This reserve does not increase the phase total. Request, database
and anonymous-write permits move into an owned provider lease before connecting.
A canceled frontend drops its transaction into one cleanup task, retaining those
permits and its per-request provider gate until stop acknowledgement. Connecting
itself runs in that owned task boundary, so dropping its receiver cannot release
capacity while a hidden connection or BEGIN is still running.

There is at most one work connection and one private PostgreSQL control connection
per admitted database slot. With the existing eight slots this bounds ordinary
connections to eight work and eight control connections; the clock retains its
separately reserved capacity. There is at most one ordinary cleanup task per
admitted provider gate, with no additional executor or unbounded queue. Existing
request, hash, database, guest and queue limits remain in force.

PostgreSQL cleanup reuses the clock's host-captured PID, random application name,
backend start time and same database/user checks. The original work socket remains
owned. Control cancellation targets only that identity; a later ROLLBACK is physical
cleanup and never establishes that a sent COMMIT aborted. Work close is followed
by observed backend disappearance, then control close acknowledgement. The latter
proves the control connection closed; it does not substitute for the work-backend
observation. The trusted provider/operator and catalog identity assumptions remain
those documented for the clock. No guest supplies a cancellation target.

SQLite requests use host-owned opaque connection options. Bootstrap may establish
WAL; ordinary connections verify WAL and FULL durability without changing journal
mode. Foreign keys and trusted_schema=OFF remain enforced. Busy handling is clamped
to remaining work time. SQLx close acknowledgement is awaited with optimization on
close disabled. Tests observe actual busy-worker identities, rather than treating
cached file descriptors as evidence of executing work.

Acknowledged COMMIT returns its prepared result without awaiting further cleanup.
Unlock and close remain owned work; navigation waits for that provider gate.
An unacknowledged sent COMMIT remains Unknown even if later cleanup succeeds.
Non-action mutation wrappers retain the same distinction. Capacity uncertainty
is separate from semantic commit uncertainty.

Receipt replay carries evidence of the original validated commitment outside its
cancellable delivery future. A failed fresh read or its aborted COMMIT cannot undo
that earlier fact. The fallback contains no edit secret; fresh credential and
navigation checks continue to govern handover and read access. Changed canonical
input cannot acquire original receipt authority. Its existing already-used form
response remains non-secret. Rotation replay likewise preserves known commitment
while refusing to expose credentials when current target checks fail.

If stop or close cannot be acknowledged by the original phase deadline, the slot
is permanently quarantined in that Application instance. Its request/database
permits cannot admit replacement work. Service drain reports uncertainty and still
attempts the separate clock shutdown. This bounds admission when the provider or
kernel cannot prove termination; it does not claim a client timeout forcibly stops
all provider/kernel work. Restart/recovery must not interpret quarantine or a
ROLLBACK response as proof of COMMIT abort.

Trusted operator initialization, schema operations and standalone Database account
administration are outside Application request admission and this registry. Their
typed commit frontier remains authoritative; this registry does not certify
request-permit ownership for operator commands.

## Actual statement accounting

One root owns the ordinary request's supplemental maximum of256 charged provider
statements. Application::with_database_statement_limit(u16) may lower it to1..=256
before active/quarantined work; every created request keeps its own immutable
allowance. Existing logical16 action calls,4096 list calls, rows, bytes, candidates,
queues and phase deadlines remain enforced. Classification, endpoint work, retries,
postcommit navigation, setup and cleanup share this root without a new allowance.

Every issued host statement is charged before issue, including PostgreSQL timeout
SETs, connection identity, durability/advisory setup, COMMIT, ROLLBACK, unlock and
bounded stop polling. SQLx0.8.6 is pinned: ordinary SQLite's fixed startup batch is
precharged3 units before connect; bootstrap's4 statements belong to the separate
operator path. PostgreSQL startup GUCs use startup protocol parameters, not SQL.
The isolated observer records only synthetic statement metadata and fingerprints,
never parameters, application JSON, credentials, URLs or a production subscriber.
Precharging is conservative when transmission/startup fails; actual issued work
cannot exceed charged units. This is an upper bound, not a promise that every
charged unit reached the provider after cancellation.

Each admitted PostgreSQL work connection reserves40 units from the SAME total.
Identity capture uses1 protected unit so exhausted application work cannot prevent
cancellation setup. Worst-case identity/unlock/cancel/rollback and16 stop polls use
at most38. Ordinary application work cannot spend protected units. Confirmed stop
releases only unused reserve; consumed work is never refunded. Unconfirmed cleanup
retains both its allowance and physical capacity. SQLite closes without SQL because
optimization on close is disabled. A refused COMMIT unit remains NotAttempted;
a sent unacknowledged COMMIT stays Unknown. Original receipt/acknowledged-success
evidence takes precedence over later quota or delivery failure. Database-unavailable
authentication is Busy; invalid credentials retain Authentication denial.

Bootstrap/exclusive operator connections are denied inside an ordinary request,
including an admitted owner calling initialize. CPU loops use required
RequestScope::checkpoint_current: missing, cancelled or expired scope fails closed,
with no fallback owner/timer. Normal nested success or error completion does not
cancel the root; dropping an owning future does. Offline rebuild obtains an explicit
OperatorCheckpoint only from a bounded active nonordinary/nonmaintenance transaction.
The token carries that transaction's original deadline/cancellation lifetime, rejects
request-context reuse and ends on commit/rollback attempt or drop. It cannot turn
clock maintenance into operator authority.

Provider tests measure the default 8 work + 8 control plateau in one
Application using real host authentication/classification, with a ninth queued
request opening no provider. This local result does not certify arbitrary provider,
crash, multiple-process or job cancellation behavior.
