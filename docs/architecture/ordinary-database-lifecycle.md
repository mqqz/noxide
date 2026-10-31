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

If stop or close cannot be acknowledged by the original phase deadline, the slot
is permanently quarantined in that Application instance. Its request/database
permits cannot admit replacement work. Service drain reports uncertainty and still
attempts the separate clock shutdown. This bounds admission when the provider or
kernel cannot prove termination; it does not claim a client timeout forcibly stops
all provider/kernel work. Restart/recovery must not interpret quarantine or a
ROLLBACK response as proof of COMMIT abort.

Trusted operator initialization, schema operations and standalone Database account
administration are outside Application request admission and this registry. Their
typed commit frontier remains authoritative; this checkpoint does not certify
request-permit ownership for operator commands. Ordinary SQL accounting is a
separate pending change: this lifecycle checkpoint does not claim that the existing
logical action-call allowance counts all physical provider statements. Jobs,
outbox execution and Blob runtime admission remain unavailable.
