# Transaction COMMIT frontier

An ordinary transaction records whether COMMIT has not been attempted, was
authoritatively refused, may have been sent, or was acknowledged. The sent marker
is set before polling the provider future. Timeout, canceled acknowledgement and
IO errors therefore cannot be retried as known aborts. Physical ROLLBACK cleanup
does not erase this marker: ROLLBACK can succeed after COMMIT already committed.

Only narrowly acknowledged provider refusals retain retry eligibility: PostgreSQL
serialization/deadlock errors and SQLite BUSY/BUSY_SNAPSHOT. A generic elapsed
timeout is never such a refusal. The frontier also survives successful cleanup.

A COMMIT acknowledgement remains authoritative if subsequent advisory unlock,
close or other cleanup fails. The web adapter returns its already prepared
committed-success fallback; fresh navigation cannot turn that write into a
rejection. The web action adapter returns OutcomeUnknown for a sent but unacknowledged commit and uses the
same invocation's semantic receipt for authoritative recovery before reexecution.
The test-only lost-ack hook precedes publication of the acknowledgement marker;
production has no selectable fault mode.

This state model covers outcome classification only. Ordinary provider cleanup
ownership, capacity retention/quarantine, fresh 500ms cleanup windows and actual
SQL statement metering are covered by the
[ordinary database lifecycle](ordinary-database-lifecycle.md). It does not claim
that a timeout, dropped socket or 30s job lease proves provider termination.
No jobs capability is enabled by this state model.

Non-action registration, session and capability mutation callers do not yet use
the shared lifecycle wiring and honest result mapping; this document does not
claim those public mappings are fixed. Public Database/CLI
callers retain the typed committed-versus-unknown error.
