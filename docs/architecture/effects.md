# Approved external effects

P11 acceptance is unfinished. The isolated integration branch connects effect
admission, the common action executor, outbox workers and the reviewed Tor
transport. Delivery requires explicit operator endpoint and secret-slot grants.
The accepted branch remains at P10 until the native and independent review gates
pass. No deployment or live external delivery is authorized by this work.

## Frozen integration contract

`Manifest.effects` contains `EffectContract { endpoints, emissions }`.
`EffectEndpoint { name, secret_slot }` names a destination and optional host-only
secret slot. `EmitEffect { source_action, ordinal, endpoint, fields }` fixes each
payload mapping; every `PayloadField { schema: Input, value: Value }` declares an
independent JSON key/type/bound and its approved source. Endpoint and field vector
order is canonicalized by name; the effect ordinal remains semantic. At most two
emissions per action, 32 endpoints, 32 fields per emission and 64 KiB encoded body
are allowed, subject to the unchanged manifest and action budgets. Duplicate
names/ordinals, unknown fields and blob/upload-handle payloads fail closed.

The existing checked scalar evaluator supplies strings, booleans and integer
JSON values, including millisecond timestamps/durations and explicitly disclosed
account/record identities. Missing optional scalars become null. Snapshot field
access requires the existing compute projection. Current-row reads are excluded
at the post-step capture site. All expression nodes share the source action's
64-node/depth-eight allowance, including mutations and job scheduling. Host-only
identity values remain typed until this approved disclosure boundary.

The common successful action path evaluates and inserts outbox captures in the
same transaction as resource mutations, jobs and the full semantic receipt.
Receipt replay performs no new enqueue. Immutable origin scope/invocation and
ordinal determine the receiver key; fences, retry rounds and runtime epoch do
not change that key. Bodies and schema/destination digests are captured once.
No network operation runs in an action or other database transaction.

Operator configuration binds each approved tenant/endpoint to exact canonical
HTTPS host, port and path, POST JSON, Tor SOCKS proxy and secret-slot identity.
Approval covers these choices and field disclosures; values of secrets remain
outside manifests, approval output, projections and logs. Secrets are resolved
at send time from bounded private host files. There is no production mock/direct
transport or guest URL. The existing transport performs remote SOCKS RESOLVE,
checks the globally routable numeric address, then numeric CONNECT with the
approved hostname retained for TLS/SNI/Host. There is no system DNS or fallback.

Outbox bookkeeping shares the existing `nx_job_runtime` generation/contract/epoch
and restore/clock-pause authority; the historical table name is retained. Effects
have separate durable grants, quotas, fairness, claim fences and at most two
physical delivery slots. Expired wall-clock leases cannot establish that a live
socket stopped. Reuse the existing host process-fence primitive if required to
retain slots through actual cancellation; do not add another workflow executor
or replay subsystem. The proposed 60-second outbox lease covers a 30-second
attempt; job leases remain 30 seconds. Connect is bounded to ten seconds.
A separate delivery request root has a single 30-second total deadline across
claim, authorization, secrets, transport and finalization, with two seconds
reserved for finalization/cleanup. It retains the existing 16 logical calls and
256 actual-statement ceiling; it never extends the source action deadline.

Up to five automatic attempts fit within 24 hours of first eligibility, using
bounded backoff/Retry-After. Validated 2xx means delivered even if response discard
fails; 429/5xx and ambiguous transport failures retry, other 4xx and redirects are
terminal. Responses are discarded within 16 KiB and never become guest data.
Revocation pauses future attempts and cannot retract an admitted request.
Delivery attempts are at least once; receivers must deduplicate the stable key.

Operator inspect/cancel/revoke/grant/explicit retry/reconciliation controls expose
metadata only. Restore/fork rotates the shared runtime epoch and pauses jobs and
effects until explicit reconciliation. Deliberate retries preserve the original
receiver key and payload. Pending/Running/Paused rows count against at most 1,000
per app and tenant, with downward operator limits. Contract/destination/secret
grant changes pause captured work instead of silently rebinding it.

Native layout audits, forged-contract and disclosure tests, provider atomicity,
claim/fence/revocation/timeout/restore tests, real local proxy/TLS fixtures,
physical shutdown barriers and exact integrated checks remain mandatory. No
live Tor delivery, deployment, security audit or whole-program acceptance is
claimed by this contract.
