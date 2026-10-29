# Noxide agent guidance

## Mandatory security principles

Preserve these requirements in implementation, reviews, tests, and documentation.
Treat application code and dependencies as hostile during builds and execution.

1. Application compromise must not trivially become host compromise. Guests have
   no filesystem, network, process, or host-secret access without explicit,
   narrowly scoped, operator-approved capabilities enforced by the host. Build
   untrusted application code only inside the disposable build VM.
2. Applications cannot bypass authentication or authorization. Security-sensitive
   operations must pass host-enforced checks; guest logic can only reduce authority.
3. Browser output is safe by default. The host owns escaping, headers, CSRF, and
   validated Document IR rendering. Do not add guest raw-response escape hatches.
4. Every request has enforced memory, CPU/fuel, execution-time, input-size, and
   output-size limits. Include host calls, database work, retries, rendering, and
   cleanup; bound concurrency and queues. Fuel alone cannot bound blocked host work.
5. Preserve anonymity by default: no external requests, third-party resources,
   sensitive logs, or unexpected network access. Explicit deployment infrastructure
   does not grant guest network authority.

A capability declaration or an `unsafe`/`dangerous` API name does not bypass these
requirements. Check new authority against deployment policy and request scope.
See [README](README.md#security-principles) and the
[runtime security contract](docs/architecture/runtime.md#security-contract).
Document implementation gaps honestly; do not present design requirements as
proof of audited security or transport anonymity.
