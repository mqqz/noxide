# Noxide agent guidance

## Mandatory security principles

Preserve these requirements in implementation, reviews, tests, and documentation.
Treat application code as hostile during execution. Local builds are for trusted
application code and dependencies; use isolated builds for untrusted inputs.

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

## Design principles

These principles guide development for both small and large applications. Keep
the implementation auditable by people and tools, and account for high network
latency when designing APIs and page flows.

1. Enforce security by default.

    Handle escaping, CSRF protection, hardened cookies, CSP, request limits,
    redirects, local assets, and URL validation in the framework. Any additional
    authority must be explicit, narrowly scoped, operator-approved, and checked
    by the host. An API name or capability declaration alone grants no authority.

2. Design for anonymity networks.

    Support deployment behind Tor/I2P over loopback or Unix sockets. Expect high
    latency and strict browser settings. Keep logging sensitive to privacy and
    treat accidental clearnet access as a security failure that can deanonymize
    users.

3. Require no client-side scripts.

    Core functionality must work with HTML, CSS, URLs, forms, and server-side
    rendering. Prefer native browser features for interaction: `<details>`,
    popovers, dialogs, `:has()`, `:target`, and container queries.

4. Keep runtime dependencies local.

    Applications should be self-contained by default. External fonts, scripts,
    stylesheets, icons, analytics, avatars, CDNs, APIs, and other resources require
    explicit permission.

5. Grant capabilities explicitly.

    Access to networking, files, processes, raw HTML, and raw SQL must require
    a capability. Application code must not receive that authority by default.

6. Use secure defaults.

    Common operations should require little configuration. Choose secure
    defaults for routing, headers, sessions, forms, error handling, logging,
    assets, and deployment; reserve configuration for intentional deviations.

7. Make the secure API easier to use.

    Typed forms, route generation, authentication, and database access should
    need less code than working with raw HTTP or HTML. Apply the same standard
    to server-side components, validation, layouts, flash messages, pagination,
    and testing, so developers have little reason to bypass framework checks.

8. Encode trust boundaries in types.

    Use types to distinguish values with different security properties wherever
    that improves correctness without making application code harder to write.

9. Small, general capability model with multiple ergonomic ways of using it.

    A developer can build a new kind of application by composing existing
    resources, queries, policies, actions, and rendering primitives—without
    modifying `noxide-host`.

## Backward Compatibility and Breaking Changes

This code is not in use at the moment so breaking changes are fine. The main
concern is having elegant code so avoid wasting time and adding complexity
on ensuring backward's compatibility with previous versions.
