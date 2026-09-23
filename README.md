# Noxide

Noxide is a server-rendered Rust web framework for NoJS applications, with
anonymity and security policies enforced by default.

> [!WARNING]
> Noxide is experimental and has not had a security audit or production validation.
> Use it at your own risk.

## Workspace

| Crate | Target | Purpose |
| --- | --- | --- |
| `noxide` | Library | Framework API and packaged WIT world |
| `noxide-macros` | Procedural macro library | Framework macros |
| `noxide-cli` | `noxide` binary | Command-line tools |
| `noxide-protocol` | Library | Constrained document and application contracts |
| `noxide-host` | Trusted library | Wasmtime, HTTP, authentication, policy, SQLite/PostgreSQL |

The private-notes example uses host-owned forms, sessions and authorization. Each
request runs in a fresh guest instance, with transactional replay protection on
SQLite and PostgreSQL. Applications return a constrained Document IR for the host
to render.

Raw HTML, arbitrary URLs/headers, WASI, and generic SQL/network access are
unavailable. The SDK uses typed Rust values; template macros remain future work.

Follow [Running an application](docs/running-applications.md) to build the example
inside a disposable VM, approve its declarative permissions, provision accounts,
and run it. Application build scripts and macros must execute inside that VM.

Build and check the trusted framework from the repository root with Rust 1.98.0:

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -p noxide-cli --bin noxide --locked
```

Shared package metadata and local dependencies are defined in the root `Cargo.toml`.
Workspace crates share the root `Cargo.lock` and `target/` directory. The isolated
application example has its own lockfile and is excluded from host workspace builds.

## Design principles

These principles guide development for both small and large applications. Keep
the implementation auditable by people and tools, and account for high network
latency when designing APIs and page flows.

1. Enforce security by default.

    Handle escaping, CSRF protection, hardened cookies, CSP, request limits,
    redirects, local assets, and URL validation in the framework. Any exception
    that weakens a security invariant must be explicit, through an API such as
    `unsafe_*` or `dangerous::*`, or a capability declaration.

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

## Runtime design

The [HTTP/application runtime design](docs/architecture/runtime.md) records the
Wasmtime boundary, host-rendered document protocol, explicit authorization,
transactional actions, and isolated builds.

## License

This project's code is licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
