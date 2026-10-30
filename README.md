```
    ▄▄▄▄▄▄▄          ▄█▀▀██▒▓▄▄      ▄     ▄▄       ▄█▄▓▄  ▄▄▀▀▀██▒▓▄▄      ▄▄▀▀▀████░░▒▓▄ 
  ▄█▀▀▀█░░▒▓▓▄     ▄▀  ▄   ▀░▒▓▓▄   █▓▓   ░▒▒▓▓▄    ▐▒▀▄▌ ▀▄ ▄    ▀░▒▓▓▄   ▀  ▄     ▀███▒▓▌
 ▀▄  ▄   ▀ ░▒▓▓▄    ▄▒▓      █▒▓▓▄  ▒░▓   ▀ ░▒▓▓▌    ▀██    ▐▒▓     █▒▓▓▄    ▐▒▓      ▀██▒▓
    ▐▒▓    ▀█░▒▓▌  ▐░░▌      ▐░░▒▓  ▐░░▌   ▐█░▒▓     ▐▒▓    ▐░░     ▐░░▒▓    ▐░░        ░  
    ▐░░      ▀█░░  ▐░░        ██░▒▌  ▀▀█▄  █░▒▀      ▐░░    ▐░░      ██░▒▌   ▐░░  ▄    ▀   
    ▐░░       ▐█░▌  ▒▌        ███░▌      ▄███▄▄▄     ▐░░     ▒▌      ███░▌    ▒▌ ▐▒▌       
     ▒▌         █   ▐▓▌      ▐██░█▌   ▄▓   ▀██░▒▓▄    ▒▌     ▓▌     ▐██░█▌    ▓▌  ▀    ▀▄  
     ▓▌        ▐▌    ▐█      ██░██   ▄░▀     ██░▒▓▌   ▓▌     █      ██░██     █         ▒▓▄
     █         █    ▄ ▀▀▄  ▄████    ▐▒▌      ▐█░▒▓▌   █      ▐    ▄████       ▐       ▄█░▒▓
     ▐        ▄▀     ▀█▄▄▄████▀▀     ▀▓▄     █░▒▓░    ▐    ▀▄▄ ▄▄████▀▀     ▀▄▄   ▄▄▄█░█░░▀
             ▀         ▀▀▀▀▀                  ▀▀▀             ▀▀▀▀▀            ▀▀▀▀▀▀▀▀▀   
```
---

_**Noxide**_ is a server-rendered Rust web framework for NoJS applications, with
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

Create and run a starter with the installed CLI:

```sh
noxide new my-notes
cd my-notes
noxide dev
noxide test
noxide build
noxide serve
```

The CLI includes its SDK and approved offline dependency catalog. Development
watches sources and keeps private local state; serving uses a separately approved
contract. Local builds execute native dependency and macro code with your user
permissions. Select `--isolated` explicitly for untrusted inputs after configuring
a trusted VM kernel and Rust toolchain with
`noxide setup --kernel KERNEL --toolchain TOOLCHAIN_DIRECTORY`.

`new` writes the starter without running application code.
Start with an inline `#[noxide::app]` module: declare resources, receive typed
`List<Resource>`/`Read<Resource>` capabilities in pages, and name mutations in a
`crud!` block. Noxide generates the existing typed declarations and reviewable
contract. Ownership is explicit, and public reads retain explicit visibility and
field projections. See the [application API](docs/application-api.md).

The private-notes example supports creation, editing and deletion through
host-owned forms. Each request runs in a fresh guest instance, with authorization
and transactional replay protection on SQLite and PostgreSQL. Stale edits preserve
the user's input for review before resubmission. Applications return a constrained
Document IR for the host to render.

Raw HTML, arbitrary URLs/headers, WASI, and generic SQL/network access are
unavailable. The SDK provides typed declarations, route handles, form layouts, and template macros that emit Document IR.

Follow [Running an application](docs/running-applications.md) to build the example
locally, approve its declarative permissions, provision accounts, and run it.
Local builds trust app code and dependencies with host access. Use `--isolated`
for untrusted code to build inside a disposable VM.

Build and check the trusted framework from the repository root with Rust 1.98.0:

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -p noxide-cli --bin noxide --locked
```

Shared package metadata and local dependencies are defined in the root `Cargo.toml`.
Workspace crates share the root `Cargo.lock` and `target/` directory. The standalone
application example has its own lockfile and is excluded from host workspace builds.

[Continuous integration](docs/ci.md) covers both databases, packaged SDK builds,
NoJS browser acceptance, and scheduled hostile-build checks.

## Security principles

These five requirements govern Noxide's APIs, runtime, and defaults. They are
review criteria for every change, not a claim of audited security. The
[runtime security contract](docs/architecture/runtime.md#security-contract)
explains the enforcement boundaries and limitations.

1. **Contain application compromise.** Guest code cannot access the filesystem,
   network, processes, or host secrets without an explicit, narrowly scoped
   capability approved and enforced by the host. Application compromise must not
   trivially become host compromise.
2. **Keep authentication and authorization authoritative in the host.**
   Applications cannot bypass either; security-sensitive operations pass through
   host-enforced checks. Guest logic can restrict authority, never expand it.
3. **Make browser output safe by default.** Noxide owns escaping, security
   headers, CSRF protection, and validated document rendering. Applications
   describe intent through Document IR rather than constructing raw responses.
4. **Bound every request's resource consumption.** Enforce memory, CPU/fuel,
   execution-time, input-size, and output-size limits, including host operations
   and retries. Bound concurrency and queues as well as individual requests.
5. **Preserve anonymity by default.** No external requests, third-party
   resources, sensitive logs, or unexpected network access. Any additional
   network authority requires explicit approval and host-enforced scope.

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

## Runtime design

The [HTTP/application runtime design](docs/architecture/runtime.md) records the
Wasmtime boundary, host-rendered document protocol, explicit authorization,
transactional actions, and isolated builds.

## Application API

The [application API guide](docs/application-api.md) covers typed declarations,
templates, forms, isolated builds, and schema migrations.

## License

This project's code is licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

