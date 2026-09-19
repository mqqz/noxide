# Noxide

> A batteries-included, server-rendered Rust web framework for large NoJS applications,
> with anonymity and security properties enforced by default.

> [!WARNING]
> this project is not security audited or battle-tested yet.
> It's very much still in its infancy. So use at your own risk.

## Workspace

| Crate | Target | Purpose |
| --- | --- | --- |
| `noxide` | Library | Framework API |
| `noxide-macros` | Procedural macro library | Framework macros |
| `noxide-cli` | `noxide` binary | Command-line tools |

The crates currently contain scaffolding. Framework APIs, macros, and CLI commands
are not implemented yet.

Run these commands from the repository root with a Rust toolchain that supports
edition 2024:

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -p noxide-cli --bin noxide --locked
```

Shared package metadata and local dependencies are defined in the root `Cargo.toml`.
All crates share the root `Cargo.lock` and `target/` directory.


---
## Design Principles

_Secure by construction. Anonymous-network native. Zero JavaScript. Self-contained. Typed at trust boundaries.
Server-rendered. Fast under high latency. Ergonomic enough that developers do not bypass safety. 
Scalable from a single page to a large application. Auditable by both humans and tooling._

In more detail:

1. Secure by construction, not by configuration.

    The safe path should also be the easiest path. Escaping, CSRF protection, hardened cookies,
    CSP, request limits, safe redirects, local assets, and strict URL handling should happen automatically.
    Anything that weakens a security invariant should require an explicit, visually obvious escape hatch
    such as `unsafe_*`, `dangerous::*`, or a capability declaration.

2. Designed for anonymity networks first.

    Tor/I2P should not be an afterthought. Assumptions should include high latency, users with strict browser settings,
    no external resources, privacy-sensitive logging, possible clearnet deanonymization risks, and deployment behind
    Tor/I2P over loopback or Unix sockets. The framework should treat accidental clearnet access as a serious security failure.

3. Zero client-side scripting.

    The framework should assume JavaScript is unavailable. Core functionality must work using HTML, CSS, URLs, forms,
    and server-side rendering only. Interactive UI should prefer native browser primitives such as `<details>`, popovers, 
    dialogs, forms, `:has()` `:target`, container queries, and other declarative features.


4. No hidden external dependencies at runtime.

    Fonts, scripts, stylesheets, icons, analytics, avatars, CDNs, APIs, and other external resources should not appear
    unless explicitly permitted. A default application should be completely self-contained.

5. Capability-oriented access to dangerous resources.

    Networking, filesystem access, process execution, raw HTML, raw SQL, and similar powerful operations should not
    be ambient capabilities.

6. Convention over configuration.

    Common operations should require almost no configuration: The framework should choose secure defaults for routing,
    headers, sessions, forms, error handling, logging, assets, and deployment. Configuration should mostly exist for
    intentional deviations.

7. Ergonomics are part of security.

    If the secure API is unpleasant, developers will bypass it. Typed forms, route generation, authentication,
    database access, server-side components, validation, layouts, flash messages, pagination, and testing should all
    be easy enough that there is little incentive to drop down to raw HTTP or HTML.

    "The secure way should require less code than the insecure way."

8. Strong types at trust boundaries.

    Avoid passing undifferentiated strings around.
    The type system should encode meaningful security properties whenever doing so improves correctness without
    making ordinary code painful.

## License

This project's code is licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

