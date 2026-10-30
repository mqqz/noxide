# Continuous integration

[CI](../.github/workflows/ci.yml) runs on pull requests, pushes to `main`, merge
queues, manual dispatch, and every Monday at 03:23 UTC. For branch protection,
require `PR checks`. Publishing and deployment are outside this workflow.

Pull requests run formatting, a locked workspace build, Clippy across all targets
with warnings denied (`-D warnings`), Python build-input and local-runner tests,
and ShellCheck. Database tests and VM application builds run in the other jobs.
`Runtime` and `Packaged SDK and browser` run on pushes to `main`, merge queues,
manual dispatch, and the weekly schedule. Both jobs are skipped on pull requests;
database and browser integration failures can therefore be discovered after
merging when a merge queue is not used.

## Checks

`PR checks` runs on every workflow event using Rust 1.98.0 on Ubuntu 24.04.
It checks workspace and example formatting, fetches locked dependencies, builds
the workspace offline, and runs Clippy across all targets with warnings denied.
It also runs Python build-input and local-runner tests and ShellCheck.

`Runtime` uses Rust 1.98.0 on Ubuntu 24.04. It checks workspace and example
formatting, Clippy with warnings denied, documentation with warnings denied,
ShellCheck, Python build-input and local-runner tests, and the Rust tests against SQLite and
a disposable PostgreSQL 18.4 service configured for 512 connections to support
the concurrent GET regressions. Ignored PostgreSQL tests are included
explicitly; the internal crash subprocess and separately run browser fixture are
excluded.

`Packaged SDK and browser` packages the SDK crates, then compiles the
private-notes example against their versioned archive directories locally on the runner. This exercises the distributed WIT contract without relying on sibling
monorepo paths. The typed SDK suite also compiles the notes, task-board, and
public-articles convenience examples and their explicit equivalents. It compares
complete contracts and uses the trusted CLI to require matching approval hashes.
It also builds a CLI-generated starter, tests multiple resources with tenant/role
and anonymous/capability CRUD policies, and requires declaration reordering to
preserve approval hashes. Policy changes require new approval hashes, and schema
additions that omit create fields fail admission.
The trusted CLI admits the resulting component. A separately built public
application is exercised through real HTTP for row visibility, projected fields,
public cookie behavior, missing records, and escaped text. The forum is built and
checked through HTTP for registration, account and anonymous replies, parent-scoped
pagination, editing, moderation, and stale forms after locking. Firefox then
exercises creation, two-tab edit conflicts, explicit resubmission, deletion, and
receipt recovery with JavaScript disabled. It uses SQLite on localhost and
PostgreSQL through the test onion-origin proxy. This proxy does not establish Tor
transport behavior.

`Hostile application builds` runs weekly and on manual dispatch. It checks
build-script and procedural-macro containment in two fresh VMs, including host
file/socket/network access, writes outside scratch, cross-build persistence, and
termination of an infinite native build-script loop. Use manual dispatch before
merging changes to the VM boundary. This scheduled check is not a required PR
check because it is skipped on pull requests.

## Execution boundary

Jobs use disposable GitHub-hosted runners with read-only repository tokens and
discard checkout credentials before running checks. All action references use
full commit pins. Forks use the `pull_request` event; the workflow has no
`pull_request_target` trigger, deployment secrets, or shared application build
caches.

The framework and trusted repository examples/SDK fixtures compile directly on
the disposable runner, including native build scripts, macros, and metadata
collectors. Routine application checks pass `--local` and do not install QEMU or
a kernel. Hostile fixtures remain exclusively in the weekly/manual VM job.
Examples remain outside the root Cargo workspace. Framework dependencies are
fetched from the lockfile before subsequent offline checks.

VM jobs install QEMU and a guest kernel from Ubuntu's package repositories; they
use TCG and do not require KVM or nested virtualization. The selected kernel hash
and tool versions are printed in the job log. Firefox and geckodriver come from
the [Ubuntu 24.04 runner image](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
and can change as GitHub updates that image. Rust and PostgreSQL versions are
explicit in the workflow.

Build logs, VM metrics, browser screenshots, and browser request metadata are
retained for seven days. The PostgreSQL fixture retains browser files only on
failure. Upload paths deliberately exclude runtime configuration, host keys,
databases, passwords, and token-bearing HTML. These diagnostic artifacts have
no deployment approval.

## Run locally

The exact commands live in the workflow. Start with:

```sh
cargo fetch --locked
cargo fmt --all --check
rustfmt --edition 2024 --check examples/private-notes/src/lib.rs examples/task-board/src/lib.rs
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked --offline
python3 tools/test_build_inputs.py
```

For the full runtime job, set `NOXIDE_TEST_POSTGRES` to a disposable local cluster
whose role can create databases, then run:

```sh
cargo test --workspace --locked --offline -- \
  --include-ignored \
  --skip failure_tests::crash_worker \
  --skip postgres_nojs_browser_flow \
  --skip postgres_typed_forms_browser_flow
```

See [Running an application](running-applications.md) for local VM prerequisites
and browser commands. Pass `--local` to `tools/test_sdk_package.py` or
`tools/test_sdk_api.py` for trusted local checks. Without it they require the same `--kernel`,
`--toolchain`, and new `--output` paths as the normal VM builder. Use its returned
`private_notes.wasm` with `noxide component` before running the browser suite.
`tools/ci/setup-vm.sh` installs packages with sudo and is intended only for the
disposable Ubuntu CI runner.

The application job also builds task-board, 28 compile-pass and 26 compile-fail SDK fixtures
locally. It checks typed routes, field projections, control compatibility,
and constrained templates. Both examples exercise NoJS browser flows; generated
manifests travel with their components. PostgreSQL runs the same typed form flow
as SQLite. Framework tests cover atomic application schema changes on both
providers.

Native form-layout metadata collection runs the same host-file, socket, network,
UID, and capability probes as build scripts. Two fresh VMs verify containment
and scratch isolation; the native-loop fixture checks deadline enforcement.

The application job also runs `tools/test_lifecycle.py` against a generated
project with an empty Cargo cache. It covers development approval, registration,
note persistence across rebuilds, compile failure recovery, changed-contract
rejection, tests, builds, and separate serving approval.
`tools/test_cli_package.py` builds the source archives outside the workspace,
relocates those sources, and uses the detached CLI to check a new application.

## Account-reference checks

The host suite tests stable account identities and lifecycle, same-tenant binding,
SQL/row policy equivalence, historical references, and full inbox pagination on
SQLite and PostgreSQL. The inbox benchmark includes 100,000 unrelated records.
`query-metrics` enables test-only SQLite scan-status and PostgreSQL analyzed-plan
instrumentation:

```sh
LIBSQLITE3_FLAGS=SQLITE_ENABLE_STMT_SCANSTATUS cargo test -p noxide-host \
  --features query-metrics --lib sqlite_account_bindings_and_full_pages -- --nocapture
LIBSQLITE3_FLAGS=SQLITE_ENABLE_STMT_SCANSTATUS cargo test -p noxide-host \
  --features query-metrics --lib postgres_account_bindings_and_full_pages -- --ignored --nocapture
```

Set `NOXIDE_TEST_POSTGRES` to a disposable local database with CREATE DATABASE
permission for the second command. Each ordered owner/recipient scan must examine
21 records for a 20-record page; the combined upper bound is 42 candidates before
deduplication, independent of unrelated population. This measures index visits,
not just returned result count. General residual policies retain the bounded
short-page fallback.

`tools/test_private_inbox.py` tests the built component through real HTTP,
including account-ID display, private reads, sender-only deletion, restart/replay,
and revocation. With `--geckodriver`, it also runs Firefox with JavaScript disabled
and saves a recipient screenshot. CI runs this on SQLite and PostgreSQL.
