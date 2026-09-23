# Continuous integration

[CI](../.github/workflows/ci.yml) runs on pull requests, pushes to `main`, merge
queues, manual dispatch, and every Monday at 03:23 UTC. For branch protection,
require both PR checks: `Runtime` and `Packaged SDK and browser`.
Publishing and deployment are outside this workflow.

## Checks

`Runtime` uses Rust 1.98.0 on Ubuntu 24.04. It checks workspace and example
formatting, Clippy with warnings denied, documentation with warnings denied,
ShellCheck, Python build-input validation, and the Rust tests against SQLite and
a disposable PostgreSQL 18.4 service. Ignored PostgreSQL tests are included
explicitly; the internal crash subprocess and separately run browser fixture are
excluded.

`Packaged SDK and browser` packages the SDK crates, then compiles the
private-notes example against their versioned archive directories inside a fresh
QEMU VM. This exercises the distributed WIT contract without relying on sibling
monorepo paths. The trusted CLI admits the resulting component. Firefox then
exercises the NoJS form flow with SQLite on localhost and PostgreSQL through the
test onion-origin proxy. This proxy does not establish Tor transport behavior.

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

Only the trusted framework is compiled directly on the runner. Application
compilation, including dependency build scripts and macros, runs inside the
existing VM recipe with no NIC, disks, host shares, credentials, or host sockets.
The example remains outside the root Cargo workspace. Framework dependencies are
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
rustfmt --edition 2024 --check examples/private-notes/src/lib.rs
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
  --skip postgres_nojs_browser_flow
```

See [Running an application](running-applications.md) for local VM prerequisites
and browser commands. `tools/test_sdk_package.py` accepts the same `--kernel`,
`--toolchain`, and new `--output` paths as the normal VM builder. Use its returned
`private_notes.wasm` with `noxide component` before running the browser suite.
`tools/ci/setup-vm.sh` installs packages with sudo and is intended only for the
disposable Ubuntu CI runner.
