# Architecture refactor validation

Starting checkout: `dca07b5015b6d24bc391c7e45cacc67ea0e7f767` (PR #15 merge),
with a clean working tree. Baseline captures preceded production changes.
No reset, schema migration, database reset or deployment reapproval was performed.

## Preserved surface

The five-crate workspace, root SDK re-exports, prelude and `__private` generated
paths remain unchanged. Macro implementation functions moved; emitted application
declarations were not wrapped in new scopes. Protocol source, serde declarations,
WIT, storage, policies, runtime transaction flow and packaging inputs did not change.
The host change documents the lifecycle and adds wire fixtures only.

Complete canonical contracts and approval hashes match frozen baselines for
notes, task board, public articles, repeated actions and both forum versions.
Their schema and submission metadata remain part of the complete contract;
no normalization removes identities, policies, ordering, projections or layouts.
The existing forum conversion fixtures are unchanged. Wasm binary hashes are not
compatibility assertions.

PR #15 remains baseline: independent repeated actions, layouts and hooks, role
commands and fresh host role checks, dependency check/resolve, forum validation
and moderator onboarding, and transactional public fixture creation ordering.
No such feature was reimplemented.

## Commands and evidence

Commands were run from the repository root. All application inputs were trusted
repository fixtures. Local execution was never substituted for hostile builds.
Output directories were fresh. The shell's `CARGO_HOME` fallback was
`${CARGO_HOME:-$HOME/.cargo}` and toolchain was `$(rustc --print sysroot)`.

| Command | Result |
| --- | --- |
| `cargo fetch --locked` | Passed |
| `cargo fmt --all --check` | Passed |
| `rustfmt --edition 2024 --check examples/private-notes/src/lib.rs examples/task-board/src/lib.rs examples/public-articles/src/lib.rs examples/forum/src/lib.rs` | Passed |
| `cargo build --workspace --locked --offline` | Passed |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | Passed |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked --offline` | Passed |
| `python3 tools/test_build_inputs.py` | Passed: 23 tests |
| `python3 tools/test_build_local.py` | Passed: 4 tests |
| `python3 tools/test_dependencies.py` | Passed: 13 tests |
| `python3 -m py_compile tools/test_sdk_api.py` | Passed |
| `python3 tools/test_sdk_api.py --local --toolchain "$(rustc --print sysroot)" --cargo-home "${CARGO_HOME:-$HOME/.cargo}" --output /tmp/noxide-refactor-baseline-v2` | Passed before production moves: 35 pass and 39 fail fixtures |
| Same SDK command with `--output /tmp/noxide-refactored-sdk` | Passed after moves, including all frozen contract/hash comparisons |
| `python3 tools/test_sdk_package.py --local --toolchain "$(rustc --print sysroot)" --cargo-home "${CARGO_HOME:-$HOME/.cargo}" --metadata --output /tmp/noxide-refactor-package` | Passed; archive-only SDK/WIT consumer |
| `python3 tools/test_sdk_package.py --kernel /boot/vmlinuz-6.18.58_1 --toolchain "$(rustc --print sysroot)" --cargo-home "${CARGO_HOME:-$HOME/.cargo}" --metadata --output /tmp/noxide-refactor-vm-sdk` | Passed in a fresh disposable QEMU VM |
| `python3 tools/test_cli_package.py --output /tmp/noxide-refactor-cli-package` | Passed; relocated source archives and detached CLI with empty dependency cache |
| `python3 tools/test_lifecycle.py --output /tmp/noxide-refactor-lifecycle` | Passed |
| `python3 tools/build_vm.py --local --toolchain "$(rustc --print sysroot)" --source examples/public-articles --name public_articles --metadata --output /tmp/noxide-refactor-public` | Passed |
| `target/debug/noxide component /tmp/noxide-refactor-public/public_articles.wasm /tmp/noxide-refactor-public/public_articles.component.wasm` | Passed |
| `python3 tools/test_public_app.py --component /tmp/noxide-refactor-public/public_articles.component.wasm --manifest /tmp/noxide-refactor-public/manifest.json --output /tmp/noxide-refactor-public-http` | Passed |
| `target/debug/noxide build --framework "$PWD" --app examples/forum --name forum --output /tmp/noxide-refactor-forum` | Passed |
| `python3 tools/test_forum.py --bundle /tmp/noxide-refactor-forum --output /tmp/noxide-refactor-forum-http` | Passed |
| `cargo test --workspace --locked --offline -- --test-threads=1` | Passed with local listener/signal permissions; 229 passed, 31 ignored |
| `cargo test -p noxide-host frozen_receipt_wire_formats_round_trip --locked --offline` | Passed |

Initial restricted workspace tests failed in executor termination and Unix socket
checks. The same full workspace command passed with required local listener and
signal permissions; these were environment failures, not accepted regressions.
The preliminary skip-based run also stopped on the restricted Unix socket check;
its result is not used as a passing workspace run. Existing token tests retain
opaque encoding, expiry, domain/context binding and revocation coverage rather
than freezing randomized ciphertext.

## Unavailable checks

No disposable PostgreSQL cluster or `NOXIDE_TEST_POSTGRES` was available. The CI
runtime command with `--include-ignored --test-threads=1 --skip
failure_tests::crash_worker --skip postgres_nojs_browser_flow --skip
postgres_typed_forms_browser_flow` remains required against a documented disposable
cluster. PostgreSQL ignored tests were not claimed as executed.

`geckodriver` was unavailable. `tools/test_render_browser.py`, SQLite notes and
task-board `tools/test_browser.py` flows, and the dedicated PostgreSQL browser
fixtures (`cargo test -p noxide-host --test browser --locked --offline -- --ignored
--nocapture`) remain unrun. Firefox alone does not establish browser coverage.
`ShellCheck` was unavailable, so `shellcheck tools/ci/setup-vm.sh` was not run.
The weekly/manual hostile VM build suite was not run; it remains the required
separate check for hostile build containment. No remote CI, deployment or
independent security audit is claimed.

The unrun browser commands from the workflow require component conversion of
`/tmp/noxide-refactor-package/private_notes.wasm` and
`/tmp/noxide-refactored-sdk/task_board.wasm` before execution:

```sh
python3 tools/test_render_browser.py --geckodriver "$NOXIDE_GECKODRIVER" --output /tmp/noxide-refactor-render
python3 tools/test_browser.py --component /tmp/noxide-refactor-package/private_notes.component.wasm --manifest /tmp/noxide-refactor-package/manifest.json --geckodriver "$NOXIDE_GECKODRIVER" --output /tmp/noxide-refactor-browser-sqlite
python3 tools/test_browser.py --component /tmp/noxide-refactored-sdk/task_board.component.wasm --manifest /tmp/noxide-refactored-sdk/manifest.json --tasks --custom-presentation --geckodriver "$NOXIDE_GECKODRIVER" --output /tmp/noxide-refactor-task-browser
cargo test -p noxide-host --test browser --locked --offline -- --ignored --nocapture
python3 tools/test_build_vm.py --kernel /boot/vmlinuz-6.18.58_1 --toolchain "$(rustc --print sysroot)" --output /tmp/noxide-refactor-hostile
```
