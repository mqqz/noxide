# __NAME__

A private notes application. Signed-in users can create, edit, and delete their
own notes. Start in `src/lib.rs`; the privacy regression is in `tests/contract.rs`.

On Linux x86-64, with the Noxide CLI, Python 3.11+, native compiler/linker tools, and a Rust
toolchain with `wasm32-unknown-unknown` installed:

```sh
noxide dev
noxide test
noxide build
noxide serve
```

`dev` builds and watches your sources. Review and approve its contract on first
start, then open http://localhost:8080 and register a development account.
Failed rebuilds keep the previous application running. Changed contracts require
approval again; persistent schema changes require an explicit migration.

`test` runs native application tests and validates runtime activation with a
fresh disposable database. `build` prints the completed bundle path under
`target/noxide/`. `serve` starts the latest successful build and asks for a
separate serving approval. Serving registration is closed by default; its output
shows the configuration path and the command for creating an account.

Local builds are the default. Dependency build scripts, procedural macros,
tests, and the native metadata collector execute with your user permissions.
Use isolated mode for untrusted applications or dependencies, and keep editor
macro expansion and other native builds inside that boundary too:

```sh
noxide setup --kernel /path/to/trusted/vmlinuz --toolchain /path/to/trusted/rust-toolchain
noxide dev --isolated
noxide test --isolated
noxide build --isolated
```

Setup records operator-selected prerequisites. Select the toolchain directory
independently of application-controlled rustup overrides; isolated builds require
this saved selection or an explicit `--toolchain DIRECTORY`. Isolated builds require Linux
x86-64 and QEMU; they never fall back to local execution. Both build modes use
the same SDK, compilation recipe, contract format, and runtime admission checks.

SDK sources and approved dependency archives ship with the CLI. Builds run
offline and need no framework checkout or manually selected output directory.
The generated SDK dependency also works with local Rust editor tooling. Advanced
build selection supports `--app . --name __CRATE__`; workspace projects must
select the application package directory explicitly.

Keys, databases, and approvals live outside the project under
`$XDG_STATE_HOME/noxide` (default `~/.local/state/noxide`), separately for development
and serving. Moving the project selects new deployment state. Build outputs
cannot approve themselves. In automation, explicitly approve a reviewed digest
with `noxide approve [--dev] CONTRACT_DIGEST` before starting the deployment.

See the [running guide](https://github.com/mqqz/noxide/blob/main/docs/running-applications.md)
for custom deployment configuration and migrations, and the
[API guide](https://github.com/mqqz/noxide/blob/main/docs/application-api.md)
for queries, policies, and forms.
