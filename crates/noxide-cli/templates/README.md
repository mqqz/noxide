# __NAME__

A private notes application. Each signed-in user can create, edit, and delete
only their own notes. Start in `src/lib.rs`: the app module contains the resource,
pages, validation, and enabled mutations.

From this directory, check the application using your installed Noxide CLI and
Rust toolchain with the wasm32-unknown-unknown target:

```sh
noxide check --app . --name __CRATE__ \
  --output /tmp/__NAME__-check
```

If the CLI was installed separately, add `--framework /path/to/noxide` to select
the trusted framework checkout.

Use `noxide build` with a new output directory when you need the application
bundle. Every output directory must be new. Builds run locally by default and
trust the application and its dependencies, including build scripts, macros, and
the native metadata collector. The builder stages the SDK at the dependency path
in `Cargo.toml`.

For untrusted apps or dependencies, add `--isolated --kernel /path/to/vmlinuz
--toolchain /path/to/rust-toolchain` to run in a disposable VM. Keep editor macro
expansion and other native builds of untrusted code inside that boundary too.

The build produces a reviewable contract. An operator must approve it before
serving the application; generated code does not grant authority by itself.
See the [running guide](https://github.com/mqqz/noxide/blob/main/docs/running-applications.md)
for deployment and account setup, and the [API guide](https://github.com/mqqz/noxide/blob/main/docs/application-api.md)
for public queries, custom policies, and forms.
