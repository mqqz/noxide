# __NAME__

A private notes application. Each signed-in user can create, edit, and delete
only their own notes. Start in `src/lib.rs`: the app module contains the resource,
pages, validation, and enabled mutations.

From this directory, check the application using your installed Noxide CLI and
operator-selected kernel and toolchain:

```sh
noxide check --app . --name __CRATE__ \
  --kernel /path/to/vmlinuz \
  --toolchain "$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu" \
  --output /tmp/__NAME__-check
```

If the CLI was installed separately, add `--framework /path/to/noxide` to select
the trusted framework checkout.

Use `noxide build` with a new output directory when you need the application
bundle. Every output directory must be new. Both commands run application builds
inside the disposable VM. The SDK dependency path in `Cargo.toml` refers to that
VM's fixed SDK layout; the builder supplies the trusted framework sources there.
Do not run application Cargo, build scripts, or editor-triggered builds on the
host.

The build produces a reviewable contract. An operator must approve it before
serving the application; generated code does not grant authority by itself.
See the [running guide](https://github.com/mqqz/noxide/blob/main/docs/running-applications.md)
for deployment and account setup, and the [API guide](https://github.com/mqqz/noxide/blob/main/docs/application-api.md)
for public queries, custom policies, and forms.
