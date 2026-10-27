# Running an application

The private-notes application supports creating, editing, and deleting notes,
including recovery of repeated submissions. The runtime supports SQLite and
PostgreSQL. Pages and forms work without JavaScript. Application code runs in fresh Wasmtime
components; the host owns HTML, authentication, permissions, and transactions.

The implementation is new and has not had an external security audit. The tested
platform is Linux x86-64, Rust 1.98.0, QEMU 11.0.2 with TCG, PostgreSQL 18.4, and
Firefox 153.0.1. The browser suite covers HTTP localhost and an HTTP `.onion`
origin through an isolated test proxy. It does not establish Tor Browser or I2P
transport behavior.

## Build the trusted framework

Only the framework and its reviewed dependencies belong in this host build. Do
not run application Cargo commands, rust-analyzer project builds, build scripts,
or procedural macros on the developer or serving host.

```sh
cargo fetch --locked
cargo build --workspace --locked --offline
cargo test --workspace --locked --offline
```

`target/debug/noxide --help` lists the host commands. Application sources remain
outside the host workspace build; `examples/private-notes` has its own lockfile.

## Build the application in a disposable VM

Install a trusted Linux x86-64 kernel with built-in initramfs, devtmpfs, procfs,
sysfs, tmpfs, and serial-console support. The recipe was tested with Linux
6.18.41. Install QEMU with TCG and seccomp support, Python 3.11 or later, GCC,
binutils, bash, coreutils, and util-linux. The selected Rust 1.98.0 toolchain must
include `wasm32-unknown-unknown` standard libraries.

The recipe snapshots the selected toolchain and its system libraries, the public
SDK sources, the approved SDK dependency catalog from the framework lockfile,
and the selected application source. Cached `.crate` archives are verified against
that lockfile before bounded extraction. No Cargo home configuration, private
registry credentials, SSH agent, Docker socket, home directory, or deployment
directory is passed into the VM. This initial catalog supports the supplied SDK
and source dependencies; extending registry dependencies requires an explicitly
reviewed acquisition catalog.

Run from the repository root, substituting the installed kernel and toolchain
paths. `--output` must name a new directory.

```sh
target/debug/noxide build \
  --app examples/private-notes --name private_notes \
  --kernel /boot/vmlinuz-6.18.41_1 \
  --toolchain "$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu" \
  --output /tmp/noxide-notes-build
```

The build command performs Cargo resolution and application compilation inside QEMU.
It uses two virtual CPUs, 6 GiB RAM, a 2 GiB scratch tmpfs, a 600-second outer
deadline, and no NIC, disk, host share, or monitor socket. Native build code runs
without capabilities as UID 65534 with `no_new_privs`. Every build gets fresh
scratch. Inputs are root-owned and read-only to the build user. The source reader
rejects links, special files, hidden inputs, oversized trees, and directory escape.

The build command also wraps portable core Wasm into a component and independently
checks the runtime import/feature contract. It never loads native Wasmtime caches.
Neither a successful compiler exit nor builder metadata grants runtime authority.
Before compilation, the host also bounds the expanded component graph to 1,024
core/component instances and 8 MiB of component bodies, with at most 32 lexical
component levels. Component-valued imports and instance-export aliases are not
admitted; host-function imports and bounded local/outer component references are
supported. These checks also apply when loading a component with `serve`.

Build output includes a sanitized log, a bounded core Wasm file, the application
lockfile, and VM timing/memory measurements. The checked-in notes lockfile is built
with `--locked --offline`; an initial source without a lockfile resolves only
against the fixed catalog inside the VM and returns its lockfile for review.

## Approve the contract and initialize storage

Read [the notes declarations](../examples/private-notes/manifest.json). They request
owner-scoped list/read, create, update, and delete operations. An update writes
exactly the submitted `body` to the note bound to its form. Ownership, tenant,
record incarnation, and revision come from the host. The separate deployment
configuration records the operator's approval digest; a manifest shipped by an
application cannot approve itself.

After reviewing that contract, create a private runtime directory and configuration:

```sh
umask 077
mkdir /tmp/noxide-notes-run
python3 - <<'PY'
import json, pathlib, subprocess
root = pathlib.Path.cwd()
manifest = pathlib.Path('/tmp/noxide-notes-build/manifest.json')
approved = subprocess.check_output(
    [root / 'target/debug/noxide', 'contract-hash', manifest], text=True).strip()
config = {
    'database': {'sqlite': 'notes.db'},
    'keys': 'host-keys.json',
    'component': '/tmp/noxide-notes-build/private_notes.component.wasm',
    'manifest': str(manifest),
    'approved_contract': approved,
    'origin': 'http://localhost:8080',
    'listen': {'tcp': '127.0.0.1:8080'},
}
with open('/tmp/noxide-notes-run/runtime.json', 'x') as file:
    json.dump(config, file, indent=2)
PY

target/debug/noxide init /tmp/noxide-notes-run/runtime.json
```

Paths in configuration are relative to the configuration file. Host keys and
SQLite databases must be private; the CLI creates them with mode 0600 and rejects
group/world-readable existing files. Use a private directory for the database and
its journal files. Keep keys outside application inputs and source control.

For PostgreSQL, replace the database setting with a local connection, for example:

```json
{"postgres":"postgresql://noxide@localhost/notes?host=/run/postgresql"}
```

Create the database and role through PostgreSQL administration, and restrict the
runtime role to its dedicated database. Receipts and application writes must
share one authoritative database and transaction. Remote PostgreSQL connections
and cross-provider transactions are unsupported.

## Provision accounts and serve

Passwords contain 12–256 UTF-8 bytes. Provisioning is a trusted operator command;
the application has no account, password, role, or session database capability.
Create a temporary private password file without putting its contents in shell
history:

```sh
python3 - <<'PY'
import getpass, os
descriptor = os.open('/tmp/noxide-notes-run/password', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, 'w') as file:
    file.write(getpass.getpass('Password for Alice: '))
PY
target/debug/noxide account /tmp/noxide-notes-run/runtime.json alice /tmp/noxide-notes-run/password
rm /tmp/noxide-notes-run/password
target/debug/noxide serve /tmp/noxide-notes-run/runtime.json
```

Visit `http://localhost:8080`. Sign in, save text containing `<script>` or an image
tag, and confirm it appears literally. Provision Bob the same way to verify that
his list and direct note requests cannot expose Alice's content. Lists have a
host-owned next-page link, and every authenticated page offers sign-out.

Open a note in two tabs. Save an edit in one, then submit the other tab's edit.
The conflict page shows the current text alongside the entered text. Review it
and select **Save these changes** to submit against the current revision. The
**Delete record** button removes the note with one POST; there is no confirmation
round trip or trash view.

Declarations use protocol version 3. A record route declares its generated resource ID;
list routes use `null`. Every action declares a `fields` list: all resource fields
for creation, a nonempty subset for updates, and an empty list for deletion.
The host rejects extra fields and missing required values, supplies false/None
for omitted checkboxes/optional fields, and preserves fields outside an update's
projection. Generated action handlers return the host's outcome for the bound
target. Custom handlers use `Submission<Action>::apply()`.

Actions receive no stored values by default. An optional declaration such as
`"inspect": {"operation": 2, "fields": ["body"]}` supplies those original values
in `RequestView.inspection`, after the host checks the declared read policy.
The snapshot stays unchanged during the attempt, including after a staged update
or delete. It grants no general read import.

The host accepts only the configured Host and Origin. It ignores forwarding
headers. TCP listeners bind only loopback; `{"unix":"/private/run/noxide.sock"}`
selects a Unix socket in a directory controlled by the operator. Normal shutdown
removes that socket. After an abrupt process kill, verify the old host has stopped
before removing its stale socket. For an onion deployment, set `origin` to its exact public
HTTP origin and connect Tor to this private listener. An HTTPS origin assumes a
trusted TLS terminator and makes cookies Secure; HTTP onion/local origins use
host-only HttpOnly, SameSite=Strict cookies without Secure. Application code
cannot alter cookie or security-header policy.

## Failures, upgrades, and recovery

Every mutation carries a host-authenticated token with a 15-minute expiry. Repeat
the POST with the same canonical input to recover its outcome; changing the input
on a used form returns a conflict and cannot save again. Validation pages preserve
entered text. For an uncertain save, the page keeps the original token and makes
the input read-only so the user can check that submission before starting another
one.

Edit and delete tokens bind the note's incarnation and revision. A stale revision
returns a host-rendered conflict before guest execution and issues a fresh token
only after current permissions pass. A missing or unauthorized target returns
the same unavailable page. A completed receipt can still recover its redirect
after deletion or revoked mutation permission; the session, token, and deployment
must remain valid, and following the redirect performs normal read authorization.

A handler may return `ResponseIntent::Rejected { field_errors, message }`.
The host validates the errors, rolls back all staged effects and the receipt
claim, and renders an editable form with the same token. Corrected input can be
submitted with that token because the rejected attempt committed nothing.

Resources are released before sending a committed response. A slow browser does
not retain a Store or database transaction. Shutdown stops accepting connections,
allows three seconds for active connections, then cancels them. A disconnected
client may still have a committed result and must use the same submission token.

Existing version-1 runtime databases require an offline storage migration. Stop
all serving processes and other writers, make a backup, then run the new CLI:

```sh
target/debug/noxide migrate /tmp/noxide-notes-run/runtime.json
```

The command preserves existing records, assigns each a fresh incarnation and
revision 1, and atomically replaces the storage layout. It retires old deployment
forms. Rebuild the application with the version-3 SDK, review its new declarations,
update `approved_contract`, then restart. `init` and serving refuse unmigrated
storage; repeating a successful migration is safe. The migration is bounded to
five minutes and requires room for a transactional copy of the records.

This command only upgrades framework storage. Activation also checks the persisted
application resource schema. Runtime storage version 3 adds a stable resource
catalog and migration history. After upgrading v2 storage, explicitly import its
original approved manifest with `noxide schema import CONFIG LEGACY_MANIFEST`.
See [schema evolution](application-api.md#schema-evolution) for declarative
application migrations on both databases.
Changing the component bytes or approved declaration digest creates a new
deployment identity, retires the previous generation, and rejects old forms,
including receipt requests. Code rollback creates another generation, so it
cannot revive previously issued forms. Allow a drain period if outstanding
submissions must finish before replacement.

On backup restoration, a database fork, or lossy failover, stop serving, generate
new keys, update the configuration's `keys` path, and restart:

```sh
target/debug/noxide keygen /tmp/noxide-notes-run/restored-host-keys.json
```

Never restore the old key alongside a database that has lost acknowledged history.
New keys invalidate old authentication sessions and forms. The runtime cannot
automatically distinguish an unannounced restored database from its original.

Run `noxide maintain CONFIG.json` periodically. Each invocation removes at most
256 expired receipts and 256 expired sessions, after a 60-second grace period.
Expiry is authenticated, so deleting a receipt cannot authorize an old token.
A persisted clock high-water mark fences admission if time moves backwards;
restore trusted time before resuming. Do not reset the fence to revive tokens.

SQLite requires WAL and `synchronous=FULL`. PostgreSQL requires `fsync` and
`full_page_writes` enabled and uses synchronous commits. These settings assume
local storage that correctly honors flushes. Tests cover real-provider rollback,
host process crashes, and replay; they do not certify hardware power-loss behavior.

## Run the acceptance suites

```sh
cargo test --workspace --locked --offline
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
python3 tools/test_build_inputs.py
```

The PostgreSQL tests require a disposable cluster with CREATE DATABASE permission;
they create uniquely named databases and drop them on success. They are explicitly
ignored by the default suite, so run them separately:

```sh
export NOXIDE_TEST_POSTGRES='postgresql://test@localhost/postgres?host=/private/test/socket'
cargo test --workspace --locked --offline -- \
  --include-ignored \
  --skip failure_tests::crash_worker \
  --skip postgres_nojs_browser_flow
```

For VM and browser acceptance:

```sh
python3 tools/test_sdk_package.py \
  --kernel /boot/vmlinuz-6.18.41_1 \
  --toolchain "$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu" \
  --output /tmp/noxide-packaged-sdk

python3 tools/test_build_vm.py \
  --kernel /boot/vmlinuz-6.18.41_1 \
  --toolchain "$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu" \
  --output /tmp/noxide-hostile-builds

python3 tools/test_browser.py \
  --component /tmp/noxide-notes-build/private_notes.component.wasm \
  --geckodriver /path/to/geckodriver \
  --output /tmp/noxide-browser-local

export NOXIDE_TEST_COMPONENT=/tmp/noxide-notes-build/private_notes.component.wasm
export NOXIDE_GECKODRIVER=/path/to/geckodriver
cargo test -p noxide-host --test browser --locked --offline -- --ignored
```

Browser tests create private, disposable accounts, configuration, keys, screenshots,
and diagnostics. Use test databases and retain those artifacts only as test evidence.
The hostile VM tests run both build-script and procedural-macro canaries twice,
then verify that an infinite native build loop is killed by the VM deadline.
The SDK package test creates actual Cargo archives without building application
code on the host, then compiles the example in a VM using versioned package
directories. It verifies that WIT binding generation needs no monorepo paths.
