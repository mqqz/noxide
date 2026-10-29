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

## Start a project

Application lifecycle commands currently target Linux x86-64. Install the Noxide
CLI, Python 3.11+, native compiler/linker tools, and Rust
1.98.0 with `rustup target add wasm32-unknown-unknown`. Then:

```sh
noxide new my-forum
cd my-forum
noxide dev
noxide test
noxide build
noxide serve
```

`new` writes a standalone owner-scoped notes starter, including a privacy
regression test. It executes no application code and downloads nothing. The CLI
ships the SDK, shared builder, and checksum-verified approved dependency archives;
a framework checkout is unnecessary. Its generated SDK path supports local
editor tooling. The builder remaps that path to its own snapshot for both modes.
Applications using dependencies outside the approved catalog require a reviewed
catalog extension; local mode does not silently resolve them over the network.

`dev` builds and watches the application, asks for approval of its validated
contract, and serves on http://localhost:8080. Register a development account
there. Source changes trigger one rebuild at a time. Failed builds and rejected
contracts leave the previous application running. A changed persistent schema
requires an explicit migration; development never resets the database for you.

`test` runs native application tests through the selected executor, admits the
compiled component and contract, and checks activation against disposable SQLite
storage. It does not approve a persistent deployment. `build` records its latest
successful complete bundle under `target/noxide/`; failed builds do not replace
that pointer. `serve` serves that bundle without compiling, using a separate
serving approval, database, and keys. Serving registration defaults to closed;
the CLI prints the configuration path and account creation command.

Review the displayed contract before typing `approve`. Approval records the
existing contract digest in operator-owned deployment configuration. In automation,
use `noxide approve [--dev] CONTRACT_DIGEST` after reviewing that exact contract.
Development approval does not authorize serving. Build provenance grants no
runtime authority: both modes use identical component admission, contract
validation, and deployment checks.

Private state lives under `$XDG_STATE_HOME/noxide`, defaulting to
`~/.local/state/noxide`, keyed by the canonical project path. Development and
serving state are separate and remain outside source snapshots. Moving the
project selects fresh deployment state. `serve CONFIG.json` remains available
for explicit deployment configuration, including Unix/Tor listeners and PostgreSQL.
Project discovery walks upward to `Cargo.toml`; ambiguous workspace roots need
`--app PACKAGE_DIRECTORY` for check/test/build. `dev` operates on the current
application project.

## Choose the build executor

Local builds are the default. Build scripts, procedural macros, native tests,
and the metadata collector execute with the developer's host permissions.
Offline dependency resolution is not network containment. Use local mode only
for trusted application code and dependencies. Keep editor macro expansion and
native builds of untrusted code inside an isolated environment too.

Configure a trusted VM kernel once and select isolation explicitly:

```sh
noxide setup --kernel /path/to/trusted/vmlinuz --toolchain /path/to/trusted/rust-toolchain
noxide dev --isolated
noxide test --isolated
noxide build --isolated
```

Local builds discover the active Rust toolchain automatically. Isolated builds
require an operator-selected toolchain supplied through `setup --toolchain DIR`
or `--toolchain DIR`; they never run rustup discovery in the application directory.
Select a trusted installed toolchain directory independently of application
`rust-toolchain` files and directory overrides. Per-command `--kernel` and `--toolchain`
override saved settings. `NOXIDE_VM_KERNEL` overrides the saved kernel. Settings
live outside the application in the private Noxide state directory. Missing VM
prerequisites fail the build; there is no fallback to local execution. See the VM
requirements below before selecting a kernel.

## Build and package the trusted framework

Build the CLI and its reviewed dependencies on the host:

```sh
cargo fetch --locked
cargo build --workspace --locked --offline
cargo test --workspace --locked --offline
```

The CLI build embeds the shared recipe, public SDK sources, and approved
checksum-verified dependency archives. No application is compiled during this
step. To prepare a CLI source archive, generate its build asset first:

```sh
python3 tools/package_build_kit.py
cargo package --workspace --allow-dirty --no-verify --offline
```

The generated asset is included in the archive and ignored in the working tree;
it is derived from the same authoritative sources used by repository builds.
Repository builds always regenerate their embedded asset from source. Packaged
CLI builds consume the included asset without requiring a framework checkout.
`--no-verify` skips Cargo's archive build verification; release validation must
also build the extracted archive in a clean consumer environment.

## Build a trusted application locally

On Linux, install Python 3.11+, Rust 1.98.0 with the `wasm32-unknown-unknown` target,
and native compiler/linker tools. The installed CLI includes its approved dependency catalog. With a source-checkout
CLI, fetch the trusted framework dependencies before building the CLI, then run:

```sh
target/debug/noxide build --app examples/private-notes --name private_notes \
  --output /tmp/noxide-notes-build
```

The CLI uses the active Rust toolchain unless `--toolchain` is supplied. `check`
also collects and validates the contract; `build` additionally admits the component.
Both use a fresh source snapshot and the same offline dependency catalog.
Local builds execute build scripts, procedural macros, and the metadata collector
with your host permissions. Offline Cargo is not network containment. Use this
mode only when you trust the app and its dependencies. Logs are raw local build
output; no VM resource or isolation guarantees apply.

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
target/debug/noxide build --isolated \
  --app examples/private-notes --name private_notes \
  --kernel /boot/vmlinuz-6.18.41_1 \
  --toolchain "$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu" \
  --output /tmp/noxide-notes-build
```

The build command performs Cargo resolution and application compilation inside QEMU.
It uses two virtual CPUs, 6 GiB RAM, a 2 GiB scratch tmpfs, a 900-second guest
build deadline, a 1,020-second outer deadline, and no NIC, disk, host share, or monitor socket. Native build code runs
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

VM build output includes a sanitized log, a bounded core Wasm file, the application
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

## Deployment presentation

The HTTP server omits `Date` and `Server` headers. It serves no stylesheet by
default. Cookie names default to `session` and `login`; host endpoints use
`/login`, `/logout`, and `/actions/{id}`. Tokens use authenticated encryption so
browser values hide their issue/expiry timestamps and authority metadata. Each
service should have its own host key file.

The trusted operator can add a `presentation` object to the runtime configuration:

```json
{
  "presentation": {
    "session_cookie": "account",
    "login_cookie": "challenge",
    "anonymous_cookie": "visitor",
    "csrf_field": "check",
    "submission_field": "ticket",
    "capability_field": "edit_key",
    "registration_path": "/join",
    "capability_path": "/manage",
    "login_path": "/signin",
    "logout_path": "/signout",
    "action_path": "/submit",
    "stylesheet_path": "/theme.css",
    "stylesheet": "body { max-width: 50rem; margin: 2rem auto } pre { white-space: pre-wrap; overflow-wrap: anywhere }"
  }
}
```

Omitted settings retain their defaults. All pages, including sign-in and form
recovery, use these settings. Cookie security attributes remain host-controlled.
Cookie names must be distinct ASCII letters, digits, underscores, or hyphens,
with at most 64 bytes. Host form field names use the same characters with at most
32 bytes, must differ from each other, and cannot collide with resource fields
or `username`, `password`, or `invite`. Endpoint paths must be distinct local
paths without escapes, queries, or fragments; paths that overlap application routes are rejected before
activation. Action path segments use the application route identifier grammar:
a lowercase letter followed by lowercase letters, digits, or underscores, up to
32 bytes per segment.

The anonymous cookie defaults to `noxide_anon`; the host field defaults are
`_csrf`, `_submission`, and `_capability`. Registration defaults to `/register`.
The capability path defaults to `/_noxide/capability` and takes no trailing slash:
resource and record IDs are appended, for example `/manage/1/42`. All host pages,
failure links, recovery forms and submission parsing use the configured names.
Historical names and endpoints are not aliases after changing the settings.
Existing browser cookies and already rendered forms using the old names must be
replaced when these settings change. Choosing custom names removes these fixed
markers; it does not guarantee that a site's framework cannot be identified.

CSS is deployment-owned data, never guest output. The `stylesheet` string accepts
literal selectors and declarations, with a 64 KiB limit; the CLI's total runtime
configuration limit is 16 KiB. Strings, escapes, comments, functions, at-rules,
and nested rules are rejected. This subset permits ordinary layout and text
styling without resource-loading syntax. Set `stylesheet` to `null` to omit both
the link and the asset. The content security policy continues to forbid remote
styles and other resources.

Choose presentation separately for services that should not share an appearance.
Reusing this example verbatim creates another shared marker. These settings
reduce explicit framework identifiers; common markup, authentication flows,
token formats, response timing, and infrastructure still permit fingerprinting.
They do not establish unlinkability. Check the public endpoint too: a reverse
proxy can reintroduce its own `Date` or `Server` headers.

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

Declarations use protocol version 4. A record route declares its generated resource ID;
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

## Tor deployment

Use `tor_unix` to accept Tor's PROXY v1 circuit information on a private Unix
socket. Set `origin` to the exact public onion origin and configure the numeric
GID of the Tor service account:

```json
{"listen": {"tor_unix": {"path": "/srv/noxide/run/app.sock", "tor_gid": 115}}}
```

Prepare the directory as the operator, with the host account as owner and the
Tor account's group (commonly `debian-tor`):

```sh
install -d -o noxide -g debian-tor -m 2750 /srv/noxide/run
```

The host requires directory mode 2750 and the configured group. The setgid bit
makes the socket inherit that group; the host sets socket mode 0660 and checks
its identity and ownership before serving. A group-writable directory, a missing
setgid bit, or an existing socket path prevents startup. Shutdown removes only
the socket created by this listener.

Configure Tor with:

```text
HiddenServiceDir /var/lib/tor/app
HiddenServicePort 80 unix:/srv/noxide/run/app.sock
HiddenServiceExportCircuitID haproxy
HiddenServicePoWDefensesEnabled 1
HiddenServiceMaxStreams 16
HiddenServiceMaxStreamsCloseCircuit 1
```

Only this listener accepts PROXY v1 lines. Ordinary `tcp` and `unix` listeners
keep local-peer semantics and reject a PROXY line as malformed HTTP. Tor circuit
information stays inside the host; it is not sent to the guest or browser and
is not stored in the database or logged.

The server permits at most 256 connections, with four per Tor circuit. The PROXY
line has a two-second deadline and a 107-byte limit including CRLF. HTTP headers
have a 15-second deadline; each connection retains its 60-second lifetime cap.
Requests have 64 active slots and at most 64 waiters for two seconds. Database
transactions and Wasm execution each have eight slots and at most 16 waiters for
one second. Argon2 has two slots, at most eight waiters for one second, and a
global token bucket of 60 attempts per minute. Admission failures return the same
host-owned HTML busy page with status 503, the usual security headers, and no
`Retry-After` header. Disconnected hash workers retain their capacity until the
work finishes.

## Failures and recovery

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

Initialization creates the current framework storage layout. Serving rejects
unsupported or incomplete layouts. Application schema changes remain explicit;
see [schema evolution](application-api.md#schema-evolution) for declarative
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
The persisted clock high-water mark tolerates backward corrections of up to
60 seconds. Requests and maintenance use the greater of wall time and the
persisted mark for all token issuance, verification, and expiry collection.
Time never moves backwards within that authority. A single correction can extend
a token's wall-time lifetime by up to 60 seconds. Request execution deadlines
continue to use monotonic elapsed time.

Larger corrections fence admission. To recover without waiting for the old time
to catch up, stop all runtime instances and correct the system clock. Generate a
fresh host key, update the configuration, then run recovery before restarting:

```sh
target/debug/noxide keygen /tmp/noxide-notes-run/clock-host-keys.json
# Set "keys": "clock-host-keys.json" in runtime.json.
target/debug/noxide recover-clock /tmp/noxide-notes-run/runtime.json
target/debug/noxide serve /tmp/noxide-notes-run/runtime.json
```

Recovery atomically resets the clock mark, switches the accepted key incarnation
and deployment generation, and deletes authentication sessions. Application
records and receipts are preserved. Users must sign in again and reopen forms;
old tokens cannot authorize another execution even if their receipts were
already collected. The command refuses the current host key and rolls back on
failure. Always generate a new key; never reuse a retired one or lower the clock
mark through SQL. `noxide maintain CONFIG.json` reports a clock-fence error with
the recovery command when the correction exceeds tolerance.

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

### Edit keys and fresh capability storage

The nullable-owner capability layout was introduced in storage version 4. The
current runtime requires fresh version-5 storage; older storage is rejected and
no storage converter is provided.
`noxide keygen` and `noxide init` create one signing edit key. A manifest with
public creates or capability actions requires a signing edit key at activation.

To add a signing edit key while retaining older keys for verification:

```sh
noxide edit-key-rotate keys.json
```

Restart serving processes after updating the key file. Keep its permissions
private (0600). Key rotation preserves token authority and existing edit-secret
versions; rotating an individual record through its host-owned capability form
revokes that record's older secrets under every edit key. Removing an older key
also prevents its receipts from recovering an edit secret.

The anonymous cookie defaults to `noxide_anon` and can be renamed through
`presentation.anonymous_cookie`. All three configured cookie names must differ.

## Registration

Registration defaults to `"registration": "closed"`; the configured registration
path (`/register` by default) returns 404.
Set `"registration": "invite"` to require an operator-issued invite, or
`"registration": "open"` to allow registration without one. Both enabled modes
use fixed host-owned pages and the same bounded password-hashing admission as
login. Registration never signs the visitor in automatically: success redirects
to the configured login page.

Registration uses fresh storage version 5, including the invite table. Initialize
fresh storage; version-4 storage is rejected and no converter is provided.

In invite mode, mint a single-use code with the trusted CLI:

```sh
noxide invite config.json
noxide invite config.json --expires-days 2
```

The default expiry is seven days. The CLI prints the code once and stores only
its SHA-256 hash with the operator as issuer. Give that code to the intended
visitor outside application URLs. Invite redemption and account creation commit
in one transaction. Expired, reused and invalid codes produce the same generic
failure page as other registration failures. There is no inviter role.
Clock recovery invalidates all outstanding invites; redeemed invite records are retained.

New accounts use the existing identifier rules and a password of 12–256 bytes.
They start with an empty tenant, epoch 1 and no roles. All responses retain
`Cache-Control: no-store`; the registration form includes a browser-bound
challenge and CSRF value.
