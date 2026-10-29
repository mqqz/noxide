# Forum development example

A text forum with account-owned and anonymous posts, owner/edit-secret editing,
and moderator publication and thread locking. Named actions use two `crud!`
blocks. Typed layouts provide text inputs, eight-row textareas, and moderation
checkboxes; the host supplies credentials, CSRF, recovery, and pagination.

## Disposable development setup

Use the following Bash flow from the trusted repository checkout. It uses one
explicit configuration throughout; development-state approval commands are not
part of this example. Install the trusted CLI, Python 3.11+, and a trusted Rust
toolchain with `wasm32-unknown-unknown` first. The selected catalog's archives
must already be cached. Local processing requires trusted application code and
dependencies; for untrusted inputs add `--isolated --kernel /path/to/trusted/kernel`
to each dependency/build command below, retaining the selected toolchain.

```sh
# Build the trusted host CLI from this checkout and its cached dependencies.
cargo build -p noxide-cli --locked --offline
export FRAMEWORK="$PWD"
export HOST_CLI="$FRAMEWORK/target/debug/noxide"
export TOOLCHAIN="$(rustc --print sysroot)"
umask 077
export FORUM_RUN="$(mktemp -d /tmp/noxide-forum.XXXXXX)"
export XDG_STATE_HOME="$FORUM_RUN/state"

"$HOST_CLI" deps resolve --app "$FRAMEWORK/examples/forum" \
  --framework "$FRAMEWORK" --toolchain "$TOOLCHAIN" \
  --output "$FORUM_RUN/lock-candidate"
diff -u examples/forum/Cargo.lock "$FORUM_RUN/lock-candidate/Cargo.lock"
```

Review the candidate and confirm that the application manifest and trusted
catalog have not changed. A nonzero `diff` means there are differences to review.
Resolution alone does not compile or approve the application. Install the
reviewed candidate explicitly, then use the same catalog and toolchain:

```sh
cp -- "$FORUM_RUN/lock-candidate/Cargo.lock" "$FRAMEWORK/examples/forum/Cargo.lock"
"$HOST_CLI" deps check --app "$FRAMEWORK/examples/forum" \
  --framework "$FRAMEWORK" --toolchain "$TOOLCHAIN"
"$HOST_CLI" check --app "$FRAMEWORK/examples/forum" \
  --framework "$FRAMEWORK" --toolchain "$TOOLCHAIN" --output "$FORUM_RUN/check"
"$HOST_CLI" build --app "$FRAMEWORK/examples/forum" \
  --framework "$FRAMEWORK" --toolchain "$TOOLCHAIN" --output "$FORUM_RUN/bundle"
python3 -m json.tool "$FORUM_RUN/bundle/manifest.json"
"$HOST_CLI" contract-hash "$FORUM_RUN/bundle/manifest.json"
```

Review this emitted manifest: authors write title/body only, new posts are
unpublished, and only global `moderator` actions write publication/lock fields.
The two CRUD blocks preserve the original action identities and permissions.
Custom layouts change the contract digest and require ordinary contract approval.
Enter the displayed digest only after reviewing that exact bundle:

```sh
read -r -p 'Reviewed contract digest: ' APPROVED_DIGEST
export APPROVED_DIGEST
python3 - <<'PY'
import json, os, pathlib, subprocess
run = pathlib.Path(os.environ['FORUM_RUN'])
manifest = run / 'bundle/manifest.json'
approved = os.environ['APPROVED_DIGEST']
actual = subprocess.check_output(
    [os.environ['HOST_CLI'], 'contract-hash', manifest], text=True).strip()
if approved != actual:
    raise SystemExit('Reviewed digest does not match the emitted manifest')
config = {
    'database': {'sqlite': 'forum.db'},
    'keys': 'host-keys.json',
    'component': 'bundle/forum.component.wasm',
    'manifest': 'bundle/manifest.json',
    'approved_contract': approved,
    'origin': 'http://localhost:8080',
    'listen': {'tcp': '127.0.0.1:8080'},
    'registration': 'open',
}
with (run / 'runtime.json').open('x') as file:
    json.dump(config, file, indent=2)
PY
"$HOST_CLI" init "$FORUM_RUN/runtime.json"
python3 - <<'PY'
import getpass, os, pathlib
password = pathlib.Path(os.environ['FORUM_RUN']) / 'moderator-password'
with password.open('x') as file:
    file.write(getpass.getpass('Moderator password (12–256 bytes): '))
password.chmod(0o600)
PY
"$HOST_CLI" account "$FORUM_RUN/runtime.json" moderator "$FORUM_RUN/moderator-password"
rm -- "$FORUM_RUN/moderator-password"
"$HOST_CLI" role grant "$FORUM_RUN/runtime.json" moderator moderator --global
"$HOST_CLI" role list "$FORUM_RUN/runtime.json" moderator
"$HOST_CLI" serve "$FORUM_RUN/runtime.json"
```

All configured paths are relative to this `runtime.json`. Role grants verify
`bundle/manifest.json` against its `approved_contract`; serving uses that same
manifest, component, database, and fresh keys. No prior deployment activation is
needed for the grant. This run uses a fresh storage-version-6 database. Keep its
private directory outside application sources; do not reuse production keys.

Visit `http://localhost:8080`, register an ordinary account, and submit a thread.
Its owner can follow the record URL immediately, but it remains absent from the
public list. In a separate session sign in as `moderator`, open `/moderation`,
select the thread, check **Published**, and save. Verify the thread in a signed-out
session. Replies follow the same publication process. Registration never grants
roles. Whitespace-only titles/messages are rejected with the typed layout,
entered values, field errors, and host recovery controls preserved. Valid content
is stored without trimming.

To revoke authority, use another terminal with the same `FORUM_RUN` and `HOST_CLI`:

```sh
"$HOST_CLI" role revoke "$FORUM_RUN/runtime.json" moderator moderator --global
"$HOST_CLI" role list "$FORUM_RUN/runtime.json" moderator
```

Existing sessions observe the revocation on subsequent authorization transactions.
An unused moderator form cannot perform a new mutation afterward. Recovery of an
already committed submission does not perform a second write. In-flight
transactions retain their existing isolation behavior. Changed/unchanged command
receipts are not a durable audit trail; reconcile state before retrying an
indeterminate error when another operator may have changed the assignment.

Stop the foreground server with Ctrl-C when finished. This example uses HTTP on
loopback for disposable development; it is not an anonymity or production
transport deployment procedure.

## Repeatable HTTP acceptance

After the build, run against another new disposable database and loopback port:

```sh
python3 tools/test_forum.py --host-cli "$HOST_CLI" \
  --bundle "$FORUM_RUN/bundle" --output "$FORUM_RUN/http-check"
```

`--host-cli` also accepts an installed binary outside the checkout. The test
covers registration, CLI moderator provisioning/revocation, existing-session role
freshness, stale forms and committed replay, pending owner access, anonymous
handover/editing, typed recovery layouts, escaped content, locking, hidden parents,
and returned pagination links. Maximum-size ASCII and quote-filled fixtures
retain the existing creation-sequence invariants and rendering budgets. Only
fixture records use SQL; role provisioning needs none. Results and server logs
remain in the test output directory. These are HTTP assertions, not browser
verification; the separate NoJS browser suites require Firefox and geckodriver.

## Pages and behavior

- `/`: public threads and available account/anonymous creation forms.
- `/threads/{thread}`: opening message, paginated replies, and available editing
  and reply forms. Locked threads show existing content and reject new replies.
- `/replies/{reply}`: a reply with available owner/edit-secret editing.
- `/moderation` and `/moderation/{thread}`: moderator review, publication, locks,
  and links to reply moderation.
- `/reply_review/{reply}`: moderator publication for one reply.

New threads and replies start unpublished; threads start unlocked. Only moderator
actions change these values. Signed-in owners can read/edit pending posts on the
usual record URLs, including their own replies beneath hidden threads. Anonymous
and unrelated readers remain denied until publication. Reply creation/editing
redirects to the reply page, and moderation redirects to reply review; this example
does not adopt the framework's optional parent redirects.

Save the anonymous edit secret on the host's handover page before continuing.
The secret never appears in a URL. It grants mutation authority, not read access:
anonymous authors cannot read/edit pending posts through these pages until
approval. A secret read/unlock flow remains deferred. Hiding a thread hides its
replies from public readers, including direct reply URLs. Moderators can still
review them; owners retain their own record access.

`Reply.thread: Id<Thread>` is host-bound and cannot be submitted or changed.
The host rechecks parent visibility and locking inside the write transaction.
See the [relationship API](../../docs/application-api.md#parent-relationships-and-scoped-pagination).

Public replies request up to six records in immutable creation order; moderator
reply lists request up to twenty and render links only. Other lists retain three
records. Serialized byte limits may shorten pages. Follow the opaque `?cursor=`
links returned by the host. Cursors expire after 15 minutes; restart after expiry
or redeployment. Traversal is live, so publishing an older reply behind the cursor
requires restarting to see it. The document title stays **Thread**; the actual
title appears in the page heading. Titles are bounded to 200 bytes and bodies to
4096 bytes, rendered as escaped plain text.

## Remaining limitations

Edits to approved content become public immediately; pending revisions and
reapproval are deferred. Search, public author profiles, attachments, and
multi-resource write workflows are not implemented. Choice-enum `initial` macro
syntax and an operator summary of actions that can write each initial field also
remain deferred. The security requirements are not proof of an independent audit
or transport anonymity.
