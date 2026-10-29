# Forum development example

A text forum using the public SDK: public threads, replies scoped to each thread,
account-owned and anonymous posting, owner/edit-secret editing, and moderator
hide/restore and thread locking. Registration and pagination are host-owned.

## Build and run

From the repository root, with the trusted toolchain and cached dependencies:

```sh
cargo run -p noxide-cli -- build --framework "$PWD" \
  --app examples/forum --name forum --output /tmp/forum-build
```

Use a fresh output directory. Follow [running applications](../../docs/running-applications.md)
for approval, database initialization, accounts, and serving the generated
`forum.component.wasm` and `manifest.json`. Enable host registration with
`"registration": "open"` or `"invite"`. Registration never grants roles. The CLI currently has no role-management command;
a trusted operator can grant the role directly in the deployment database after
creating the account (replace `alice` with that account's ID):

```sql
INSERT INTO nx_roles(principal, name, tenant) VALUES ('alice', 'moderator', '');
```
If the default state directory is unavailable, set `XDG_STATE_HOME` to a writable
absolute directory outside the application source.

Run the repeatable integration check against a disposable SQLite database and
localhost server:

```sh
python3 tools/test_forum.py --bundle /tmp/forum-build --output /tmp/forum-http
```

It exercises registration/login, two threads with interleaved replies, owner
editing, anonymous creation and edit secrets, actual pagination links, thread
lock races, hiding/restoring threads, and direct reply URLs under hidden parents.
The moderator role is granted through operator-controlled test SQL. This check
uses HTTP, not browser automation, and leaves results and server logs in the
output directory.

## Pages and behavior

- `/`: public threads and account/anonymous creation forms.
- `/threads/{thread}`: opening message, paginated replies, reply creation and
  thread editing. Locked threads retain existing content and reject new replies.
- `/replies/{reply}`: a reply with owner and edit-secret editing.
- `/moderation` and `/moderation/{thread}`: moderator review, visibility, locks,
  and links to individual reply moderation.
- `/reply_review/{reply}`: moderator hide/restore for a reply.

New threads and replies start unpublished and await moderator approval. Save the anonymous edit secret
on the host's handover page. Authors edit content only; moderator visibility and
lock state cannot be changed by owner or edit-secret updates. Hiding a thread
removes its replies from public access, including direct reply URLs. Moderators
can still review hidden content. A lock prevents new replies; existing replies
remain editable.

`Reply.thread: Id<Thread>` is assigned by the host from the thread page and cannot
be submitted or changed. Parent visibility and lock conditions are checked again
inside the reply's write transaction. See the [relationship API](../../docs/application-api.md#parent-relationships-and-scoped-pagination).

## Remaining development findings

- Public reply lists request up to six records in host-controlled creation order.
  This reserves Document IR space for the parent, forms, and markup even when
  maximum-length text requires JSON escaping. Moderator lists request up to 20
  replies and render links only. Serialized byte limits may shorten a page.
  Opaque cursors expire after 15 minutes; restart pagination after expiry or
  redeployment. Traversal is live:
  publishing an older reply behind the cursor requires restarting to see it.
- Multiple create/update actions require explicit `#[action]` declarations;
  `crud!` permits one declaration per operation kind.
- Text is bounded to 4096 bytes per field and rendered as escaped plain text.
- Moderator role administration currently requires operator database access.
- Search, public author profiles, and multi-resource write workflows are not
  implemented. Attachments remain deferred.

Signed-in owners can read and edit their pending threads and replies on the usual
record URLs, including their own replies beneath hidden threads. Other readers
still receive a 404 until publication.

- Edit secrets grant updates/deletes, not read access. Anonymous authors cannot
  view or edit pending posts through these pages until approval. Save the secret
  at handover. A host-authorized secret read/unlock flow remains deferred.
- Moderation gates initial publication only. Owner and edit-secret changes to
  approved content become public immediately. Keeping approved content visible
  while edits await approval needs separate pending revisions and host-enforced,
  atomic approval of the exact reviewed revision; this remains deferred.
- Choice-enum `initial` syntax in the macro remains deferred; the host already
  validates choice initial values.
- A readable operator approval summary listing which update actions can write
  each initial field remains deferred.
