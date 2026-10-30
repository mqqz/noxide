# SDK lowering contract

The simplified SDK generates the same typed SDK definitions used by explicit
applications. The host, protocol, WIT world, rendering, admission, authorization,
transaction machinery, and resource budgets are shared.

## Reviewable examples

| Application | Simplified source | Explicit equivalent |
| --- | --- | --- |
| Private notes | [source](../examples/private-notes/src/lib.rs) | [declarations](../tools/fixtures/sdk/private-notes-explicit.rs) |
| Task board | [source](../examples/task-board/src/lib.rs) | [declarations](../tools/fixtures/sdk/task-board-explicit.rs) |
| Policy matrix | [fixture](../tools/fixtures/sdk/policy-board-simple.rs) | [declarations](../tools/fixtures/sdk/policy-board-explicit.rs) |
| Public articles | [source](../examples/public-articles/src/lib.rs) | [declarations](../tools/fixtures/sdk/public-articles-explicit.rs) |
| Repeated actions | [fixture](../tools/fixtures/sdk/repeated-simple.rs) | [declarations](../tools/fixtures/sdk/repeated-explicit.rs) |
| Forum conversion before layouts | [fixture](../tools/fixtures/sdk/forum-simple.rs) | [baseline declarations](../tools/fixtures/sdk/forum-explicit.rs) |

The explicit equivalents are maintained independently. They use the same crate
and module identities during comparison, including deterministic generated query
names. Exact JSON contracts must match, so the same canonical fingerprint
algorithm receives identical inputs. No policy or scope fields are removed from
the comparison and identifiers are not normalized away.

## Expansion

1. Inspect immediate declarations in the supplied inline module token stream.
2. Consume the resource owner shorthand, retaining its explicit persistent key.
3. Lower `List<R>` and `Read<R>` to existing owner query expansions and rewrite
   handler inputs to `Query<GeneratedQuery>`.
4. Lower named CRUD entries and single-operation actions to one-step transactions.
   Derive typed inputs from the listed field schemas; preserve policies, redirects
   and optional hooks. Explicit transactions declare inputs and ordered assignments
   directly. Both forms use the same host executor.
5. Collect pages, actions, and layouts in canonical order and invoke existing
   application expansion. Expose `noxide_manifest()` at crate root for build-time
   metadata extraction and emit the existing component export.

Queries have one deterministic name per operation/resource within the module.
CRUD action names are supplied by the developer; operation kinds may repeat. Each
entry lowers independently through the same action implementation, with its own
policy, inputs, steps, revision requirement, redirect, hooks and layout. Collisions produce compilation
errors. Meaningful order, including resource fields and form layouts, is retained.
The macro neither reads files nor analyzes function bodies.

## Authority and identity

`owner` supplies a default policy, not an invariant on all resource access.
Public reads continue requiring explicit visibility and projected fields. Existing
action policy restrictions apply unchanged. A resource addition alone grants no
operations; page signatures and explicit mutations declare the requested authority.
The operator approves the generated contract and the host checks actual calls.

Action transaction contracts replace the previous writable-field and guest-mutation
model. Approval digests and receipt storage change; development databases must be
recreated. No compatibility or identity migration layer is provided. Wrapping an
application in a new module changes namespace-derived IDs and requires reapproval. Persistent resource keys are explicit;
field keys may be inferred. Changes to inferred keys are detected as schema
changes and require the existing explicit schema-change workflow.

## Validation

`tools/test_sdk_api.py` compiles the examples, explicit equivalents, and negative
fixtures locally in routine CI, with an optional disposable VM backend. It compares
complete generated contracts, verifies independent item reordering, checks explicit versus default
owner policy, and ensures adding fields does not widen action projections.
The same job checks public field exclusion, missing visibility/projection,
conditional declarations/hooks, and invalid shorthand. Its multi-resource policy
matrix covers tenant/role compositions, anonymous create, capability mutations,
and separate create/update field projections. Reordering resources, queries,
pages, and CRUD blocks must preserve the entire contract and approval hash.
Repeated-action fixtures cover two creates, three updates, two deletes, independent
hooks and layouts, raw identifiers, and ordinary/parent redirects. Frozen forum
fixtures isolate pure shorthand conversion from intentional layout changes.
Adding a query must retain every existing operation and policy; removing a form
must change only its route binding. Cross-resource mutation forms and forms on
strictly public routes must fail host admission.

The CLI-generated starter is also snapshotted and built with the selected backend,
including its generated Cargo manifest and native contract collector. Its complete contract
and approval hash must match the independently reviewed notes example. CLI tests
verify destination protection and reject invalid names and symlinks. The snapshot
ignores a regular `.gitignore` without reading it; other hidden source inputs
remain rejected.

The usual packaged SDK job builds private notes from Cargo archives, and the
host security suite exercises admission, ownership, anonymous projections, CSRF,
replay, transaction rollback, escaping, and runtime budgets. The public example
also receives its own build, component admission, and HTTP acceptance test
through `tools/test_public_app.py`, including seeded published/unpublished records
and a private field excluded from both queries. These checks are
local evidence, not a claim of an independent security audit.

## Review notes

The implementation review covered declaration discovery, policy defaults,
route/action bindings, field projections, contract identities, macro diagnostics,
and starter file output. Layout registration now retains parsed action types so
valid raw action identifiers cannot panic the macro. Read shorthand rejects
unrelated qualified `List`/`Read` types rather than silently assigning framework
capabilities to them. Starter creation refuses existing destinations, and the
builder never transports its regular `.gitignore` into the VM.

Focused regressions exercise these fixes and the generated starter. Local
SQLite/PostgreSQL coverage includes fresh role authorization, quota races, and
receipt recovery; the SDK suite compares complete contracts and approval hashes.
Browser smoke tests and remote CI are separate checks. These reviews and local
checks do not constitute an independent security audit.

## Implementation modules and frozen baselines

See [architecture layers](architecture/layers.md) for enforcement ownership.
`noxide-macros/src/lib.rs` contains entry points and result conversion;
`syntax.rs` holds shared type and key checks, and `registration.rs` assembles the
application. `declaration/` owns operation parsing and explicit resource, query,
action, policy, page, choice and template expansion. `convenience/app.rs` discovers
immediate declarations and associates hooks; `crud.rs` lowers each named action
independently and `inferred_queries.rs` rewrites supported read arguments through
the explicit query expander. No declaration module depends on convenience code.

The SDK harness compares complete JSON and approval digests against the transaction
contracts in `tools/fixtures/sdk/baseline`. These snapshots were updated for the
declared transaction protocol, including operation reference eligibility, action
input schemas, assignments, revision requirements and navigation sources. Notes,
task board, public articles, repeated actions and both forum contracts retain their
resource identities, policies, ordering and layouts. The laid-out forum has a
separate explicit counterpart. Future refactors must preserve these baselines;
intentional contract changes require explicit review.

## Action decisions and transactions

`ActionType::operations()` and `resources()` expose the finite declarations needed
by every step. Registration collects all step resources and operations, plus any
inspection read. `ActionType::definition()` returns the same canonical `Action`
regardless of convenience syntax. The protocol contains action-level `Input`
schemas, `Revision`, `Step`, `Assignment`, and `Change`; no single-operation action
fields or guest mutation callback remain.

A handler returns `Result<Execute<A>, ActionError<A>>`.
`Submission::execute()` constructs the decision without a storage call. Without a
handler registration returns that decision directly. The host supplies immutable
canonical input and authorized inspection, then executes the approved steps after
`Execute`. Route storage imports are unavailable during actions.

The explicit `transaction(...)` syntax supports `set`, `increase`, `decrease`,
required guard rejections and references to `target` or named earlier creates.
Updates and deletes target the signed record; adjustments appear only in updates.
`revision = identity` is explicit; lowering otherwise chooses `Exact`. The host
independently checks that the declaration is strong enough. Input fields and
controls are generated once even when several steps consume the same input.

See [shop](../examples/shop/src/lib.rs) and the
[transaction contract](architecture/transactions.md) for the three-step example
and the host's admission, rollback, replay and budget rules.
`tools/test_shop.py` exercises the built component through HTML forms: product
creation, the three-step order and note, receipt replay, and stock rejection from
a distinct preissued identity form. These implementation
and test descriptions do not establish audited security or transport anonymity.
