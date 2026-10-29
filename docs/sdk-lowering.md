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
4. Lower named CRUD entries to existing action expansions. Preserve explicit
   field projections, policies, redirects, and optional hooks.
5. Collect pages, actions, and layouts in canonical order and invoke existing
   application expansion. Expose `noxide_manifest()` at crate root for isolated
   metadata extraction and emit the existing component export.

Queries have one deterministic name per operation/resource within the module.
CRUD action names are supplied by the developer. Collisions produce compilation
errors. Meaningful order, including resource fields and form layouts, is retained.
The macro neither reads files nor analyzes function bodies.

## Authority and identity

`owner` supplies a default policy, not an invariant on all resource access.
Public reads continue requiring explicit visibility and projected fields. Existing
action policy restrictions apply unchanged. A resource addition alone grants no
operations; page signatures and explicit mutations declare the requested authority.
The operator approves the generated contract and the host checks actual calls.

Existing identity algorithms are unchanged. Wrapping an older application in a
new module changes namespace-derived IDs and requires reapproval. No compatibility
or identity migration layer is provided. Persistent resource keys are explicit;
field keys may be inferred. Changes to inferred keys are detected as schema
changes and require the existing explicit schema-change workflow.

## Validation

`tools/test_sdk_api.py` compiles the examples, explicit equivalents, and negative
fixtures inside a disconnected disposable VM. It compares complete generated
contracts, verifies independent item reordering, checks explicit versus default
owner policy, and ensures adding fields does not widen action projections.
The same job checks public field exclusion, missing visibility/projection,
conditional declarations/hooks, and invalid shorthand. Its multi-resource policy
matrix covers tenant/role compositions, anonymous create, capability mutations,
and separate create/update field projections. Reordering resources, queries,
pages, and CRUD blocks must preserve the entire contract and approval hash.
Adding a query must retain every existing operation and policy; removing a form
must change only its route binding. Cross-resource mutation forms and forms on
strictly public routes must fail host admission.

The CLI-generated starter is also snapshotted and built in this VM, including
its generated Cargo manifest and native contract collector. Its complete contract
and approval hash must match the independently reviewed notes example. CLI tests
verify destination protection and reject invalid names and symlinks. The snapshot
ignores a regular `.gitignore` without reading it; other hidden source inputs
remain rejected.

The usual packaged SDK job builds private notes from Cargo archives, and the
host security suite exercises admission, ownership, anonymous projections, CSRF,
replay, transaction rollback, escaping, and runtime budgets. The public example
also receives its own VM build, component admission, and HTTP acceptance test
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

Focused regressions exercise these fixes and the generated starter. Full Firefox
and PostgreSQL validation, and remote CI execution, remain deferred. The review
and local checks do not constitute an independent security audit.
