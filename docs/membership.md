# Membership and resource expiry

Canonical wire/admission, policy/SQL helpers, runtime read/mutation hooks, SDK
lowering, native schema enforcement, provider action/lifecycle tests, SDK
equivalence checks and a script-free HTTP example application are implemented.
Membership and expiry are not yet certified for activation in deployments. See
the [security contract](architecture/runtime.md#security-contract).

`ExistsRelated` declares one membership resource, one immutable resource-reference
field, an immutable account field matching the current principal, and up to four
literal Boolean/Choice conditions. Its reference matches either the protected
row's identity or one named immutable reference on that row. An operation has at
most two membership atoms. The schema and typed SDK independently check field
kinds, reference targets and canonical literal values. There are no recursive
policies, chains, arbitrary joins, caller-selected accounts or policy callbacks.

Lookup authority inspects only the declared existence/condition fields. It grants
no membership read/list operation and requires no such operation. The SDK
registers the membership schema as metadata. Existing owner, global-role and
tenant-role predicates keep their semantics. Membership-row ownership never
substitutes for the declared role-management policy.

Every witness requires the current active principal account, matching principal,
protected-row, membership and account tenants, and the current deployment fence.
Resource expiry applies both to the protected row and each membership witness.
Revoked/deleted/status-mismatched or expired memberships cannot authorize a new
operation. All conditions must match the same membership row; separate incomplete
rows cannot combine. Historical duplicates do not multiply an existence result.

One request attempt owns its authority context and fixed typed `AttemptTime`.
Witnesses are prepared for at most 64 candidate rows and two predicates at once,
with at most 128 retained witnesses. A single provider query resolves all distinct
keys for one predicate batch. The context reuses unchanged witnesses within the
transaction and clears them after every mutation or principal switch. Before a
batch it clears the map if the worst-case incoming keys would exceed 128. A retry
constructs a new context. A temporary anonymous picker
principal cannot inherit an authenticated witness. No cross-request/transaction
cache exists. Catalog reads and witness queries debit the existing shared DB-call
allowance and use the transaction's existing monotonic deadline.

Membership lookup indexes share the existing eight derived shapes/resource with
list indexes. The equality prefix is tenant, reference, account and canonical
condition-field order, followed by a numeric expiry range when present. SQL uses
the catalog-derived resource constant, enabling PostgreSQL partial-index proof.
EXISTS/LIMIT 1 avoids returning duplicate matches. Required index presence and
actual provider work remain activation and measurement requirements; one SQL
roundtrip alone is not evidence of bounded physical scan work.

Optional `unique(reference, account)` declares provider-enforced creation
uniqueness. There are at most four distinct tuples/resource. Two indexed scalar
columns preserve canonical identity without ambiguous concatenation. Resource
storage is deployment-scoped; status, role, owner and tenant do not partition the
unique tuple. Revoked or historical rows still occupy a declared tuple. Without a
unique declaration, historical duplicates remain legal and use the same bounded
specialized lookup. Schema activation validates canonical raw records and rejects
invalid encodings or newly prohibited duplicates, preserving operator data.

## Expiry and write horizons

A resource expiry declaration names a required canonical Timestamp field and an
explicit `max_after` Duration, at most 30 days. The typed SDK default is 30 days;
the emitted contract always contains the chosen bound for operator approval. A
deployment may lower it. Business timestamps without an expiry declaration are
unaffected.

The host checks a create or actual expiry-field change against
`expires_at <= attempt_time + max_after`, with checked arithmetic. Past/equal
expiry is valid and immediately invisible to ordinary operations. Updating other
fields without changing expiry does not revalidate against a newly lowered
horizon. Ordinary operations still cannot update an expired target to revive it.
There is no raw wall-clock sample in this check.

Ordinary visibility requires `expires_at > attempt_time`. Apply this to GET,
lists, follows, targets, inspection, navigation, reference eligibility and
mutations before data or guard disclosure. Future search/aggregate/download paths
must consume the same authority context. Expiry does not delete rows or release
inventory. No ordinary-route maintenance bypass is exposed; cleanup that accesses expired
rows requires separately admitted host maintenance authority.

The accepted lifecycle service supplies one durable watermark per attempt and
requires maintenance progress within five monotonic seconds. GET performs no
clock writes. Applications declaring expiry or membership conservatively require
fresh temporal admission for every attempt. Computed-action expressions and expiry
visibility share that same captured time. A new retry gets a new time; receipt replay does
not rerun original temporal guards. Current delivery authorization uses a fresh
read attempt. Public parent gates constrain public grants only; independent
private read grants retain their authority.

A public child read checks the gated parent's current visibility and expiry. An
independent Owner or Member child read keeps its own grant when the parent expires;
a follow to that parent must still deny because the parent itself is expired.
An Owner OR membership policy remains owner-readable after membership revocation
or expiry. A child List grant never substitutes for a parent Read grant.

Postcommit delivery uses the unspent portion of the existing total 16-call action
pool plus its already-deducted navigation reserve (four calls, or six for a gated
destination). Transferring those calls zeros the source. It does not add a new
allowance. Fresh delivery catalog, clock and membership work charges this same
pool; exhaustion after commit returns committed success/handover without claiming
a rollback. The existing fixed schema/admission envelope remains separately
bounded, and the original absolute deadline is retained.

Computed-action snapshots retain the initial approved read/projection values for that one
invocation. An earlier step cannot erase data already captured under that grant.
The declared flow may use those initial values after membership revocation or a
source expiry change; it does not reload or obtain a new source read grant.
Every later current-row read, guard authority check and mutation policy uses
fresh witnesses. A retry captures a fresh snapshot, and a later ordinary request
must independently authorize the source. Exact revision/review rules still apply.

## Explicit typed declarations

```rust,ignore
#[derive(Resource)]
#[resource(key = "memberships", unique(workspace, account),
           expiry(expires_at, max_after_seconds = 3600))]
struct Membership {
    #[id] id: Id<Self>,
    #[field()] workspace: Id<Workspace>,
    #[field(scope = same_tenant)] account: AccountId,
    #[field()] role: Role,
    #[field()] expires_at: Timestamp,
}

#[query(read(Workspace), allow = exists_related(Membership,
    reference = workspace, target = self_record, account = account,
    conditions(role = Role::Admin)))]
struct AdminWorkspace;
```

Use `target = reference(workspace)` when protecting a document with an immutable
workspace reference. Final proposed-row create authorization enables the approved
bootstrap: workspace create, then membership create with `Created(0)`, `Principal`
and a literal admin role. Membership-management actions require the workspace
admin policy; ordinary membership ownership cannot grant or change roles.

The SDK equivalence and compile-diagnostic tests check literal lowering, field
keys, identity/reference matching, metadata-only schema registration, unique tuple
and horizon declarations. Required same-tenant account action inputs lower to the
same explicit host input/operation metadata; missing or unsupported scopes fail
macro expansion. The submitted recipient is preserved.

The [team documents example](../examples/team-documents/README.md) bootstraps a
workspace and administrator membership in one real action, then uses active
membership to grant document access and an explicit administrator policy for
member management. Its actual SDK Wasm component passes the script-free HTTP
walkthrough against SQLite and disposable PostgreSQL. Provider action tests cover
native duplicate rollback and receipt recovery, cross-tenant recipients,
principal-owned membership denial, immediate expiry and stale lifecycle time.
Sequential tests preserve initial approved snapshots while requiring fresh
membership/expiry decisions for later mutations and CurrentField guards.

The exact production batch64 SQL has been measured against 100,000 unrelated rows,
100,000 wrong-role duplicates and 100,000 expired otherwise-matching duplicates,
without planner overrides. SQLite scanstatus reports 67 examined rows; PostgreSQL
EXPLAIN scan-node accounting reports 3. These provider metrics use different
instrumentation and are not a speed comparison. The specialized lookup, native
index activation and bounded shared budgets have dedicated provider regressions.
No deployment, audited-security or anonymity claim follows from local checks.
