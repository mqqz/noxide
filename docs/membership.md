# Membership preparation

Status: disabled P07 leaf modules. The production module roots do not register
these files. There is no enabled `ExistsRelated` predicate, SDK declaration, or
membership-authorized application in this checkpoint. The
[capability expansion contract](architecture/capability-contracts.md) and
[security contract](architecture/runtime.md#security-contract) govern integration.

`noxide-protocol/src/membership.rs` defines the proposed specialized declaration:
one membership resource, its immutable resource-reference field, its immutable
account field, and at most four literal Boolean/Choice conditions. The reference
matches the protected row's identity or one named immutable reference on that
row. The account always matches the authenticated current principal. An operation
may declare at most two membership predicates. Conditions use a sorted map and
typed values; there are no nested policies, recursive joins, arbitrary expressions,
caller-selected accounts, or membership-row read/list grants.

`noxide-host/src/membership.rs` independently validates these shapes against
resource schemas. Its lookup returns only Boolean witnesses, in protected-row
order. It requires a nonempty principal tenant and a canonical account identity.
The provider checks the current account is active and that its tenant, membership
tenant, protected tenant, and principal tenant match. The current deployment
contract/incarnation/generation is checked inside the query. Existing global and
tenant roles retain their separate semantics; this module does not change them.

One request attempt owns its witness map and a typed `AttemptTime`. The host must
obtain that value through the lifecycle freshness guard. Every retry constructs a
new map. A batch has at most 64 protected rows; one query resolves all distinct
uncached reference keys. Duplicate memberships do not duplicate results. The map
holds at most 128 scoped witnesses, including denials, and checks capacity before
querying. Its key includes the admitted declaration, storage resource and full
deployment fence. Database work uses the existing transaction deadline and debits
the caller's shared database-call allowance. Cache reuse never changes the fixed
attempt time. Integration must clear the map after **every** mutation step.

The provider uniqueness helper creates a partial unique index for the canonical
`(reference, account)` tuple on one storage resource. It compares two scalar
columns directly, avoiding ambiguous concatenation. The database belongs to one
deployment; the index is stricter than tenant-partitioned uniqueness and rejects
the same tuple even with another stored tenant. Status, role and owner do not
partition it: a revoked or historical membership still occupies its tuple.
Distinct accounts and references remain possible. Canonical validation rejects
alternate reference encodings and invalid account encodings before creation.
Schema activation must validate canonical existing records and reject historical
duplicates before reconciling this index. This checkpoint provides DDL and tests;
it does not install schema-management hooks or add storage migrations.

Final create authorization must evaluate the fully resolved proposed row. The
workspace bootstrap is a workspace create followed by membership create with
the created workspace reference, current principal account, and literal initial
admin role. P04 must supply those assignments and final proposed-row policy
evaluation. Existing membership-row ownership grants no role-management authority.
Managing members uses the declared admin policy for that workspace; an ordinary
member cannot grant themselves an admin role. No empty-row owner shortcut is
implemented here.

## Verification and remaining integration

The focused tests register only the two new module roots in a disposable copy.
They execute the production transaction code against real SQLite and PostgreSQL.
They compare SQL results with a separate stored-row predicate check, exercise
both protected identity and protected-reference matching, and cover inactive or
wrong-tenant accounts, other accounts, wrong tenants, wrong deployment/storage
scopes, historical duplicates, revoked/status-expired rows, mutation invalidation,
batch/call/cache bounds and provider-enforced uniqueness. The PostgreSQL test
creates and drops its own fixture database and fails if its provider URL is
absent. No skipped provider test is counted as successful evidence.

The literal `status = expired` test proves Choice-condition behavior. It does
**not** prove resource temporal expiry. The current baseline has no timestamp
field or resource expiry declaration. Requiring typed attempt time alone cannot
enforce expiry. No substitute expiry flag is introduced.

Before enabling this feature, integrate all of the following together:

- Protocol/root registration, manifest admission and approval hashing, plus
  explicit SDK lowering and forged-manifest tests.
- P03 named immutable references, storage ID resolution and reference integrity;
  P04 timestamp fields, resource expiry and proposed-row authorization.
- The existing policy interpreter and parameterized SQL, plus every ordinary
  read/list/follow/navigation/inspection/mutation path. Existing public gates may
  constrain public authority only; an independent private read stays independent.
- Batched preparation in existing list/follow paths, shared budgets, per-step
  invalidation and a fresh witness map on every retry. Index admission/reconciliation
  must support the specialized lookup without introducing a second query engine.
- Lifecycle expiry filtering on protected rows and membership witnesses using
  the one fixed attempt watermark, failing closed when freshness is unavailable.
- Schema preflight and provider index reconciliation, bootstrap/admin-management
  application proof, SQL/direct policy parity, negative authority tests and the
  independent combined P04/P07 review.

Service/job authority remains unavailable until P10. These leaf tests do not
establish integrated P07 completion, deployment acceptance, audited security,
query performance, or transport anonymity.
