# Private inbox feasibility

The existing public explicit SDK cannot safely express the complete inbox below.
This exercise adds no authority and registers no broken application in CI.

## Acceptance cases and retention

An authenticated sender creates a message addressed to one validated recipient.
Only that sender and recipient may read it, through both direct URLs and lists.
Unrelated users must neither discover nor read it. The recipient must identify an
existing eligible account and cannot be reassigned through an ordinary edit.
The minimal proposed retention rule is immutable messages with sender-only hard
deletion; deletion removes access for both parties. Recipient deletion, delivery,
notifications, attachments and time-based expiry are outside this exercise.
This is neither email-grade delivery nor end-to-end encryption.

## Attempt using explicit declarations

The owner-only portion can use existing declarations, without `#[app]`, CRUD or
inferred queries:

```rust,ignore
#[derive(noxide::Resource)]
#[resource(key = "messages")]
pub struct Message {
    #[id] id: noxide::Id<Self>,
    #[field(max_bytes = 128)] recipient: String,
    #[field(max_bytes = 4096)] body: String,
}
#[noxide::query(list(Message), allow = owner)]
struct SentMessages;
#[noxide::query(read(Message), allow = owner)]
struct SentMessage;
#[noxide::action(create(Message), fields(recipient, body), allow = owner, redirect = show_message)]
struct SendMessage;
#[noxide::action(delete(Message), allow = owner, redirect = index)]
struct DeleteMessage;
```

The owner-only sketch was compiled in a standalone temporary Cargo consumer
with explicit `index` and `show_message` pages and `noxide::application!`
registration (`cargo check --manifest-path
/tmp/noxide-inbox-owner-probe/Cargo.toml --offline`, passed). It used the public
SDK, no shorthand, no inferred queries and no added authority. The temporary
consumer is diagnostic evidence rather than a shipped example.

This is a declaration sketch, not a working private inbox. Explicit pages would
accept `Query<SentMessages>` and `Query<SentMessage>` and register with
`noxide::application!`. Ordinary Rust helpers can validate message text and build
layouts. No update action is declared, so existing action projection checks
prevent changing recipient or body after creation.

The `recipient` string is untrusted text, not a validated account reference. It
grants no recipient access. Giving the read operations public access and filtering
in the handler would violate the acceptance cases.

## Exact blockers

[`noxide-protocol::Predicate`](../../crates/noxide-protocol/src/lib.rs) contains only `Public`, `Capability`, `Owner`,
`SameTenant` and `Role`. The host's [`policy::bind`](../../crates/noxide-host/src/policy.rs) binds ownership to the current
user ID and tenant membership to the current user's tenant. Neither compares the
principal with an admitted recipient field. `Capability` is a dedicated mutation
grant, not a recipient read predicate. Combining existing atoms cannot express
sender-or-recipient row access while excluding unrelated users.

`FieldKind::Parent` refers to an application resource and its admitted visibility
and creation constraints. It does not refer to the host account directory.
`FieldValue` decodes typed resource IDs and scalar values; a bounded string cannot
prove recipient existence or eligibility. The public guest `Context` has no
account-lookup authority. A per-conversation tenant, global recipient role or
operator SQL per message would change the model rather than solve these blockers.

## Smallest candidate primitive for a later change

Investigate one immutable, host-validated account-recipient field and one explicit
read-policy predicate comparing that field to the authenticated principal. Retain
owner as sender and combine owner-or-recipient using the existing policy disjunction.
This is a candidate requiring separate design approval, not implemented syntax.
Avoid introducing generalized references, arbitrary expressions or multi-resource
transactions to solve this single case.

The protocol would need to represent the account binding and predicate explicitly;
the host would independently admit eligible field/policy combinations, validate
recipient identity at create time and enforce the same comparison in parameterized
list filtering and direct row authorization. Account lookup must use bounded,
indexed host work within the request deadline and database-call budget, with no
network or guest SQL. Define account deletion/disable semantics and account-ID
reuse before implementation. Validation errors must avoid enabling unrestricted
account enumeration. Immutable recipient binding must survive replay, recovery,
restart and ordinary upgrades.

Required negative tests include forged account strings/IDs, nonexistent or
ineligible recipients, unrelated direct reads and list/cursor discovery,
cross-account cursor reuse, forged manifests and direct guest calls, attempted
recipient reassignment, owner/recipient account disablement, account-ID reuse,
concurrent deletion, duplicate submission and lost-response recovery. Both SQLite
and PostgreSQL must enforce the same rules within query and output limits.

## Classification

| Finding | Classification |
| --- | --- |
| Repeated layout and body validation helpers | SDK inconvenience; ordinary Rust helpers suffice |
| Sender-or-recipient reads in direct and list operations | Missing host-enforced capability |
| Validated immutable recipient identity | Missing host-enforced capability |
| Message length, empty-body rejection, labels and page composition | Application behavior using existing bounds and helpers |
| Sender-only hard deletion | Existing owner delete action |

No safe full inbox is claimed. The safe owner-only subset proves only sent-note
storage; it does not meet recipient delivery or recipient-read acceptance.

## Implementation follow-up

The blocker analysis above records the original exercise. The implementation in
[`examples/private-inbox`](../../examples/private-inbox/) now uses `AccountId`,
explicit `scope = same_tenant`, and `principal_is(recipient)` composed with owner.
See the [account-reference API](../application-api.md#account-references-and-principal-policies)
and [identity lifecycle contract](runtime.md#account-identity-and-bindings).
The original string-recipient sketch remains diagnostic history, not the current
implementation. Database and real-component validation results must be reported
separately; a compiled example alone does not prove the acceptance cases.
