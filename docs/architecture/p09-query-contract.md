# P09 wire11 contract checkpoint

This checkpoint defines declarations and SDK lowering. P09 query extensions are
rejected by host admission until the executor, schema, work checkpoints and cursor
bindings are complete. Blob runtime remains denied. Wire11 is allocated; storage13
is reserved by C, not enabled/migrated. These contracts do not establish provider or runtime acceptance.

`protocol/query.rs` defines resource search declarations, list search/range,
scalar order direction and immutable/live-view mode, explicit inference
disclosures, aggregate source/function/outcome, and created/scalar cursor keys.
Resource search fields and query disclosure sets are sorted for canonical hashing;
duplicates fail admission. Existing fields default to mutable, except intrinsic
Reference/Account/Blob immutability. `initial` does not imply immutable. Macro
update checks, host assignment admission and repository mutation validation enforce
explicit immutability independently.

`#[resource(search(fields(body,title),max_bytes=4096))]` lowers Rust field names
through their canonical resource keys. The tokenizer identity pins Unicode17,
normalization/category crate versions and Rust1.98 full-string default lowercase.
The previously reviewed tokenizer leaves remain unregistered. Bounds are four
fields,16KiB indexed raw text,64KiB normalization stages,512 distinct strings,
2,048 deduplicated field/token postings and32KiB posting token bytes. Query input
is4KiB, stages8KiB, eight occurrences before deduplication and64 scalars/token.
Preflight rejects more than63 decomposed nonstarters before normalization reorder.
Every excess rejects; no truncation is permitted.

List declarations support `search(fields(body),parameter=terms)`,
`order=field(rank,ascending,immutable)` and
`range(rank,lower=inclusive(-10),upper=exclusive(param(max)))`. Range keys must be
the ordered scalar. Required Text order keys are bounded to512 UTF8 bytes with
C/BINARY ordering; numeric keys must fit i64. Mutable order requires explicit
`live_view`, with stable record-ID ties. Public unprojected search/order/range
inference requires exact `disclose_search`, `disclose_order`, `disclose_range`.
Existing Bool/Choice filters retain their original disclosure semantics.

`count(Base)`, `sum(Base,score)`, `min(Base,at)`, `max(Base,rank)` refer to a direct
List registered as metadata. The aggregate envelope must match its source's
resource, policy, scope, selection, projection and visibility. Its own query
declaration contains only aggregate source/function and aggregate disclosure.
Public aggregate inference always requires `disclose_aggregate`. Aggregate SDK
uses a distinct `AggregateQuery` trait and `Aggregate<Q>` wrapper with one Context
invocation; it has no fabricated row-ID/row-conversion methods. A count-only page
grants only the aggregate operation; base metadata grants no row invocation.

Ordinary aggregate execution must examine at most1,000 candidates plus one bounded
lookahead. Search aggregates share the request's256 search-candidate frontier
with lists/previews/pickers. Hidden or expired rows never contribute. Incomplete
execution returns typed `LimitExceeded`, without a partial value. Sum requires
checked i128 host accumulation and final checked i64 conversion. Runtime work must
use the existing repaired request deadline/cancellation owner, with no timer or
counter reset. Operator rebuild requires the transaction's explicit operator token.

The first repeated-facts postings DDL draft is withdrawn:16KiB copied to2,048 rows
would materialize32MiB per record before index overhead. Recommended replacement
keeps protected/order metadata once in nx_records and uses minimal postings.
Exact-scope/scalar-order plans seal a bounded ordered record frontier before
token-AND; broad creation-order plans seal posting candidates. C approved this fixed-plan direction; runtime acceptance still requires
both-provider100k measurements. Empty pages
with continuation are possible; no scan-until-match or corpus-wide grouping before
LIMIT is permitted. Existing eight index-shape accounting and P00 measurements,
including the known moderator=false ~100,021 visits, remain unchanged.

Central requests and unexecuted minimal SQL and withdrawn repeated-facts design evidence are recorded in
`target/capability-evidence/p09-queries/p09-central-patch-requests.md` in the main
workspace. C owns schema/storage/init/index registry. D owns RequestScope and
transaction work guards, application/cursor transport and actual statement meter.
Cursor authentication must bind canonical normalized search tokens, range/order/
mode and every existing principal/scope/contract/incarnation parameter. No SQL,
HTTP, native-store or provider proof is claimed by this checkpoint.
