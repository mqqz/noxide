# Bounded search, ordering and aggregates

Wire11 defines portable token-AND search, scalar ordering, ranges and exact
aggregates. Storage13 adds normalized search metadata and postings. These extend
the existing query executor and shared authorization.

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
The host registers the tokenizer with an exact compiler/table guard. Bounds are four
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

Ordinary aggregate execution examines at most1,000 candidates plus one bounded
lookahead. Search aggregates share the request's256 search-candidate frontier
with lists/previews/pickers. Hidden or expired rows never contribute. Incomplete
execution returns typed `LimitExceeded`, without a partial value. Sum requires
checked i128 host accumulation and final checked i64 conversion. Runtime work must
use the existing request deadline/cancellation owner, with no timer or
counter reset. Operator rebuild requires the transaction's explicit operator token.

Protected/order metadata stays once in nx_records alongside minimal postings.
Exact-scope/scalar-order plans seal a bounded ordered record frontier before
token-AND; broad creation-order plans seal posting candidates. Empty pages
with continuation are possible; no scan-until-match or corpus-wide grouping before
LIMIT is permitted. Existing eight index-shape accounting and baseline query measurements,
including the known moderator=false ~100,021 visits, remain unchanged.

Cursor authentication binds canonical normalized search tokens, range/order/
mode and every existing principal/scope/contract/incarnation parameter. Browser
query inputs retain their1,024-byte raw limit; one opaque cursor has the existing
2,048-byte token allowance separately, with a3,080-byte combined raw ceiling.
Encoded controls and padding cannot borrow cursor space. Existing stricter
field, record, URI, statement and deadline limits apply before larger search bounds.

`QueryForm::new(RouteRef)` renders a native GET form whose controls come from the
declared destination query. Supply canonical nonsearch parameters; omit search
prefill for a blank search control. The host resolves the local action path,
escapes labels/values, shares the existing form-count bound and omits cursors.
An aggregate-only route derives parameter metadata from its source without
granting an independent List invocation. See the
[SDK fixture](../../tools/fixtures/query-app/src/lib.rs) and
[normal CLI/HTTP walkthrough](../../tools/test_query_http.py).

After approving a configuration, initialize the fresh database and run
`noxide schema indexes CONFIG` before serving. Native index verification checks
the approved owning table, expressions, key order, collation and predicates.
New empty search resources acquire a ready index state; populated resources
require explicit `AddSearchIndex`, `RebuildSearchIndex` or `RemoveSearchIndex`
schema operations. Rebuilds use the original operator transaction/deadline and
bounded pages; invalid data or index bounds roll back records, postings, state
and schema history together. Schema transformations touching already indexed
text maintain that derived index in the same transaction. Unrelated fields do
not trigger a rebuild. Existing storage12 databases require a separately reviewed
migration or an explicit new development database; no database is reset silently.

The postings adapter serializes compact `[field,"token"]`
pairs, with common metadata bound separately. Its worst-case JSON payload is
47,105 bytes: seven framing/separator bytes per 2,048 pairs, 32,768 token bytes,
and one final byte. It requires a supplied work checkpoint before work, every 64
pairs and after serialization. This payload bound does not establish physical
storage/write bytes, provider plan visits or runtime budget fit. Tests exercise all 2,048
pairs without truncation, cancellation failure and handwritten Unicode payloads.

The aggregate module `query_plan/aggregate.rs` visits every seeded candidate once,
including nonmatching/hidden candidates, and accepts typed operands only after the
caller authorizes them. Its local search cap cannot exceed 256 and grants no new
shared allowance. It exposes no partial-value getter; only proven source exhaustion
can finish successfully. The ordinary 1,001st lookahead poisons prior arithmetic.
Search must never issue an extra 257th candidate beyond the shared request cap;
without independently proven completion it returns `LimitExceeded`. All failures
remain terminal for that scan. Empty count/sum are 0, empty extrema are typed None,
and checked i128 sum converts to i64 only at successful completion.

The index registry now pins Records/Postings owning table, equality prefix,
numeric/binary scalar ordering and stable ID tie in a canonical shape hash.
Record index names intentionally change with that complete shape. A single
physical `nx_search_tokens` index consumes one of eight shapes for each searchable
resource; it is not recreated per resource. Schema consumers use expected
provider-specific DDL and verify actual table/namespace/column/expression/order/
collation/predicate/validity. String-generation tests
do not prove native index correctness or provider plan efficiency.

Scalar keysets validate the signed storage ID domain, exact scalar representation
and canonical field domain before binding. SQL compares scalar then ID in the same
direction, with numeric casts or explicit C/BINARY ordering. Dynamic range bounds
are validated together before parameters are appended; no endpoint arithmetic is
used. Mutable LiveView ordering can omit or repeat a row when another request
moves its sort key across a cursor. That behavior is explicitly chosen by the
declaration; immutable ordering prevents those key moves.

Tokenizer/index construction requires the caller's mutable checkpoint:
`canonical_query(text, &mut checkpoint)` and
`indexed_record(values, max_bytes, &mut checkpoint)` return `anyhow::Result`.
Typed input-limit errors remain downcastable, and request/operator checkpoint
errors propagate unchanged. There is no unchecked production wrapper; infallible
wrappers exist only in the test module. Preflight checks decomposed scalars before
normalization reorder; normalization/splitting poll within 64 scalars, full-string
lowercase polls before and after, and dictionary/posting preparation polls bounded
groups. Failure injection at every reachable boundary returns no query/postings.
The callback type and pure tests do not prove real host ownership: every
production call site must pass the existing required RequestScope
checkpoint or a valid OperatorCheckpoint from its bounded transaction.

The bounded posting frontier factors the existing conservative list-merge cutoff:
at most four ordered streams of 64 raw seeds, validated signed identities and
incarnation/revision facts. It seals the earliest saturated-stream boundary in
ascending order (latest in descending order). Rows fetched beyond that boundary
are deferred; an empty authorized page must not advance past them. Aliases merge
as identities but remain in raw/planned work, without refunds. The helper requires
a work checkpoint and creates no counter. Runtime must charge the original shared
request's planned window before SQL and advance only through fully consumed seeds.

Opaque internal facts are limited to aggregate/search candidate policy and expiry.
Their host-computed spec includes every policy OR branch, expiry, gate reference,
scope, visibility, selection, scalar range/order and approved aggregate operand.
Protected native identity/owner/tenant/incarnation/revision remain separate from
guest fields. Required selected keys must all exist; optional absence retains its
canonical empty-string representation rather than a fabricated default.

Facts bind the exact declaration/contract, principal, spec identity and a private
attempt/mutation epoch. New attempts, principal mismatches and mutation invalidation
reject old facts. Witness-only eviction creates no row mutation and preserves the
epoch. The existing policy/expiry formula is factored once; ordinary full-row
authorization still performs complete canonical field validation. Visibility,
parent gates, scope and selection remain their existing repository checks, and
must all finish before operand/count/output. Partial policy success is never a
Read grant and the facts API cannot produce Record/StoredRecord or serve Create,
Read, Update or Delete purposes.

Facts rely on the invariant that host writes and operator activation maintain
canonical stored rows. They validate all eligibility inputs, but cannot assert the
validity of omitted business data after out-of-band database corruption. The full
row validator still rejects such corruption. Pure spec/ordinary-predicate tests do
not prove membership, gate, durable expiry, SQL equivalence or aggregate budget fit;
those properties require differential provider tests.
