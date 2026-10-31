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

The subsequent unregistered postings leaf serializes compact `[field,"token"]`
pairs, with common metadata bound separately. Its worst-case JSON payload is
47,105 bytes: seven framing/separator bytes per2,048 pairs,32,768 token bytes,
and one final byte. It requires a supplied work checkpoint before work, every64
pairs and after serialization. This payload bound does not establish physical
storage/write bytes, provider plan visits or runtime budget fit. The independent
leaf harness preserves root-locked registry identities and exercises all2,048
pairs without truncation, cancellation failure and handwritten Unicode payloads.

The arithmetic leaf `query_plan/aggregate.rs` visits every seeded candidate once,
including nonmatching/hidden candidates, and accepts typed operands only after the
caller authorizes them. Its local search cap cannot exceed256 and grants no new
shared allowance. It exposes no partial-value getter; only proven source exhaustion
can finish successfully. The ordinary1,001st lookahead poisons prior arithmetic.
Search must never issue an extra257th candidate beyond the shared request cap;
without independently proven completion it returns `LimitExceeded`. All failures
remain terminal for that scan. Empty count/sum are0, empty extrema are typed None,
and checked i128 sum converts to i64 only at successful completion.

The index registry now pins Records/Postings owning table, equality prefix,
numeric/binary scalar ordering and stable ID tie in a canonical shape hash.
Record index names intentionally change with that complete shape. A single
physical `nx_search_tokens` index consumes one of eight shapes for each searchable
resource; it is not recreated per resource. C schema consumers must use expected
provider-specific DDL and verify actual table/namespace/column/expression/order/
collation/predicate/validity. The temporary old consumer bridge is removed when
C switches atomically; it cannot render binary P09 shapes. String-generation tests
do not prove native index correctness or provider plan efficiency.

Scalar keysets validate the signed storage ID domain, exact scalar representation
and canonical field domain before binding. SQL compares scalar then ID in the same
direction, with numeric casts or explicit C/BINARY ordering. Dynamic range bounds
are validated together before parameters are appended; no endpoint arithmetic is
used. Mutable LiveView ordering can omit or repeat a row when another request
moves its sort key across a cursor. That behavior is explicitly chosen by the
declaration; immutable ordering prevents those key moves.

Tokenizer/index construction now requires the caller's mutable checkpoint:
`canonical_query(text, &mut checkpoint)` and
`indexed_record(values, max_bytes, &mut checkpoint)` return `anyhow::Result`.
Typed input-limit errors remain downcastable, and request/operator checkpoint
errors propagate unchanged. There is no unchecked production wrapper; infallible
wrappers exist only in the test module. Preflight checks decomposed scalars before
normalization reorder; normalization/splitting poll within64 scalars, full-string
lowercase polls before and after, and dictionary/posting preparation polls bounded
groups. Failure injection at every reachable boundary returns no query/postings.
The callback type and pure tests do not prove real host ownership: registration
requires every production call site to pass the existing required RequestScope
checkpoint or a valid OperatorCheckpoint from its bounded transaction.

The bounded posting frontier factors the existing conservative list-merge cutoff:
at most four ordered streams of64 raw seeds, validated signed identities and
incarnation/revision facts. It seals the earliest saturated-stream boundary in
ascending order (latest in descending order). Rows fetched beyond that boundary
are deferred; an empty authorized page must not advance past them. Aliases merge
as identities but remain in raw/planned work, without refunds. The helper requires
a work checkpoint and creates no counter. Runtime must charge the original shared
request's planned window before SQL and advance only through fully consumed seeds.
