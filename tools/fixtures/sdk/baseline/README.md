# Frozen SDK contracts

Captured with the trusted local SDK harness and re-recorded for the typed
reference protocol in PR #25. The SDK equivalence fixtures define the application
being compared; query-track snapshots may evolve independently. In particular,
`public-articles-simple.rs` is paired with `public-articles-explicit.rs`, while
`tools/fixtures/queries/public-articles.rs` covers newer query features.

JSON files are complete canonical manifests; approval-hashes.json contains the
host-computed approved contract digests. Do not normalize away identities,
policies, ordering, layouts or projections. `forum.json` preserves the pre-layout
conversion pair, while `forum-layout.json` represents the actual post-PR example.
The harness compares frozen -> shorthand -> explicit and checks approval hashes.

These are contract baselines, not Wasm binary hashes, deployment approvals,
wire-token ciphertext snapshots or proof of runtime security.
