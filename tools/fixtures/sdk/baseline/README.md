# Frozen SDK contracts

Captured before production changes at PR #15 merge
`dca07b5015b6d24bc391c7e45cacc67ea0e7f767` using the trusted local SDK harness.
The first capture was `/tmp/noxide-refactor-baseline-sdk`; the independently
registered laid-out forum was verified in `/tmp/noxide-refactor-baseline-v2`.

JSON files are complete canonical manifests; approval-hashes.json contains the
host-computed approved contract digests. Do not normalize away identities,
policies, ordering, layouts or projections. `forum.json` preserves the pre-layout
conversion pair, while `forum-layout.json` represents the actual post-PR example.
The harness compares frozen -> shorthand -> explicit and checks approval hashes.

These are contract baselines, not Wasm binary hashes, deployment approvals,
wire-token ciphertext snapshots or proof of runtime security.
