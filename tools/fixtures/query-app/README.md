# SDK query fixture

This trusted fixture exercises the explicit public SDK through the normal CLI
and native GET forms. It uses private owner documents, token-AND Arabic/mixed
script search, immutable rank ordering with ID ties, scalar ranges, a Boolean
filter, and Count/Sum/Min/Max. `/statistics` grants aggregate operations while
registering their source List only as metadata.

Use new output directories and a dedicated empty PostgreSQL database. The harness
retains failures and never resets a database or removes previous artifacts.
Production P09 admission must be enabled before the normal CLI build can pass.

```sh
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
target/debug/noxide build --framework "$PWD" --app tools/fixtures/query-app --name query-app --output "$RUNNER_TEMP/noxide-query-bundle"
python3 tools/test_query_http.py --bundle "$RUNNER_TEMP/noxide-query-bundle" --output "$RUNNER_TEMP/noxide-query-sqlite" --host-cli target/debug/noxide
python3 tools/test_query_http.py --bundle "$RUNNER_TEMP/noxide-query-bundle" --output "$RUNNER_TEMP/noxide-query-postgres" --host-cli target/debug/noxide --postgres "$NOXIDE_QUERY_POSTGRES"
```

The harness creates synthetic accounts and records through host actions, checks
canonical equivalent tokens and authenticated cursor scopes, reads a filtered-out
record through its independent Read operation, and checks exact/empty aggregates
and typed sum overflow. Every GET compares complete persisted record, receipt,
posting and search-state digests. An explicit approved label-only contract update
restarts the same fixture and rejects the previous contract's cursor without
resetting data. `result.json` records successful checkpoints; HTML, logs and
`get-checkpoints.json` remain available on failure.

The harness checks HTTP form behavior without client scripts. Browser-engine and
broader team-document/membership/expiry acceptance are separate gates. The lockfile is
copied from the reviewed blob fixture with only its root package name changed.
