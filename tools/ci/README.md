# CI coverage and build reuse

`PR checks` owns formatting, Clippy, lockfile validation, Python build-input
checks and shellcheck on every workflow event. Runtime does not repeat them.

On main, merge groups and manual/scheduled runs:

- Runtime runs non-host framework tests with two test threads. Executor shutdown
  runs separately; host/provider tests remain serial because they combine short
  production deadlines with contention and stress. Crash workers are invoked by
  their parent tests; browser fixtures run in the SDK job.
- Query index work has a separate job and cache for `query-metrics` and
  `SQLITE_ENABLE_STMT_SCANSTATUS` builds.
- A host CLI build supplies an artifact to separate SDK/browser and example
  application matrix jobs. Artifact transfer preserves bytes but requires chmod.
- Packaged CLI lifecycle builds archives into a fresh target directory, moves
  their extracted sources away, then runs the complete lifecycle against the
  detached binary. The generated app starts with an empty Cargo cache.
- Hostile build tests remain scheduled/manual and execute inside the build VM.

Caches include the runner OS/architecture, Rust version, job/matrix lane,
lockfiles, manifests and workflow configuration. Each revision saves a new cache;
subsequent revisions restore the latest compatible lane. Fresh archive consumer
builds and generated-project dependency caches are deliberately outside cached
paths. Cargo still validates restored artifacts against current sources.

Validate workflow edits with `actionlint .github/workflows/ci.yml`. Measure both
elapsed job time and total runner minutes after deployment: parallel jobs improve
feedback time but can increase aggregate compilation work on cold caches. Local
checks do not prove hosted timing or cache-hit behavior.
