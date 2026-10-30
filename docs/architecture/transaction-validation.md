# Transaction implementation validation

Validated locally on 2026-10-31. This records implementation evidence, not an
independent security audit, deployment acceptance or transport anonymity proof.
The browser tests route an onion-shaped test origin through a local proxy; they
do not test a real Tor or I2P connection.

## Checks

All required commands passed on the final implementation:

```sh
cargo fmt --all --check
rustfmt --edition 2024 --check examples/*/src/lib.rs
cargo build --workspace --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline -- --include-ignored --test-threads=1 --skip failure_tests::crash_worker
cargo doc --workspace --no-deps --locked --offline
for m in examples/*/Cargo.toml; do cargo metadata --manifest-path "$m" --locked --offline --format-version 1 >/dev/null; done
```

The complete workspace run passed 322 tests, with zero failures and zero ignored
tests. The crash-worker entry point was filtered as requested; the process-crash
tests invoke that worker themselves. PostgreSQL 18.6 ran in a disposable local
cluster. Both PostgreSQL browser tests ran with Firefox 158.0.1, geckodriver 0.36.0
and JavaScript disabled. The test environment supplied `NOXIDE_TEST_POSTGRES`,
`NOXIDE_TEST_COMPONENT`, `NOXIDE_TEST_MANIFEST`, `NOXIDE_TASK_COMPONENT`,
`NOXIDE_TASK_MANIFEST` and `NOXIDE_GECKODRIVER`, using locally built, trusted
private-notes and task-board components.

Additional checks passed:

- The SDK harness: generated starter, typed example, 36 compile-pass and 41
  compile-fail fixtures, contract equivalence and approval digests.
- Exact query contract verification: 19 serialized contracts.
- Trusted local builds of private-notes, task-board and shop.
- The actual shop component's HTML-form walkthrough on SQLite and PostgreSQL:
  create one unit, create an order and escaped first note, replay the receipt,
  reject another preissued order form, and verify zero remaining stock.
- Each code-stage snapshot passed workspace formatting, build and Clippy.

Initial runs exposed stale fixtures and assertions, which were migrated before
the successful final run. Sandboxed listener tests could not open sockets; their
successful rerun used local socket access. No security tests were removed,
skipped or weakened to obtain the final result. No required check remains unrun.

## Acceptance coverage

The provider-paired tests below live in
[`transactions.rs`](../../crates/noxide-host/tests/transactions.rs). Both the
`sqlite_` and `postgres_` variants ran.

| Specification item | Covering tests |
| --- | --- |
| Distinct orders compete for the last unit | `sqlite_last_unit_orders`, `postgres_last_unit_orders` |
| Concurrent submissions with one token converge | `sqlite_same_token_concurrency_and_recovery`, `postgres_same_token_concurrency_and_recovery` |
| Each step's failure, rejection, trap and deadline roll back mutations and claim | `sqlite_transaction_rollback_and_authorization`, `postgres_transaction_rollback_and_authorization`, `sqlite_transaction_revisions_and_guards`, `postgres_transaction_revisions_and_guards`, `sqlite_action_guest_failures`, `postgres_action_guest_failures` |
| Denial matches missing target; unauthorized guards stay hidden | `sqlite_transaction_rollback_and_authorization`, `postgres_transaction_rollback_and_authorization`; `capability_denial_reincarnation_and_missing_target_are_indistinguishable` |
| Two signed steps avoid self-conflict; later authority sees earlier writes | `sqlite_transaction_revisions_and_guards`, `postgres_transaction_revisions_and_guards`, `sqlite_transaction_rollback_and_authorization`, `postgres_transaction_rollback_and_authorization` |
| Exact conflicts, Identity orders and admission's minimum revision | `sqlite_transaction_revisions_and_guards`, `postgres_transaction_revisions_and_guards`; `transaction_admission_checks_revision_and_multistep_authority` |
| Arithmetic overflow, both bounds, extreme spans and invalid amounts | `transaction_adjustments_guard_overflow_and_both_bounds`, `transaction_adjustment_span_uses_i128_and_inputs_are_shared`, `transaction_input_canonicalization_enforces_quantity_and_byte_bounds`, both provider `transaction_revisions_and_guards` tests |
| Shared input appears once and has one canonical digest value | Both provider `same_token_concurrency_and_recovery` tests; `transaction_lowering_keeps_shared_input_and_created_step_identity` |
| Every listed admission rejection, including adjustments on creates | `transaction_admission_rejects_step_create_and_delete_combinations`, `transaction_admission_rejects_forward_wrong_and_constant_references`, `transaction_admission_rejects_duplicate_protected_and_missing_assignments`, `transaction_admission_rejects_undeclared_unused_duplicate_and_invalid_inputs`, `transaction_admission_rejects_create_unbounded_noninteger_and_invalid_adjustments`, `transaction_admission_checks_revision_and_multistep_authority`, `transaction_input_domains_fit_integer_text_choice_and_optionality` |
| All three action-time storage imports fail | `sqlite_action_guest_failures`, `postgres_action_guest_failures`; `sqlite_record_actions`, `postgres_record_actions` |
| Every specified contract change alters digest and invalidates tokens | `transaction_digest_covers_input_assignment_constant_order_guard_revision_inspection_redirect`, `sqlite_transaction_contract_changes_invalidate_tokens`, `postgres_transaction_contract_changes_invalidate_tokens` |
| Lost acknowledgement recovers outcomes/handover; destination authority is rechecked | `sqlite_failure_protocol`, `postgres_failure_protocol`, `committed_anonymous_create_recovers_original_secret_after_disconnect`, `postcommit_lookup_failure_and_deadline_preserve_handover`, both provider `same_token_concurrency_and_recovery` tests |

The admission tests are in `manifest.rs`, arithmetic tests in `repository.rs`,
input canonicalization tests in `noxide-protocol`, and SDK lowering tests in
`crates/noxide/tests/transactions.rs`. Failure and handover tests retain their
existing host modules.

## Intentional test migrations

Guest fixtures return decisions instead of performing mutations and constructing
outcomes. Forged guest outcomes are now rejected; the corresponding test is
`public_create_rejects_guest_outcomes_and_requires_an_edit_signing_key`.
Rejection-after-mutation fixtures now reject before the host executor runs.
Negative storage-import fixtures remain and include all three forbidden imports.

Stale Exact reference forms now expect 409; gate denial remains 404. Reference
binding itself no longer compares revisions. Revoked mutation authority, invalid
capability credentials, missing targets and changed incarnations produce the
same unavailable response and no mutation or receipt. Replaying a committed
mutation whose destination is no longer authorized returns the success fallback
without a Location header. Delete conflict tests retain their previously
authorized current-value assertions.

Tests that deliberately change resource schemas also change their action input
schemas, keeping their unrelated action contracts valid. Serialized contracts,
approval digests, cursor scopes and the expected framework storage version were
updated for the replaced protocol and storage format.

## Clarifications and implementation choices

The user approved four specification clarifications before their implementation:

1. Adjustments occur only in signed update steps; creates use Set.
2. Input carries `max_bytes`, because the existing Text kind has no byte bound.
3. Account inputs and Set assignments are permitted on creates, retaining active
   account and tenant-scope checks; account updates remain prohibited.
4. Initial values are host-applied on creates; authorized updates may change them,
   preserving forum moderation.

Redirects use an explicit route and `RedirectSource`; step indices are zero-based.
Named SDK create results lower to those indices. Reference eligibility is stored
on the create operation, and the SDK spells it `eligible = Query` within create.
Constants cannot supply reference IDs: SignedTarget and Created are the only
admitted reference sources.

The existing policy vocabulary cannot predicate on mutable ordinary scalar
fields. The later-authorization test therefore uses a create gate whose current
product state was changed by an earlier step, alongside two-signed-step tests.
No new policy vocabulary was introduced.

Stages 1–2 share a commit. Mechanical one-step SDK lowering, input-form adaptation
and fixture/example handler migrations accompany it to keep the protocol removal
compiling. Executor Created/adjustment semantics and their provider race tests
also landed together, rather than temporarily introducing another mutation path.
Separate commits add the expanded form parser, full transaction macro syntax,
shop walkthrough and final documentation. The parser permits at most 35 fields:
32 structurally possible action inputs plus three host controls; the existing
input-byte limit still applies. Framework storage version 10 rejects old receipt
layouts. The shop lockfile reuses the approved example dependency graph without
widening the dependency catalog.
