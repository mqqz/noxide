# Reservations

This trusted proof app reserves inventory at the product price reviewed by the
customer. It uses native HTML forms without JavaScript. Prices and totals are
integer minor units. It takes no payments and sends no mail or network requests.

Build with `noxide build --app examples/reservations --name reservations
--framework . --output NEW_DIR`. Use isolated builds for untrusted application
code and dependencies. Configure the generated manifest/component and explicitly
approve the deployment before serving. Create two active accounts in the same
tenant: the product owner and a customer.

The owner creates a product and edits its price, currency and availability. A
customer reviews that product and submits a quantity from one to ten. The host
checks current stock, decrements it, copies the reviewed price/currency and
computes the total with checked multiplication in one transaction. A changed
product revision requires another review, including a concurrent stock change.
The separate stock-only host fixture retains its identity-only concurrency
contract; this app does not weaken price review to obtain that behavior.

The order records durable transaction time and expires fifteen minutes later.
Quantity, copied pricing, total and lifecycle timestamps are immutable fields;
there are no browser inputs for these authoritative values except the initial
bounded quantity. Resource expiry makes the order unavailable to ordinary reads
and mutations at its cutoff. The expiry timestamp is an application field with
host-enforced schema, assignment and visibility checks, not protected host creation
metadata. Guest code cannot supply the transaction clock.

Cancellation takes no quantity input. It requires the order owner in the same
tenant, checks the current pending status, changes it to cancelled and restores
the initially stored quantity to the product referenced by that order. Both
changes and the receipt commit together. A replay recovers the original receipt;
a second cancellation cannot restore stock again. Once cancelled, the page no
longer displays its cancellation form.

The distinct `Expire reservation` action has no browser binding or inputs. Its
`reservation_expiry` service identity receives explicit Service + SameTenant
policies, maintenance order Read/Update/List operations, a separate eligible
product Read and a guarded stock update. It derives the product from the order,
checks pending status and elapsed expiry, then changes status to expired and
restores the stored quantity. It receives no user identity or owner authority.
Stock-only updates occur exclusively in the reserve, cancel and expiry plans;
there is no independent stock binding or raw mutation import.

Each reservation transaction schedules one sealed job for its newly created
order and the referenced product. Its due expression exactly matches the stored
expiry expression. A recurring maintenance query supplies repair every sixty
seconds: creation order, a literal pending-status filter and expiry-repair
selection. The host persists its cutoff/frontier and seals each eligible target
with independent read authorization. Fanout is at most twenty per bounded batch
and may be lower under the existing request budgets. The pending-state guard
prevents overlapping one-shot and repair jobs from restocking twice.

Logical expiry hides an order immediately after the durable host cutoff.
Inventory remains reserved until a guarded cancellation or expiry job commits.
A delayed or revoked worker can therefore leave stock reserved after the order
page disappears. The product page explains this boundary. The app does not delete
expired orders or claim exact-time inventory release.

Configure a grant for the exact tenant and the expiry action ID from the manifest:

```json
{
  "jobs": {
    "grants": [
      { "worker": "reservation_expiry", "tenant": "alpha", "actions": ["REPLACE_WITH_NUMERIC_EXPIRY_ACTION_ID"] }
    ],
    "limits": {
      "pending_per_app": 100,
      "pending_per_tenant": 100,
      "worker_concurrency": 1
    }
  }
}
```

Replace the quoted placeholder with the numeric ID before validating the config.
Run `noxide deployment-hash RUNTIME.json`, review its requested/effective jobs and
store its `deployment_digest` as `approved_contract`. A manifest-only contract
hash does not approve the job deployment policy. Initialize a fresh store, then
run `noxide schema indexes RUNTIME.json` before serving. Operator commands such as
`noxide jobs inspect RUNTIME.json` and `noxide jobs worker-once RUNTIME.json` are
trusted local controls. They are not guest APIs or browser routes. Revocation
pauses captured work; regrant resumes recurring scans, while earlier paused
one-shots need explicit reconciliation. See the [jobs operations guide](../../docs/architecture/jobs-operations.md).

Run the NoJS harness with a built bundle, trusted host CLI and a new output path:

```sh
python tools/test_reservations.py --bundle BUNDLE --host-cli HOST_CLI --output NEW_OUTPUT
python tools/test_reservations.py --bundle BUNDLE --host-cli HOST_CLI --output NEW_PG_OUTPUT --postgres DISPOSABLE_LOOPBACK_DATABASE_URL
```

The default lane covers reviewed-price conflicts, authoritative totals, forged
inputs, owner/tenant denial, cancellation and receipt replay. Add `--await-expiry`
to run the actual fifteen-minute lifecycle lane. It revokes the worker before
expiry, observes the committed host watermark, proves hidden pending orders still
hold stock, reconciles one sealed job for operator `worker-once`, and proves the
recurring repair releases another order whose one-shot was explicitly cancelled.
Polling is bounded by committed state predicates. It does not rewrite timestamps,
change the production duration or add a clock bypass. The external harness has no
short deterministic fake-clock source; that faster gate requires the parent host
test process. It reports expiry as not run unless explicitly enabled.

`crates/noxide/tests/reservation_jobs.rs` checks the exact public SDK job lowering
and registration boundaries. The simple and explicit SDK fixture sources emit the
same contract; JSON baselines and approval hashes require central regeneration.
Source changes alone do not establish provider, browser-engine, worker-budget or
packaged-build acceptance. In particular, central integration must admit and meter
recurring selection with this service-root plus derived-product target shape.
These requirements and checks do not establish audited security or transport
anonymity; deployment infrastructure grants no guest external authority.
