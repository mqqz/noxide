# Shop transaction example

Create a product with one unit of stock, then order it with an initial note.
The host decreases stock, creates the order and creates its note in one
transaction. A second order receives “Not enough stock” and commits nothing.
The quantity appears once in the form and feeds two assignments.

From the repository root, build this trusted example:

```sh
cargo build --workspace --locked --offline
./target/debug/noxide build --app examples/shop --output /tmp/noxide-shop --framework .
```

The build command produces a component and manifest. To run it, create a runtime
configuration following [the application guide](../../docs/application-api.md),
pointing `component` at `shop.component.wasm` and `manifest` at `manifest.json`.
Approve the digest printed by `noxide contract-hash`. Initialize its database,
create an account with `noxide account`, and start `noxide serve`.

For a complete disposable walkthrough using actual HTML forms without JavaScript:

```sh
python3 tools/test_shop.py --bundle /tmp/noxide-shop --output /tmp/noxide-shop-walk
```

The walkthrough creates its own runtime configuration, database and account. It
checks product creation, the three-step order, escaped note rendering, successful
receipt replay and rejection of a distinct order form after stock runs out. It
saves the resulting pages in the output directory. Both output paths must be new.
Use `--postgres URL` for an empty disposable PostgreSQL database.

This example stores no accepted price, so its guarded stock transaction declares
`Identity`. Use `Exact` when the user's decision depends on a displayed price or
other versioned state. Local builds execute trusted dependencies on the host;
untrusted build inputs require `--isolated` and the disposable VM configuration.
