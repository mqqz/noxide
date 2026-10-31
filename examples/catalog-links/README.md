# Project contacts and tickets

Run `noxide dev` here with the current framework checkout. Create a project, add a
contact on that project's page, then return home and create a ticket by selecting
the contact. The native HTML picker needs no JavaScript.

`CreateTicket` declares two existing targets. The selected contact has an explicit
owner Read and compute projection; the project comes from its immutable reference
and passes its own owner Read. Only the contact name appears in the picker. The
host creates both ticket references in its existing transaction executor. IDs in
URLs or form fields confer no target authority.

The picker uses the first twenty contacts in creation order (newest first). The
example deliberately has no search or pagination UI for the selector.

After building a component bundle, run the real HTTP walkthrough from the
framework root:

```sh
python3 tools/test_catalog_links.py --bundle /tmp/catalog-bundle \
  --host-cli target/debug/noxide --output /tmp/catalog-walkthrough
```

The script checks owner-scoped choices, escaped labels, raw-ID rejection, the
derived project, both stored references and committed replay. `--postgres` accepts
an empty disposable PostgreSQL database. Local checks are implementation evidence;
they do not establish audited security or transport anonymity.
