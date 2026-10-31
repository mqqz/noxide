#!/usr/bin/env python3
"""Exercise reservations through native HTML forms and approved operator jobs.

Use a fresh output directory and an empty disposable PostgreSQL database when
--postgres is supplied. --await-expiry additionally waits for the real fifteen
minute host lifecycle cutoff; it never changes stored time, the clock or the
contract. Failures retain the database and evidence. No browser engine is claimed.
"""
import argparse
import contextlib
import csv
import io
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import time
import urllib.parse

from test_query_http import Browser, Document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-cli", type=Path, required=True)
    parser.add_argument("--postgres", help="dedicated empty disposable loopback PostgreSQL URL")
    parser.add_argument("--await-expiry", action="store_true", help="run real-time expiry, worker-once and recurring repair (about fifteen minutes)")
    args = parser.parse_args()
    output, bundle, cli = args.output.resolve(), args.bundle.resolve(), args.host_cli.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = dict(os.environ, XDG_STATE_HOME=str(output / "state"))
    if args.postgres:
        assert urllib.parse.urlsplit(args.postgres).hostname in ("localhost", "127.0.0.1", "::1"), "loopback fixture database required"

    def postgres(sql):
        result = subprocess.run(["psql", args.postgres, "--no-psqlrc", "--csv", "--tuples-only", "--command", sql], capture_output=True, text=True, check=False, timeout=20)
        assert result.returncode == 0, "fixture PostgreSQL read failed; database retained"
        return list(csv.reader(io.StringIO(result.stdout)))

    if args.postgres:
        assert postgres("SELECT COUNT(*) FROM pg_catalog.pg_tables WHERE schemaname='public'") == [["0"]], "fixture database must be empty"
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    actions = {action["name"]: action for action in manifest["actions"]}
    operations = {operation["id"]: operation for operation in manifest["operations"]}
    resources = {resource["name"]: resource["id"] for resource in manifest["resources"]}
    reserve, cancel, expire = (actions[name] for name in ("Reserve", "Cancel", "Expire reservation"))
    create = next(action for action in actions.values() if len(action["steps"]) == 1 and operations[action["steps"][0]["operation"]]["kind"] == "create")
    edit = next(action for action in actions.values() if len(action["steps"]) == 1 and operations[action["steps"][0]["operation"]]["kind"] == "update")
    path = lambda action: f'/actions/{action["id"]}'
    assert len(manifest["jobs"]["workers"]) == 1
    worker = manifest["jobs"]["workers"][0]["name"]
    assert not any(binding["action"] == expire["id"] for binding in manifest["web_bindings"])
    assert expire["inputs"] == cancel["inputs"] == []
    config_path = output / "runtime.json"
    config = {
        "database": {"postgres": args.postgres} if args.postgres else {"sqlite": "reservations.db"},
        "keys": "keys.json", "manifest": str(manifest_path),
        "component": str(bundle / "reservations.component.wasm"), "approved_contract": "",
        "origin": origin, "listen": {"tcp": f"127.0.0.1:{port}"},
        "jobs": {"grants": [{"worker": worker, "tenant": "alpha", "actions": [expire["id"]]}],
                 "limits": {"pending_per_app": 100, "pending_per_tenant": 100, "worker_concurrency": 1}},
    }
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    command_count = 0

    def command(*arguments):
        nonlocal command_count
        command_count += 1
        result = subprocess.run([str(cli), *map(str, arguments)], capture_output=True, check=False, env=environment, timeout=30)
        (output / f"cli-{command_count:03d}-{arguments[0]}.log").write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, f"fixture CLI {arguments[0]} failed; output retained"
        return result.stdout

    approval = json.loads(command("deployment-hash", config_path))
    assert not (output / "reservations.db").exists() and not (output / "keys.json").exists()
    config["approved_contract"] = approval["deployment_digest"]
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    command("init", config_path)
    command("schema", "indexes", config_path)
    password = "isolated reservations proof password"
    secret = output / "password.txt"
    secret.write_text(password)
    secret.chmod(0o600)
    try:
        for name, tenant in (("alice", "alpha"), ("bob", "alpha"), ("eve", "beta")):
            command("account", config_path, name, secret, tenant)
    finally:
        secret.unlink()

    def rows(sql):
        if args.postgres:
            return postgres(sql)
        with sqlite3.connect(output / "reservations.db") as database:
            return [[None if item is None else str(item) for item in row] for row in database.execute(sql)]

    def records():
        return [{"resource": int(resource), "id": int(identity), "fields": json.loads(fields), "revision": int(revision)}
                for resource, identity, fields, revision in rows("SELECT resource,id,fields,revision FROM nx_records ORDER BY resource,id")]

    def snapshot():
        # Clock heartbeats and recurring scan progress are deliberately excluded.
        return {"records": records(), "receipts": rows("SELECT COUNT(*) FROM nx_receipts")}

    def product_stock():
        return next(row["fields"]["stock"] for row in records() if row["resource"] == resources["products"])

    def orders():
        return {row["id"]: row["fields"] for row in records() if row["resource"] == resources["orders"]}

    def jobs():
        result = json.loads(command("jobs", "inspect", config_path))
        return {item["id"]: item for item in result["jobs"]}

    def read(browser, route, label, expected=200):
        before = snapshot()
        status, headers, page = browser.request(route)
        (output / f"{label}.html").write_bytes(page)
        assert status == expected, f"{label}: expected {expected}, got {status}"
        assert snapshot() == before, f"{label}: GET changed records or receipts"
        document = Document(page)
        document.local_only()
        return headers, page, document

    def controls(document, action):
        form = next(form for form in document.forms if form["action"] == path(action))
        return dict(form["controls"])

    def submit(browser, action, fields, label, expected=303):
        status, headers, body = browser.request(path(action), urllib.parse.urlencode(fields).encode(), "application/x-www-form-urlencoded")
        (output / f"{label}.html").write_bytes(body)
        assert status == expected, f"{label}: expected {expected}, got {status}"
        Document(body).local_only()
        return headers

    @contextlib.contextmanager
    def server(label):
        with (output / f"server-{label}.log").open("wb") as log:
            process = subprocess.Popen([str(cli), "serve", str(config_path)], stdout=log, stderr=subprocess.STDOUT, env=environment)
            try:
                deadline = time.monotonic() + 25
                while True:
                    assert process.poll() is None, "fixture host exited; log retained"
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, "fixture listener did not become ready"
                        time.sleep(.02)  # readiness retry, never a commit ordering proof
                yield
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=65)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise AssertionError("fixture shutdown exceeded original transport bound")
                assert process.returncode == 0, "fixture host did not stop cleanly"

    report = {"provider": "postgres" if args.postgres else "sqlite", "normal_forms": False,
              "expiry": {"status": "not_run", "reason": "requires --await-expiry or parent host test-process clock fixture"}}
    report_path = output / "result.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    with server("forms"):
        alice, bob, eve = (Browser(origin) for _ in range(3))
        for browser, name in ((alice, "alice"), (bob, "bob"), (eve, "eve")):
            browser.login(name, password)
        _, _, home = read(alice, "/", "home")
        created = submit(alice, create, {**controls(home, create), "name": "Reviewed <price>", "stock": "10", "price_minor": "125", "currency": "sar", "active": "true"}, "create")
        product = created["Location"]
        _, page, document = read(bob, product, "review-125")
        assert b"Reviewed &lt;price&gt;" in page and b"Available stock: 10" in page
        assert not any(form["action"] == path(edit) for form in document.forms)
        stale = {**controls(document, reserve), "quantity": "3"}
        _, _, owner = read(alice, product, "edit-form")
        submit(alice, edit, {**controls(owner, edit), "price_minor": "150", "currency": "sar", "active": "true"}, "edit-price")
        before = snapshot()
        submit(bob, reserve, stale, "review-conflict", 409)
        assert snapshot() == before, "stale price review wrote inventory or order"
        _, _, document = read(bob, product, "review-150")
        reserve_fields = {**controls(document, reserve), "quantity": "3"}
        assert "total_minor" not in reserve_fields and "unit_price_minor" not in reserve_fields
        before = snapshot()
        submit(bob, reserve, {**reserve_fields, "total_minor": "1"}, "forged-total", 400)
        assert snapshot() == before, "caller-provided total changed the transaction"
        saved = submit(bob, reserve, reserve_fields, "reserve")
        order = saved["Location"]
        first_order = next(iter(orders().values()))
        assert {key: first_order[key] for key in ("quantity", "unit_price_minor", "currency", "total_minor", "status")} == {
            "quantity": "3", "unit_price_minor": "150", "currency": "sar", "total_minor": "450", "status": "pending"}
        assert int(first_order["expires_at"]) - int(first_order["reserved_at"]) == 900000
        assert rows("SELECT due_ms,worker,action FROM nx_jobs ORDER BY id") == [[first_order["expires_at"], worker, str(expire["id"])]], "one-shot due differs from stored expiry"
        assert product_stock() == "7"
        before = snapshot()
        assert submit(bob, reserve, reserve_fields, "reservation-replay")["Location"] == order
        assert snapshot() == before
        read(alice, order, "other-owner-order", 404)
        read(eve, product, "other-tenant-product", 404)
        read(eve, order, "other-tenant-order", 404)
        _, page, document = read(bob, order, "reservation")
        assert all(text in page for text in (b"Quantity: 3", b"Unit price in minor units: 150", b"Total in minor units: 450"))
        first_cancel = controls(document, cancel)
        assert set(first_cancel).issubset({key for key in first_cancel if key.startswith("_")}), "cancellation has caller-controlled quantity"
        _, _, second = read(bob, order, "second-cancel-form")
        second_cancel = controls(second, cancel)
        before = snapshot()
        submit(bob, cancel, {**first_cancel, "quantity": "10"}, "forged-restock-quantity", 400)
        assert snapshot() == before, "caller-provided cancellation quantity changed stock"
        submit(bob, cancel, first_cancel, "cancel")
        assert product_stock() == "10" and next(iter(orders().values()))["status"] == "cancelled"
        before = snapshot()
        submit(bob, cancel, first_cancel, "cancel-replay")
        assert snapshot() == before
        submit(bob, cancel, second_cancel, "repeated-cancellation", 409)
        assert snapshot() == before
        _, _, document = read(bob, order, "cancelled-reservation")
        assert not any(form["action"] == path(cancel) for form in document.forms)
        # A service action cannot be reached as an independent web binding.
        before = snapshot()
        submit(bob, expire, {}, "service-web-denial", 404)
        assert snapshot() == before
        report["normal_forms"] = True

        if args.await_expiry:
            # Cancel the completed reservation's future one-shot before starting
            # the expiry experiment. Inspection never exposes payloads or seals.
            for identity in jobs():
                command("jobs", "cancel", config_path, identity)
            expiry_orders, expiry_jobs = [], []
            for ordinal in range(2):
                known_orders, known_jobs = set(orders()), set(jobs())
                _, _, document = read(bob, product, f"expiry-review-{ordinal}")
                submit(bob, reserve, {**controls(document, reserve), "quantity": "2"}, f"expiry-reserve-{ordinal}")
                new_orders, new_jobs = set(orders()) - known_orders, set(jobs()) - known_jobs
                assert len(new_orders) == len(new_jobs) == 1, "reservation must capture one transactional job"
                expiry_orders.append(new_orders.pop())
                expiry_jobs.append(new_jobs.pop())
            assert product_stock() == "6"
            command("jobs", "revoke", config_path, "alpha", worker)
            # The second order deliberately loses its one-shot. Its only future
            # release will be the declared bounded recurring repair selection.
            command("jobs", "cancel", config_path, expiry_jobs[1])
            cutoff = max(int(orders()[identity]["expires_at"]) for identity in expiry_orders)
            deadline = time.monotonic() + 925
            while int(rows("SELECT lifecycle_ms FROM nx_clock WHERE singleton=1")[0][0]) < cutoff:
                assert time.monotonic() < deadline, "host lifecycle watermark did not reach declared expiry"
                time.sleep(.25)  # predicate is committed host time, not sleep duration
            assert product_stock() == "6" and all(orders()[identity]["status"] == "pending" for identity in expiry_orders)
            for identity in expiry_orders:
                read(bob, f"/orders/{identity}", f"hidden-expired-{identity}", 404)
            report["expiry"] = {"status": "visibility_passed", "cutoff": cutoff}

    if args.await_expiry:
        # With serving stopped, worker-once does not run recurring selection.
        # This isolates the reconciled sealed one-shot from repair execution.
        command("jobs", "grant", config_path, "alpha", worker)
        replacement = json.loads(command("jobs", "reconcile", config_path, expiry_jobs[0]))["reconciled"]["id"]
        assert command("jobs", "worker-once", config_path).strip() == b"completed"
        assert jobs()[replacement]["state"] == "succeeded"
        assert orders()[expiry_orders[0]]["status"] == "expired" and orders()[expiry_orders[1]]["status"] == "pending"
        assert product_stock() == "8"
        before = snapshot()
        assert command("jobs", "worker-once", config_path).strip() == b"idle"
        assert snapshot() == before, "repeated worker-once restocked twice"
        before_repair_jobs = set(jobs())
        with server("repair"):
            deadline = time.monotonic() + 30
            while orders()[expiry_orders[1]]["status"] != "expired":
                assert time.monotonic() < deadline, "bounded recurring repair did not commit"
                time.sleep(.05)  # predicate is the committed guarded transition
            assert product_stock() == "10"
            assert set(jobs()) - before_repair_jobs, "repair did not enqueue a sealed occurrence"
            read(bob, f"/orders/{expiry_orders[1]}", "repaired-order-hidden", 404)
        before = snapshot()
        assert command("jobs", "worker-once", config_path).strip() == b"idle"
        assert snapshot() == before
        report["expiry"]["status"] = "visibility_worker_once_and_repair_passed"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
