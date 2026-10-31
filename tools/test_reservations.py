#!/usr/bin/env python3
"""Exercise the trusted reservation SDK bundle through script-free HTTP forms."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import time
from test_forum import Client, Forms


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-cli", type=Path, required=True)
    parser.add_argument("--postgres", help="Disposable empty PostgreSQL database URL")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cli, bundle = args.host_cli.resolve(), args.bundle.resolve()
    manifest = bundle / "manifest.json"
    contract = json.loads(manifest.read_text())
    actions = {a["name"]: next(f'/actions/{b["id"]}' for b in contract["web_bindings"]
                             if b["action"] == a["id"]) for a in contract["actions"]}
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = output / "runtime.json"
    config.write_text(json.dumps({
        "database": {"postgres": args.postgres} if args.postgres else {"sqlite": "reservations.db"},
        "keys": "keys.json", "manifest": str(manifest),
        "component": str(bundle / "reservations.component.wasm"),
        "approved_contract": subprocess.check_output([cli, "contract-hash", manifest], text=True).strip(),
        "origin": f"http://localhost:{port}", "listen": {"tcp": f"127.0.0.1:{port}"},
    }))
    subprocess.run([cli, "init", config], check=True, capture_output=True)
    password = output / "password"
    password.write_text("Reservation walkthrough password")
    password.chmod(0o600)
    for user, tenant in (("alice", "shop"), ("bob", "shop"), ("eve", "other")):
        subprocess.run([cli, "account", config, user, password, tenant], check=True, capture_output=True)
    password.unlink()
    with (output / "server.log").open("wb") as log:
        server = subprocess.Popen([cli, "serve", config], stdout=log, stderr=subprocess.STDOUT)
        try:
            alice, bob, eve = Client(port), Client(port), Client(port)
            for _ in range(100):
                assert server.poll() is None, "host exited; inspect server.log"
                try:
                    if alice.request("GET", "/login")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.1)
            else:
                raise TimeoutError("host did not start")
            for name, client in (("alice", alice), ("bob", bob), ("eve", eve)):
                _, _, html = client.request("GET", "/login")
                assert client.submit(html, "/login", username=name, password="Reservation walkthrough password")[0] == 303
            _, _, html = alice.request("GET", "/")
            status, headers, _ = alice.submit(html, actions["Create product"], name="Reviewed <product>", stock="3",
                                               price_minor="125", currency="sar", active="true")
            assert status == 303
            product = headers["location"]
            _, _, old_review = bob.request("GET", product)
            assert 'name="quantity"' in old_review and 'name="total_minor"' not in old_review
            assert eve.request("GET", product)[0] == 404
            _, _, edit = alice.request("GET", product)
            assert alice.submit(edit, actions["Edit product"], price_minor="150", currency="sar", active="true")[0] == 303
            assert bob.submit(old_review, actions["Reserve"], quantity="2")[0] == 409
            _, _, review = bob.request("GET", product)
            reserve = next(values for action, values in Forms(review).forms if action == actions["Reserve"])
            assert bob.request("POST", actions["Reserve"], {**reserve, "quantity": "2", "total_minor": "1"})[0] == 400
            values = {**reserve, "quantity": "2"}
            status, headers, _ = bob.request("POST", actions["Reserve"], values)
            assert status == 303
            order = headers["location"]
            status, _, html = bob.request("GET", order)
            assert status == 200 and "Quantity: 2" in html and "Total in minor units: 300" in html
            assert "Unit price in minor units: 150" in html and "pending" in html.lower()
            assert alice.request("GET", order)[0] == 404
            (output / "order.html").write_text(html)
            status, headers, _ = bob.request("POST", actions["Reserve"], values)
            assert status == 303 and headers["location"] == order
            cancel = next(values for action, values in Forms(html).forms if action == actions["Cancel"])
            assert "quantity" not in cancel and not any(name.startswith("_target_") for name in cancel)
            status, _, _ = bob.request("POST", actions["Cancel"], cancel)
            assert status == 303
            assert bob.request("POST", actions["Cancel"], cancel)[0] == 303
            status, _, html = bob.request("GET", order)
            assert status == 200 and "cancelled" in html.lower() and actions["Cancel"] not in html
            (output / "cancelled.html").write_text(html)
            status, _, html = bob.request("GET", product)
            assert status == 200 and "Available stock: 3" in html
            assert "Reviewed &lt;product&gt;" in html
            (output / "product.html").write_text(html)
        finally:
            server.terminate()
            server.wait(timeout=10)
    print("Reservation NoJS forms: reviewed price, checked total, owner/tenant checks, stored-quantity cancellation and replay passed.")


if __name__ == "__main__":
    main()
