#!/usr/bin/env python3
"""Exercise the built shop transaction through HTML forms without JavaScript."""
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
    parser.add_argument("--host-cli", type=Path, default=Path("target/debug/noxide"))
    parser.add_argument("--postgres", help="Disposable empty PostgreSQL database URL")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cli = args.host_cli.resolve()
    bundle = args.bundle.resolve()
    manifest = bundle / "manifest.json"
    contract = json.loads(manifest.read_text())
    create = next(a for a in contract["actions"] if len(a["steps"]) == 1)
    place = next(a for a in contract["actions"] if len(a["steps"]) == 3)
    create_path, place_path = (f'/actions/{a["id"]}' for a in (create, place))
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = output / "runtime.json"
    config.write_text(json.dumps({
        "database": {"postgres": args.postgres} if args.postgres else {"sqlite": "shop.db"},
        "keys": "keys.json", "manifest": str(manifest),
        "component": str(bundle / "shop.component.wasm"),
        "approved_contract": subprocess.check_output([cli, "contract-hash", manifest], text=True).strip(),
        "origin": f"http://localhost:{port}", "listen": {"tcp": f"127.0.0.1:{port}"},
    }))
    subprocess.run([cli, "init", config], check=True, capture_output=True)
    password = output / "password"
    password.write_text("Shop walkthrough password")
    password.chmod(0o600)
    subprocess.run([cli, "account", config, "alice", password, "shop"], check=True, capture_output=True)
    password.unlink()
    with (output / "server.log").open("wb") as log:
        server = subprocess.Popen([cli, "serve", config], stdout=log, stderr=subprocess.STDOUT)
        try:
            client = Client(port)
            for _ in range(100):
                assert server.poll() is None, "host exited; inspect server.log"
                try:
                    if client.request("GET", "/login")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.1)
            else:
                raise TimeoutError("host did not start")
            _, _, html = client.request("GET", "/login")
            assert client.submit(html, "/login", username="alice", password="Shop walkthrough password")[0] == 303
            status, _, html = client.request("GET", "/")
            assert status == 200 and "No products yet." in html
            status, headers, _ = client.submit(html, create_path, name="Last copy", stock="1")
            assert status == 303
            product = headers["location"]
            status, _, first = client.request("GET", product)
            assert status == 200 and "Available stock: 1" in first
            assert first.count('name="quantity"') == 1
            _, _, second = client.request("GET", product)
            first_values = next(values for action, values in Forms(first).forms if action == place_path)
            first_values = {**first_values, "quantity": "1", "body": "First <note>"}
            status, headers, _ = client.request("POST", place_path, first_values)
            assert status == 303
            order = headers["location"]
            status, _, html = client.request("GET", order)
            assert status == 200 and "Quantity: 1" in html and "First &lt;note&gt;" in html
            (output / "order.html").write_text(html)
            status, headers, _ = client.request("POST", place_path, first_values)
            assert status == 303 and headers["location"] == order
            status, _, html = client.submit(second, place_path, quantity="1", body="Second note")
            assert status == 422 and "Not enough stock" in html and "Second note" in html
            (output / "stock-rejection.html").write_text(html)
            status, _, html = client.request("GET", product)
            assert status == 200 and "Available stock: 0" in html
            (output / "product.html").write_text(html)
        finally:
            server.terminate()
            server.wait(timeout=10)
    print("Shop HTML forms: create, three-step order, note, replay and stock rejection passed.")


if __name__ == "__main__":
    main()
