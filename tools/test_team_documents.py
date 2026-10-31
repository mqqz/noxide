#!/usr/bin/env python3
"""Exercise the trusted membership SDK bundle through script-free HTTP forms."""
import argparse
import json
from pathlib import Path
import re
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
        "database": {"postgres": args.postgres} if args.postgres else {"sqlite": "team-documents.db"},
        "keys": "keys.json", "manifest": str(manifest),
        "component": str(bundle / "team_documents.component.wasm"),
        "approved_contract": subprocess.check_output([cli, "contract-hash", manifest], text=True).strip(),
        "origin": f"http://localhost:{port}", "listen": {"tcp": f"127.0.0.1:{port}"},
    }))
    subprocess.run([cli, "init", config], check=True, capture_output=True)
    # Index installation is explicit operator work; activation cannot invent it.
    subprocess.run([cli, "schema", "indexes", config], check=True, capture_output=True)
    password = output / "password"
    password.write_text("Membership walkthrough password")
    password.chmod(0o600)
    accounts = {}
    for user, tenant in (("alice", "team"), ("bob", "team"), ("eve", "other")):
        subprocess.run([cli, "account", config, user, password, tenant], check=True, capture_output=True)
        accounts[user] = subprocess.check_output([cli, "account-lookup", config, user], text=True).strip()
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
                assert client.submit(html, "/login", username=name, password="Membership walkthrough password")[0] == 303
            _, _, html = alice.request("GET", "/")
            status, headers, _ = alice.submit(html, actions["Create workspace"], name="Private <team>")
            assert status == 303, f"Create workspace: expected 303, received {status}"
            workspace = headers["location"]
            assert bob.request("GET", workspace)[0] == 404
            assert eve.request("GET", workspace)[0] == 404
            status, _, html = alice.request("GET", workspace)
            assert status == 200 and "Private &lt;team&gt;" in html
            assert alice.submit(html, actions["Add member"], account=accounts["bob"])[0] == 303
            _, _, html = alice.request("GET", workspace)
            assert alice.submit(html, actions["Add member"], account=accounts["eve"])[0] == 404
            _, _, html = bob.request("GET", workspace)
            assert actions["Add member"] not in html and actions["Create document"] in html
            status, headers, _ = bob.submit(html, actions["Create document"], title="Shared <document>", body="Private <content>")
            assert status == 303
            document = headers["location"]
            status, _, html = bob.request("GET", document)
            assert status == 200 and "Private &lt;content&gt;" in html and actions["Edit document"] not in html
            assert eve.request("GET", document)[0] == 404
            (output / "member-document.html").write_text(html)
            _, _, html = alice.request("GET", document)
            assert alice.submit(html, actions["Edit document"], title="Updated", body="Admin content")[0] == 303
            _, _, html = alice.request("GET", workspace)
            membership = next(link for account, link in re.findall(r'<p>([A-Za-z0-9_-]{43})[^<]*</p><a href="(/memberships/[0-9]+)"', html) if account == accounts["bob"])
            assert bob.request("GET", membership)[0] == 404
            _, _, html = alice.request("GET", membership)
            assert alice.submit(html, actions["Edit member"], role="member", active="false")[0] == 303
            assert bob.request("GET", document)[0] == 404
            assert bob.request("GET", workspace)[0] == 404
            status, _, html = alice.request("GET", workspace)
            assert status == 200 and "Updated" in html
            assert "<script" not in html.lower() and 'src="http' not in html.lower()
            (output / "admin-workspace.html").write_text(html)
        finally:
            server.terminate()
            server.wait(timeout=10)
    print("Team documents NoJS HTTP: bootstrap, principal binding, recipient/tenant checks, member create/read, admin-only management, escaped output and revocation passed.")


if __name__ == "__main__":
    main()
