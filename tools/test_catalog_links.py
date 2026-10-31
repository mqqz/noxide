#!/usr/bin/env python3
"""Exercise named selection and derived references through script-free HTTP forms."""
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import socket
import subprocess
import time
from test_forum import Client, Forms


class Selections(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.name = None
        self.options = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "select":
            self.name = attrs["name"]
            self.options[self.name] = []
        elif tag == "option" and self.name and attrs.get("value"):
            self.options[self.name].append(attrs["value"])

    def handle_endtag(self, tag):
        if tag == "select":
            self.name = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-cli", type=Path, default=Path("target/debug/noxide"))
    parser.add_argument("--postgres", help="Disposable empty PostgreSQL database URL")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cli, bundle = args.host_cli.resolve(), args.bundle.resolve()
    manifest = bundle / "manifest.json"
    contract = json.loads(manifest.read_text())
    actions = {a["name"]: f'/actions/{a["id"]}' for a in contract["actions"]}
    project_action, contact_action, ticket_action = (actions[name] for name in
                                                   ("Create project", "Create contact", "Create ticket"))
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = output / "runtime.json"
    config.write_text(json.dumps({
        "database": {"postgres": args.postgres} if args.postgres else {"sqlite": "catalog.db"},
        "keys": "keys.json", "manifest": str(manifest),
        "component": str(bundle / "catalog_links.component.wasm"),
        "approved_contract": subprocess.check_output([cli, "contract-hash", manifest], text=True).strip(),
        "origin": f"http://localhost:{port}", "listen": {"tcp": f"127.0.0.1:{port}"},
    }))
    subprocess.run([cli, "init", config], check=True, capture_output=True)
    password = output / "password"
    password.write_text("Catalog walkthrough password")
    password.chmod(0o600)
    for user in ("alice", "bob"):
        subprocess.run([cli, "account", config, user, password, "catalog"], check=True, capture_output=True)
    password.unlink()
    with (output / "server.log").open("wb") as log:
        server = subprocess.Popen([cli, "serve", config], stdout=log, stderr=subprocess.STDOUT)
        try:
            alice, bob = Client(port), Client(port)
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
            for user, client in (("alice", alice), ("bob", bob)):
                _, _, html = client.request("GET", "/login")
                assert client.submit(html, "/login", username=user, password="Catalog walkthrough password")[0] == 303
            destinations = {}
            for user, client in (("alice", alice), ("bob", bob)):
                status, _, html = client.request("GET", "/")
                assert status == 200 and not Selections(html).options["_target_contact"]
                status, headers, _ = client.submit(html, project_action, title=f"{user} project")
                assert status == 303
                project = headers["location"]
                _, _, html = client.request("GET", project)
                status, headers, _ = client.submit(html, contact_action, name=f"{user} <contact>")
                assert status == 303
                destinations[user] = (project, headers["location"])
            _, _, html = alice.request("GET", "/")
            assert "alice &lt;contact&gt;" in html and "bob &lt;contact&gt;" not in html
            options = Selections(html).options["_target_contact"]
            assert len(options) == 1 and not options[0].isdecimal()
            assert alice.submit(html, ticket_action, body="forged", _target_contact="1")[0] == 400
            values = next(values for action, values in Forms(html).forms if action == ticket_action)
            values = {**values, "body": "Ticket <body>", "_target_contact": options[0]}
            status, headers, _ = alice.request("POST", ticket_action, values)
            assert status == 303
            ticket = headers["location"]
            status, _, result = alice.request("GET", ticket)
            assert status == 200 and "Ticket &lt;body&gt;" in result
            assert all(f'href="{path}"' in result for path in destinations["alice"])
            status, headers, _ = alice.request("POST", ticket_action, values)
            assert status == 303 and headers["location"] == ticket
            (output / "ticket.html").write_text(result)
        finally:
            server.terminate()
            server.wait(timeout=10)
    print("Catalog NoJS forms: scoped opaque picker, derived project, two references, raw-ID rejection and replay passed.")


if __name__ == "__main__":
    main()
