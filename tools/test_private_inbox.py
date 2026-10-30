#!/usr/bin/env python3
"""Exercise the private inbox component through real HTTP on either database."""
import argparse
import base64
import json
import re
from html import unescape
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
    parser.add_argument("--geckodriver", help="Run a Firefox walkthrough with JavaScript disabled")
    parser.add_argument("--postgres", help="Disposable empty local PostgreSQL database URL")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True)
    cli = args.host_cli.resolve()
    bundle = args.bundle.resolve()
    manifest = bundle / "manifest.json"
    contract = json.loads(manifest.read_text())
    operations = {op["id"]: op for op in contract["operations"]}
    actions = {operations[a["operation"]]["kind"]: f'/actions/{a["id"]}' for a in contract["actions"]}
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = output / "runtime.json"
    config.write_text(json.dumps({
        "database": {"postgres": args.postgres} if args.postgres else {"sqlite": "inbox.db"},
        "keys": "keys.json", "manifest": str(manifest),
        "component": str(bundle / "private_inbox.component.wasm"),
        "approved_contract": subprocess.check_output([cli, "contract-hash", manifest], text=True).strip(),
        "origin": f"http://localhost:{port}", "listen": {"tcp": f"127.0.0.1:{port}"},
    }))
    subprocess.run([cli, "init", config], check=True, capture_output=True)
    password = output / "password"
    password.write_text("Private inbox test password")
    password.chmod(0o600)
    ids = {name: subprocess.check_output([cli, "account", config, name, password, "team"], text=True).strip()
           for name in ("alice", "bob", "eve")}
    password.unlink()
    log = (output / "server.log").open("wb")
    server = None

    def start():
        process = subprocess.Popen([cli, "serve", config], stdout=log, stderr=subprocess.STDOUT)
        for _ in range(100):
            assert process.poll() is None, "host exited; inspect server.log"
            try:
                if Client(port).request("GET", "/login")[0] == 200:
                    return process
            except OSError:
                pass
            time.sleep(0.1)
        process.terminate()
        raise TimeoutError("host did not start")

    def login(name):
        client = Client(port)
        _, _, html = client.request("GET", "/login")
        assert client.submit(html, "/login", username=name, password="Private inbox test password")[0] == 303
        return client

    try:
        server = start()
        alice, bob, eve = (login(name) for name in ("alice", "bob", "eve"))
        assert Client(port).request("GET", "/account")[0] == 303
        for name, client in (("alice", alice), ("bob", bob), ("eve", eve)):
            status, _, html = client.request("GET", "/account")
            assert status == 200 and ids[name] in html
            assert all(value not in html for other, value in ids.items() if other != name)
        status, _, html = alice.request("GET", "/")
        assert status == 200, (status, html)
        form = next(values for action, values in Forms(html).forms if action == actions["create"])
        values = {**form, "recipient": ids["bob"], "body": "private <script>message</script>"}
        status, headers, _ = alice.request("POST", actions["create"], values)
        assert status == 303, status
        target = headers["location"]
        # Retry after a lost response, including a host restart.
        server.terminate()
        server.wait(timeout=10)
        server = start()
        status, headers, _ = alice.request("POST", actions["create"], values)
        assert status == 303 and headers["location"] == target
        assert alice.request("POST", actions["create"], {**values, "recipient": ids["eve"]})[0] not in (200, 303)
        for client in (alice, bob):
            status, _, html = client.request("GET", target)
            assert status == 200 and "&lt;script&gt;message&lt;/script&gt;" in html
            assert client.request("GET", "/")[2].count("Open message") == 1
        assert eve.request("GET", target)[0] == 404
        assert "Open message" not in eve.request("GET", "/")[2]
        assert actions["delete"] not in bob.request("GET", target)[2]
        for index in range(20):
            status, _, html = alice.request("GET", "/")
            assert status == 200
            status, headers, _ = alice.submit(html, actions["create"], recipient=ids["bob"], body=f"Cursor message {index}")
            assert status == 303
            retained_target = headers["location"]
        status, _, html = bob.request("GET", "/")
        assert status == 200 and html.count("Open message") == 20
        cursor = unescape(re.search(r'href="([^"]*cursor=[^"]+)"', html).group(1))
        assert eve.request("GET", cursor)[0] != 200
        status, _, html = bob.request("GET", cursor)
        assert status == 200 and html.count("Open message") == 1

        _, _, html = alice.request("GET", target)
        assert alice.submit(html, actions["delete"])[0] == 303
        assert bob.request("GET", target)[0] == 404
        # A form issued before disablement cannot establish a new binding.
        _, _, html = alice.request("GET", "/")
        subprocess.run([cli, "account-disable", config, ids["bob"]], check=True)
        assert alice.submit(html, actions["create"], recipient=ids["bob"], body="undeliverable")[0] not in (200, 303)
        assert bob.request("GET", "/account")[0] == 303
        subprocess.run([cli, "account-delete", config, ids["bob"]], check=True)
        assert subprocess.run([cli, "account-enable", config, ids["bob"]], capture_output=True).returncode != 0
        password.write_text("Private inbox test password")
        password.chmod(0o600)
        replacement = subprocess.check_output([cli, "account", config, "bob", password, "team"], text=True).strip()
        password.unlink()
        assert replacement != ids["bob"]
        replacement_client = login("bob")
        assert replacement_client.request("GET", retained_target)[0] == 404
        assert "Open message" not in replacement_client.request("GET", "/")[2]

        if args.geckodriver:
            from test_browser import ELEMENT, call, port as free_port, ready
            endpoint = f"http://127.0.0.1:{free_port()}"
            with (output / "browser.log").open("w") as browser_log:
                driver = subprocess.Popen([args.geckodriver, "--host", "127.0.0.1", "--port", endpoint.rsplit(":", 1)[1]], stdout=browser_log, stderr=subprocess.STDOUT)
                session = None
                try:
                    ready(endpoint + "/status")
                    browser = call(endpoint + "/session", "POST", {"capabilities": {"alwaysMatch": {"browserName": "firefox", "moz:firefoxOptions": {"args": ["-headless"], "prefs": {"javascript.enabled": False, "network.proxy.type": 1, "network.proxy.http": "127.0.0.1", "network.proxy.http_port": 9, "network.proxy.ssl": "127.0.0.1", "network.proxy.ssl_port": 9, "network.proxy.no_proxies_on": "localhost,127.0.0.1", "network.dns.disablePrefetch": True, "network.prefetch-next": False, "network.captive-portal-service.enabled": False, "network.connectivity-service.enabled": False}}}}})
                    session = endpoint + "/session/" + browser["sessionId"]
                    def navigate(path):
                        call(session + "/url", "POST", {"url": f"http://localhost:{port}{path}"})
                    def element(selector):
                        return call(session + "/element", "POST", {"using": "css selector", "value": selector})[ELEMENT]
                    def fill(selector, text):
                        call(session + "/element/" + element(selector) + "/value", "POST", {"text": text})
                    def click(selector):
                        call(session + "/element/" + element(selector) + "/click", "POST", {})
                    def browser_login(name):
                        navigate("/login")
                        fill("input[name=username]", name)
                        fill("input[name=password]", "Private inbox test password")
                        click("button")
                    browser_login("alice")
                    navigate("/account")
                    assert ids["alice"] in call(session + "/source")
                    navigate("/")
                    fill("input[name=recipient]", ids["eve"])
                    fill("textarea[name=body]", "Message sent with JavaScript disabled")
                    click(f'form[action="{actions["create"]}"] button')
                    target_url = call(session + "/url")
                    assert "/messages/" in target_url
                    call(session + "/cookie", "DELETE")
                    browser_login("eve")
                    call(session + "/url", "POST", {"url": target_url})
                    source = call(session + "/source")
                    assert "Message sent with JavaScript disabled" in source
                    assert actions["delete"] not in source
                    (output / "recipient.png").write_bytes(base64.b64decode(call(session + "/screenshot")))
                    print("Firefox NoJS sender/recipient walkthrough passed")
                finally:
                    if session:
                        call(session, "DELETE")
                    driver.terminate()
                    driver.wait(timeout=10)
        print("Private inbox HTTP/component checks passed")
    finally:
        if server is not None:
            server.terminate()
            server.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    main()
