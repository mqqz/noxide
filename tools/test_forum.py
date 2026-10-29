#!/usr/bin/env python3
"""Exercise the built forum through real HTTP; fixture moderation uses operator SQL."""
import argparse
from html.parser import HTMLParser
from http.cookies import SimpleCookie
import http.client
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent.parent


class Forms(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.forms = []
        self.current = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = [attrs["action"], {}]
            self.forms.append(self.current)
        elif tag == "input" and self.current is not None and "name" in attrs:
            if attrs.get("type") != "checkbox" or "checked" in attrs:
                self.current[1][attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class Client:
    def __init__(self, port):
        self.port = port
        self.cookies = {}

    def request(self, method, path, data=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": f"localhost:{self.port}", "Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())}
        if data is not None:
            headers.update({"Content-Type": "application/x-www-form-urlencoded", "Origin": f"http://localhost:{self.port}"})
        try:
            conn.request(method, path, urlencode(data) if data is not None else None, headers)
            response = conn.getresponse()
            for key, value in response.getheaders():
                if key.lower() == "set-cookie":
                    cookie = SimpleCookie(value)
                    self.cookies.update({k: v.value for k, v in cookie.items()})
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            conn.close()

    def submit(self, html, action, **values):
        form = next(f for f in Forms(html).forms if f[0] == action)
        return self.request("POST", action, {**form[1], **values})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = ROOT / "target/debug/noxide"
    manifest = args.bundle.resolve() / "manifest.json"
    component = args.bundle.resolve() / "forum.component.wasm"
    declarations = json.loads(manifest.read_text())
    operations = {op["id"]: op for op in declarations["operations"]}
    resources = {r["name"]: r["id"] for r in declarations["resources"]}

    def action(resource, kind, policy):
        matches = [a for a in declarations["actions"] if operations[a["operation"]]["resource"] == resources[resource]
                   and operations[a["operation"]]["kind"] == kind
                   and operations[a["operation"]]["policy"] == {"any": [[policy]]}]
        assert len(matches) == 1
        return f'/actions/{matches[0]["id"]}'

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    digest = subprocess.check_output([binary, "contract-hash", manifest], text=True).strip()
    config = args.output / "runtime.json"
    config.write_text(json.dumps({"database": {"sqlite": "forum.db"}, "keys": "host-keys.json",
        "component": str(component), "manifest": str(manifest), "approved_contract": digest,
        "origin": f"http://localhost:{port}", "listen": {"tcp": f"127.0.0.1:{port}"}, "registration": "open"}))
    subprocess.run([binary, "init", config], check=True, timeout=15)
    anonymous = Client(port)
    with (args.output / "server.log").open("wb") as log:
        server = subprocess.Popen([binary, "serve", config], stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                assert server.poll() is None, "host exited; inspect server.log"
                try:
                    if anonymous.request("GET", "/")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.1)
            else:
                raise TimeoutError("forum did not start")
            user = Client(port)
            _, _, html = user.request("GET", "/register")
            status, _, _ = user.submit(html, "/register", username="alice", password="Forum integration password")
            assert status in (302, 303), status
            _, _, html = user.request("GET", "/login")
            assert user.submit(html, "/login", username="alice", password="Forum integration password")[0] in (302, 303)
            # Operator grants moderation authority; creates still cannot choose visibility.
            with sqlite3.connect(args.output / "forum.db") as db:
                db.execute("INSERT INTO nx_roles(principal,name,tenant) VALUES('alice','moderator','')")
            moderator = {"role": {"name": "moderator", "tenant_scoped": False}}
            def publish(path, resource):
                review = path.replace("/threads/", "/moderation/").replace("/replies/", "/reply_review/")
                _, _, form = user.request("GET", review)
                values = {"published": "true"}
                if resource == "threads":
                    values["locked"] = "false"
                assert user.submit(form, action(resource, "update", moderator), **values)[0] == 303
            _, _, html = user.request("GET", "/")
            status, headers, _ = user.submit(html, action("threads", "create", "owner"), title="First thread", body="Opening message")
            assert status == 303, status
            first = headers["location"]
            assert anonymous.request("GET", first)[0] == 404
            publish(first, "threads")
            _, _, html = user.request("GET", "/")
            status, headers, _ = user.submit(html, action("threads", "create", "owner"), title="Second thread", body="Other conversation")
            assert status == 303
            second = headers["location"]
            publish(second, "threads")
            reply_urls = []
            for i in range(8):
                thread = first if i % 2 == 0 else second
                _, _, html = user.request("GET", thread)
                status, headers, _ = user.submit(html, action("replies", "create", "owner"), body=f"Reply number {i}")
                assert status == 303, status
                reply_urls.append(headers["location"])
                publish(headers["location"], "replies")
            _, _, html = user.request("GET", reply_urls[0])
            assert user.submit(html, action("replies", "update", "owner"), body="Tampered", published="false")[0] != 303
            _, _, html = user.request("GET", reply_urls[0])
            assert user.submit(html, action("replies", "update", "owner"), body="Edited reply")[0] == 303
            # Follow actual next-page links and ensure no replies from the other parent leak.
            from html import unescape
            import re
            bodies = []
            path = first
            while path:
                status, headers, html = anonymous.request("GET", path)
                assert status == 200 and "no-store" in headers["cache-control"]
                bodies.append(html)
                match = re.search(r'href="([^"]+)">Next page', html)
                path = unescape(match[1]) if match else None
                if path:
                    assert path.startswith(first + "?before="), path
            assert len(bodies) == 2
            joined = "".join(bodies)
            assert "Edited reply" in joined
            for i in (2, 4, 6):
                assert f"Reply number {i}" in joined
            for i in (1, 3, 5, 7):
                assert f"Reply number {i}" not in joined
            _, _, html = anonymous.request("GET", first)
            status, _, handover = anonymous.submit(html, action("replies", "create", "public"), body="Anonymous reply")
            assert status == 200 and "<pre>" in handover
            secret = unescape(re.search(r"<pre>(.*?)</pre>", handover)[1])
            reply_path = re.search(r'href="(/replies/\d+)"', handover)[1]
            assert anonymous.request("GET", reply_path)[0] == 404
            publish(reply_path, "replies")
            _, _, html = anonymous.request("GET", reply_path)
            form = next(f for f in Forms(html).forms if f[0] == action("replies", "update", "capability"))
            secret_name = "_capability"
            assert anonymous.request("POST", form[0], {**form[1], secret_name: "wrong-secret", "body": "Unauthorized edit"})[0] != 303
            assert "Unauthorized edit" not in anonymous.request("GET", reply_path)[2]
            status, _, _ = anonymous.request("POST", form[0], {**form[1], secret_name: secret, "body": "Edited anonymously"})
            assert status == 303, status
            # Exercise actual moderation forms.
            reply_review = reply_urls[0].replace("/replies/", "/reply_review/")
            _, _, html = user.request("GET", reply_review)
            assert user.submit(html, action("replies", "update", moderator), published="false")[0] == 303
            assert anonymous.request("GET", reply_urls[0])[0] == 404
            _, _, html = user.request("GET", reply_review)
            assert user.submit(html, action("replies", "update", moderator), published="true")[0] == 303
            assert anonymous.request("GET", reply_urls[0])[0] == 200
            review = first.replace("/threads/", "/moderation/")
            _, _, stale = anonymous.request("GET", first)
            _, _, html = user.request("GET", review)
            assert user.submit(html, action("threads", "update", moderator), published="true", locked="true")[0] == 303
            status, _, html = anonymous.submit(stale, action("replies", "create", "public"), body="Late reply")
            assert "<pre>" not in html, (status, html)
            _, _, html = user.request("GET", review)
            assert user.submit(html, action("threads", "update", moderator), published="false", locked="true")[0] == 303
            assert anonymous.request("GET", first)[0] == 404
            assert anonymous.request("GET", reply_urls[0])[0] == 404
            assert anonymous.request("GET", reply_path)[0] == 404
            assert anonymous.request("GET", second)[0] == 200
            _, _, html = user.request("GET", review)
            assert user.submit(html, action("threads", "update", moderator), published="true", locked="false")[0] == 303
            assert anonymous.request("GET", reply_path)[0] == 200
            (args.output / "results.json").write_text(json.dumps({"registration": True, "authenticated_replies": True,
                "anonymous_editing": True, "scoped_pagination": True, "moderation": True, "stale_form_lock": True}, indent=2))
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
    print("Forum HTTP checks passed.")


if __name__ == "__main__":
    main()
