#!/usr/bin/env python3
"""Exercise the built forum through real HTTP; moderator provisioning uses the operator CLI."""
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
        self.textarea = None
        self.controls = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = [attrs["action"], {}]
            self.forms.append(self.current)
        elif tag in ("input", "textarea") and self.current is not None and "name" in attrs:
            self.controls[(self.current[0], attrs["name"])] = (tag, attrs)
            if tag == "textarea":
                self.textarea = attrs["name"]
                self.current[1][self.textarea] = ""
                return
            if attrs.get("type") != "checkbox" or "checked" in attrs:
                self.current[1][attrs["name"]] = attrs.get("value", "")

    def handle_data(self, data):
        if self.current is not None and self.textarea is not None:
            self.current[1][self.textarea] += data

    def handle_endtag(self, tag):
        if tag == "textarea":
            # HTML consumes the renderer-supplied initial LF in a textarea.
            if self.current is not None and self.textarea is not None:
                value = self.current[1][self.textarea]
                self.current[1][self.textarea] = value.removeprefix("\n")
            self.textarea = None
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
    parser.add_argument("--host-cli", type=Path, default=ROOT / "target/debug/noxide",
                        help="trusted host binary; may be installed outside this checkout")
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = args.host_cli.resolve()
    manifest = args.bundle.resolve() / "manifest.json"
    component = args.bundle.resolve() / "forum.component.wasm"
    declarations = json.loads(manifest.read_text())
    operations = {op["id"]: op for op in declarations["operations"]}
    resources = {r["name"]: r["id"] for r in declarations["resources"]}
    for operation in operations.values():
        if operation["kind"] == "list":
            public = operation["policy"] == {"any": [["public"]]}
            size = (6 if public else 20) if operation["resource"] == resources["replies"] else 3
            assert operation["list"] == {"order": "created_asc", "page_size": size}

    def action(resource, kind, policy):
        matches = [a for a in declarations["actions"] if operations[a["steps"][0]["operation"]]["resource"] == resources[resource]
                   and operations[a["steps"][0]["operation"]]["kind"] == kind
                   and operations[a["steps"][0]["operation"]]["policy"] == {"any": [[policy]]}]
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
    password = args.output / "moderator-password"
    password.write_text("Forum moderator password\n")
    password.chmod(0o600)
    subprocess.run([binary, "account", config, "moderator", password], check=True, timeout=15)
    moderator_id = subprocess.check_output([binary, "account-lookup", config, "moderator"], text=True).strip()
    password.unlink()

    def role(command):
        # Resolve config-relative paths from a different working directory.
        result = subprocess.run([binary, "role", command, config, moderator_id, "moderator", "--global"],
                                cwd=args.bundle.resolve(), check=True, capture_output=True, text=True, timeout=10)
        assert f"user={moderator_id} role=moderator scope=global tenant=-: changed" in result.stdout
        assert not result.stderr

    def stored(path):
        with sqlite3.connect(args.output / "forum.db") as db:
            row = db.execute("SELECT fields,revision FROM nx_records WHERE id=?", (int(path.rsplit("/", 1)[1]),)).fetchone()
        return json.loads(row[0]), row[1]

    def pending_path(resource):
        # Operator inspection locates pending records for moderation. Anonymous
        # handover pages must not disclose a destination without read authority.
        with sqlite3.connect(args.output / "forum.db") as db:
            record_id = db.execute("SELECT id FROM nx_records WHERE resource=(SELECT storage_id FROM nx_resource_catalog WHERE resource_key=?) ORDER BY created_seq DESC LIMIT 1", (resource,)).fetchone()[0]
        assert record_id is not None
        return f"/{resource}/{record_id}"

    def layout(html, destination, title=False, moderation=False, thread=False):
        forms = Forms(html)
        fields = next(f[1] for f in forms.forms if f[0] == destination)
        assert "_csrf" in fields and "_submission" in fields
        if moderation:
            for name in (["published", "locked"] if thread else ["published"]):
                tag, attrs = forms.controls[(destination, name)]
                assert tag == "input" and attrs["type"] == "checkbox"
        else:
            tag, attrs = forms.controls[(destination, "body")]
            assert tag == "textarea" and attrs["rows"] == "8"
            if title:
                tag, attrs = forms.controls[(destination, "title")]
                assert tag == "input" and attrs["type"] == "text"
        return fields

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
            status, _, start = anonymous.request("GET", "/")
            assert status == 200 and "No public threads yet." in start
            assert "Start a thread" not in start and "Post with an edit secret" in start
            layout(start, action("threads", "create", "public"), title=True)
            user = Client(port)
            _, _, html = user.request("GET", "/register")
            status, _, _ = user.submit(html, "/register", username="alice", password="Forum integration password")
            assert status in (302, 303), status
            _, _, html = user.request("GET", "/login")
            assert user.submit(html, "/login", username="alice", password="Forum integration password")[0] in (302, 303)
            outsider = Client(port)
            _, _, html = outsider.request("GET", "/register")
            assert outsider.submit(html, "/register", username="bob", password="Forum outsider password")[0] in (302, 303)
            _, _, html = outsider.request("GET", "/login")
            assert outsider.submit(html, "/login", username="bob", password="Forum outsider password")[0] in (302, 303)
            operator = Client(port)
            _, _, html = operator.request("GET", "/login")
            assert operator.submit(html, "/login", username="moderator", password="Forum moderator password")[0] in (302, 303)
            # Grant after login; the existing session must observe current roles.
            role("grant")
            moderator = {"role": {"name": "moderator", "tenant_scoped": False}}
            def publish(path, resource):
                review = path.replace("/threads/", "/moderation/").replace("/replies/", "/reply_review/")
                _, _, form = operator.request("GET", review)
                layout(form, action(resource, "update", moderator), moderation=True, thread=resource == "threads")
                values = {"published": "true"}
                if resource == "threads":
                    values["locked"] = "false"
                assert operator.submit(form, action(resource, "update", moderator), **values)[0] == 303
            _, _, html = user.request("GET", "/")
            layout(html, action("threads", "create", "owner"), title=True)
            with sqlite3.connect(args.output / "forum.db") as db:
                before_count = db.execute("SELECT COUNT(*) FROM nx_records").fetchone()[0]
            invalid_body = '<script>alert("retained")</script>'
            status, _, rejected = user.submit(html, action("threads", "create", "owner"), title="   ", body=invalid_body)
            assert status == 422 and "Enter a title." in rejected and 'aria-invalid="true"' in rejected
            assert "Retry this submission" in rejected and '<script>' not in rejected
            retained = layout(rejected, action("threads", "create", "owner"), title=True)
            assert retained["title"] == "   " and retained["body"] == invalid_body
            with sqlite3.connect(args.output / "forum.db") as db:
                assert db.execute("SELECT COUNT(*) FROM nx_records").fetchone()[0] == before_count
            status, headers, _ = user.submit(rejected, action("threads", "create", "owner"), title="First <script>alert(1)</script>", body="Opening message")
            assert status == 303, status
            first = headers["location"]
            assert anonymous.request("GET", first)[0] == 404
            status, _, pending = user.request("GET", first)
            assert status == 200 and "Opening message" in pending
            assert "<script>" not in pending and "&lt;script&gt;alert(1)&lt;/script&gt;" in pending
            fields, _ = stored(first)
            assert fields["published"] == "false" and fields["locked"] == "false"
            before = stored(first)
            assert user.submit(pending, action("threads", "update", "owner"), title="Tampered", body="Tampered", published="true", locked="true")[0] >= 400
            assert stored(first) == before
            assert user.submit(pending, action("threads", "update", "owner"), title="First thread", body="Edited pending thread")[0] == 303
            assert "Edited pending thread" in user.request("GET", first)[2]
            assert anonymous.request("GET", first)[0] == 404
            assert outsider.request("GET", first)[0] == 404
            publish(first, "threads")
            _, _, html = user.request("GET", "/")
            status, headers, _ = user.submit(html, action("threads", "create", "owner"), title="Second thread", body="Other conversation")
            assert status == 303
            second = headers["location"]
            publish(second, "threads")
            # Anonymous threads use the same host handover, with no pending read authority.
            from html import unescape
            import re
            _, _, html = anonymous.request("GET", "/")
            status, headers, handover = anonymous.submit(html, action("threads", "create", "public"),
                title="Anonymous <script>alert(2)</script>", body="Literal <script>alert(3)</script>")
            assert status == 200 and "location" not in headers
            thread_secret = unescape(re.search(r"<pre>(.*?)</pre>", handover)[1])
            assert re.search(r'href="/threads/\d+"', handover) is None
            anonymous_thread = pending_path("threads")
            assert thread_secret not in anonymous_thread and "?" not in anonymous_thread
            unavailable = anonymous.request("GET", anonymous_thread)
            assert unavailable[0] == 404, unavailable[0]
            assert stored(anonymous_thread)[0]["published"] == "false"
            assert stored(anonymous_thread)[0]["locked"] == "false"
            publish(anonymous_thread, "threads")
            _, _, html = anonymous.request("GET", anonymous_thread)
            assert "<script>" not in html and "&lt;script&gt;alert(3)&lt;/script&gt;" in html
            assert "Edit your thread" not in html and "Reply with your account" not in html
            before = stored(anonymous_thread)
            assert anonymous.submit(html, action("threads", "update", "capability"), _capability=thread_secret,
                title="Tampered", body="Tampered", published="false", locked="true")[0] >= 400
            assert stored(anonymous_thread) == before
            reply_urls = []
            for i in range(8):
                thread = first if i % 2 == 0 else second
                _, _, html = user.request("GET", thread)
                status, headers, _ = user.submit(html, action("replies", "create", "owner"), body=f"Reply number {i}")
                assert status == 303, status
                reply_urls.append(headers["location"])
                path = headers["location"]
                assert anonymous.request("GET", path)[0] == 404
                status, _, pending = user.request("GET", path)
                assert status == 200 and f"Reply number {i}" in pending
                assert stored(path)[0]["published"] == "false"
                layout(pending, action("replies", "update", "owner"))
                if i == 0:
                    assert user.submit(pending, action("replies", "update", "owner"), body="Edited pending reply")[0] == 303
                    assert "Edited pending reply" in user.request("GET", path)[2]
                assert anonymous.request("GET", path)[0] == 404
                assert outsider.request("GET", path)[0] == 404
                publish(path, "replies")
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
                    assert path.startswith(first + "?cursor="), path
            assert len(bodies) == 1
            joined = "".join(bodies)
            assert "Edited reply" in joined
            for i in (2, 4, 6):
                assert f"Reply number {i}" in joined
            for i in (1, 3, 5, 7):
                assert f"Reply number {i}" not in joined
            # Maximum-sized parent and replies must leave room for Document IR
            # framing. Quotes exercise the worst legal JSON expansion (2x).
            for fill in ("x", '"'):
                body = fill * 4096
                expected = []
                # Operator fixtures avoid exhausting deliberate action rate limits.
                # HTTP reads still execute the actual compiled guest and renderer.
                with sqlite3.connect(args.output / "forum.db") as db:
                    thread_template = db.execute("SELECT resource, owner, tenant FROM nx_records WHERE id=?",
                                                 (int(first.rsplit("/", 1)[1]),)).fetchone()
                    last_id = db.execute("SELECT MAX(id) FROM nx_records").fetchone()[0]
                    thread_id = last_id + 1
                    sequence = db.execute("UPDATE nx_creation_counter SET value=value+1 WHERE singleton=1 RETURNING value").fetchone()[0]
                    fields = json.dumps({"title": fill * 200, "body": body, "published": "true", "locked": "false"})
                    db.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES(?,?,?,?,?,?,1,?)",
                               (thread_template[0], thread_id, *thread_template[1:], fields, f"budget-thread-{sequence}", sequence))
                    large_thread = f"/threads/{thread_id}"
                    template = db.execute("SELECT resource, owner, tenant FROM nx_records WHERE id=?",
                                          (int(reply_urls[0].rsplit("/", 1)[1]),)).fetchone()
                    last_id = thread_id
                    for index in range(15):
                        record_id = last_id + index + 1
                        sequence = db.execute("UPDATE nx_creation_counter SET value=value+1 WHERE singleton=1 RETURNING value").fetchone()[0]
                        fields = json.dumps({"thread": large_thread.rsplit("/", 1)[1], "body": body, "published": "true"})
                        db.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES(?,?,?,?,?,?,1,?)",
                                   (template[0], record_id, *template[1:], fields, f"budget-fixture-{sequence}", sequence))
                        expected.append(f"/replies/{record_id}")
                for client in (anonymous, user):
                    path, seen, pages = large_thread, [], 0
                    while path:
                        status, _, html = client.request("GET", path)
                        assert status == 200, (status, large_thread)
                        seen.extend(re.findall(r'href="(/replies/\d+)">View or edit reply', html))
                        match = re.search(r'href="([^"]+)">Next page', html)
                        path = unescape(match[1]) if match else None
                        pages += 1
                        assert pages <= 3
                    assert seen == expected, (seen, expected)
                    assert pages == 3
            _, _, html = anonymous.request("GET", first)
            status, _, handover = anonymous.submit(html, action("replies", "create", "public"), body="Anonymous reply")
            assert status == 200 and "<pre>" in handover
            assert '<script>' not in handover
            secret = unescape(re.search(r"<pre>(.*?)</pre>", handover)[1])
            assert re.search(r'href="/replies/\d+"', handover) is None
            reply_path = pending_path("replies")
            assert secret not in reply_path and "?" not in reply_path
            assert stored(reply_path)[0]["published"] == "false"
            assert anonymous.request("GET", reply_path)[0] == 404
            publish(reply_path, "replies")
            _, _, html = anonymous.request("GET", reply_path)
            form = next(f for f in Forms(html).forms if f[0] == action("replies", "update", "capability"))
            secret_name = "_capability"
            assert anonymous.request("POST", form[0], {**form[1], secret_name: "wrong-secret", "body": "Unauthorized edit"})[0] != 303
            assert "Unauthorized edit" not in anonymous.request("GET", reply_path)[2]
            before = stored(reply_path)
            assert anonymous.request("POST", form[0], {**form[1], secret_name: secret, "body": "Tampered", "published": "false"})[0] >= 400
            assert stored(reply_path) == before
            status, _, _ = anonymous.request("POST", form[0], {**form[1], secret_name: secret, "body": "Edited anonymously"})
            assert status == 303, status
            # Exercise actual moderation forms.
            reply_review = reply_urls[0].replace("/replies/", "/reply_review/")
            _, _, html = operator.request("GET", reply_review)
            assert operator.submit(html, action("replies", "update", moderator), published="false")[0] == 303
            assert anonymous.request("GET", reply_urls[0])[0] == 404
            _, _, html = operator.request("GET", reply_review)
            assert operator.submit(html, action("replies", "update", moderator), published="true")[0] == 303
            assert anonymous.request("GET", reply_urls[0])[0] == 200
            review = first.replace("/threads/", "/moderation/")
            _, _, stale = anonymous.request("GET", first)
            _, _, html = operator.request("GET", review)
            assert operator.submit(html, action("threads", "update", moderator), published="true", locked="true")[0] == 303
            status, _, html = anonymous.submit(stale, action("replies", "create", "public"), body="Late reply")
            assert "<pre>" not in html, (status, html)
            status, _, locked_page = user.request("GET", first)
            assert status == 200 and "This thread is closed to new replies." in locked_page
            assert "Reply with your account" not in locked_page and "Reply with an edit secret" not in locked_page
            before = stored(first)
            assert user.submit(locked_page, action("threads", "update", "owner"), title="First thread", body="Cannot unlock", locked="false")[0] >= 400
            assert stored(first) == before
            # An unpublished owner reply remains readable/editable beneath a hidden parent.
            _, _, html = operator.request("GET", reply_review)
            assert operator.submit(html, action("replies", "update", moderator), published="false")[0] == 303
            assert stored(reply_urls[0])[0]["published"] == "false"
            _, _, html = operator.request("GET", review)
            assert operator.submit(html, action("threads", "update", moderator), published="false", locked="true")[0] == 303
            assert anonymous.request("GET", first)[0] == 404
            assert user.request("GET", first)[0] == 200
            status, _, hidden_reply = user.request("GET", reply_urls[0])
            assert status == 200
            assert user.submit(hidden_reply, action("replies", "update", "owner"), body="Owner edit under hidden parent")[0] == 303
            assert anonymous.request("GET", reply_urls[0])[0] == 404
            assert outsider.request("GET", reply_urls[0])[0] == 404
            assert stored(reply_urls[0])[0]["published"] == "false"
            assert anonymous.request("GET", reply_path)[0] == 404
            assert anonymous.request("GET", second)[0] == 200
            _, _, html = operator.request("GET", review)
            assert operator.submit(html, action("threads", "update", moderator), published="true", locked="false")[0] == 303
            assert anonymous.request("GET", reply_path)[0] == 200
            # Provision and revoke through the real CLI while keeping the browser session.
            _, _, committed_form = operator.request("GET", review)
            assert operator.submit(committed_form, action("threads", "update", moderator), published="true", locked="false")[0] == 303
            _, _, unused_form = operator.request("GET", review)
            before = stored(first)
            role("revoke")
            assert operator.submit(unused_form, action("threads", "update", moderator), published="false", locked="true")[0] >= 400
            assert stored(first) == before
            # Recovery of an already committed submission must not perform a new write.
            assert operator.submit(committed_form, action("threads", "update", moderator), published="true", locked="false")[0] in (200, 303)
            assert stored(first) == before
            role("grant")
            assert operator.request("GET", review)[0] == 200
            (args.output / "results.json").write_text(json.dumps({"registration": True, "authenticated_replies": True,
                "anonymous_editing": True, "scoped_pagination": True, "maximum_document_pagination": True, "moderation": True, "stale_form_lock": True, "typed_layout_recovery": True, "cli_role_freshness": True, "escaped_content": True, "moderation_defaults": True}, indent=2))
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
