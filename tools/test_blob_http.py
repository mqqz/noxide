#!/usr/bin/env python3
"""Prove the explicit SDK blob app through the normal CLI and NoJS HTTP paths.

Use a fresh output directory and, for --postgres, a dedicated empty disposable
fixture database. Failures retain output and database evidence. No existing
objects, directories or database rows are reset by setup.
"""
import argparse
import hashlib
import copy
import http.cookiejar
from html.parser import HTMLParser
import json
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


class Document(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.forms, self.links, self.current = [], [], None
        self.feed(body.decode("utf-8"))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"action": attrs["action"], "enctype": attrs.get("enctype"), "controls": []}
            self.forms.append(self.current)
        elif self.current is not None and tag in ("input", "textarea") and "name" in attrs:
            self.current["controls"].append((attrs["name"], attrs.get("value", ""), attrs.get("type", tag)))
        elif tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class Browser:
    def __init__(self, origin):
        self.origin = origin
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())

    def request(self, path, data=None, content_type=None, extra=None):
        assert path.startswith("/") and not path.startswith("//"), "same-origin URL required"
        headers = dict(extra or {})
        if data is not None:
            headers.update(Origin=self.origin, **{"Content-Type": content_type})
        request = urllib.request.Request(self.origin + path, data=data, headers=headers)
        try:
            response = self.opener.open(request, timeout=20)
        except urllib.error.HTTPError as response:
            return response.code, response.headers, response.read(262145)
        with response:
            return response.status, response.headers, response.read(262145)

    def login(self, name, password):
        status, _, page = self.request("/login")
        assert status == 200
        form = next(form for form in Document(page).forms if any(name == "username" for name, _, _ in form["controls"]))
        fields = [(key, value) for key, value, _ in form["controls"] if key.startswith("_")]
        fields += [("username", name), ("password", password)]
        status, _, _ = self.request(form["action"], urllib.parse.urlencode(fields).encode(),
                                    "application/x-www-form-urlencoded")
        assert status == 303, "fixture sign-in failed"

    def upload(self, form, title, filename, payload, csrf=None):
        assert form["enctype"] == "multipart/form-data"
        assert form["controls"][-1][2] == "file", "file control must be last"
        boundary = "noxide-sdk-blob-fixture-boundary"
        body = bytearray()
        for name, value, kind in form["controls"]:
            if kind == "file":
                body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '
                         f'filename="{filename}"\r\nContent-Type: text/html\r\n\r\n').encode()
                body += payload + b"\r\n"
            else:
                if name == "title":
                    value = title
                if name == "_csrf" and csrf is not None:
                    value = csrf
                body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"'
                         f'\r\n\r\n{value}\r\n').encode()
        body += f"--{boundary}--\r\n".encode()
        return self.request(form["action"], body, f"multipart/form-data; boundary={boundary}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-cli", type=Path, required=True)
    parser.add_argument("--postgres", help="dedicated empty disposable PostgreSQL fixture URL")
    args = parser.parse_args()
    output, bundle, cli = args.output.resolve(), args.bundle.resolve(), args.host_cli.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.postgres:
        parsed = urllib.parse.urlsplit(args.postgres)
        assert parsed.hostname in ("localhost", "127.0.0.1", "::1"), "local disposable PostgreSQL only"

    def postgres(query):
        result = subprocess.run(["psql", args.postgres, "--no-psqlrc", "--tuples-only", "--no-align", "--command", query],
                                capture_output=True, text=True, check=False)
        assert result.returncode == 0, "disposable PostgreSQL fixture query failed"
        return result.stdout.strip()

    if args.postgres:
        assert postgres("SELECT COUNT(*) FROM pg_catalog.pg_tables WHERE schemaname='public'") == "0", "fixture database must be empty"
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    origin = f"http://127.0.0.1:{port}"
    config = {
        "database": {"postgres": args.postgres} if args.postgres else {"sqlite": "blob.db"},
        "keys": "keys.json", "component": str(bundle / "blob_app.component.wasm"),
        "manifest": str(bundle / "manifest.json"), "approved_contract": "",
        "origin": origin, "listen": {"tcp": f"127.0.0.1:{port}"},
        "blobs": {"directory": "objects", "ceilings": {"limits": {
            "file_bytes": 1048576, "app_bytes": 16777216, "objects": 64,
            "live_stages": 4, "uploads": 2, "downloads": 2}, "anonymous": None}},
    }
    path = output / "config.json"
    path.write_text(json.dumps(config, indent=2) + "\n")
    environment = dict(__import__("os").environ, XDG_STATE_HOME=str(output / "state"))

    def command(*values):
        result = subprocess.run([str(cli), *map(str, values)], capture_output=True, check=False, env=environment)
        assert result.returncode == 0, f"fixture CLI {values[0]} failed; output retained"
        return result.stdout

    manifest = json.loads((bundle / "manifest.json").read_text())
    forged = []
    bad = copy.deepcopy(manifest); bad["blobs"] = None; forged.append(bad)
    bad = copy.deepcopy(manifest); bad["blobs"]["uploads"][0]["input"] = "title"; forged.append(bad)
    bad = copy.deepcopy(manifest)
    assignment = next(a for a in bad["actions"][0]["steps"][0]["assign"] if a["field"] == "file")
    assignment["change"] = {"set": {"literal": {"text": "b1_" + "a" * 64}}}; forged.append(bad)
    for index, bad in enumerate(forged):
        forged_path = output / f"forged-manifest-{index}.json"
        forged_path.write_text(json.dumps(bad))
        result = subprocess.run([str(cli), "contract-hash", str(forged_path)], capture_output=True, env=environment, check=False)
        assert result.returncode != 0, "production host must independently reject forged Blob authority"
    approval = json.loads(command("deployment-hash", path))
    assert not (output / "objects").exists() and not (output / "blob.db").exists() and not (output / "keys.json").exists(), "deployment-hash must not open deployment resources"
    assert approval["manifest_digest"] != approval["deployment_digest"]
    assert approval["effective_blobs"]["limits"]["file_bytes"] == 1048576
    config["approved_contract"] = approval["deployment_digest"]
    path.write_text(json.dumps(config, indent=2) + "\n")
    command("init", path)
    password = "isolated blob fixture password"
    secret = output / "password.txt"
    secret.write_text(password)
    secret.chmod(0o600)
    for name in ("alice", "bob"):
        command("account", path, name, secret)
    bad_config = copy.deepcopy(config)
    bad_config["approved_contract"] = "A" * 43
    bad_config["blobs"]["directory"] = "unapproved-store"
    unapproved = output / "unapproved-config.json"
    unapproved.write_text(json.dumps(bad_config))
    result = subprocess.run([str(cli), "serve", str(unapproved)], capture_output=True, env=environment, timeout=10, check=False)
    assert result.returncode != 0 and not (output / "unapproved-store").exists(), "approval must precede store opening"

    def query(sql):
        if args.postgres:
            return postgres(sql)
        with sqlite3.connect(output / "blob.db") as database:
            rows = database.execute(sql).fetchall()
        return "\n".join("|".join(str(value) for value in row) for row in rows)

    checkpoints = {}

    def snapshot():
        return tuple(query(sql) for sql in (
            "SELECT COUNT(*) FROM nx_records", "SELECT COUNT(*) FROM nx_receipts",
            "SELECT COUNT(*) FROM nx_blobs", "SELECT reserved_bytes FROM nx_blob_store",
            "SELECT used_bytes FROM nx_blob_store", "SELECT objects FROM nx_blob_store"))

    with (output / "server.log").open("wb") as log:
        process = subprocess.Popen([str(cli), "serve", str(path)], stdout=log, stderr=subprocess.STDOUT, env=environment)
        try:
            deadline = time.monotonic() + 20
            while True:
                assert process.poll() is None, "fixture server failed; log retained"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "fixture server did not start"
                    time.sleep(.02)  # readiness retry, never race ordering
            alice, bob = Browser(origin), Browser(origin)
            alice.login("alice", password)
            bob.login("bob", password)
            status, _, page = alice.request("/")
            assert status == 200
            (output / "upload-page.html").write_bytes(page)
            form = next(form for form in Document(page).forms if form["enctype"] == "multipart/form-data")
            assert snapshot() == ("0", "0", "0", "0", "0", "0")
            payload = b"<svg><script>untrusted attachment</script></svg>"
            assert alice.upload(form, "accepted", "file.html", payload, csrf="forged")[0] in (400, 403)
            assert snapshot() == ("0", "0", "0", "0", "0", "0")
            status, _, page = alice.upload(form, "reject", "../../unsafe.html", payload)
            assert status == 422
            retry = next(form for form in Document(page).forms if form["enctype"] == "multipart/form-data")
            assert query("SELECT state FROM nx_blobs") == "staged"
            checkpoints["known_rejection"] = {"state": "staged", "counters": snapshot()}
            assert snapshot() == ("0", "0", "1", "0", str(len(payload)), "1")
            assert alice.upload(retry, "accepted", "replacement.bin", b"replacement")[0] == 400
            stage = query("SELECT upload_handle FROM nx_blobs")
            status, _, fresh = alice.request("/")
            assert status == 200
            foreign = next(form for form in Document(fresh).forms if form["enctype"] == "multipart/form-data")
            fields = [(key, value) for key, value, kind in foreign["controls"] if kind != "file" and key != "title"]
            fields = [(key, value) for key, value in fields if key != "_upload"] + [("title", "accepted"), ("file", stage)]
            assert alice.request(foreign["action"], urllib.parse.urlencode(fields).encode(), "application/x-www-form-urlencoded")[0] >= 400
            assert snapshot() == ("0", "0", "1", "0", str(len(payload)), "1")
            status, headers, _ = alice.upload(retry, "accepted", "", b"")
            assert status == 303
            location = headers["Location"]
            assert snapshot() == ("1", "1", "1", "0", str(len(payload)), "1")
            assert query("SELECT state FROM nx_blobs") == "attached"
            checkpoints["attachment"] = {"state": "attached", "counters": snapshot()}
            status, replay_headers, _ = alice.upload(retry, "accepted", "", b"")
            assert status == 303 and replay_headers["Location"] == location
            assert snapshot() == ("1", "1", "1", "0", str(len(payload)), "1")
            checkpoints["committed_replay"] = {"state": query("SELECT state FROM nx_blobs"), "counters": snapshot()}
            status, _, page = alice.request(location)
            assert status == 200 and payload not in page
            download = next(link for link in Document(page).links if link.startswith("/_noxide/download?ticket="))
            status, headers, body = alice.request(download)
            assert status == 200 and body == payload
            assert headers["Content-Type"] == "application/octet-stream"
            assert headers["Content-Disposition"] == 'attachment; filename="unsafe.html"'
            assert headers["X-Content-Type-Options"] == "nosniff" and headers["Cache-Control"] == "no-store"
            assert "default-src 'none'" in headers["Content-Security-Policy"]
            assert bob.request(location)[0] == 404 and bob.request(download)[0] == 404
            blob = query("SELECT blob_ref FROM nx_blobs")
            assert alice.request("/_noxide/download?ticket=" + blob)[0] == 404
            assert alice.request(download, extra={"Range": "bytes=0-1"})[0] == 404
            account = command("account-lookup", path, "alice").decode().strip()
            command("account-disable", path, account)
            assert alice.request(download)[0] == 404
            assert snapshot() == ("1", "1", "1", "0", str(len(payload)), "1")
            result = {"provider": "postgresql" if args.postgres else "sqlite", "sdk_component_sha256": hashlib.sha256((bundle / "blob_app.component.wasm").read_bytes()).hexdigest(),
                      "deployment_digest": approval["deployment_digest"], "counter_columns": ["records", "receipts", "blobs", "reserved_bytes", "used_bytes", "objects"], "persisted_checkpoints": checkpoints, "passed": ["independent_manifest_admission", "approval_before_store_open", "read_only_approval", "effective_ceilings", "csrf_before_quota", "rejected_stage_reuse", "no_replacement", "foreign_nonce", "atomic_attachment_receipt", "committed_replay", "direct_read_download", "safe_headers", "foreign_session", "blob_id_denial", "range_denial", "revocation"]}
            (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=65)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("fixture server shutdown exceeded its original transport bound")
    print("production SDK NoJS upload/download passed (" + result["provider"] + ")")


if __name__ == "__main__":
    main()
