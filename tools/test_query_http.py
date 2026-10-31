#!/usr/bin/env python3
"""Prove the trusted explicit SDK query fixture through normal CLI and NoJS HTTP.

Requires a new output directory and, for --postgres, a dedicated empty loopback
fixture database. Retains every failure artifact and never resets database rows.
Browser-engine acceptance is a separate gate; this harness submits native forms.
"""
import argparse
import contextlib
import copy
import csv
import hashlib
import http.cookiejar
from html.parser import HTMLParser
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
import urllib.request

from test_blob_http import Browser as FormBrowser, NoRedirect


class Browser(FormBrowser):
    def __init__(self, origin):
        self.origin = origin
        # Environment proxy settings must not send this loopback proof elsewhere.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())


class Document(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.forms, self.links, self.tags = [], [], []
        self.current, self.select = None, None
        self.feed(body.decode("utf-8"))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "form":
            assert self.current is None, "nested form"
            self.current = {"action": attrs["action"], "method": attrs.get("method", "get").lower(), "controls": {}}
            self.forms.append(self.current)
        elif self.current is not None:
            if tag == "input" and "name" in attrs:
                name = attrs["name"]
                assert name not in self.current["controls"], "duplicate control"
                self.current["controls"][name] = attrs.get("value", "")
            elif tag == "select":
                self.select = attrs["name"]
                assert self.select not in self.current["controls"]
            elif tag == "option" and self.select is not None:
                if self.select not in self.current["controls"] or "selected" in attrs:
                    self.current["controls"][self.select] = attrs.get("value", "")
            elif tag == "textarea":
                self.current["controls"][attrs["name"]] = ""
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None
        elif tag == "select":
            self.select = None

    def local_only(self):
        assert not any(tag == "script" for tag, _ in self.tags), "fixture requires no script"
        for _, attrs in self.tags:
            for key in ("href", "src", "action"):
                if key in attrs:
                    value = attrs[key]
                    assert value.startswith("/") and not value.startswith("//"), "external resource or destination"


def query_path(path, **updates):
    parts = urllib.parse.urlsplit(path)
    fields = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    fields.update({key: str(value) for key, value in updates.items()})
    return parts.path + "?" + urllib.parse.urlencode(fields)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-cli", type=Path, required=True)
    parser.add_argument("--postgres", help="dedicated empty disposable PostgreSQL URL on loopback")
    args = parser.parse_args()
    output, bundle, cli = args.output.resolve(), args.bundle.resolve(), args.host_cli.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = dict(os.environ, XDG_STATE_HOME=str(output / "state"))
    if args.postgres:
        assert urllib.parse.urlsplit(args.postgres).hostname in ("localhost", "127.0.0.1", "::1"), "loopback fixture database required"

    def postgres(sql):
        result = subprocess.run(["psql", args.postgres, "--no-psqlrc", "--csv", "--tuples-only", "--command", sql],
                                capture_output=True, text=True, check=False)
        assert result.returncode == 0, "fixture PostgreSQL read failed; database retained"
        return list(csv.reader(io.StringIO(result.stdout)))

    if args.postgres:
        assert postgres("SELECT COUNT(*) FROM pg_catalog.pg_tables WHERE schemaname='public'") == [["0"]], "fixture database must be empty"
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    origin = f"http://127.0.0.1:{port}"
    component = bundle / "query_app.component.wasm"
    config = {
        "database": {"postgres": args.postgres} if args.postgres else {"sqlite": "query.db"},
        "keys": "keys.json", "component": str(component),
        "manifest": str(bundle / "manifest.json"), "approved_contract": "",
        "origin": origin, "listen": {"tcp": f"127.0.0.1:{port}"},
    }
    config_path = output / "config.json"

    def write_config():
        config_path.write_text(json.dumps(config, indent=2) + "\n")

    def command(*values):
        result = subprocess.run([str(cli), *map(str, values)], capture_output=True, check=False, env=environment)
        (output / f"cli-{values[0]}-{len(list(output.glob('cli-*')))}.log").write_bytes(result.stdout + result.stderr)
        assert result.returncode == 0, f"fixture CLI {values[0]} failed; output retained"
        return result.stdout

    manifest = json.loads((bundle / "manifest.json").read_text())
    routes = {route["path"]: route for route in manifest["routes"]}
    operations = {op["id"]: op for op in manifest["operations"]}
    source = operations[routes["/search"]["operations"][0]]
    assert source["kind"] == "list" and source["list"]["page_size"] == 2
    aggregate_ids = routes["/statistics"]["operations"]
    assert len(aggregate_ids) == 4 and all(operations[op]["kind"] == "aggregate" for op in aggregate_ids)
    assert source["id"] not in aggregate_ids, "aggregate source metadata must not grant row invocation"
    assert all(operations[op]["query"]["aggregate"]["source"] == source["id"] for op in aggregate_ids)
    write_config()
    approval = json.loads(command("deployment-hash", config_path))
    assert not (output / "query.db").exists() and not (output / "keys.json").exists(), "approval hashing must not open resources"
    config["approved_contract"] = approval["deployment_digest"]
    write_config()
    command("init", config_path)
    password = "isolated query fixture password"
    secret = output / "password.txt"
    secret.write_text(password)
    secret.chmod(0o600)
    for name in ("alice", "bob"):
        command("account", config_path, name, secret)

    def rows(sql):
        if args.postgres:
            return postgres(sql)
        with sqlite3.connect(output / "query.db") as database:
            return [[None if value is None else str(value) for value in row] for row in database.execute(sql)]

    def snapshot():
        result = {}
        for table, order in (("nx_records", "resource,id"), ("nx_receipts", "nonce"),
                             ("nx_search_postings", "resource,record_id,field,token"), ("nx_search_state", "resource")):
            data = rows(f"SELECT * FROM {table} ORDER BY {order}")
            result[table] = {"count": len(data), "sha256": hashlib.sha256(json.dumps(data, ensure_ascii=False).encode()).hexdigest()}
        return result

    checks = {}

    def read(browser, path, label, expected=200):
        before = snapshot()
        status, headers, page = browser.request(path)
        (output / f"{label}.html").write_bytes(page)
        after = snapshot()
        checks[label] = {"expected_status": expected, "actual_status": status,
                         "before": before, "after": after}
        (output / "get-checkpoints.json").write_text(json.dumps(checks, indent=2) + "\n")
        assert after == before, f"{label}: GET changed records, receipts or search index"
        assert status == expected, f"{label}: expected {expected}, got {status}; body and state retained"
        document = Document(page)
        document.local_only()
        return headers, page, document

    @contextlib.contextmanager
    def server(label):
        with (output / f"server-{label}.log").open("wb") as log:
            process = subprocess.Popen([str(cli), "serve", str(config_path)], stdout=log, stderr=subprocess.STDOUT, env=environment)
            try:
                deadline = time.monotonic() + 25
                while True:
                    assert process.poll() is None, "fixture server failed; log retained"
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, "fixture listener did not become ready"
                        time.sleep(.02)  # readiness retry only, never race ordering
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
                assert process.returncode == 0, "fixture server did not stop cleanly"

    with server("original"):
        alice, bob = Browser(origin), Browser(origin)
        alice.login("alice", password)
        bob.login("bob", password)
        _, home, document = read(alice, "/", "home")
        assert b"Search &lt;Arabic &amp; Rust&gt;" in home and b"Apply &lt;filters&gt;" in home
        form = next(form for form in document.forms if form["method"] == "get" and form["action"] == "/search")
        assert set(form["controls"]) == {"terms", "minimum", "maximum", "included"}
        assert form["controls"]["terms"] == "" and form["controls"]["included"] == "true"
        assert "cursor" not in form["controls"]
        assert snapshot()["nx_records"]["count"] == snapshot()["nx_receipts"]["count"] == snapshot()["nx_search_postings"]["count"] == 0

        def create(browser, title, body, rank, quantity, included=True):
            _, _, document = read(browser, "/", f"create-form-{snapshot()['nx_records']['count']}")
            form = next(form for form in document.forms if form["method"] == "post" and "title" in form["controls"])
            fields = {key: value for key, value in form["controls"].items() if key.startswith("_")}
            fields.update(title=title, body=body, rank=str(rank), quantity=str(quantity), included=str(included).lower())
            before = snapshot()
            status, headers, response = browser.request(form["action"], urllib.parse.urlencode(fields).encode(), "application/x-www-form-urlencoded")
            (output / f"create-{before['nx_records']['count']}.html").write_bytes(response)
            assert status == 303, f"document create failed: {status}"
            after = snapshot()
            assert after["nx_records"]["count"] == before["nx_records"]["count"] + 1
            assert after["nx_receipts"]["count"] == before["nx_receipts"]["count"] + 1
            assert after["nx_search_postings"]["count"] > before["nx_search_postings"]["count"]
            return headers["Location"]

        first = create(alice, 'First <script>alert("x")</script>', "عربي Rust alpha beta", 10, 2)
        second = create(alice, "Second عربي", "Rust alpha beta", 10, 3)
        third = create(alice, "Third عربي", "Rust alpha beta", 20, 5)
        # Host record identities are random, so the stable ID tie is numeric ID
        # order rather than creation order.
        tie_order = sorted((first, second), key=lambda path: int(path.rsplit("/", 1)[1]))
        filtered = create(alice, "Filtered private", "عربي Rust alpha beta", 30, 7, included=False)
        unrelated = create(alice, "Unrelated private", "unrelated", 40, 11)
        private = create(bob, "Other account private decoy", "عربي Rust alpha beta", 10, 1000)
        search_path = "/search?" + urllib.parse.urlencode(dict(form["controls"], terms="عربي Rust"))
        _, page, document = read(alice, search_path, "search-first")
        assert b'First &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;' in page and b"<script>" not in page
        assert "Terms: rust عربي" in page.decode()
        links = [link for link in document.links if link.startswith("/documents/")]
        assert links == tie_order, "immutable rank ordering must use stable record-ID ties"
        assert third not in links and filtered not in links and unrelated not in links and private not in links
        next_page = next(link for link in document.links if "cursor=" in link)
        _, page, document = read(alice, next_page, "search-second")
        assert [link for link in document.links if link.startswith("/documents/")] == [third]
        assert not any("cursor=" in link for link in document.links)
        _, _, canonical = read(alice, query_path(search_path, terms="Ｒｕｓｔ عربي RUST"), "canonical-first")
        assert [link for link in canonical.links if link.startswith("/documents/")] == tie_order
        _, _, equivalent = read(alice, query_path(next_page, terms="Ｒｕｓｔ عربي RUST"), "canonical-cursor")
        assert [link for link in equivalent.links if link.startswith("/documents/")] == [third]
        for label, changes in (("changed-terms", {"terms": "Rust"}), ("changed-range", {"maximum": 99}),
                               ("changed-filter", {"included": "false"})):
            read(alice, query_path(next_page, **changes), label, 400)
        read(bob, next_page, "other-principal-cursor", 400)
        token = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(next_page).query))["cursor"]
        forged = ("A" if token[0] != "A" else "B") + token[1:]
        read(alice, query_path(next_page, cursor=forged), "forged-cursor", 400)
        read(alice, filtered, "filtered-direct-read")
        assert b"Filtered private" in (output / "filtered-direct-read.html").read_bytes()
        read(bob, filtered, "other-principal-direct-read", 404)
        read(alice, private, "private-decoy-direct-read", 404)
        _, _, false_matches = read(alice, query_path(search_path, included="false"), "false-filter")
        assert [link for link in false_matches.links if link.startswith("/documents/")] == [filtered]
        _, _, narrow = read(alice, query_path(search_path, minimum=20, maximum=21), "typed-range")
        assert [link for link in narrow.links if link.startswith("/documents/")] == [third]
        stats = search_path.replace("/search?", "/statistics?", 1)
        read(Browser(origin), stats, "anonymous-statistics", 303)
        _, values, _ = read(alice, stats, "statistics")
        assert all(text in values for text in (b"Count: 3", b"Sum: 10", b"Min: 2", b"Max: 5"))
        _, values, _ = read(bob, stats, "private-statistics")
        assert all(text in values for text in (b"Count: 1", b"Sum: 1000", b"Min: 1000", b"Max: 1000"))
        assert b"Count: 3" not in values and b"Sum: 10<" not in values
        _, values, _ = read(alice, query_path(stats, terms="absent"), "empty-statistics")
        assert all(text in values for text in (b"Count: 0", b"Sum: 0", b"Min: none", b"Max: none"))
        for label, changes, expected in (
            ("empty-search", {"terms": ""}, 404),
            ("punctuation-search", {"terms": "!!!"}, 400),
            ("eight-tokens", {"terms": "one two three four five six seven eight"}, 200),
            ("too-many-tokens", {"terms": "one two three four five six seven eight nine"}, 400),
            ("sixty-four-scalars", {"terms": "ش" * 64}, 200),
            ("long-token", {"terms": "ش" * 65}, 400),
            ("noncanonical-range", {"minimum": "01"}, 404),
            ("out-of-domain-range", {"minimum": "-1"}, 404),
            ("invalid-boolean", {"included": "TRUE"}, 404),
            ("reversed-range", {"minimum": 21, "maximum": 20}, 422),
            ("malicious-search", {"terms": '<script onload="bad">&'}, 200),
        ):
            # Preserve the existing public categories: malformed route input is
            # 404, tokenizer limits are 400, runtime-rejected ranges are 422.
            # A valid malicious spelling is searched and rendered as plain text.
            _, body, _ = read(alice, query_path(search_path, **changes), label, expected)
            assert b"<script" not in body
        read(alice, search_path + "&terms=duplicate", "duplicate-parameter", 404)
        read(alice, search_path + "&undeclared=1", "undeclared-parameter", 404)
        read(alice, query_path(search_path, terms="x" * 1025), "query-url-limit", 404)
        read(alice, "/documents/01", "noncanonical-record-path", 404)
        create(alice, "Overflow one", "overflow", 60, 9223372036854775807)
        create(alice, "Overflow two", "overflow", 61, 9223372036854775807)
        _, values, _ = read(alice, query_path(stats, terms="overflow"), "checked-overflow")
        assert b"Count: 2" in values and b"Sum error: Overflow" in values and b"Sum: " not in values
        assert b"Min: 9223372036854775807" in values and b"Max: 9223372036854775807" in values
        before_upgrade = snapshot()

    # An explicit operator-approved contract update uses the same fixture keys
    # and data. Labels are excluded from normalized storage schema; no migration,
    # database reset, field data write or receipt rewrite is involved.
    upgraded = copy.deepcopy(manifest)
    upgraded["resources"][0]["fields"][0]["label"] += " revised"
    upgraded_path = output / "upgraded-manifest.json"
    upgraded_path.write_text(json.dumps(upgraded, ensure_ascii=False, indent=2) + "\n")
    config["manifest"] = str(upgraded_path)
    write_config()
    new_approval = json.loads(command("deployment-hash", config_path))
    assert new_approval["deployment_digest"] != approval["deployment_digest"]
    config["approved_contract"] = new_approval["deployment_digest"]
    write_config()
    with server("upgraded"):
        # A current successful GET proves old-cursor denial is caused by its
        # bound contract, rather than a failed deployment or broken session.
        read(alice, search_path, "new-contract-search")
        read(alice, next_page, "old-contract-cursor", 400)
        assert snapshot() == before_upgrade
    result = {
        "provider": "postgresql" if args.postgres else "sqlite",
        "sdk_component_sha256": hashlib.sha256(component.read_bytes()).hexdigest(),
        "deployment_digest": approval["deployment_digest"],
        "upgraded_deployment_digest": new_approval["deployment_digest"],
        "persisted_get_checkpoints": checks,
        "final_state": before_upgrade,
        "scope": "normal CLI plus native NoJS form HTTP; browser-engine proof is separate",
    }
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("production SDK NoJS query flow passed (" + result["provider"] + ")")


if __name__ == "__main__":
    main()
