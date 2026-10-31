#!/usr/bin/env python3
"""Prove anonymous paste forms against a built bundle and fresh disposable store.

The explicit synthetic endpoint uses a loopback SOCKS fixture that rejects all
remote requests. It never resolves DNS, connects remotely or accepts delivery.
--await-expiry waits for the real one-hour host cutoff; a short deterministic
expiry and actual 2xx receiver proof belong to the parent host test fixture.
"""
import argparse
import contextlib
import csv
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.parse

from test_query_http import Browser

SYNTHETIC_HOST = "hooks.example.com"


class Markup(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.forms, self.links, self.tags, self.secrets = [], [], [], []
        self.current, self.in_pre = None, False
        self.feed(body.decode("utf-8"))

    def handle_starttag(self, tag, pairs):
        attrs = dict(pairs)
        self.tags.append((tag, attrs))
        if tag == "form":
            assert self.current is None
            self.current = {"action": attrs["action"], "enctype": attrs.get("enctype"), "controls": []}
            self.forms.append(self.current)
        elif self.current is not None and tag in ("input", "textarea") and "name" in attrs:
            self.current["controls"].append((attrs["name"], attrs.get("value", ""), attrs.get("type", tag)))
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        if tag == "pre":
            self.in_pre = True
            self.secrets.append("")

    def handle_data(self, data):
        if self.in_pre:
            self.secrets[-1] += data

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None
        if tag == "pre":
            self.in_pre = False

    def local_only(self):
        assert not any(tag in ("script", "iframe", "object") for tag, _ in self.tags)
        for _, attrs in self.tags:
            for key in ("href", "src", "action"):
                if key in attrs:
                    assert attrs[key].startswith("/") and not attrs[key].startswith("//"), "undeclared external browser destination"


class RejectingProxy:
    """One bounded loopback acceptor. Every SOCKS request receives failure."""
    def __enter__(self):
        self.stop = threading.Event()
        self.attempted = threading.Event()
        self.errors, self.commands = [], []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.listener.settimeout(.2)
        self.address = f"127.0.0.1:{self.listener.getsockname()[1]}"
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    @staticmethod
    def exact(stream, count):
        result = bytearray()
        while len(result) < count:
            part = stream.recv(count - len(result))
            if not part:
                raise EOFError("incomplete local SOCKS fixture request")
            result.extend(part)
        return bytes(result)

    def run(self):
        while not self.stop.is_set():
            try:
                stream, peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with stream:
                stream.settimeout(1)
                try:
                    assert peer[0] == "127.0.0.1"
                    version, count = self.exact(stream, 2)
                    assert version == 5 and 1 <= count <= 8
                    assert 0 in self.exact(stream, count)
                    stream.sendall(b"\x05\x00")
                    version, command, reserved, kind = self.exact(stream, 4)
                    assert version == 5 and reserved == 0 and command in (0xf0, 1)
                    if kind == 3:
                        width = self.exact(stream, 1)[0]
                        assert 1 <= width <= 253
                        host = self.exact(stream, width)
                        assert host == SYNTHETIC_HOST.encode()
                    else:
                        assert kind in (1, 4)
                        self.exact(stream, 4 if kind == 1 else 16)
                    self.exact(stream, 2)
                    self.commands.append(command)
                    # No resolver or outgoing socket exists in this fixture.
                    stream.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                    self.attempted.set()
                except (AssertionError, OSError, EOFError) as error:
                    self.errors.append(type(error).__name__)
                    self.attempted.set()

    def __exit__(self, *_args):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive(), "local rejecting proxy did not stop"
        assert not self.errors, "local SOCKS fixture protocol failed"
        assert all(command == 0xf0 for command in self.commands), "host attempted CONNECT after rejected RESOLVE"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--host-cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--postgres", help="dedicated empty disposable loopback PostgreSQL database URL")
    parser.add_argument("--await-expiry", action="store_true", help="also wait one hour for actual expiry and cleanup/repair")
    args = parser.parse_args()
    bundle, cli, output = args.bundle.resolve(), args.host_cli.resolve(), args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = dict(os.environ, XDG_STATE_HOME=str(output / "state"))
    if args.postgres:
        assert urllib.parse.urlsplit(args.postgres).hostname in ("localhost", "127.0.0.1", "::1"), "loopback disposable fixture only"

    # The restore exercise later switches every helper to the restored deployment.
    active = {"postgres": args.postgres, "sqlite": output / "paste.db", "config": output / "runtime.json"}

    def postgres(sql, url=None):
        result = subprocess.run(["psql", url or active["postgres"], "--no-psqlrc", "--csv", "--tuples-only", "--command", sql], capture_output=True, text=True, check=False, timeout=20)
        assert result.returncode == 0, "fixture PostgreSQL read failed; database retained"
        return list(csv.reader(io.StringIO(result.stdout)))

    if args.postgres:
        assert postgres("SELECT COUNT(*) FROM pg_catalog.pg_tables WHERE schemaname='public'") == [["0"]], "fixture database must be empty"
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    actions = {action["name"]: action for action in manifest["actions"]}
    create, cleanup = actions["Create paste"], actions["Cleanup paste"]
    create_path = f'/actions/{create["id"]}'
    assert len(create["steps"]) == 1 and {item["name"] for item in create["inputs"]} == {"title", "body", "file"}
    assert not any(binding["action"] == cleanup["id"] for binding in manifest["web_bindings"])
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    config_path = active["config"]
    command_count = 0

    def command(*arguments, success=True):
        nonlocal command_count
        command_count += 1
        result = subprocess.run([str(cli), *map(str, arguments)], capture_output=True, env=environment, check=False, timeout=35)
        (output / f"cli-{command_count:03d}-{arguments[0]}.log").write_bytes(result.stdout + result.stderr)
        assert (result.returncode == 0) == success, f"fixture CLI {arguments[0]} exit {result.returncode}; output retained"
        return result.stdout

    def rows(sql):
        if args.postgres:
            return postgres(sql)
        with sqlite3.connect(active["sqlite"]) as database:
            return [[None if value is None else str(value) for value in row] for row in database.execute(sql)]

    def pastes():
        return {int(identity): json.loads(fields) for identity, fields in rows("SELECT id,fields FROM nx_records ORDER BY resource,id")}

    def snapshot():
        # Background clock/outbox claim state is allowed to advance independently.
        return {
            "records": rows("SELECT resource,id,fields,revision FROM nx_records ORDER BY resource,id"),
            "receipts": rows("SELECT COUNT(*) FROM nx_receipts"),
            "blobs": rows("SELECT state FROM nx_blobs ORDER BY blob_ref"),
            # The host creates its zero quota row lazily after startup.
            "quota": rows("SELECT reserved_bytes,used_bytes,objects FROM nx_blob_store") or [["0", "0", "0"]],
            "jobs": rows("SELECT id,due_ms FROM nx_jobs ORDER BY id"),
            "effects": rows("SELECT id,payload_digest FROM nx_outbox ORDER BY id"),
        }

    def parse(body):
        document = Markup(body)
        document.local_only()
        return document

    def read(browser, path, label, expected=200):
        before = snapshot()
        status, headers, body = browser.request(path)
        (output / f"{label}.html").write_bytes(body)
        assert status == expected, f"{label}: expected {expected}, got {status}"
        assert snapshot() == before, f"{label}: GET changed application state"
        return headers, body, parse(body)

    def upload_form(document):
        return next(form for form in document.forms if form["action"] == create_path and form["enctype"] == "multipart/form-data")

    def upload(browser, form, title, body, filename, payload, label, expected, csrf=None):
        assert form["controls"][-1] == ("file", "", "file"), "file must be the final submitted control"
        boundary = "noxide-expiring-paste-fixture"
        encoded = bytearray()
        for name, value, kind in form["controls"]:
            if kind == "file":
                encoded += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\nContent-Type: text/html\r\n\r\n').encode()
                encoded += payload + b"\r\n"
            else:
                value = {"title": title, "body": body}.get(name, value)
                if name == "_csrf" and csrf is not None:
                    value = csrf
                encoded += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n').encode()
        encoded += f"--{boundary}--\r\n".encode()
        status, headers, response = browser.request(form["action"], encoded, f"multipart/form-data; boundary={boundary}")
        (output / f"{label}.html").write_bytes(response)
        allowed = expected if isinstance(expected, tuple) else (expected,)
        assert status in allowed, f"{label}: expected {expected}, got {status}"
        return headers, response, parse(response)

    def invalid_handle(browser, form, handle, label):
        fields = [(name, value) for name, value, kind in form["controls"] if kind != "file" and name not in ("_upload", "title", "body")]
        fields += [("title", "Foreign handle"), ("body", "Rejected handle fixture"), ("file", handle)]
        before = snapshot()
        status, _, response = browser.request(create_path, urllib.parse.urlencode(fields).encode(), "application/x-www-form-urlencoded")
        (output / f"{label}.html").write_bytes(response)
        assert status in (400, 403, 404, 422), f"{label}: expected bounded rejection, got {status}"
        assert snapshot() == before, f"{label}: reused or foreign handle committed"

    @contextlib.contextmanager
    def server(label):
        with (output / f"server-{label}.log").open("wb") as log:
            process = subprocess.Popen([str(cli), "serve", str(active["config"])], stdout=log, stderr=subprocess.STDOUT, env=environment)
            try:
                deadline = time.monotonic() + 25
                while True:
                    assert process.poll() is None, "fixture host exited; inspect retained log"
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, "fixture listener did not become ready"
                        time.sleep(.02)  # readiness only
                yield
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=65)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise AssertionError("fixture host shutdown exceeded original transport bound")
                assert process.returncode == 0, "fixture host did not shut down cleanly"

    report = {"provider": "postgres" if args.postgres else "sqlite", "normal_forms": False,
              "delivery": "not_delivered_local_proxy_rejects_all_requests", "expiry": "not_run_parent_clock_fixture_or_await_expiry_required"}
    with RejectingProxy() as proxy:
        secret = output / "synthetic-token"
        secret.write_bytes(b"expiring-paste-local-fixture-token")
        secret.chmod(0o600)
        limits = {"file_bytes": 1048576, "app_bytes": 16777216, "objects": 64, "live_stages": 2, "uploads": 1, "downloads": 2}
        config = {
            "database": {"postgres": args.postgres} if args.postgres else {"sqlite": "paste.db"},
            "keys": "keys.json", "manifest": str(manifest_path), "component": str(bundle / "expiring_paste.component.wasm"),
            "origin": origin, "listen": {"tcp": f"127.0.0.1:{port}"}, "approved_contract": "",
            "blobs": {"directory": "objects", "ceilings": {"limits": limits, "anonymous": {
                "deployment": {"stages": 4, "bytes": 4194304}, "capability": {"stages": 2, "bytes": 2097152}}}},
            "jobs": {"grants": [{"worker": "paste_cleanup", "tenant": "", "actions": [cleanup["id"]]}],
                     "limits": {"pending_per_app": 64, "pending_per_tenant": 64, "worker_concurrency": 1}},
            "effects": {"grants": [{"endpoint": "synthetic_events", "tenant": "", "host": SYNTHETIC_HOST, "port": 443, "path": "/published"}],
                        "secrets": [{"slot": "synthetic_events_token", "path": "synthetic-token"}], "tor_proxy": proxy.address,
                        "limits": {"pending_per_app": 64, "pending_per_tenant": 64, "worker_concurrency": 1}},
        }
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        approval = json.loads(command("deployment-hash", config_path))
        assert not any((output / name).exists() for name in ("paste.db", "keys.json", "objects")), "approval hashing opened runtime resources"
        assert approval["effective_blobs"]["anonymous"] is not None and approval["effective_effects"]["grants"]
        config["approved_contract"] = approval["deployment_digest"]
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        command("init", config_path)
        command("schema", "indexes", config_path)
        payload = b"<svg><script>untrusted public attachment</script></svg>"
        text = "Public text <script>alert('escaped')</script>"
        with server("forms"):
            creator, foreign = Browser(origin), Browser(origin)
            _, _, home = read(creator, "/", "home")
            form = upload_form(home)
            before = snapshot()
            upload(creator, form, "Public <paste>", text, "file.html", payload, "csrf-rejection", (400, 403), csrf="forged")
            assert snapshot() == before, "CSRF rejection consumed quota or staged bytes"
            _, _, retry = upload(creator, form, "   ", text, "../../unsafe.html", payload, "staged-title-rejection", 422)
            retry_form = upload_form(retry)
            assert rows("SELECT state FROM nx_blobs") == [["staged"]]
            assert not pastes() and rows("SELECT COUNT(*) FROM nx_outbox") == [["0"]]
            handle = rows("SELECT upload_handle FROM nx_blobs")[0][0]
            _, _, other_home = read(foreign, "/", "foreign-home")
            invalid_handle(foreign, upload_form(other_home), handle, "foreign-handle-rejection")
            _, handover, owned = upload(creator, retry_form, "Public <paste>", text, "", b"", "handover", 200)
            assert len(owned.secrets) == 1 and owned.secrets[0] and "edit secret" in handover.decode().lower()
            identity, stored = next(iter(pastes().items()))
            route = f"/pastes/{identity}"
            assert route in owned.links
            assert stored["published"] == "true" and int(stored["expires_at"]) - int(stored["created_at"]) == 3600000
            assert rows("SELECT state,anonymous FROM nx_blobs") == [["attached", "1"]]
            assert rows("SELECT due_ms FROM nx_jobs") == [[stored["expires_at"]]]
            capture = json.loads(rows("SELECT payload FROM nx_outbox")[0][0])
            assert json.loads(capture["body"]) == {"at": int(stored["created_at"]), "event": "published", "paste": identity}
            assert all(value not in capture["body"] for value in (text, payload.decode(), stored["file"], handle, "expiring-paste-local-fixture-token"))
            before = snapshot()
            _, replay, _ = upload(creator, retry_form, "Public <paste>", text, "", b"", "handover-replay", 200)
            assert replay == handover and snapshot() == before, "replay created another attachment, job or effect"
            _, _, fresh_home = read(creator, "/", "fresh-home")
            invalid_handle(creator, upload_form(fresh_home), handle, "reused-handle-rejection")
            _, page, public = read(foreign, route, "public-paste")
            assert b"Public &lt;paste&gt;" in page and b"&lt;script&gt;" in page and payload not in page
            download = next(link for link in public.links if link.startswith("/_noxide/download?ticket="))
            before = snapshot()
            status, headers, body = foreign.request(download)
            assert status == 200 and body == payload and snapshot() == before
            assert headers["Content-Type"] == "application/octet-stream" and headers["Content-Disposition"] == 'attachment; filename="unsafe.html"'
            assert headers["X-Content-Type-Options"] == "nosniff" and headers["Cache-Control"] == "no-store"
            assert "default-src 'none'" in headers["Content-Security-Policy"]
            assert foreign.request(download, extra={"Range": "bytes=0-1"})[0] == 404
            assert foreign.request("/_noxide/download?ticket=" + stored["file"])[0] == 404
            # Valid page credentials must still reach no browser binding for the service action.
            credentials = [(name, value) for name, value, _ in upload_form(fresh_home)["controls"] if name in ("_csrf", "_submission")]
            status, _, _ = creator.request(f'/actions/{cleanup["id"]}', urllib.parse.urlencode(credentials).encode(), "application/x-www-form-urlencoded")
            assert status == 404, "service cleanup acquired a browser binding"
            assert proxy.attempted.wait(timeout=15), "outbox did not reach the isolated rejecting proxy"
            deadline = time.monotonic() + 10
            while rows("SELECT state,attempts FROM nx_outbox") != [["pending", "1"]]:
                assert time.monotonic() < deadline, "outbox did not settle a bounded retry after proxy rejection"
                time.sleep(.02)  # committed outbox state determines completion
            report["normal_forms"] = True
            if args.await_expiry:
                original_jobs = {row[0] for row in rows("SELECT id FROM nx_jobs")}
                _, _, home = read(creator, "/", "repair-create-form")
                _, _, _ = upload(creator, upload_form(home), "Repair fixture", "Public repair fixture", "second.bin", b"repair bytes", "repair-handover", 200)
                repair_identity = next(key for key in pastes() if key != identity)
                repair_job = next(row[0] for row in rows("SELECT id FROM nx_jobs") if row[0] not in original_jobs)
        # CLI job/effect commands open the exclusively leased blob store. Run
        # them only after serving has drained and released that store lease.
        metadata = json.loads(command("effects", "inspect", config_path))["effects"]
        assert metadata and all(item["state"] != "delivered" for item in metadata)
        (output / "outbox-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
        if args.await_expiry:
            first_job = next(iter(original_jobs))
            command("jobs", "revoke", config_path, "", "paste_cleanup")
            command("jobs", "cancel", config_path, repair_job)
            command("effects", "revoke", config_path, "", "synthetic_events")
            cutoff = max(int(record["expires_at"]) for record in pastes().values())
            with server("expiry-visibility"):
                deadline = time.monotonic() + 3625
                first_cutoff = int(pastes()[identity]["expires_at"])
                # Refresh direct-read provenance near the cutoff so the tested
                # download ticket remains within its own fifteen-minute life.
                while int(rows("SELECT lifecycle_ms FROM nx_clock WHERE singleton=1")[0][0]) < first_cutoff - 5000:
                    assert time.monotonic() < deadline, "durable host time did not approach the one-hour cutoff"
                    time.sleep(.5)
                boundary_reader = Browser(origin)
                _, _, near_expiry = read(boundary_reader, route, "pre-expiry-fresh-download")
                expiry_download = next(link for link in near_expiry.links if link.startswith("/_noxide/download?ticket="))
                while int(rows("SELECT lifecycle_ms FROM nx_clock WHERE singleton=1")[0][0]) < cutoff:
                    assert time.monotonic() < deadline, "durable host time did not reach the one-hour cutoff"
                    time.sleep(.1)  # real committed host watermark, never a fake clock
                assert len(pastes()) == 2 and rows("SELECT state FROM nx_blobs ORDER BY blob_ref") == [["attached"], ["attached"]]
                read(foreign, route, "expired-paste-hidden", 404)
                read(foreign, f"/pastes/{repair_identity}", "expired-repair-paste-hidden", 404)
                _, listing, listing_document = read(foreign, "/", "expired-list-hidden")
                assert route not in listing_document.links and f"/pastes/{repair_identity}" not in listing_document.links
                assert boundary_reader.request(expiry_download)[0] == 404, "fresh attachment ticket bypassed resource expiry"
            command("jobs", "grant", config_path, "", "paste_cleanup")
            replacement = json.loads(command("jobs", "reconcile", config_path, first_job))["reconciled"]["id"]
            assert command("jobs", "worker-once", config_path).strip() == b"completed"
            assert rows(f"SELECT state FROM nx_jobs WHERE id='{replacement}'") == [["succeeded"]]
            assert identity not in pastes() and repair_identity in pastes()
            before = snapshot()
            assert command("jobs", "worker-once", config_path).strip() == b"idle"
            assert snapshot()["records"] == before["records"], "repeated cleanup changed another paste"
            with server("repair-cleanup"):
                deadline = time.monotonic() + 35
                while pastes() or rows("SELECT state FROM nx_blobs WHERE state <> 'deleted'"):
                    assert time.monotonic() < deadline, "bounded recurring cleanup and physical blob GC did not finish"
                    time.sleep(.05)  # committed deletion/quota predicates, no assumed ordering
                assert rows("SELECT used_bytes,reserved_bytes,objects FROM nx_blob_store") == [["0", "0", "0"]]
            report["expiry"] = "visibility_sealed_worker_once_repair_and_blob_gc_passed"
        # Backup: with serving stopped and the store lease released, copy metadata,
        # immutable objects and pairing markers as one unit, then restore it as a
        # fork with fresh host keys. Old effects and jobs must stay paused.
        restored = output / "restored"
        restored.mkdir(mode=0o700)
        restored_config = json.loads(config_path.read_text())
        if args.postgres:
            source = urllib.parse.urlsplit(args.postgres)
            name = source.path.lstrip("/") + "_restored"
            postgres(f'CREATE DATABASE "{name}" TEMPLATE "{source.path.lstrip("/")}"', source._replace(path="/postgres").geturl())
            restored_url = source._replace(path="/" + name).geturl()
            restored_config["database"] = {"postgres": restored_url}
        else:
            # The host requires a private database file; create it 0600 first.
            os.close(os.open(restored / "paste.db", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            with sqlite3.connect(output / "paste.db") as original, sqlite3.connect(restored / "paste.db") as copy:
                original.backup(copy)
        shutil.copy2(output / "synthetic-token", restored / "synthetic-token")
        command("keygen", restored / "keys.json")
        shutil.copytree(output / "objects", restored / "objects", copy_function=shutil.copy2)
        (restored / "runtime.json").write_text(json.dumps(restored_config, indent=2) + "\n")
        # A copied effect queue is refused until the explicit restore fork adopts it.
        command("effects", "inspect", restored / "runtime.json", success=False)
        assert b"another owner directory" in sorted(output.glob("cli-*-effects.log"))[-1].read_bytes()
        assert json.loads(command("deployment-hash", restored / "runtime.json"))["deployment_digest"] == restored_config["approved_contract"]
        active.update(config=restored / "runtime.json", sqlite=restored / "paste.db", postgres=restored_url if args.postgres else None)
        before_jobs, before_effects = rows("SELECT id,state FROM nx_jobs"), rows("SELECT id,state FROM nx_outbox")
        command("jobs", "fork", active["config"])
        # Metadata without its paired immutable object store is refused.
        (restored / "objects-missing").mkdir(mode=0o700)
        unpaired = {**restored_config, "blobs": {**restored_config["blobs"], "directory": "objects-missing"}}
        (restored / "unpaired.json").write_text(json.dumps(unpaired, indent=2) + "\n")
        command("effects", "inspect", restored / "unpaired.json", success=False)
        refusal = sorted(output.glob("cli-*-effects.log"))[-1].read_bytes()
        assert b"owner directory" not in refusal, refusal
        (output / "unpaired-refusal.log").write_bytes(refusal)
        assert rows("SELECT state FROM nx_jobs") == [["paused"]] and rows("SELECT state FROM nx_outbox") == [["paused"]]
        assert [row[0] for row in rows("SELECT id,state FROM nx_jobs")] == [row[0] for row in before_jobs]
        assert [row[0] for row in rows("SELECT id,state FROM nx_outbox")] == [row[0] for row in before_effects]
        proxy_before = len(proxy.commands)
        with server("restored"):
            reader = Browser(origin)
            _, page, public = read(reader, route, "restored-paste")
            assert b"Public &lt;paste&gt;" in page
            restored_download = next(link for link in public.links if link.startswith("/_noxide/download?ticket="))
            status, _, body = reader.request(restored_download)
            assert status == 200 and body == payload, "restored object did not match its metadata"
            assert reader.request(download)[0] == 404, "a pre-backup download ticket survived host-key rotation"
            time.sleep(2)  # paused rows must stay paused while the restored host runs
            assert rows("SELECT state FROM nx_outbox") == [["paused"]] and len(proxy.commands) == proxy_before
        effect = rows("SELECT id FROM nx_outbox")[0][0]
        command("effects", "resume", active["config"], effect, success=False)  # grant is revoked by the fork
        command("effects", "grant", active["config"], "", "synthetic_events")
        command("effects", "grant-secret", active["config"], "synthetic_events_token")
        command("effects", "resume", active["config"], effect)
        assert rows("SELECT state FROM nx_outbox") == [["pending"]]
        report["backup_restore"] = "paired_copy_fork_paused_download_verified_explicit_regrant"
        report["proxy_requests_rejected"] = len(proxy.commands)
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
