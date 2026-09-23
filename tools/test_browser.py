#!/usr/bin/env python3
"""Test the admitted Rust component in Firefox with JavaScript disabled.

Requires Firefox, geckodriver, and a built noxide CLI. All browser HTTP(S) passes
through a local proxy, which allows requests only to the test origin. The onion
case tests browser rules without emulating Tor's anonymity.
"""
import argparse
import base64
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ELEMENT = "element-6066-11e4-a52e-4f735466cecf"


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def call(url, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data, {"Content-Type": "application/json"}, method=method)
    with HTTP.open(request, timeout=60) as response:
        return json.load(response)["value"]


def ready(url):
    for _ in range(100):
        try:
            HTTP.open(url, timeout=0.2).close()
            return
        except urllib.error.HTTPError:
            return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise RuntimeError("test service did not start")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", type=Path, required=True)
    parser.add_argument("--geckodriver", default="geckodriver")
    parser.add_argument("--database", help="URL of an empty disposable PostgreSQL database; default SQLite")
    parser.add_argument("--onion", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = ROOT / "target/debug/noxide"
    manifest = ROOT / "examples/private-notes/manifest.json"
    approved = subprocess.check_output([binary, "contract-hash", manifest], text=True).strip()
    backend_port, driver_port = port(), port()
    authority = ("a" * 56 + ".onion") if args.onion else f"localhost:{backend_port}"
    origin = "http://" + authority
    config = {"database": {"postgres": args.database} if args.database else {"sqlite": "notes.db"},
              "keys": "host-keys.json", "component": str(args.component.resolve()),
              "manifest": str(manifest), "approved_contract": approved,
              "origin": origin, "listen": {"tcp": f"127.0.0.1:{backend_port}"}}
    configuration = args.output / "runtime.json"
    configuration.write_text(json.dumps(config))
    subprocess.run([binary, "init", configuration], check=True)
    for user, password in [("alice", "Alice private test password"), ("bob", "Bob private test password")]:
        path = args.output / f"{user}.password"
        path.write_text(password)
        path.chmod(0o600)
        subprocess.run([binary, "account", configuration, user, path], check=True)
        path.unlink()
    paths = []
    requests = []
    blocked = []

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_CONNECT(self):
            blocked.append(self.path)
            self.send_error(403)

        def forward(self):
            url = urllib.parse.urlsplit(self.path)
            if url.scheme != "http" or url.netloc != authority:
                blocked.append(self.path)
                self.send_error(403)
                return
            path = url.path + ("?" + url.query if url.query else "")
            paths.append(path)
            size = int(self.headers.get("Content-Length", "0"))
            assert size <= 65536
            body = self.rfile.read(size) if size else None
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ("connection", "proxy-connection", "host")}
            headers["Host"] = authority
            connection = http.client.HTTPConnection("127.0.0.1", backend_port, timeout=5)
            try:
                connection.request(self.command, path, body, headers)
                response = connection.getresponse()
                requests.append({"method": self.command, "path": path, "origin": self.headers.get("Origin"), "status": response.status})
                payload = response.read(262145)
                assert len(payload) <= 262144
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in ("connection", "transfer-encoding", "content-length"):
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            finally:
                connection.close()

        do_GET = forward
        do_POST = forward

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    proxy.daemon_threads = True
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    server_log = (args.output / "server.log").open("w")
    driver_log = (args.output / "browser.log").open("w")
    server = subprocess.Popen([binary, "serve", configuration], stdout=server_log, stderr=subprocess.STDOUT)
    driver = subprocess.Popen([args.geckodriver, "--host", "127.0.0.1", "--port", str(driver_port)], stdout=driver_log, stderr=subprocess.STDOUT)
    session = None
    try:
        ready(f"http://127.0.0.1:{backend_port}/")
        endpoint = f"http://127.0.0.1:{driver_port}"
        ready(endpoint + "/status")
        prefs = {"javascript.enabled": False, "network.proxy.type": 1,
                 "network.proxy.http": "127.0.0.1", "network.proxy.http_port": proxy.server_port,
                 "network.proxy.ssl": "127.0.0.1", "network.proxy.ssl_port": proxy.server_port,
                 "network.proxy.no_proxies_on": "", "network.proxy.allow_hijacking_localhost": True,
                 "network.dns.disablePrefetch": True, "network.prefetch-next": False,
                 "network.captive-portal-service.enabled": False, "network.connectivity-service.enabled": False,
                 "app.update.auto": False, "datareporting.healthreport.uploadEnabled": False,
                 "toolkit.telemetry.enabled": False, "dom.push.enabled": False}
        result = call(endpoint + "/session", "POST", {"capabilities": {"alwaysMatch": {"browserName": "firefox", "moz:firefoxOptions": {"args": ["-headless"], "prefs": prefs}}}})
        session = endpoint + "/session/" + result["sessionId"]

        def webdriver(path, method="GET", value=None):
            return call(session + path, method, value)

        def element(selector):
            return webdriver("/element", "POST", {"using": "css selector", "value": selector})[ELEMENT]

        def text(selector, value):
            webdriver("/element/" + element(selector) + "/value", "POST", {"text": value})

        def click(selector):
            webdriver("/element/" + element(selector) + "/click", "POST", {})

        def attribute(selector, name):
            return webdriver("/element/" + element(selector) + "/attribute/" + name)

        def visit(path):
            webdriver("/url", "POST", {"url": origin + path})

        def login(user, password):
            visit("/login")
            text('[name="username"]', user)
            text('[name="password"]', password)
            click("main button")

        login("alice", "Alice private test password")
        assert "No notes yet" in webdriver("/source")
        submission = attribute('[name="_submission"]', "value")
        csrf = attribute('main [name="_csrf"]', "value")
        note = '\n<script>window.evil=true</script>\n<img src="https://attacker.invalid/x">\nAlice only'
        text('[name="body"]', note)
        click("main button")
        source = webdriver("/source")
        assert "&lt;script&gt;" in source and "Alice only" in source
        assert webdriver("/element/" + element("pre") + "/property/textContent") == note
        assert not webdriver("/elements", "POST", {"using": "css selector", "value": "script,img,iframe"})
        location = webdriver("/url")
        cookies = webdriver("/cookie")
        session_cookie = next(c for c in cookies if c["name"] == "noxide_session")
        assert session_cookie["httpOnly"] and session_cookie["sameSite"] == "Strict"
        assert not session_cookie["secure"]  # Both tested origins use HTTP.
        saved = urllib.parse.urlencode({"_csrf": csrf, "_submission": submission, "body": note}).encode()

        def raw_post(body):
            connection = http.client.HTTPConnection("127.0.0.1", backend_port, timeout=5)
            connection.request("POST", "/_noxide/action/1", body,
                               {"Host": authority, "Origin": origin, "Content-Type": "application/x-www-form-urlencoded",
                                "Cookie": "noxide_session=" + session_cookie["value"]})
            response = connection.getresponse()
            result = (response.status, response.getheader("Location"), response.read().decode())
            assert response.getheader("Cache-Control") == "no-store"
            assert "default-src 'none'" in response.getheader("Content-Security-Policy")
            connection.close()
            return result

        # Discarding a committed response and repeating its original POST uses
        # exactly the same receipt protocol as an ambiguous connection failure.
        first = raw_post(saved)
        second = raw_post(saved)
        assert first[:2] == second[:2] == (303, urllib.parse.urlsplit(location).path)
        changed = urllib.parse.urlencode({"_csrf": csrf, "_submission": submission, "body": "different input"}).encode()
        status, _, conflict = raw_post(changed)
        assert status == 409 and "already saved different content" in conflict
        assert '_submission' not in conflict
        visit("/")
        assert webdriver("/source").count("Alice only") == 1
        assert webdriver("/element/" + element("pre") + "/property/textContent") == note
        fresh = attribute('[name="_submission"]', "value")
        invalid = urllib.parse.urlencode({"_csrf": csrf, "_submission": fresh, "body": " "}).encode()
        status, _, html = raw_post(invalid)
        assert status == 422 and 'aria-invalid="true"' in html and fresh in html
        (args.output / "notes.png").write_bytes(base64.b64decode(webdriver("/screenshot")))
        text('[name="body"]', '\n ')
        click("main button")
        assert webdriver("/element/" + element('[name="body"]') + "/property/value") == '\n '
        assert 'aria-invalid="true"' in webdriver("/source")
        visit("/")
        click('nav form[action="/logout"] button')
        login("bob", "Bob private test password")
        assert "No notes yet" in webdriver("/source")
        visit(urllib.parse.urlsplit(location).path)
        assert "Alice only" not in webdriver("/source")
        assert "This note is not available." in webdriver("/source")
        assert all(p.startswith(("/",)) for p in paths)
        assert not any("attacker" in p for p in paths)
        assert not any("attacker.invalid" in destination for destination in blocked), "browser attempted to load the injected external image"
        print(json.dumps({"browser": result["capabilities"]["browserVersion"], "origin": origin,
                          "javascript": False, "cookie_policy": "HttpOnly; SameSite=Strict; HTTP transport",
                          "flow": "create, literal escaping, replay, field recovery, logout, cross-user denial passed"}))
    except Exception:
        if session:
            try:
                (args.output / "failure.html").write_text(call(session + "/source"))
                (args.output / "failure.png").write_bytes(base64.b64decode(call(session + "/screenshot")))
            except Exception:
                pass
        raise
    finally:
        if session:
            try:
                call(session, "DELETE")
            except Exception:
                pass
        for process in (driver, server):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        proxy.shutdown()
        proxy.server_close()
        server_log.close()
        driver_log.close()
        (args.output / "requests.json").write_text(json.dumps(requests, indent=2))
        (args.output / "blocked-browser-requests.json").write_text(json.dumps(blocked, indent=2))


if __name__ == "__main__":
    main()
