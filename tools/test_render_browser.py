#!/usr/bin/env python3
"""Check host-rendered textarea values in Firefox with JavaScript disabled."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from test_browser import ELEMENT, ROOT, call, port, ready


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--geckodriver", default="geckodriver")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    fixtures = args.output / "forms.json"
    # Compile only trusted framework tests. No application build runs on the host.
    subprocess.run([
        "cargo", "test", "-p", "noxide-host", "--test", "render", "--locked", "--offline",
        "--", "--exact", "textarea_preserves_browser_normalized_newlines",
    ], cwd=ROOT, env={**os.environ, "NOXIDE_TEST_FORM_FIXTURES": str(fixtures)}, check=True)
    cases = json.loads(fixtures.read_text())
    endpoint = f"http://127.0.0.1:{port()}"
    session = None
    with (args.output / "browser.log").open("w") as log:
        driver = subprocess.Popen([
            args.geckodriver, "--host", "127.0.0.1", "--port", endpoint.rsplit(":", 1)[1],
        ], stdout=log, stderr=subprocess.STDOUT)
        try:
            ready(endpoint + "/status")
            prefs = {"javascript.enabled": False, "network.proxy.type": 1,
                     "network.proxy.http": "127.0.0.1", "network.proxy.http_port": 9,
                     "network.proxy.ssl": "127.0.0.1", "network.proxy.ssl_port": 9,
                     "network.dns.disablePrefetch": True, "network.prefetch-next": False,
                     "network.captive-portal-service.enabled": False,
                     "network.connectivity-service.enabled": False}
            browser = call(endpoint + "/session", "POST", {
                "capabilities": {"alwaysMatch": {"browserName": "firefox", "moz:firefoxOptions": {
                    "args": ["-headless"], "prefs": prefs,
                }}},
            })
            session = endpoint + "/session/" + browser["sessionId"]
            for i, case in enumerate(cases):
                page = args.output / f"form-{i}.html"
                page.write_bytes(case["html"].encode("utf-8"))
                call(session + "/url", "POST", {"url": page.as_uri()})
                element = call(session + "/element", "POST", {
                    "using": "css selector", "value": "textarea[name=body]",
                })[ELEMENT]
                value = call(session + "/element/" + element + "/property/value")
                assert value == case["expected"], (
                    f"input {case['input']!r}: expected {case['expected']!r}, got {value!r}"
                )
            print(f"Firefox {browser['capabilities']['browserVersion']}: "
                  f"{len(cases)} textarea cases passed with JavaScript disabled")
        finally:
            try:
                if session:
                    call(session, "DELETE")
            finally:
                driver.terminate()
                try:
                    driver.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    driver.kill()
                    driver.wait()


if __name__ == "__main__":
    main()
