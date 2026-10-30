#!/usr/bin/env python3
"""Exercise the VM-built public example through the real host and HTTP server.

Only the trusted CLI executes on the host. The component remains isolated by the
runtime. Database rows below are operator-controlled test fixtures.
"""
import argparse
import http.client
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import time
import re
from html import unescape

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = ROOT / "target/debug/noxide"
    digest = subprocess.check_output(
        [binary, "contract-hash", args.manifest.resolve()], text=True, timeout=10).strip()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = args.output / "runtime.json"
    config.write_text(json.dumps({
        "database": {"sqlite": "articles.db"}, "keys": "host-keys.json",
        "component": str(args.component.resolve()), "manifest": str(args.manifest.resolve()),
        "approved_contract": digest, "origin": f"http://localhost:{port}",
        "listen": {"tcp": f"127.0.0.1:{port}"},
    }))
    subprocess.run([binary, "init", config], check=True, timeout=10)
    subprocess.run([binary, "schema", "indexes", config], check=True, timeout=10)

    def get(path, cookie=""):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", path, headers={"Host": f"localhost:{port}", "Cookie": cookie})
            response = connection.getresponse()
            body = response.read(131073)
            assert len(body) <= 131072
            return response.status, dict(response.getheaders()), body.decode()
        finally:
            connection.close()

    with (args.output / "server.log").open("wb") as log:
        server = subprocess.Popen([binary, "serve", config], stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                assert server.poll() is None, "host exited; inspect server.log"
                try:
                    status, _, _ = get("/")
                    if status == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.1)
            else:
                raise TimeoutError("public host did not become ready")
            with sqlite3.connect(args.output / "articles.db") as database:
                database.execute("BEGIN IMMEDIATE")
                resource = database.execute(
                    "SELECT storage_id FROM nx_resource_catalog WHERE resource_key='articles'"
                ).fetchone()[0]
                for identifier, published in ((1, "true"), (2, "false"), (3, "true"), (4, "true")):
                    fields = {"title": "Public <script>" if identifier == 1 else (f"Other public {identifier}" if published == "true" else "Unpublished fixture"),
                              "body": "Published body" if identifier == 1 else "Hidden body",
                              "published": published, "private_notes": "Private editorial fixture", "category": "games" if identifier == 4 else "books"}
                    # Allocate creation order in the same transaction as the fixture row.
                    sequence = database.execute(
                        "UPDATE nx_creation_counter SET value=value+1 "
                        "WHERE singleton=1 AND value<9223372036854775807 RETURNING value"
                    ).fetchone()[0]
                    database.execute(
                        "INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES(?,?,NULL,'',?,?,1,?)",
                        (resource, identifier, json.dumps(fields), f"fixture-{identifier}", sequence))
            status, headers, body = get("/")
            assert status == 200 and "Public &lt;script&gt;" in body
            assert "Unpublished fixture" not in body and "Private editorial fixture" not in body
            assert "<script>" not in body
            assert "no-store" in headers["cache-control"]
            assert "content-security-policy" in headers
            assert "set-cookie" not in headers
            assert get("/", "session=invalid")[2] == body, "public page must ignore cookies"
            status, _, body = get("/articles/1")
            assert status == 200 and "Published body" in body
            assert "Private editorial fixture" not in body and "<script>" not in body
            for path in ("/articles/2", "/articles/999"):
                status, _, body = get(path)
                assert status == 404
                assert "Hidden body" not in body and "Private editorial fixture" not in body
            status, _, body = get("/categories?category=books")
            assert status == 200 and "Public &lt;script&gt;" in body
            link = unescape(re.search(r'href="([^"]*cursor=[^"]+)"', body).group(1))
            assert "category=books&amp;cursor=" in body
            assert get(link)[0] == 200
            assert get(link.replace("category=books", "category=games"))[0] != 200
            assert get("/categories?category=games")[0] == 200
            status, _, overview = get("/overview?category=books")
            assert status == 200 and "More in category" in overview and ">See all</a>" in overview
            assert 'href="/categories?category=books"' in overview
            next_overview = unescape(re.search(r'href="([^"]*cursor=[^"]+)"', overview).group(1))
            status, _, second = get(next_overview)
            assert status == 200 and "Public &lt;script&gt;" in second, "preview must ignore the paginated cursor"
            status, _, complete = get("/overview?category=games")
            assert status == 200 and "More in category" not in complete and ">See all</a>" not in complete
            status, _, highlights = get("/highlights?category=books")
            assert status == 200 and ">Next page</a>" not in highlights
            assert get("/highlights?category=books&cursor=ignored")[2] == highlights
            missing = get("/missing")
            for query in ("", "?category=unknown", "?category=Books", "?category=books&category=games", "?other=books", "?category=books&other=x", "?category=%GG"):
                invalid = get("/categories" + query)
                assert invalid[0] == missing[0] == 404 and invalid[2] == missing[2]
            (args.output / "results.json").write_text(json.dumps({
                "public_list": True, "public_read": True, "unpublished_hidden": True,
                "private_projection_hidden": True, "escaped": True,
            }, indent=2) + "\n")
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
    print("Public component HTTP checks passed: visibility, projections, cookies, and escaping.")


if __name__ == "__main__":
    main()
