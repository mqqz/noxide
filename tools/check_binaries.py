#!/usr/bin/env python3
"""Fail when a deployed process links code outside its authority.

The crate graph cannot state this: `noxide-cli` builds every binary. Symbols can.
Run after `cargo build --workspace`.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = {
    # The server has no outbound transport, parses no asset formats and runs no guest.
    "noxide-server": ["rustls", "webpki", "cssparser", "image::codecs", "noxide_asset_admission", "wasmtime"],
    # The worker holds no keys, runs no HTTP and handles no logins.
    "noxide-effects-worker": ["noxide_keys", "hyper", "axum", "argon2", "cssparser", "wasmtime"],
    # A guest worker holds only its socket: no keys, database, HTTP or transport.
    "noxide-guest": ["noxide_keys", "sqlx", "hyper", "axum", "rustls", "argon2", "noxide_store"],
    # The key service has no network, no database and no guest runtime.
    "noxide-keyd": ["rustls", "sqlx", "wasmtime", "hyper", "tokio"],
}


def main():
    directory = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target/debug"
    failures = []
    for binary, forbidden in FORBIDDEN.items():
        symbols = subprocess.run(
            ["nm", "--demangle", "--defined-only", str(directory / binary)],
            check=True, capture_output=True, text=True).stdout
        for name in forbidden:
            if name in symbols:
                failures.append(f"{binary} links {name}")
    print("\n".join(failures) or "deployed binaries ok")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
