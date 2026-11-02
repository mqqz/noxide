#!/usr/bin/env python3
"""Fail when a crate or noxide-host module reaches outside its layer.

Modules in the same layer may depend on each other; extraction into crates turns
each boundary into a compiler rule. Test code is excluded.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "crates/noxide-host/src"
LAYERS = [
    ["deployment"],
    ["application"],
    ["http"],
]
RANK = {module: rank for rank, modules in enumerate(LAYERS) for module in modules}
SKIP = re.compile(r"(_tests\.rs|_tests/|/tests\.rs|/tests/|/test_support|/test_account)")


def production(text):
    """Remove #[cfg(test)] items, line comments and string contents."""
    lines, out, i = text.split("\n"), [], 0
    while i < len(lines):
        if re.match(r"\s*#\[cfg\((all\()?test\b", lines[i]):
            depth, opened = 0, False
            i += 1
            while i < len(lines):
                line = re.sub(r'"(\\.|[^"\\])*"', '""', lines[i]).split("//")[0]
                depth += line.count("{") - line.count("}")
                opened |= "{" in line
                i += 1
                if (opened and depth <= 0) or (not opened and line.rstrip().endswith(";")):
                    break
        else:
            out.append(re.sub(r'"(\\.|[^"\\])*"', '""', lines[i]).split("//")[0])
            i += 1
    return "\n".join(out)


def targets(code):
    found = set(re.findall(r"\bcrate::([a-z_]+)", code))
    for group in re.findall(r"\bcrate::\{(.*?)\};", code, re.S):
        depth = 0
        token = ""
        for char in group + ",":
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            elif char == "," and depth == 0:
                name = re.match(r"\s*([a-z_]+)", token)
                if name:
                    found.add(name.group(1))
                token = ""
                continue
            if depth == 0:
                token += char
    return found


# External crates that carry authority, and the only workspace crates allowed them.
RESTRICTED = {
    "sqlx": {"noxide-store"},
    "rustls": {"noxide-effect-delivery"},
    "tokio-rustls": {"noxide-effect-delivery"},
    "webpki-roots": {"noxide-effect-delivery"},
    "httparse": {"noxide-effect-delivery"},
    "noxide-effect-delivery": {"noxide-cli"},
    "argon2": {"noxide-authority"},
    "wasmtime": {"noxide-sandbox"},
    "wasmparser": {"noxide-sandbox"},
    "cssparser": {"noxide-asset-admission"},
    "image": {"noxide-asset-admission"},
    "hmac": {"noxide-keys"},
    "chacha20poly1305": {"noxide-keys"},
    "landlock": {"noxide-confine"},
    "seccompiler": {"noxide-confine"},
}
# Workspace crates that perform no I/O, and may depend only on each other.
# The store depends on these and on nothing above them.
STORE_ALLOWED = {"noxide-protocol", "noxide-admission", "noxide-sql", "noxide-assets", "noxide-sql-macros"}
PURE = {"noxide-admission", "noxide-assets", "noxide-host-calls", "noxide-render", "noxide-sql", "noxide-sql-macros"}
ROOT = SRC.parent.parent.parent
TEST_ONLY = {"noxide-test-support"}


def crate_failures():
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--offline", "--no-deps"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout)
    workspace = {package["name"] for package in metadata["packages"]}
    failures = []
    for package in metadata["packages"]:
        name = package["name"]
        for dependency in package["dependencies"]:
            target = dependency["name"]
            if dependency["kind"] == "dev":
                continue
            if name in RESTRICTED.get(target, {name}):
                pass
            else:
                failures.append(f"{name} must not depend on {target}")
            if target in TEST_ONLY:
                failures.append(f"{name} has a production dependency on {target}")
            if name == "noxide-store" and target in workspace and target not in STORE_ALLOWED:
                failures.append(f"noxide-store must not depend on {target}")
            if name in PURE and target in workspace and target not in PURE | {"noxide-protocol"}:
                failures.append(f"pure crate {name} must not depend on {target}")
    tree = subprocess.run(
        ["cargo", "tree", "-p", "noxide-cli", "--offline", "--edges", "normal,build",
         "--format", "{p} {f}"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout
    if "test-support" in tree:
        failures.append("a deployed binary enables a test-support feature")
    return failures


# Rust has no friend crates, so these calls are confined here instead.
POLICY_COMPILERS = {
    "filter_with": {"noxide-authority"},
    "filter": {"noxide-authority", "noxide-repository"},
}


def filter_failures():
    failures = []
    for crate in sorted((ROOT / "crates").iterdir()):
        if crate.name == "noxide-admission":
            continue
        for path in sorted((crate / "src").rglob("*.rs")):
            if SKIP.search("/" + path.relative_to(crate).as_posix()):
                continue
            code = production(path.read_text())
            for name, allowed in POLICY_COMPILERS.items():
                if crate.name not in allowed and re.search(rf"\bpolicy::{name}\b", code):
                    failures.append(f"{path.relative_to(ROOT)}: must not compile a policy filter")
    return failures


def main():
    failures = crate_failures() + filter_failures()
    for path in sorted(SRC.rglob("*.rs")):
        relative = path.relative_to(SRC).as_posix()
        if SKIP.search("/" + relative) or relative == "lib.rs":
            continue
        module = relative.split("/")[0].removesuffix(".rs")
        if module not in RANK:
            failures.append(f"{relative}: module {module} has no layer")
            continue
        code = production(path.read_text())
        for target in targets(code):
            if target in RANK and RANK[target] > RANK[module]:
                failures.append(f"{relative}: {module} must not depend on {target}")
    print("\n".join(failures) or "host layers ok")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
