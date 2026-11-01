#!/usr/bin/env python3
"""Fail when a noxide-host production module depends on a higher layer.

Modules in the same layer may depend on each other; extraction into crates turns
each boundary into a compiler rule. Test code is excluded.
"""
import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "crates/noxide-host/src"
LAYERS = [
    ["database", "lifecycle_clock"],
    ["limiter", "security", "auth", "authority", "operator_roles"],
    ["blob_state", "blob_io", "blob_store", "blob_inspect", "blob_metadata", "blob_pairing",
     "blob_transport", "blob_multipart", "blob_upload"],
    ["deployment", "effect_deployment", "job_deployment", "repository", "jobs", "effects"],
    ["application"],
    ["http"],
]
RANK = {module: rank for rank, modules in enumerate(LAYERS) for module in modules}
SKIP = re.compile(r"(_tests\.rs|/tests\.rs|/tests/|/test_support|/test_account)")


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


def main():
    failures = []
    for path in sorted(SRC.rglob("*.rs")):
        relative = path.relative_to(SRC).as_posix()
        if SKIP.search("/" + relative) or relative == "lib.rs":
            continue
        module = relative.split("/")[0].removesuffix(".rs")
        if module not in RANK:
            failures.append(f"{relative}: module {module} has no layer")
            continue
        for target in targets(production(path.read_text())):
            if target in RANK and RANK[target] > RANK[module]:
                failures.append(f"{relative}: {module} must not depend on {target}")
    print("\n".join(failures) or "host layers ok")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
