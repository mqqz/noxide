#!/usr/bin/env python3
"""Compile trusted SDK filter positive and negative cases locally."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    board = (ROOT / "tools/fixtures/sdk/task-board-advanced.rs").read_text()
    inbox = (ROOT / "tools/fixtures/queries/private-inbox.rs").read_text()
    public = (ROOT / "examples/public-articles/src/lib.rs").read_text()
    anchor = "list(Task), allow = owner"
    cases = [
        ("boolean", board.replace(anchor, anchor + ", filter(completed = false)"), True),
        ("choice", board.replace(anchor, anchor + ", filter(priority = Priority::Normal)"), True),
        ("unknown", board.replace(anchor, anchor + ", filter(missing = false)"), False),
        ("text", board.replace(anchor, anchor + ', filter(title = String::from("x"))'), False),
        ("account", inbox.replace("page_size = 20", "filter(recipient = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\".parse::<noxide::AccountId>().unwrap()), page_size = 20"), False),
        ("read", board.replace("read(Task), allow = owner", "read(Task), allow = owner, filter(completed = false)"), False),
        ("disclosure", public.replace("list(Article),", "list(Article), filter(published = true),"), False),
    ]
    with tempfile.TemporaryDirectory(prefix="noxide-filter-sdk-") as scratch:
        work = Path(scratch)
        env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / "target/query-filters"))
        (work / "Cargo.toml").write_text('[package]\nname="filter_sdk"\nversion="0.0.0"\nedition="2024"\n[dependencies]\nnoxide={path=' + json.dumps(str(ROOT / "crates/noxide")) + '}\n[workspace]\n')
        (work / "src").mkdir()
        for name, source, valid in cases:
            (work / "src/lib.rs").write_text(source)
            result = subprocess.run(["cargo", "check", "--offline", "--quiet", "--manifest-path", str(work / "Cargo.toml")], env=env, capture_output=True, text=True)
            assert (result.returncode == 0) == valid, f"{name}: {result.stderr}"
    print(f"{len(cases)} SDK filter cases passed")


if __name__ == "__main__":
    main()
