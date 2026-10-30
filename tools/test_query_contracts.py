#!/usr/bin/env python3
"""Check exact contracts from trusted repository examples and SDK fixtures."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tools/fixtures/queries"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="store_true", help="explicitly replace reviewed goldens")
    args = parser.parse_args()
    sources = sorted((ROOT / "tools/fixtures/sdk").glob("*.rs"))
    sources += sorted((ROOT / "examples").glob("*/src/lib.rs"))
    with tempfile.TemporaryDirectory(prefix="noxide-query-contracts-") as scratch:
        work = Path(scratch)
        env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / "target/query-contracts"))
        for source in sources:
            example = source.is_relative_to(ROOT / "examples")
            name = source.parents[1].name if example else source.stem
            key = ("example-" if example else "sdk-") + name
            package = name.replace("-", "_") if example else "task_board"
            project = work / key
            project.mkdir()
            (project / "Cargo.toml").write_text(
                f'[package]\nname={json.dumps(package)}\nversion="0.0.0"\nedition="2024"\n'
                f'[dependencies]\nnoxide={{path={json.dumps(str(ROOT / "crates/noxide"))}}}\n[workspace]\n')
            (project / "src").mkdir()
            (project / "src/lib.rs").write_bytes(source.read_bytes())
            (project / "src/main.rs").write_text(f'fn main() {{ print!("{{}}", {package}::noxide_manifest()); }}\n')
            value = subprocess.check_output(
                ["cargo", "run", "--offline", "--quiet", "--manifest-path", str(project / "Cargo.toml")], env=env)
            path = GOLDEN / (key + ".json")
            if args.record:
                GOLDEN.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value)
            else:
                assert value == path.read_bytes(), f"contract bytes changed: {key}"
        expected = {("example-" + p.parents[1].name if p.is_relative_to(ROOT / "examples") else "sdk-" + p.stem) + ".json" for p in sources}
        assert {p.name for p in GOLDEN.glob("*.json")} == expected, "golden inventory changed"
    print(f"{len(sources)} exact query contracts checked")


if __name__ == "__main__":
    main()
