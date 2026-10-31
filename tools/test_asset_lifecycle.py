#!/usr/bin/env python3
"""Prove detached asset approval preserves an existing disposable deployment."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cli = output / "noxide"
    shutil.copy2(args.cli.resolve(), cli)
    project = output / "application"
    env = dict(os.environ, XDG_STATE_HOME=str(output / "state"),
               CARGO_HOME=str(output / "empty-cargo"), CARGO_BUILD_JOBS="2",
               CARGO_INCREMENTAL="0")
    log = (output / "lifecycle.log").open("wb")

    def run(*arguments, valid=True):
        result = subprocess.run([str(cli), *map(str, arguments)], cwd=project if project.exists() else output,
                                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=300)
        log.write(result.stdout)
        log.flush()
        if valid:
            assert result.returncode == 0, result.stdout.decode(errors="replace")
        else:
            assert result.returncode != 0, "tampered asset bundle was approved"
        return result.stdout

    try:
        run("new", project)
        example = ROOT / "examples/public-articles"
        shutil.copyfile(example / "src/lib.rs", project / "src/lib.rs")
        shutil.copytree(example / "public", project / "public")
        # No framework checkout or dependency cache is supplied to this binary.
        run("build", "--cargo-home", env["CARGO_HOME"])
        pointer = project / "target/noxide/latest.json"
        original_pointer = pointer.read_bytes()
        bundle = Path(json.loads(original_pointer))
        assert bundle.is_relative_to(project / "target/noxide")
        manifest = json.loads((bundle / "manifest.json").read_text())
        assert len(manifest["assets"]) == 3
        digest = run("contract-hash", bundle / "manifest.json").decode().strip()
        run("approve", "--dev", digest)
        configurations = list((output / "state/noxide").glob("*/dev/runtime.json"))
        assert len(configurations) == 1
        config_path = configurations[0]
        original_config = config_path.read_bytes()
        config = json.loads(original_config)
        assert Path(config["assets"]).resolve() == (bundle / "assets.pack").resolve()
        assert config["approved_contract"] == digest

        forged = output / "tampered-bundle"
        shutil.copytree(bundle, forged)
        pack = forged / "assets.pack"
        data = bytearray(pack.read_bytes())
        data[-1] ^= 1
        pack.write_bytes(data)
        try:
            pointer.write_text(json.dumps(str(forged)))
            failure = run("approve", "--dev", digest, valid=False)
            assert b"asset digest mismatch" in failure, failure.decode(errors="replace")
            assert config_path.read_bytes() == original_config, "failed approval changed deployment"
        finally:
            pointer.write_bytes(original_pointer)
        run("approve", "--dev", digest)
        assert config_path.read_bytes() == original_config
        (output / "result.json").write_text(json.dumps({
            "asset_count": 3, "empty_dependency_cache": True,
            "no_framework_argument": True, "tamper_rejected_before_config_write": True,
            "prior_deployment_preserved": True,
        }, indent=2) + "\n")
        print("Detached asset approval passed; tampering preserved the prior deployment.")
    finally:
        log.close()


if __name__ == "__main__":
    main()
