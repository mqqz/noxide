#!/usr/bin/env python3
"""Build the example against actual Cargo SDK archives in a disposable VM.

Cargo only packages the trusted framework on the host (--no-verify). Application
resolution, binding generation and compilation take place inside the VM, with
versioned package directories and no monorepo SDK paths available.
"""
import argparse
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib

from build_vm import (ROOT, MAX_OUTPUT, MAX_SOURCE, Image, INIT, BUILD, toolchain,
                      catalog, source_files, run_vm, artifact)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, default=Path.home() / ".cargo")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    packages = ("noxide-macros", "noxide-protocol", "noxide")
    command = ["cargo", "package", "--no-verify", "--allow-dirty", "--offline",
               "--target-dir", str(args.output / "packages")]
    for package in packages:
        command += ["-p", package]
    subprocess.run(command, cwd=ROOT, check=True)
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    image = Image()
    toolchain(image, args.toolchain.resolve())
    catalog(image, args.cargo_home)
    for package in packages:
        prefix = f"{package}-{version}"
        archive = args.output / f"packages/package/{prefix}.crate"
        total = 0
        with tarfile.open(archive, "r:gz") as contents:
            names = set()
            for entry in contents:
                if entry.isdir():
                    continue
                assert entry.isfile() and entry.name.startswith(prefix + "/")
                total += entry.size
                assert total <= MAX_SOURCE and len(names) < 1024
                assert entry.name not in names
                names.add(entry.name)
                image.add("src/registry/" + entry.name, contents.extractfile(entry).read())
            if package == "noxide":
                assert prefix + "/wit/application.wit" in names, "SDK archive omits its WIT contract"
    source = ROOT / "examples/private-notes"
    source_files(image, source / "src", "src/examples/private-notes/src")
    manifest = (source / "Cargo.toml").read_text().replace(
        '../../crates/noxide', f'../../registry/noxide-{version}')
    manifest += '\n[patch.crates-io]\n' + ''.join(
        f'{package} = {{ path = "../../registry/{package}-{version}" }}\n'
        for package in packages[:-1])
    image.add("src/examples/private-notes/Cargo.toml", manifest.encode())
    image.add("src/examples/private-notes/Cargo.lock", (source / "Cargo.lock").read_bytes())
    image.add("init", INIT.encode(), 0o755)
    image.add("build-command", BUILD.encode(), 0o755)
    print("Building only from the packaged SDK in a fresh VM...", flush=True)
    with tempfile.TemporaryDirectory(prefix="noxide-sdk-package-") as folder:
        initrd = Path(folder) / "input.cpio.gz"
        image.write(initrd)
        output = run_vm(args.kernel, initrd, args.output / "build.log", 600)
    wasm = artifact(output, "WASM", MAX_OUTPUT)
    assert wasm.startswith(b"\0asm\x01\0\0\0")
    (args.output / "private_notes.wasm").write_bytes(wasm)
    (args.output / "Cargo.lock").write_bytes(artifact(output, "LOCK", 131072))
    print("Packaged SDK Wasm build passed without sibling monorepo paths.")


if __name__ == "__main__":
    main()
