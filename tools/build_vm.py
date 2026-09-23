#!/usr/bin/env python3
"""Build approved application inputs inside a disposable, disconnected QEMU VM.

This Linux x86-64 recipe uses the operator's trusted kernel and Rust/GCC tools.
It never runs Cargo, build scripts, macros, or output binaries from the application
on the host. The framework lockfile is the approved public dependency catalog.
"""

import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parent.parent
MAX_SOURCE = 16 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
MAX_LOG = 16 * 1024 * 1024


def command(*args):
    return subprocess.check_output(args, text=True).strip()


class Image:
    """An allowlisted newc archive; no link following in application inputs."""

    def __init__(self):
        self.files = {}

    def add(self, name, data, mode=0o644):
        name = str(name).lstrip("/")
        if not name or ".." in Path(name).parts or name in self.files:
            raise ValueError(f"duplicate or unsafe image entry: {name}")
        self.files[name] = (data, mode)

    def trusted(self, source, destination=None):
        source = Path(source)
        name = os.path.normpath(str(destination or source)).lstrip("/")
        if name not in self.files:
            self.add(name, source.resolve(), source.stat().st_mode & 0o777)

    def executable(self, binary, destination=None):
        source = Path(shutil.which(str(binary)) or binary).resolve()
        self.trusted(source, destination or f"usr/bin/{Path(binary).name}")
        # Only operator-selected system/toolchain executables reach ldd.
        output = subprocess.run(["ldd", str(source)], text=True,
                                capture_output=True, check=False).stdout
        for library in re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)", output, re.M):
            destination = None
            if "/.rustup/toolchains/" in library:
                destination = "toolchain/lib/" + Path(library).name
            self.trusted(library, destination)

    def write(self, path):
        directories = {"dev", "proc", "sys", "tmp", "root"}
        for name in self.files:
            directories.update(str(p) for p in Path(name).parents if str(p) != ".")
        entries = [(d, b"", stat.S_IFDIR | 0o755) for d in sorted(directories)]
        entries += [(n, d, stat.S_IFREG | m) for n, (d, m) in sorted(self.files.items())]
        # Root aliases are trusted, fixed image metadata, never archive inputs.
        entries += [("bin", b"usr/bin", stat.S_IFLNK | 0o777),
                    ("sbin", b"usr/bin", stat.S_IFLNK | 0o777),
                    ("usr/sbin", b"bin", stat.S_IFLNK | 0o777)]
        with path.open("wb") as file, gzip.GzipFile(filename="",fileobj=file,mode="wb",compresslevel=1,mtime=0) as out:
            for index, (name, data, mode) in enumerate(entries + [("TRAILER!!!", b"", 0)]):
                size = data.stat().st_size if isinstance(data, Path) else len(data)
                encoded = name.encode() + b"\0"
                fields = [index + 1, mode, 0, 0, 1, 0, size, 0, 0, 0, 0, len(encoded), 0]
                out.write(b"070701" + b"".join(f"{v:08x}".encode() for v in fields))
                out.write(encoded)
                out.write(b"\0" * (-(110 + len(encoded)) % 4))
                if isinstance(data, Path):
                    with data.open("rb") as source:
                        shutil.copyfileobj(source, out, 1024 * 1024)
                else:
                    out.write(data)
                out.write(b"\0" * (-size % 4))


def source_files(image, root, prefix):
    """Caller approves this source directory, including all regular source files.

    Reject links, device files, Cargo configuration, and hidden inputs. Read via
    O_NOFOLLOW | O_NONBLOCK and validate the opened inode before reading so
    path replacement cannot escape the snapshot or block it on a FIFO.
    No credentials or general home directory are automatically included.
    """
    total = 0
    count = 0
    def walk(directory, relative, depth):
        nonlocal total, count
        if depth > 32:
            raise ValueError("source nesting limit")
        names = []
        with os.scandir(directory) as scan:
            for entry in scan:
                names.append(entry.name)
                if len(names) > 2048:
                    raise ValueError("source entry limit")
        for name in sorted(names):
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode) and name in ("target", ".git", ".cargo"):
                continue
            if name.startswith(".") or stat.S_ISLNK(before.st_mode):
                raise ValueError("hidden or linked source input")
            child = f"{relative}/{name}" if relative else name
            count += 1
            if count > 2048:
                raise ValueError("source entry limit")
            if stat.S_ISDIR(before.st_mode):
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    walk(descriptor, child, depth + 1)
                finally:
                    os.close(descriptor)
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError("application source must contain regular files")
            total += before.st_size
            if total > MAX_SOURCE:
                raise ValueError("source budget exceeded")
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, "rb") as file:
                after = os.fstat(file.fileno())
                if (not stat.S_ISREG(after.st_mode)
                        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                        or after.st_nlink != 1):
                    raise ValueError("source changed during snapshot")
                data = file.read(MAX_SOURCE + 1)
            if len(data) != before.st_size:
                raise ValueError("source changed during snapshot")
            image.add(f"{prefix}/{child}", data)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(descriptor, "", 0)
    finally:
        os.close(descriptor)


def catalog(image, cargo_home):
    packages = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
    seen = set()
    todo = ["noxide", "wit-bindgen"]
    while todo:
        reference = todo.pop().split()
        for package in packages:
            key = (package["name"], package["version"])
            if key in seen or key[0] != reference[0] or (len(reference) > 1 and key[1] != reference[1]):
                continue
            seen.add(key)
            todo.extend(package.get("dependencies", []))
            if "source" not in package:
                continue
            if package["source"] != "registry+https://github.com/rust-lang/crates.io-index":
                raise ValueError("only the approved public crates.io catalog is supported")
            roots = list((cargo_home / "registry/src").glob(f"*/{key[0]}-{key[1]}"))
            if len(roots) != 1:
                raise ValueError(f"prefetch the framework lockfile: missing {key}")
            root = roots[0]
            # Verify the cached .crate archive against Cargo.lock, then unpack
            # only bounded regular files. Do not trust modified cache checkouts.
            archive = cargo_home / "registry/cache" / root.parent.name / f"{root.name}.crate"
            with archive.open("rb") as source:
                raw = source.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise ValueError("compressed dependency archive budget")
            if hashlib.sha256(raw).hexdigest() != package["checksum"]:
                raise ValueError("catalog archive checksum mismatch")
            import io
            import tarfile
            checksums = {}
            size = 0
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                unpacked = compressed.read(128 * 1024 * 1024 + 1)
            if len(unpacked) > 128 * 1024 * 1024:
                raise ValueError("expanded dependency archive budget")
            with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as tar:
                for entry in tar:
                    parts = Path(entry.name).parts
                    if entry.isdir():
                        continue
                    if not entry.isfile() or len(parts) < 2 or parts[0] != root.name or ".." in parts:
                        raise ValueError("unsafe dependency archive entry")
                    size += entry.size
                    if size > 128 * 1024 * 1024 or len(checksums) >= 16384:
                        raise ValueError("dependency archive budget")
                    name = "/".join(parts[1:])
                    data = tar.extractfile(entry).read()
                    checksums[name] = hashlib.sha256(data).hexdigest()
                    image.add(f"vendor/{root.name}/{name}", data)
            image.add(f"vendor/{root.name}/.cargo-checksum.json", json.dumps({"package": package["checksum"], "files": checksums}).encode())


def toolchain(image, path):
    for name in ("rustc", "rustdoc", "cargo"):
        image.executable(path / "bin" / name, f"toolchain/bin/{name}")
    for directory in (path / "lib").rglob("*"):
        if directory.is_file() and "share" not in directory.parts:
            image.trusted(directory, "toolchain/" + str(directory.relative_to(path)))
    for binary in ("bash", "mount", "mkdir", "chmod", "cp", "setpriv", "env", "cat",
                   "base64", "timeout", "poweroff", "gcc", "as", "ld", "ar"):
        image.executable(binary)
    image.trusted(shutil.which("bash"), "usr/bin/sh")
    image.trusted(shutil.which("gcc"), "usr/bin/cc")
    gcc = Path(command("gcc", "-print-prog-name=collect2")).parent
    for name in ("collect2", "cc1", "lto-wrapper", "lto1"):
        image.executable(gcc / name, gcc / name)
    for path in gcc.glob("*.o"):
        image.trusted(path)
    for path in gcc.glob("*.a"):
        image.trusted(path)
    for path in gcc.glob("*.so"):
        image.trusted(path)
    for name in ("crt1.o", "crti.o", "crtn.o", "Scrt1.o", "libc_nonshared.a"):
        path = command("gcc", f"-print-file-name={name}")
        image.trusted(path)
    for name in ("c", "m", "pthread", "dl", "rt", "util", "gcc_s"):
        for suffix in ("a", "so"):
            path = command("gcc", f"-print-file-name=lib{name}.{suffix}")
            if Path(path).is_file():
                image.trusted(path)
    # GNU linker scripts can reference these names independently of ldd output.
    for name in ("libc.so.6", "libm.so.6", "libmvec.so.1", "ld-linux-x86-64.so.2", "libgcc_s.so.1"):
        path = command("gcc", f"-print-file-name={name}")
        image.trusted(path)


INIT = r'''#!/bin/sh
export PATH=/usr/bin
export LD_LIBRARY_PATH=/usr/lib:/usr/lib64
mount -t proc proc /proc -o hidepid=2
mount -t sysfs sysfs /sys -o ro
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp -o size=2048m,nosuid,nodev
chmod 1777 /tmp
mkdir /tmp/work /tmp/cargo
chmod 777 /tmp/work /tmp/cargo
cat >/tmp/cargo/config.toml <<'CONFIG'
[source.crates-io]
replace-with = "approved"
[source.approved]
directory = "/vendor"
[net]
offline = true
CONFIG
chmod 644 /tmp/cargo/config.toml
ulimit -c 0
ulimit -n 128
ulimit -u 128
ulimit -f 524288
timeout -k 2 480 setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs env -i PATH=/toolchain/bin:/usr/bin LD_LIBRARY_PATH=/usr/lib:/usr/lib64 HOME=/tmp CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/tmp/target RUST_BACKTRACE=0 /bin/sh /build-command
status=$?
echo "NOXIDE_BUILD_STATUS=$status"
if [ "$status" = 0 ]; then
    echo NOXIDE_WASM_BEGIN
    base64 /tmp/target/wasm32-unknown-unknown/release/private_notes.wasm
    echo NOXIDE_WASM_END
    echo NOXIDE_LOCK_BEGIN
    base64 /tmp/work/examples/private-notes/Cargo.lock
    echo NOXIDE_LOCK_END
fi
poweroff -f
'''

BUILD = r'''#!/bin/sh
set -eu
cp -r /src/. /tmp/work/
cd /tmp/work/examples/private-notes
if [ ! -f Cargo.lock ]; then cargo generate-lockfile --offline; fi
cargo build -vv --locked --offline --release --target wasm32-unknown-unknown -j 2
'''


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_AS, (9 * 1024**3, 9 * 1024**3))


def run_vm(kernel, initrd, log_path, seconds):
    args = ["qemu-system-x86_64", "-machine", "q35", "-accel", "tcg", "-m", "6144",
            "-smp", "2", "-nodefaults", "-display", "none", "-serial", "stdio",
            "-monitor", "none", "-no-reboot", "-nic", "none",
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
            "-kernel", str(kernel), "-initrd", str(initrd), "-append",
            "console=ttyS0 rdinit=/init panic=-1 quiet"]
    started = time.monotonic()
    peak_kib = 0
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, preexec_fn=limits) as process:
        output = bytearray()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        until = time.monotonic() + seconds
        try:
            while time.monotonic() < until:
                try:
                    status = Path(f"/proc/{process.pid}/status").read_text()
                    sample = re.search(r"VmHWM:\s+(\d+) kB",status)
                    if sample:
                        peak_kib = max(peak_kib,int(sample[1]))
                except OSError:
                    pass
                if selector.select(1):
                    chunk = os.read(process.stdout.fileno(), 65536)
                    # Process exit can leave artifact bytes in the pipe; drain to EOF.
                    if not chunk:
                        break
                    output += chunk
                    if len(output) > MAX_LOG:
                        raise ValueError("VM output limit exceeded")
            else:
                raise TimeoutError("VM build deadline exceeded")
        finally:
            process.kill() if process.poll() is None else None
            process.wait()
            selector.close()
            # Diagnostics remain untrusted. Strip terminal controls before display.
            safe = bytes(b for b in output if b in (10, 13) or 32 <= b < 127)
            log_path.write_bytes(safe)
            log_path.with_suffix(".metrics.json").write_text(json.dumps({"wall_seconds":round(time.monotonic()-started,3),"peak_rss_kib":peak_kib,"exit_code":process.returncode,"vm_memory_mib":6144,"vcpus":2,"command":args},indent=2))
    return bytes(output).replace(b"\r\n", b"\n")


def artifact(output, kind, limit):
    start, end = f"NOXIDE_{kind}_BEGIN\n".encode(), f"NOXIDE_{kind}_END".encode()
    if output.count(start) != 1 or output.count(end) != 1:
        raise ValueError(f"missing or ambiguous {kind} artifact; inspect sanitized VM log")
    encoded = output.split(start)[1].split(end)[0].replace(b"\n", b"")
    if len(encoded) > (limit + 2) // 3 * 4:
        raise ValueError("VM artifact size limit")
    data = base64.b64decode(encoded, validate=True)
    if len(data) > limit:
        raise ValueError("VM artifact size limit")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, default=Path.home() / ".cargo")
    parser.add_argument("--source", type=Path, default=ROOT / "examples/private-notes")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=600)
    options = parser.parse_args()
    options.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    image = Image()
    toolchain(image, options.toolchain.resolve())
    catalog(image, options.cargo_home)
    # Public framework SDK inputs, never the deployment directory or key files.
    for name in ("noxide", "noxide-protocol", "noxide-macros"):
        crate = ROOT / "crates" / name
        image.add(f"src/crates/{name}/Cargo.toml", (crate / "Cargo.toml").read_bytes())
        for folder in ("src", "wit"):
            if (crate / folder).is_dir():
                source_files(image, crate / folder, f"src/crates/{name}/{folder}")
    workspace = (ROOT / "Cargo.toml").read_text().replace('    "crates/noxide-cli",\n', '').replace('    "crates/noxide-host",\n', '')
    image.add("src/Cargo.toml", workspace.encode())
    image.add("src/README.md", (ROOT / "README.md").read_bytes())
    source_files(image, options.source.resolve(), "src/examples/private-notes")
    image.add("init", INIT.encode(), 0o755)
    image.add("build-command", BUILD.encode(), 0o755)
    print("Writing immutable VM input image...", flush=True)
    with tempfile.TemporaryDirectory(prefix="noxide-build-") as temporary:
        initrd = Path(temporary) / "input.cpio.gz"
        image.write(initrd)
        print("Building in a fresh QEMU VM (no NIC, disks, host shares, or sockets)...", flush=True)
        output = run_vm(options.kernel, initrd, options.output / "build.log", options.seconds)
    wasm = artifact(output, "WASM", MAX_OUTPUT)
    if not wasm.startswith(b"\0asm\x01\0\0\0"):
        raise ValueError("VM did not produce portable core Wasm")
    for name, data in (("private_notes.wasm", wasm), ("Cargo.lock", artifact(output, "LOCK", 131072))):
        with (options.output / name).open("xb") as file:
            file.write(data)
    print("Build finished. Outputs remain untrusted; use noxide component and contract admission.")


if __name__ == "__main__":
    main()
