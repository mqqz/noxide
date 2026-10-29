"""One compilation and artifact protocol for local and isolated execution."""
import re
GUEST_BUILD_SECONDS = 900


def emission(name="private_notes", check=False, metadata=False):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
        raise ValueError("artifact name must be a Rust crate identifier")
    text = 'status=$?\necho "NOXIDE_BUILD_STATUS=$status"\nif [ "$status" = 0 ]; then\n    echo NOXIDE_WASM_BEGIN\n    base64 /tmp/target/wasm32-unknown-unknown/release/private_notes.wasm\n    echo NOXIDE_WASM_END\n    echo NOXIDE_LOCK_BEGIN\n    base64 /tmp/work/examples/private-notes/Cargo.lock\n    echo NOXIDE_LOCK_END\nfi\n'
    text = text.replace("/release/private_notes.wasm", f"/release/{name}.wasm")
    if check:
        text = text.replace("    echo NOXIDE_WASM_BEGIN\n" + f"    base64 /tmp/target/wasm32-unknown-unknown/release/{name}.wasm\n" + "    echo NOXIDE_WASM_END\n", "")
    if metadata:
        text = text.replace("    echo NOXIDE_LOCK_BEGIN\n", "    echo NOXIDE_CONTRACT_BEGIN\n    base64 /tmp/work/noxide-contract.json\n    echo NOXIDE_CONTRACT_END\n    echo NOXIDE_LOCK_BEGIN\n")
    return text


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
timeout -k 2 @BUILD_SECONDS@ setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs env -i PATH=/toolchain/bin:/usr/bin LD_LIBRARY_PATH=/usr/lib:/usr/lib64 HOME=/tmp CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/tmp/target RUST_BACKTRACE=0 /bin/sh /build-command
@EMIT@
poweroff -f
'''.replace('@BUILD_SECONDS@', str(GUEST_BUILD_SECONDS)).replace('@EMIT@', emission())

BUILD = r'''#!/bin/sh
set -eu
cp -r /src/. /tmp/work/
cd /tmp/work/examples/private-notes
if [ ! -f Cargo.lock ]; then cargo generate-lockfile --offline; fi
cargo build -vv --locked --offline --release --target wasm32-unknown-unknown -j 2
'''


def recipe(name="private_notes", check=False, metadata=False, test=False):
    """Select trusted commands; never interpolate application-provided shell code."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
        raise ValueError("artifact name must be a Rust crate identifier")
    init = INIT.replace(emission(), emission(name, check, metadata))
    build = BUILD
    if check:
        build = build.replace("cargo build -vv", "cargo check -vv")
    if test:
        build += "cargo test --locked --offline --release -j 2\n"
    if metadata:
        # The application and its generated collector use the selected executor.
        # A separate bin avoids requiring a direct serde_json application dependency:
        # application! exposes noxide_manifest() as a JSON String.
        build += f'''cat >>Cargo.toml <<'COLLECTOR_TARGET'

[[bin]]
name = "noxide-contract"
path = "noxide-contract.rs"
COLLECTOR_TARGET
cat >noxide-contract.rs <<'COLLECTOR_SOURCE'
fn main() {{ print!("{{}}", {name}::noxide_manifest()); }}
COLLECTOR_SOURCE
cargo run --quiet --locked --offline --release --bin noxide-contract -j 2 > /tmp/work/noxide-contract.json
'''
    return init, build
