"""One compilation and artifact protocol for local and isolated execution."""
import re
from build_assets import MAX_ARCHIVE
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
    if metadata:
        # Run the producer in the foreground through a private FIFO so both
        # statuses survive POSIX shell execution. Head retains the archive cap.
        export = f'''    asset_tar_status=1
    asset_head_status=1
    asset_status=1
    rm -f /tmp/noxide-assets.tar /tmp/noxide-assets.fifo
    if mkfifo -m 600 /tmp/noxide-assets.fifo; then
        head -c {MAX_ARCHIVE + 1} < /tmp/noxide-assets.fifo > /tmp/noxide-assets.tar &
        asset_head_pid=$!
        if [ -e /tmp/work/examples/private-notes/public ] || [ -L /tmp/work/examples/private-notes/public ]; then
            if [ -d /tmp/work/examples/private-notes/public ] && [ ! -L /tmp/work/examples/private-notes/public ]; then
                if tar --format=ustar --sort=name -C /tmp/work/examples/private-notes/public -cf - . > /tmp/noxide-assets.fifo; then
                    asset_tar_status=0
                else
                    asset_tar_status=$?
                fi
            else
                : > /tmp/noxide-assets.fifo
            fi
        else
            if tar --format=ustar -cf - --files-from /dev/null > /tmp/noxide-assets.fifo; then
                asset_tar_status=0
            else
                asset_tar_status=$?
            fi
        fi
        if wait "$asset_head_pid"; then
            asset_head_status=0
        else
            asset_head_status=$?
        fi
        rm -f /tmp/noxide-assets.fifo
    fi
    echo "NOXIDE_ASSETS_TAR_STATUS=$asset_tar_status"
    echo "NOXIDE_ASSETS_HEAD_STATUS=$asset_head_status"
    if [ "$asset_tar_status" = 0 ] && [ "$asset_head_status" = 0 ]; then
        echo NOXIDE_ASSETS_BEGIN
        if base64 /tmp/noxide-assets.tar; then
            asset_status=0
        fi
        echo NOXIDE_ASSETS_END
    fi
    echo "NOXIDE_ASSETS_STATUS=$asset_status"
    if [ "$asset_status" != 0 ]; then
        rm -f /tmp/noxide-assets.tar
    fi
'''
        text = text.replace("    echo NOXIDE_LOCK_BEGIN\n", export + "    echo NOXIDE_LOCK_BEGIN\n")
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
cargo metadata --format-version 1 --locked --offline > /dev/null
cargo build -vv --locked --offline --release --target wasm32-unknown-unknown -j 2
'''


def recipe(name="private_notes", check=False, metadata=False, test=False, deps_check=False, deps_resolve=False):
    """Select trusted commands; never interpolate application-provided shell code."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
        raise ValueError("artifact name must be a Rust crate identifier")
    if (deps_check and deps_resolve) or ((deps_check or deps_resolve) and (check or metadata or test)):
        raise ValueError("conflicting dependency execution modes")
    if deps_check or deps_resolve:
        build = BUILD.split('if [ ! -f Cargo.lock ]')[0]
        if deps_resolve:
            build += "rm -f Cargo.lock\ncargo generate-lockfile --offline\n"
        else:
            build += "test -f Cargo.lock\ncp Cargo.lock /tmp/original.lock\n"
        build += "cargo metadata --format-version 1 --locked --offline > /dev/null\n"
        if deps_check:
            build += "cmp Cargo.lock /tmp/original.lock\n"
        return INIT.replace(emission(), emission(name, True)), build
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
