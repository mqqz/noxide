#!/usr/bin/env python3
"""Executable hostile build fixtures. Never compile these outside build_vm.py."""
import argparse
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exhaustion-only", action="store_true", help="rerun only the native loop deadline regression")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="noxide-host-canary-") as folder:
        temporary = Path(folder)
        canary = temporary / "secret"
        canary.write_text("inert host canary: must never enter a build VM")
        source = temporary / "source"
        shutil.copytree(ROOT / "examples/private-notes", source)
        (source / "Cargo.lock").unlink()
        macro = source / "probe-macro"
        macro.mkdir()
        (macro / "Cargo.toml").write_text('[package]\nname="probe-macro"\nversion="0.1.0"\nedition="2024"\n[lib]\nproc-macro=true\npath="lib.rs"\n')
        manifest = (source / "Cargo.toml").read_text().replace('[dependencies]', '[dependencies]\nprobe-macro = { path = "probe-macro" }')
        (source / "Cargo.toml").write_text(manifest)
        library = source / "src/lib.rs"
        library.write_text(library.read_text() + '\nprobe_macro::verify!();\n')
        with socket.socket() as network, socket.socket(socket.AF_UNIX) as host_socket:
            network.bind(("127.0.0.1", 0))
            network.listen()
            socket_path = temporary / "host.sock"
            host_socket.bind(str(socket_path))
            host_socket.listen()
            probe = '''
fn probe(phase: &str) {
    use std::{fs, net::{TcpStream, SocketAddr}, os::unix::net::UnixStream, time::Duration};
    assert!(fs::read(CANARY).is_err(), "host secret leaked");
    assert!(UnixStream::connect(SOCKET).is_err(), "host socket leaked");
    assert!(TcpStream::connect_timeout(&ADDRESS.parse::<SocketAddr>().unwrap(), Duration::from_millis(250)).is_err(), "host network reachable");
    assert!(TcpStream::connect_timeout(&"192.0.2.1:80".parse().unwrap(), Duration::from_millis(250)).is_err(), "external network reachable");
    for path in ["/src/poison", "/vendor/poison", "/toolchain/poison", "/root/poison"] {
        assert!(fs::write(path, b"poison").is_err(), "write outside scratch");
    }
    let state = format!("/tmp/prior-build-{phase}");
    assert!(!std::path::Path::new(&state).exists(), "state survived a VM");
    fs::write(&state, b"must disappear with this VM").unwrap();
    let status = fs::read_to_string("/proc/self/status").unwrap();
    assert!(status.contains("NoNewPrivs:\\t1"));
    assert!(status.contains("CapEff:\\t0000000000000000"));
    assert!(status.contains("Uid:\\t65534\\t65534\\t65534\\t65534"));
}
'''
            probe = ('const CANARY:&str=' + json.dumps(str(canary)) + ';\n'
                     'const SOCKET:&str=' + json.dumps(str(socket_path)) + ';\n'
                     'const ADDRESS:&str=' + json.dumps(f"127.0.0.1:{network.getsockname()[1]}") + ';\n' + probe)
            (source / "build.rs").write_text(probe + '\nfn main(){probe("build-script");println!("cargo:warning=BUILD_BOUNDARY_PROBE_PASSED");}\n')
            (macro / "lib.rs").write_text(probe + '\n#[proc_macro] pub fn verify(_:proc_macro::TokenStream)->proc_macro::TokenStream {probe("procedural-macro");proc_macro::TokenStream::new()}\n')
            base = [sys.executable, str(ROOT / "tools/build_vm.py"), "--kernel", args.kernel, "--toolchain", args.toolchain, "--source", str(source)]
            for number in (() if args.exhaustion_only else (1, 2)):
                output = args.output / f"fresh-{number}"
                subprocess.run(base + ["--output", str(output)], check=True)
                assert "BUILD_BOUNDARY_PROBE_PASSED" in (output / "build.log").read_text()
                assert canary.read_text() == "inert host canary: must never enter a build VM"
                print(f"Fresh VM {number}: build script and macro containment passed", flush=True)
            # A native build-script loop must be stopped by the VM deadline.
            # No dependencies: the deadline must test the loop itself rather
            # than time out an earlier compiler invocation. Cargo -vv streams
            # the flushed start marker while the build script is still running.
            (source / "Cargo.toml").write_text('[package]\nname="private-notes"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[lib]\ncrate-type=["cdylib"]\n')
            library.write_text('pub fn inert() {}\n')
            (source / "build.rs").write_text('fn main(){use std::io::Write; eprintln!("NOXIDE_NATIVE_LOOP_STARTED");std::io::stderr().flush().unwrap();loop {std::hint::spin_loop();}}\n')
            started = time.monotonic()
            result = subprocess.run(base + ["--output", str(args.output / "exhaustion"), "--seconds", "40"])
            assert result.returncode != 0 and time.monotonic() - started < 90
            assert not (args.output / "exhaustion/private_notes.wasm").exists()
            assert "NOXIDE_NATIVE_LOOP_STARTED" in (args.output / "exhaustion/build.log").read_text(), "deadline fired before the hostile native loop started"
            print("Build exhaustion: VM terminated within the wall budget", flush=True)


if __name__ == "__main__":
    main()
