#!/usr/bin/env python3
"""Execute the shared build recipe locally, only for trusted apps and dependencies.

Staging and offline Cargo resolution are conveniences, not a security boundary.
Native build code has the invoking user's host authority.
"""
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import tempfile


def run_local(image, toolchain, log_path, seconds):
    # The same source/catalog snapshot and recipe serve both backends. Never
    # execute the VM init script (mounts, privilege changes, poweroff) locally.
    with tempfile.TemporaryDirectory(prefix="noxide-local-") as folder:
        root = Path(folder)
        for name, (data, mode) in image.files.items():
            if not name.startswith(("src/", "vendor/")):
                continue
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data.read_bytes() if isinstance(data, Path) else data)
            destination.chmod(mode)
        scratch = root / "tmp"
        scratch.mkdir()
        (scratch / "work").mkdir()
        cargo_home = scratch / "cargo"
        cargo_home.mkdir()
        (cargo_home / "config.toml").write_text(
            '[source.crates-io]\nreplace-with = "approved"\n'
            '[source.approved]\ndirectory = ' + json.dumps(str(root / 'vendor')) + '\n'
            '[net]\noffline = true\n')
        build = image.files["build-command"][0].decode()
        tail = image.files["artifact-command"][0].decode()
        script = '(\n' + build + '\n)\n' + tail + '\nexit "$status"\n'
        script = re.sub(r'(?<![A-Za-z0-9_./-])/(src|tmp)/', lambda match: shlex.quote(str(root / match[1])) + '/', script)
        script_path = root / 'build.sh'
        script_path.write_text(script)
        env = os.environ.copy()
        env.update(CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(scratch / 'target'),
                   PATH=str(toolchain.resolve() / 'bin') + os.pathsep + env['PATH'])
        print('Local build: dependency build scripts, procedural macros, tests, and the metadata collector execute native code with your user permissions. Use --isolated for untrusted inputs.', flush=True)
        with log_path.open('wb') as log:
            process = subprocess.Popen(['sh', str(script_path)], cwd=root, env=env,
                                       stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            previous = signal.getsignal(signal.SIGTERM)
            def interrupted(signum, frame):
                raise InterruptedError("local build interrupted")
            signal.signal(signal.SIGTERM, interrupted)
            try:
                process.wait(timeout=seconds)
            finally:
                # Also clean up descendants after a successful trusted build.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                signal.signal(signal.SIGTERM, previous)
        return log_path.read_bytes()
