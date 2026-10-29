#!/usr/bin/env python3
"""Exercise local recipe execution with inert, trusted shell fixtures."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from build_local import run_local
from build_recipe import emission
from build_vm import Image, artifact, check_build_status, recipe


class LocalBuild(unittest.TestCase):
    def run_recipe(self, commands, check=False, seconds=10):
        image = Image()
        init, _ = recipe(check=check, metadata=True)
        image.add('init', init.encode())
        image.add('artifact-command', emission(check=check, metadata=True).encode())
        image.add('src/examples/app/src/input', b'snapshot')
        image.add('build-command', ('set -eu\n' + commands).encode())
        with tempfile.TemporaryDirectory() as folder:
            return run_local(image, Path('/usr'), Path(folder) / 'build.log', seconds)

    def test_build_and_check_return_artifacts_without_running_vm_init(self):
        for check in (False, True):
            output = self.run_recipe('''mkdir -p /tmp/work/examples/private-notes /tmp/target/wasm32-unknown-unknown/release
cp /src/examples/app/src/input /tmp/work/examples/private-notes/Cargo.lock
printf wasm > /tmp/target/wasm32-unknown-unknown/release/private_notes.wasm
printf '{}' > /tmp/work/noxide-contract.json
''', check=check)
            check_build_status(output)
            self.assertEqual(artifact(output, 'LOCK', 100), b'snapshot')
            self.assertEqual(artifact(output, 'CONTRACT', 100), b'{}')
            if check:
                self.assertNotIn(b'NOXIDE_WASM_BEGIN', output)
            else:
                self.assertEqual(artifact(output, 'WASM', 100), b'wasm')

    def test_failure_is_not_reported_as_success(self):
        output = self.run_recipe('exit 7\n')
        with self.assertRaises(ValueError):
            check_build_status(output)
        self.assertNotIn(b'NOXIDE_CONTRACT_BEGIN', output)

    def test_output_is_bounded_while_process_runs(self):
        with self.assertRaisesRegex(ValueError, 'output limit'):
            self.run_recipe('head -c 18000000 /dev/zero\n')

    def test_deadline_stops_process(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_recipe('sleep 30\n', seconds=0.1)


if __name__ == '__main__':
    unittest.main()
