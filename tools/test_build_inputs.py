#!/usr/bin/env python3
"""Host-side snapshot/transport tests; no application code is executed."""
import base64
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
import build_vm
from build_vm import Image, source_files, artifact


class Inputs(unittest.TestCase):
    def test_links_hidden_files_and_devices_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path / "link").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                source_files(Image(), path, "src")
            (path / "link").unlink()
            (path / ".env").write_text("inert secret")
            with self.assertRaises(ValueError):
                source_files(Image(), path, "src")

    def test_wire_artifacts_are_bounded_and_unambiguous(self):
        wire = b"NOXIDE_WASM_BEGIN\n" + base64.b64encode(b"abc") + b"\nNOXIDE_WASM_END"
        self.assertEqual(artifact(wire, "WASM", 3), b"abc")
        for value, limit in [(wire, 2), (wire + wire, 10), (b"native", 10)]:
            with self.assertRaises(ValueError):
                artifact(value, "WASM", limit)

    def test_hard_links_cannot_import_unapproved_contents(self):
        import os
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "secret").write_text("inert canary")
            source = root / "source"
            source.mkdir()
            os.link(root / "secret",source / "source.rs")
            with self.assertRaises(ValueError):
                source_files(Image(),source,"src")

    def test_archive_names_cannot_traverse(self):
        for name in ["../escape", "a/../../escape"]:
            with self.assertRaises(ValueError):
                Image().add(name, b"bad")

    def test_file_replaced_with_fifo_does_not_block_snapshot(self):
        # Run the race in a child so a blocking open fails within a fixed budget.
        script = textwrap.dedent("""
            import os
            from pathlib import Path
            import sys
            from unittest import mock
            from build_vm import Image, source_files

            root = Path(sys.argv[1])
            source = root / "source.rs"
            source.write_text("approved source")
            image = Image()
            original_open = os.open

            def replace_before_open(name, flags, **kwargs):
                if name == "source.rs":
                    source.unlink()
                    os.mkfifo(source)
                return original_open(name, flags, **kwargs)

            with mock.patch("build_vm.os.open", side_effect=replace_before_open):
                try:
                    source_files(image, root, "src")
                except ValueError:
                    pass
                else:
                    raise AssertionError("FIFO replacement was accepted")
            assert not image.files
        """)
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, "-c", script, folder],
                                    cwd=Path(build_vm.__file__).parent,
                                    capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)


class VmOutput(unittest.TestCase):
    prefix = b"building...\n"
    wasm = b"\0asm\x01\0\0\0"
    lock = b"version = 4\n"
    wire = (b"NOXIDE_WASM_BEGIN\n" + base64.b64encode(wasm)
            + b"\nNOXIDE_WASM_END\nNOXIDE_LOCK_BEGIN\n" + base64.b64encode(lock)
            + b"\nNOXIDE_LOCK_END\n")

    def run_exiting_vm(self, log_path, after_exit=None):
        # A trusted child waits until the runner reads the prefix, then writes
        # its artifacts and exits before that read returns to the runner.
        script = ("import os, sys; os.write(1, bytes.fromhex(sys.argv[1])); "
                  "os.read(0, 1); os.write(1, bytes.fromhex(sys.argv[2]))")
        with subprocess.Popen([sys.executable, "-c", script,
                               self.prefix.hex(), self.wire.hex()],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT) as process:
            read = os.read
            first_read = True

            def read_and_exit(descriptor, size):
                nonlocal first_read
                # Force several reads to drain the final artifact bytes.
                chunk = read(descriptor, min(size, 16))
                if first_read:
                    first_read = False
                    self.assertEqual(chunk, self.prefix)
                    process.stdin.write(b"\n")
                    process.stdin.flush()
                    self.assertEqual(process.wait(timeout=5), 0)
                    if after_exit is not None:
                        after_exit()
                return chunk

            try:
                with mock.patch("build_vm.subprocess.Popen", return_value=process), \
                     mock.patch("build_vm.os.read", side_effect=read_and_exit):
                    return build_vm.run_vm("kernel", "initrd", log_path, 10)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()

    def test_artifacts_are_drained_after_process_exit(self):
        expected = self.prefix + self.wire
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch("build_vm.MAX_LOG", len(expected)):
            log_path = Path(folder) / "build.log"
            output = self.run_exiting_vm(log_path)
            self.assertEqual(output, expected)
            self.assertEqual(log_path.read_bytes(), expected)
            self.assertEqual(artifact(output, "WASM", len(self.wasm)), self.wasm)
            self.assertEqual(artifact(output, "LOCK", len(self.lock)), self.lock)

    def test_output_limit_applies_after_process_exit(self):
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch("build_vm.MAX_LOG", len(self.prefix + self.wire) - 1):
            with self.assertRaisesRegex(ValueError, "VM output limit exceeded"):
                self.run_exiting_vm(Path(folder) / "build.log")

    def test_deadline_applies_after_process_exit(self):
        now = 0

        def expire():
            nonlocal now
            now = 11

        with tempfile.TemporaryDirectory() as folder, \
             mock.patch("build_vm.time.monotonic", side_effect=lambda: now):
            with self.assertRaisesRegex(TimeoutError, "VM build deadline exceeded"):
                self.run_exiting_vm(Path(folder) / "build.log", after_exit=expire)


if __name__ == "__main__":
    unittest.main()
