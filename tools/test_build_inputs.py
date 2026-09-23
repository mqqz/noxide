#!/usr/bin/env python3
"""Host-side snapshot/transport tests; no application code is executed."""
import base64
import gzip
import os
from pathlib import Path
import stat
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


class ToolchainSnapshot(unittest.TestCase):
    def test_library_aliases_are_preserved_in_initramfs(self):
        image = Image()
        image.add("lib/x86_64-linux-gnu/libmvec.so.1", b"math library")
        image.add("usr/lib64/ld-linux-x86-64.so.2", b"loader")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "image.cpio.gz"
            image.write(path)
            data = gzip.decompress(path.read_bytes())
        entries = {}
        offset = 0
        while True:
            self.assertEqual(data[offset:offset + 6], b"070701")
            fields = [int(data[offset + 6 + i * 8:offset + 14 + i * 8], 16)
                      for i in range(13)]
            mode, size, name_size = fields[1], fields[6], fields[11]
            offset += 110
            name = data[offset:offset + name_size - 1].decode()
            offset = (offset + name_size + 3) & ~3
            if name == "TRAILER!!!":
                break
            self.assertNotIn(name, entries)
            entries[name] = (stat.S_IFMT(mode), data[offset:offset + size])
            offset = (offset + size + 3) & ~3
        self.assertEqual(entries["lib"], (stat.S_IFLNK, b"usr/lib"))
        self.assertEqual(entries["lib64"], (stat.S_IFLNK, b"usr/lib64"))
        self.assertEqual(entries["usr/lib/x86_64-linux-gnu/libmvec.so.1"],
                         (stat.S_IFREG, b"math library"))
        self.assertEqual(entries["usr/lib64/ld-linux-x86-64.so.2"],
                         (stat.S_IFREG, b"loader"))
        self.assertFalse(any(name.startswith(("lib/", "lib64/")) for name in entries))

    def test_alias_paths_cannot_duplicate_or_replace_fixed_metadata(self):
        image = Image()
        image.add("lib/library.so", b"library")
        for name in ("usr/lib/library.so", "/lib/./library.so", "lib//library.so"):
            with self.assertRaises(ValueError):
                image.add(name, b"duplicate")
        for name in ("lib", "lib64", "bin", "sbin", "usr/sbin", "lib/."):
            with self.assertRaises(ValueError):
                Image().add(name, b"replace fixed alias")
        with tempfile.TemporaryDirectory() as folder:
            library = Path(folder) / "library.so"
            library.write_bytes(b"trusted library")
            image = Image()
            image.trusted(library, "lib/library.so")
            image.trusted(library, "usr/lib/library.so")
            self.assertEqual(list(image.files), ["usr/lib/library.so"])

    def check_gcc_layout(self, split_directories):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            helpers = root / "usr/libexec/gcc/x86_64-linux-gnu/13"
            libraries = (root / "usr/lib/gcc/x86_64-linux-gnu/13"
                         if split_directories else helpers)
            helpers.mkdir(parents=True)
            libraries.mkdir(parents=True, exist_ok=True)
            binary = root / "binary"
            binary.write_bytes(b"trusted tool fixture")
            for name in ("collect2", "cc1", "lto-wrapper", "lto1"):
                (helpers / name).write_bytes(b"compiler helper")
            startup = ("crtbegin.o", "crtbeginS.o", "crtend.o", "crtendS.o")
            archives = ("libgcc.a", "libgcc_eh.a")
            shared = ("liblto_plugin.so",)
            system = ("crt1.o", "crti.o", "crtn.o", "Scrt1.o", "libc_nonshared.a",
                      "libc.so.6", "libm.so.6", "libmvec.so.1",
                      "ld-linux-x86-64.so.2", "libgcc_s.so.1")
            for name in startup + archives + shared + system:
                (libraries / name).write_bytes(name.encode())

            def query(compiler, option):
                self.assertEqual(compiler, "gcc")
                if option == "-print-prog-name=collect2":
                    return str(helpers / "collect2")
                if option == "-print-libgcc-file-name":
                    return str(libraries / "libgcc.a")
                self.assertTrue(option.startswith("-print-file-name="), option)
                name = option.split("=", 1)[1]
                path = libraries / name
                return str(path) if path.is_file() else name

            image = Image()
            with mock.patch.object(image, "executable"), \
                 mock.patch("build_vm.shutil.which", return_value=str(binary)), \
                 mock.patch("build_vm.command", side_effect=query):
                build_vm.toolchain(image, root / "rust")

            for name in startup + archives + shared:
                path = libraries / name
                key = str(path).lstrip("/")
                self.assertIn(key, image.files, f"missing GCC runtime input: {name}")
                self.assertEqual(image.files[key][0].read_bytes(), name.encode())

    def test_gcc_helpers_and_runtime_can_share_a_directory(self):
        self.check_gcc_layout(split_directories=False)

    def test_gcc_runtime_is_copied_when_helpers_live_in_libexec(self):
        self.check_gcc_layout(split_directories=True)


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
