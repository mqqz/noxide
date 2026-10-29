#!/usr/bin/env python3
"""Dependency modes: real offline Cargo resolution, no compilation or collectors."""
import contextlib
import io
import os
from pathlib import Path
import shutil
import selectors
import signal
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import build_vm
from build_catalog import REGISTRY, catalog_packages, lock_packages, validate_lock, path_packages, summary, safe_log
from build_recipe import recipe

ROOT = Path(__file__).resolve().parent.parent


def lock(packages):
    return ('version = 4\n' + ''.join('\n[[package]]\n' + '\n'.join(f'{k} = "{v}"' for k, v in p.items()) + '\n' for p in packages)).encode()


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.approved = [{'name': 'sample', 'version': v, 'source': REGISTRY, 'checksum': 'a' * 64} for v in ('1.0.0', '2.0.0')]

    def test_full_identity_multiple_versions_and_path_identity(self):
        validate_lock(lock(self.approved), self.approved, set())
        validate_lock(lock([{'name': 'app', 'version': '0.1.0'}]), [], {('app', '0.1.0')})
        for change, error in (({'version': '3.0.0'}, 'outside catalog'), ({'source': 'git+https://private.invalid'}, 'unsupported'), ({'checksum': 'b' * 64}, 'checksum mismatch')):
            with self.assertRaisesRegex(ValueError, error):
                validate_lock(lock([self.approved[0] | change]), self.approved, set())
        with self.assertRaisesRegex(ValueError, 'source-free'):
            validate_lock(lock([{'name': 'rogue', 'version': '0.1.0'}]), [], set())
        self.assertIn('unavailable', summary(None, lock(self.approved)))
        self.assertIn('unavailable', summary(b'broken', lock(self.approved)))
        malformed = lock([{'name': 'https://example_user:example_secret@example.invalid', 'version': '1.0.0'}])
        self.assertIn('unavailable', summary(malformed, lock(self.approved)))
        self.assertNotIn('example_secret', summary(malformed, lock(self.approved)))

    def test_log_scrubbing_handles_joined_chunks_without_expansion(self):
        chunks = [b'error HTTPS://example_user:', b'example_secret@example.invalid\n']
        self.assertNotIn(b'example_secret', safe_log(b''.join(chunks)))
        raw = b':// ' * 1000
        self.assertLessEqual(len(safe_log(raw)), len(raw))

    def test_catalog_is_dependency_closure(self):
        packages = catalog_packages((ROOT / 'Cargo.lock').read_bytes())
        names = {p['name'] for p in packages}
        self.assertIn('noxide', names)
        self.assertIn('wit-bindgen', names)
        self.assertNotIn('noxide-host', names)
        self.assertNotIn('wasmtime', names)

    def test_conflicting_modes_and_lock_only_recipe(self):
        for flags in ({'deps_check': True, 'metadata': True}, {'deps_resolve': True, 'test': True}, {'deps_check': True, 'deps_resolve': True}):
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                recipe(**flags)
        for mode in ('deps_check', 'deps_resolve'):
            init, script = recipe(**{mode: True})
            self.assertNotIn('NOXIDE_WASM_BEGIN', init)
            self.assertNotIn('NOXIDE_CONTRACT_BEGIN', init)
            self.assertIn('cargo metadata --format-version 1 --locked --offline > /dev/null', script)
            for forbidden in ('cargo build', 'cargo check', 'cargo run', 'cargo test', '--no-deps'):
                self.assertNotIn(forbidden, script)

    def test_manifest_restrictions(self):
        for extra in ("workspace='../outside'", "workspace='/outside'", "[dependencies]\nbad={path='../escape'}", "[dependencies]\nbad={git='https://private.invalid/repo'}", "[dependencies]\nbad={workspace=true}", "[package.metadata]\nunused=true\n[workspace]\nmembers=['child']"):
            image = {'src/examples/private-notes/Cargo.toml': (("[package]\nname='app'\nversion='0.1.0'\n" + extra).encode(), 0o644)}
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                path_packages(image)


class RealResolution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.toolchain = Path(subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='noxide-deps-test-')
        self.root = Path(self.temp.name)
        self.app = self.root / "app with 'quote"
        self.app.mkdir()
        (self.app / 'src').mkdir()
        # Resolution must work despite invalid Rust and must never run build.rs.
        (self.app / 'src/lib.rs').write_text('this is deliberately invalid Rust')
        (self.app / 'build.rs').write_text('fn main() { std::fs::write("marker", "executed").unwrap(); panic!("must not run"); }')
        self.manifest = "[package]\nname='fixture'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nserde='1'\n[workspace]\n"
        (self.app / 'Cargo.toml').write_text(self.manifest)
        self.count = 0

    def tearDown(self):
        self.temp.cleanup()

    def run_mode(self, mode, success=True, output=None):
        self.count += 1
        output = output or self.root / str(self.count)
        before = {p.name: p.read_bytes() for p in (self.app / 'Cargo.toml', self.app / 'Cargo.lock') if p.exists()}
        args = ['build_vm.py', '--local', '--toolchain', str(self.toolchain), '--app', str(self.app), '--' + mode, '--output', str(output)]
        log = io.StringIO()
        with mock.patch.object(sys, 'argv', args), contextlib.redirect_stdout(log):
            if success:
                build_vm.main()
            else:
                with self.assertRaises((ValueError, FileExistsError)):
                    build_vm.main()
                self.assertFalse((output / 'Cargo.lock').exists())
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.app / 'Cargo.toml', self.app / 'Cargo.lock') if p.exists()})
        self.assertFalse((self.app / 'marker').exists())
        self.assertFalse((output / 'manifest.json').exists())
        self.assertFalse((output / 'bundle.json').exists())
        self.assertFalse(list(output.glob('*.wasm')))
        return output, log.getvalue()

    def test_credential_urls_are_absent_from_summary_and_solver_logs(self):
        old = lock([{'name': 'https://example_user:example_secret@example.invalid', 'version': '1.0.0'}])
        (self.app / 'Cargo.lock').write_bytes(old)
        output, message = self.run_mode('deps-resolve')
        self.assertIn('Comparison unavailable', message)
        self.assertNotIn('example_secret', message)
        (self.app / 'Cargo.toml').write_text(self.manifest.replace("serde='1'", "serde={version='1',features=['https://example_user:example_secret@example.invalid']}"))
        output, _ = self.run_mode('deps-resolve', success=False)
        self.assertNotIn(b'example_secret', (output / 'build.log').read_bytes())
        self.assertIn(b'[redacted URL]', (output / 'build.log').read_bytes())

    def test_cache_contents_cannot_expand_catalog(self):
        cache = self.root / 'cache/registry/cache/approved'
        cache.mkdir(parents=True)
        for package in catalog_packages((ROOT / 'Cargo.lock').read_bytes()):
            if 'source' not in package:
                continue
            name = package['name'] + '-' + package['version'] + '.crate'
            source = next((Path.home() / '.cargo/registry/cache').glob('*/' + name))
            shutil.copyfile(source, cache / name)
        # This cache entry is a valid crate, but its identity is outside the catalog.
        import tarfile
        with tarfile.open(cache / 'serde-999.0.0.crate', 'w:gz') as archive:
            for name, data in (('Cargo.toml', b'[package]\nname="serde"\nversion="999.0.0"\n'), ('src/lib.rs', b'')):
                entry = tarfile.TarInfo('serde-999.0.0/' + name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        (self.app / 'Cargo.toml').write_text(self.manifest.replace("serde='1'", "serde='=999.0.0'"))
        destination = self.root / 'unapproved'
        args = ['build_vm.py', '--local', '--toolchain', str(self.toolchain), '--app', str(self.app), '--cargo-home', str(self.root / 'cache'), '--deps-resolve', '--output', str(destination)]
        with mock.patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'dependency resolution failed'):
                build_vm.main()
        self.assertFalse((destination / 'Cargo.lock').exists())
        self.assertTrue((cache / 'serde-999.0.0.crate').exists())

    def test_fresh_resolution_ignores_missing_malformed_and_incompatible_old_locks(self):
        for old in (None, b'broken', lock([{'name': 'serde', 'version': '999.0.0', 'source': REGISTRY, 'checksum': 'a' * 64}])):
            if old is not None:
                (self.app / 'Cargo.lock').write_bytes(old)
            output, message = self.run_mode('deps-resolve')
            candidate = (output / 'Cargo.lock').read_bytes()
            self.assertIn('Review inputs, then install: cp -- ', message)
            self.assertTrue(lock_packages(candidate))
            (self.app / 'Cargo.lock').write_bytes(candidate)
            checked, _ = self.run_mode('deps-check')
            self.assertEqual((checked / 'Cargo.lock').read_bytes(), candidate)

    def test_missing_stale_and_unsatisfiable_locks_fail_without_candidate(self):
        self.run_mode('deps-check', success=False)
        output, _ = self.run_mode('deps-resolve')
        (self.app / 'Cargo.lock').write_bytes((output / 'Cargo.lock').read_bytes())
        (self.app / 'Cargo.toml').write_text(self.manifest.replace("serde='1'", "serde={version='1', features=['feature_that_does_not_exist']}"))
        self.run_mode('deps-check', success=False)
        self.run_mode('deps-resolve', success=False)
        (self.app / 'Cargo.toml').write_text(self.manifest.replace("serde='1'", "serde='=999.0.0'"))
        self.run_mode('deps-resolve', success=False)

    def test_normal_check_generates_missing_lock_and_accepts_candidate(self):
        if not (self.toolchain / 'lib/rustlib/wasm32-unknown-unknown/lib').is_dir():
            self.skipTest('normal check needs the Wasm standard library')
        (self.app / 'Cargo.toml').write_text(self.manifest.replace("serde='1'", ''))
        (self.app / 'src/lib.rs').write_text('pub fn works() {}')
        (self.app / 'build.rs').write_text('fn main() { println!("cargo:warning=NORMAL_BUILD_SCRIPT"); }')
        for existing in (False, True):
            if existing:
                resolved, _ = self.run_mode('deps-resolve')
                (self.app / 'Cargo.lock').write_bytes((resolved / 'Cargo.lock').read_bytes())
            destination = self.root / ('normal-' + str(existing))
            args = ['build_vm.py', '--local', '--toolchain', str(self.toolchain), '--app', str(self.app), '--check', '--output', str(destination)]
            with mock.patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()):
                build_vm.main()
            self.assertIn('NORMAL_BUILD_SCRIPT', (destination / 'build.log').read_text())
            self.assertTrue((destination / 'Cargo.lock').is_file())
            self.assertEqual((self.app / 'Cargo.lock').exists(), existing)

    def test_stale_lock_and_timeout_preserve_inputs(self):
        output, _ = self.run_mode('deps-resolve')
        candidate = (output / 'Cargo.lock').read_bytes()
        (self.app / 'Cargo.lock').write_bytes(candidate)
        (self.app / 'Cargo.toml').write_text(self.manifest.replace("serde='1'", "serde='1'\nserde_json='1'"))
        self.run_mode('deps-check', success=False)
        resolved, _ = self.run_mode('deps-resolve')
        self.assertNotEqual(candidate, (resolved / 'Cargo.lock').read_bytes())
        destination = self.root / 'timeout'
        args = ['build_vm.py', '--local', '--toolchain', str(self.toolchain), '--app', str(self.app), '--deps-resolve', '--seconds', '0', '--output', str(destination)]
        with mock.patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(subprocess.TimeoutExpired):
                build_vm.main()
        self.assertEqual(candidate, (self.app / 'Cargo.lock').read_bytes())
        self.assertFalse((destination / 'Cargo.lock').exists())

    def test_interrupt_preserves_source_and_publishes_no_candidate(self):
        selected = self.root / 'operator-toolchain'
        (selected / 'bin').mkdir(parents=True)
        ready = self.root / 'ready'
        os.mkfifo(ready)
        cargo = selected / 'bin/cargo'
        cargo.write_text('#!/bin/sh\nprintf ready > ' + shlex.quote(str(ready)) + '\nsleep 60\n')
        cargo.chmod(0o755)
        original = b'malformed old lock remains untouched'
        (self.app / 'Cargo.lock').write_bytes(original)
        destination = self.root / 'interrupted'
        reader = os.open(ready, os.O_RDONLY | os.O_NONBLOCK)
        selector = selectors.DefaultSelector()
        selector.register(reader, selectors.EVENT_READ)
        process = subprocess.Popen([sys.executable, str(ROOT / 'tools/build_vm.py'), '--local', '--deps-resolve', '--app', str(self.app), '--toolchain', str(selected), '--output', str(destination)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(selector.select(10), 'executor did not reach synchronization point')
            self.assertEqual(os.read(reader, 64), b'ready')
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()
            selector.close()
            os.close(reader)
        self.assertEqual((self.app / 'Cargo.lock').read_bytes(), original)
        self.assertEqual((self.app / 'Cargo.toml').read_text(), self.manifest)
        self.assertFalse((destination / 'Cargo.lock').exists())

    def test_existing_output_protected_and_no_wasm_target_required(self):
        destination = self.root / 'exists'
        destination.mkdir()
        self.run_mode('deps-resolve', success=False, output=destination)
        # Real Cargo under a toolchain directory with only bin symlink: actual rustc
        # resolves its standard library through its installed sysroot.
        selected = self.root / 'selected'
        selected.mkdir()
        (selected / 'bin').symlink_to(self.toolchain / 'bin', target_is_directory=True)
        real = self.toolchain
        self.toolchain = selected
        try:
            self.run_mode('deps-resolve')
        finally:
            self.toolchain = real


if __name__ == '__main__':
    unittest.main()
