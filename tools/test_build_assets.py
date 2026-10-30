#!/usr/bin/env python3
"""Untrusted executor asset transport regressions; no application code executes."""
import io
import re
import subprocess
import time
import struct
import tarfile
import unittest
import tempfile
from pathlib import Path
from unittest import mock
import build_vm
import build_assets as assets
from build_local import run_local
from build_recipe import emission


def archive(entries):
    out=io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name,data,kind in entries:
            info=tarfile.TarInfo(name)
            info.type=kind
            if kind==tarfile.REGTYPE:
                info.size=len(data)
            elif kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):
                info.linkname='/etc/passwd'
            tar.addfile(info,io.BytesIO(data) if kind==tarfile.REGTYPE else None)
    return out.getvalue()


class AssetTransport(unittest.TestCase):
    def test_name_boundary_is_shared_with_transport(self):
        self.assertEqual(assets.MAX_ASSET_NAME_BYTES,96)
        for size in [95,96,97]:
            name='a'*(size-4)+'.css'
            self.assertEqual(assets.valid_name(name),size<=assets.MAX_ASSET_NAME_BYTES)
            data=archive([('./'+name,b'p{color:red}',tarfile.REGTYPE)])
            if size<=assets.MAX_ASSET_NAME_BYTES:self.assertIn(name.encode(),assets.from_tar(data))
            else:
                with self.assertRaises(ValueError):assets.from_tar(data)
    def test_canonical_sorted_pack(self):
        source=archive([('./b.css',b'b',tarfile.REGTYPE),('./images',b'',tarfile.DIRTYPE),('./images/a.png',b'a',tarfile.REGTYPE)])
        pack=assets.from_tar(source)
        self.assertEqual(pack, assets.MAGIC+struct.pack('<H',2)+struct.pack('<HI',5,1)+b'b.cssb'+struct.pack('<HI',12,1)+b'images/a.pnga')
    def test_reject_unsafe_names_and_special_entries(self):
        for name in ['/x','../x','./../x','x/../y','x//y','x/./y','.hidden','x\\y','x?y']:
            with self.subTest(name=name),self.assertRaises(ValueError):
                assets.from_tar(archive([(name,b'x',tarfile.REGTYPE)]))
        for kind in [tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.FIFOTYPE,tarfile.CHRTYPE]:
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                assets.from_tar(archive([('x',b'',kind)]))
    def test_reject_duplicate_empty_count_and_byte_limits(self):
        for entries in [[('x',b'x',tarfile.REGTYPE)]*2,[('x',b'',tarfile.REGTYPE)],[(str(n),b'x',tarfile.REGTYPE) for n in range(129)], [('x',b'x'*(assets.MAX_SINGLE+1),tarfile.REGTYPE)],[(str(n),bytes([n+1])*assets.MAX_SINGLE,tarfile.REGTYPE) for n in range(5)]]:
            with self.assertRaises(ValueError): assets.from_tar(archive(entries))
    def test_truncated_and_archive_limit(self):
        with self.assertRaises((ValueError,tarfile.TarError)):
            assets.from_tar(archive([('x',b'x'*1024,tarfile.REGTYPE)])[:1024])
        with self.assertRaises(ValueError): assets.from_tar(b'x'*(assets.MAX_ARCHIVE+1))
    def test_pax_extensions_rejected(self):
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w',format=tarfile.PAX_FORMAT) as tar:
            info=tarfile.TarInfo('x');info.size=1;info.pax_headers={'comment':'extension'};tar.addfile(info,io.BytesIO(b'x'))
        with self.assertRaises(ValueError):assets.from_tar(out.getvalue())

class PublicSourceSnapshot(unittest.TestCase):
    def test_name_boundary_is_enforced_before_executor_snapshot(self):
        for size in [95,96,97]:
            with self.subTest(size=size),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);(root/'public').mkdir();name='a'*(size-4)+'.css';(root/'public'/name).write_bytes(b'p{color:red}')
                if size<=assets.MAX_ASSET_NAME_BYTES:
                    image=build_vm.Image();build_vm.source_files(image,root,'src',public_assets=True)
                    self.assertEqual(set(image.files),{'src/public/'+name})
                else:
                    with self.assertRaisesRegex(ValueError,'public source asset budget or name'):build_vm.source_files(build_vm.Image(),root,'src',public_assets=True)
    def test_public_target_asset_is_preserved_ordinary_targets_stay_excluded(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name,data in [('public/target/site.css',b'p{color:red}'),('target/debug/build-output',b'ordinary artifact'),('src/target/cache',b'nested artifact')]:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            image=build_vm.Image();build_vm.source_files(image,root,'src',public_assets=True)
            self.assertEqual(set(image.files),{'src/public/target/site.css'})
            self.assertEqual(image.files['src/public/target/site.css'][0],b'p{color:red}')
            image=build_vm.Image();build_vm.source_files(image,root,'src')
            self.assertEqual(image.files,{})
    def test_public_target_retains_public_limits_and_unsafe_entry_rejection(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);parent=root/'public/target';parent.mkdir(parents=True)
            asset=parent/'site.css';asset.write_bytes(b'ab')
            with mock.patch('build_vm.MAX_PUBLIC_SINGLE',1),self.assertRaisesRegex(ValueError,'public source asset budget'):
                build_vm.source_files(build_vm.Image(),root,'src',public_assets=True)
            asset.unlink();asset.symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError,'hidden or linked'):
                build_vm.source_files(build_vm.Image(),root,'src',public_assets=True)
            asset.unlink();(parent/'.private').write_bytes(b'private')
            with self.assertRaisesRegex(ValueError,'hidden or linked'):
                build_vm.source_files(build_vm.Image(),root,'src',public_assets=True)
            (parent/'.private').unlink();(parent/'bad name.css').write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError,'public source asset budget or name'):
                build_vm.source_files(build_vm.Image(),root,'src',public_assets=True)
    def test_asset_budget_is_separate_and_paths_stay_no_follow(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'public').mkdir();(root/'lib.rs').write_bytes(b'12345678');(root/'public/pixel.png').write_bytes(b'asset bytes')
            with mock.patch('build_vm.MAX_SOURCE',8):
                image=build_vm.Image();build_vm.source_files(image,root,'src',public_assets=True)
                self.assertEqual(image.files['src/public/pixel.png'][0],b'asset bytes')
            (root/'public/pixel.png').unlink();(root/'public/pixel.png').symlink_to(root/'lib.rs')
            with self.assertRaises(ValueError):build_vm.source_files(build_vm.Image(),root,'src',public_assets=True)
    def test_reject_public_count_size_and_name(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'public').mkdir();asset=root/'public/x.png';asset.write_bytes(b'ab')
            with mock.patch('build_vm.MAX_PUBLIC_SINGLE',1),self.assertRaises(ValueError):build_vm.source_files(build_vm.Image(),root,'src',public_assets=True)
            asset.unlink();(root/'public/bad name.png').write_bytes(b'a')
            with self.assertRaises(ValueError):build_vm.source_files(build_vm.Image(),root,'src',public_assets=True)

class LocalAssetExport(unittest.TestCase):
    def test_export_status_requires_exact_success_from_both_processes(self):
        success=b'NOXIDE_ASSETS_TAR_STATUS=0\nNOXIDE_ASSETS_HEAD_STATUS=0\nNOXIDE_ASSETS_STATUS=0\n'
        build_vm.check_asset_status(success)
        for output in [success.replace(b'TAR_STATUS=0',b'TAR_STATUS=2'),success.replace(b'HEAD_STATUS=0',b'HEAD_STATUS=1'),success.replace(b'ASSETS_STATUS=0',b'ASSETS_STATUS=1'),success.split(b'\n',1)[1],success+b'NOXIDE_ASSETS_HEAD_STATUS=0\n']:
            with self.assertRaisesRegex(ValueError,'asset export failed'):build_vm.check_asset_status(output)
    def run_export(self,log_path,name=None,commands=None,consumer=None,seconds=10):
        image=build_vm.Image()
        if name is not None:image.add('src/fixture/'+name,b'p{color:red}')
        build='set -eu\nmkdir -p /tmp/work/examples/private-notes/public\ncd /tmp/work/examples/private-notes\nprintf "version = 4\\n" > Cargo.lock\nprintf "{}" > /tmp/work/noxide-contract.json\n'
        build+=commands if commands is not None else 'cp /src/fixture/* public/\n'
        export=emission(check=True,metadata=True)
        if consumer is not None:export=export.replace('head -c '+str(assets.MAX_ARCHIVE+1),consumer)
        image.add('build-command',build.encode());image.add('artifact-command',export.encode())
        return run_local(image,Path('/usr'),log_path,seconds)
    def test_local_export_name_boundaries(self):
        for size in [95,96,97]:
            with self.subTest(size=size),tempfile.TemporaryDirectory() as folder:
                name='a'*(size-4)+'.css';output=self.run_export(Path(folder)/'build.log',name=name)
                build_vm.check_build_status(output);build_vm.check_asset_status(output)
                archive=build_vm.artifact(output,'ASSETS',assets.MAX_ARCHIVE)
                if size<=assets.MAX_ASSET_NAME_BYTES:self.assertIn(name.encode(),assets.from_tar(archive))
                else:
                    with self.assertRaises(ValueError):assets.from_tar(archive)
    def test_tar_exit_two_never_exports_partial_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            output=self.run_export(Path(folder)/'build.log',name='a'*124+'.css')
            self.assertIn(b'NOXIDE_ASSETS_TAR_STATUS=2\n',output)
            self.assertIn(b'NOXIDE_ASSETS_HEAD_STATUS=0\n',output)
            self.assertNotIn(b'NOXIDE_ASSETS_BEGIN',output)
            with self.assertRaisesRegex(ValueError,'asset export failed'):build_vm.check_asset_status(output)
    def test_consumer_cap_rejects_producer_sigpipe_without_export(self):
        with tempfile.TemporaryDirectory() as folder:
            output=self.run_export(Path(folder)/'build.log',commands='n=0\nwhile [ "$n" -lt 5 ]; do head -c 4194304 /dev/zero > "public/large$n.png"; n=$((n+1)); done\n')
            self.assertIn(b'NOXIDE_ASSETS_HEAD_STATUS=0\n',output)
            self.assertNotIn(b'NOXIDE_ASSETS_TAR_STATUS=0\n',output)
            self.assertNotIn(b'NOXIDE_ASSETS_BEGIN',output)
            with self.assertRaisesRegex(ValueError,'asset export failed'):build_vm.check_asset_status(output)
    def test_failed_consumer_never_exports_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            output=self.run_export(Path(folder)/'build.log',name='site.css',consumer='false -c '+str(assets.MAX_ARCHIVE+1))
            self.assertIn(b'NOXIDE_ASSETS_HEAD_STATUS=1\n',output)
            self.assertNotIn(b'NOXIDE_ASSETS_BEGIN',output)
            with self.assertRaisesRegex(ValueError,'asset export failed'):build_vm.check_asset_status(output)
    def test_cancelled_export_cleans_up_owned_consumer_process(self):
        with tempfile.TemporaryDirectory() as folder:
            log=Path(folder)/'build.log'
            consumer="sh -c 'echo NOXIDE_TEST_HEAD_PID=$$ >&2; exec sleep 30' --"
            with self.assertRaises(subprocess.TimeoutExpired):self.run_export(log,name='site.css',consumer=consumer,seconds=1)
            match=re.search(rb'NOXIDE_TEST_HEAD_PID=(\d+)',log.read_bytes());self.assertIsNotNone(match)
            pid=int(match[1]);until=time.monotonic()+2
            while time.monotonic()<until:
                status=Path('/proc')/str(pid)/'stat'
                try:state=status.read_text().rsplit(')',1)[1].split()[0]
                except FileNotFoundError:break
                if state=='Z':break
                time.sleep(.01)
            else:self.fail('owned export consumer survived process-group cancellation')

class ConsoleTransport(unittest.TestCase):
    def test_split_markers_and_general_diagnostics(self):
        budget=assets.ConsoleBudget()
        for chunk in [b'log\nNOXIDE_AS',b'SETS_BEGIN\r\n',b'YQ==\r\nNOXIDE_ASSETS_',b'END\r\nmore log']:
            budget.feed(chunk)
        budget.finish()
        self.assertEqual(budget.diagnostics,len(b'log\nmore log'))
        self.assertTrue(budget.seen)
    def test_asset_envelope_does_not_expand_diagnostic_limit(self):
        budget=assets.ConsoleBudget()
        budget.feed(b'NOXIDE_ASSETS_BEGIN\nYQ==\nNOXIDE_ASSETS_END\n')
        for _ in range(256): budget.feed(b'x'*65536)
        with self.assertRaises(ValueError): budget.feed(b'x'*65536)
    def test_reject_bad_duplicate_and_incomplete_envelopes(self):
        for stream in [b'NOXIDE_ASSETS_BEGIN\nhttps://evil\nNOXIDE_ASSETS_END\n',b'NOXIDE_ASSETS_BEGIN\n'+b'a'*77+b'\nNOXIDE_ASSETS_END\n',b'NOXIDE_ASSETS_BEGIN\nYQ==\n',b'NOXIDE_ASSETS_BEGIN\nYQ==\nNOXIDE_ASSETS_END\nNOXIDE_ASSETS_BEGIN\n']:
            with self.subTest(stream=stream),self.assertRaises(ValueError):
                budget=assets.ConsoleBudget();budget.feed(stream);budget.finish()
    def test_worst_case_envelope_is_below_48_mib(self):
        self.assertLess(assets.MAX_TRANSPORT,48*1024*1024)

if __name__=='__main__': unittest.main()
