#!/usr/bin/env python3
"""Untrusted executor asset transport regressions; no application code executes."""
import io
import struct
import tarfile
import unittest
import tempfile
from pathlib import Path
from unittest import mock
import build_vm
import build_assets as assets


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
