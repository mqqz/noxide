#!/usr/bin/env python3
"""Package authoritative SDK sources and checksum-verified approved dependencies."""
import argparse
from build_catalog import catalog_packages
import hashlib
import os
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent.parent

def entries():
    paths = [ROOT / name for name in ('Cargo.toml', 'Cargo.lock', 'README.md',
             'tools/build_vm.py', 'tools/build_local.py', 'tools/build_recipe.py', 'tools/build_catalog.py')]
    for name in ('noxide', 'noxide-macros', 'noxide-protocol'):
        crate = ROOT / 'crates' / name
        paths.append(crate / 'Cargo.toml')
        for folder in ('src', 'wit'):
            paths.extend(p for p in (crate / folder).rglob('*') if p.is_file())
    for path in sorted(paths):
        data = path.read_bytes()
        if path == ROOT / 'Cargo.toml':
            data = data.replace(b'    "crates/noxide-cli",\n', b'').replace(b'    "crates/noxide-host",\n', b'')
        yield path.relative_to(ROOT).as_posix(), data
    packages = catalog_packages((ROOT / 'Cargo.lock').read_bytes())
    cargo = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo')))
    for package in packages:
        if 'source' not in package:
            continue
        key = (package['name'], package['version'])
        name = f'{key[0]}-{key[1]}.crate'
        archives = list((cargo / 'registry/cache').glob('*/' + name))
        if not archives:
            raise ValueError(f'missing {name}; run cargo fetch --locked before packaging the trusted CLI')
        data = archives[0].read_bytes()
        if hashlib.sha256(data).hexdigest() != package['checksum']:
            raise ValueError('SDK dependency checksum mismatch: ' + name)
        yield 'registry/' + name, data

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'crates/noxide-cli/build-kit.bin')
    options = parser.parse_args()
    with options.output.open('wb') as stream:
        for name, data in entries():
            name = name.encode()
            stream.write(struct.pack('<II', len(name), len(data)) + name + data)
