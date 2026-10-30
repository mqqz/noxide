#!/usr/bin/env python3
"""Build CLI source archives outside the workspace and use the detached binary."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--lifecycle', action='store_true', help='Run the full lifecycle with the detached packaged CLI')
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=False)
    root = options.output.resolve()
    subprocess.run(['python3', str(ROOT / 'tools/package_build_kit.py')], check=True)
    subprocess.run(['cargo', 'package', '--workspace', '--no-verify', '--allow-dirty', '--offline', '--target-dir', str(root / 'archives')], cwd=ROOT, check=True)
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    packages = ['noxide-macros', 'noxide-protocol', 'noxide', 'noxide-host', 'noxide-cli']
    sources = root / 'sources'
    sources.mkdir()
    for name in packages:
        with tarfile.open(root / f'archives/package/{name}-{version}.crate') as archive:
            archive.extractall(sources, filter='data')
    cli = sources / f'noxide-cli-{version}'
    manifest = cli / 'Cargo.toml'
    manifest.write_text(manifest.read_text() + '\n[patch.crates-io]\n' + ''.join(
        f'{name} = {{ path = "../{name}-{version}" }}\n' for name in packages[:-1]))
    command = ['cargo', 'build', '--manifest-path', str(manifest), '--offline', '--target-dir', str(root / 'target')]
    subprocess.run(command, cwd=root, check=True)
    subprocess.run(command + ['--locked'], cwd=root, check=True)
    detached = root / 'noxide'
    shutil.copy2(root / 'target/debug/noxide', detached)
    sources.rename(root / 'unavailable-source-checkouts')
    if options.lifecycle:
        subprocess.run(['python3', str(ROOT / 'tools/test_lifecycle.py'),
                        '--cli', str(detached), '--output', str(root / 'lifecycle')],
                       cwd=root, check=True)
        return
    environment = dict(os.environ, XDG_STATE_HOME=str(root / 'state'), CARGO_HOME=str(root / 'empty-cargo'))
    app = root / 'consumer'
    subprocess.run([str(detached), 'new', str(app)], env=environment, check=True)
    subprocess.run([str(detached), 'check'], cwd=app, env=environment, check=True)
    print('Packaged CLI built and checked a generated application without its source checkout or a dependency cache.')

if __name__ == '__main__':
    main()
