#!/usr/bin/env python3
"""Run hostile asset export fixtures only inside disposable disconnected VMs.

This exercises the actual build_recipe emission/build_vm transport without
compiling fixtures or running their shell commands on the host.
"""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path
import tempfile
from build_assets import MAX_ARCHIVE, from_tar
from build_vm import Image, artifact, check_build_status, run_vm, command
from build_recipe import INIT, emission


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--woff2',type=Path)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data))
    png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',1,1,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(b'\0\xff\0\0\xff'))+chunk(b'IEND',b'')
    payloads={'pixel.png':('png',png)}
    css="p{color:red;background-image:url('/_noxide/assets/"+hashlib.sha256(png).hexdigest()+"')}"
    if args.woff2:
        font=args.woff2.read_bytes()
        payloads['face.woff2']=('woff2',font)
        css+="@font-face{font-family:'nxa-test';src:url('/_noxide/assets/"+hashlib.sha256(font).hexdigest()+"')}"
    payloads['site.css']=('css',css.encode())
    declarations=[{'name':name,'media_type':kind,'digest':hashlib.sha256(data).hexdigest()} for name,(kind,data) in sorted(payloads.items())]
    (args.output/'regular.declarations.json').write_text(json.dumps(declarations,indent=2))
    cases={
        'regular':('mkdir public\ncp /src/fixtures/* public/\n',True),
        'symlink':('mkdir public\nln -s /src/secret public/leak.css\n',False),
        'linked-root':('ln -s /src public\n',False),
        'fifo':('mkdir public\nmkfifo public/pipe.css\n',False),
        'count':('mkdir public\nn=0\nwhile [ "$n" -lt 129 ]; do printf x > "public/asset$n.css"; n=$((n+1)); done\n',False),
        'large':('mkdir public\nhead -c 4194305 /dev/zero > public/large.png\n',False),
    }
    for name,(fixture,accepted) in cases.items():
        image=Image()
        for binary in ['bash','mount','mkdir','chmod','cp','setpriv','env','cat','base64','tar','head','rm','timeout','poweroff','ln','mkfifo']:
            image.executable(binary)
        image.trusted('/usr/bin/bash','usr/bin/sh')
        # Void's ELF interpreter searches lib64 before INIT can set LD_LIBRARY_PATH.
        image.trusted(command('gcc','-print-file-name=libc.so.6'))
        image.add('src/secret',b'VM-only inert canary')
        if name=='regular':
            for filename,(_,data) in payloads.items():image.add('src/fixtures/'+filename,data)
        build='set -eu\nmkdir -p /tmp/work/examples/private-notes\ncd /tmp/work/examples/private-notes\nprintf "version = 4\\n" > Cargo.lock\nprintf "{}" > /tmp/work/noxide-contract.json\n'+fixture
        image.add('build-command',build.encode())
        image.add('init',INIT.replace(emission(),emission(check=True,metadata=True)).encode(),0o755)
        with tempfile.TemporaryDirectory(prefix='noxide-asset-vm-') as folder:
            path=Path(folder)/'input.cpio.gz';image.write(path)
            output=run_vm(args.kernel,path,args.output/(name+'.log'),60)
        check_build_status(output)
        try:pack=from_tar(artifact(output,'ASSETS',MAX_ARCHIVE))
        except (ValueError,OSError):
            if accepted:raise
            print(name+': rejected',flush=True)
        else:
            if not accepted:raise AssertionError(name+': hostile export accepted')
            (args.output/(name+'.pack')).write_bytes(pack)
            print(name+': exported bounded canonical asset pack',flush=True)

if __name__=='__main__':main()
