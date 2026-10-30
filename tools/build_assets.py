"""Bounded public-asset transport from an executor; never extracts archive paths.

Only the disconnected build VM may produce assets for hostile source inputs.
Local execution deliberately trusts application code and dependencies. The host
independently admits MIME/content/CSS after checking this binary transport.
"""
import io
import struct
import tarfile

MAX_ASSETS = 128
MAX_SINGLE = 4 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_ARCHIVE = MAX_TOTAL + 1024 * 1024
MAGIC = b"NXAS\x01\0\0\0"


def valid_name(name):
    return (0 < len(name.encode('utf-8')) <= 192
            and all(part and part not in ('.', '..') and not part.startswith('.')
                    and all(c.isascii() and (c.isalnum() or c in '_-.') for c in part)
                    for part in name.split('/')))


def from_tar(archive):
    """Turn untrusted, uncompressed tar bytes into a canonical asset pack.

    Never extract or follow a path. GNU tar's one leading './' is transport
    metadata; all remaining components are checked without normalization.
    Symlinks, hardlinks, devices, sparse entries, duplicate names and undeclared
    extension records are rejected. A later manifest match rejects extra assets.
    """
    if len(archive) > MAX_ARCHIVE:
        raise ValueError('asset archive byte limit')
    # Validate raw USTAR framing before tarfile can consume extension records or
    # stop at an early end marker. Unknown formats and concatenated archives fail.
    offset = 0
    headers = 0
    while True:
        header = archive[offset:offset + 512]
        if len(header) != 512:
            raise ValueError('truncated asset archive header')
        if header == bytes(512):
            if len(archive) - offset < 1024 or len(archive) % 512 or any(archive[offset:]):
                raise ValueError('asset archive trailing data')
            break
        headers += 1
        if (headers > 512 or header[257:263] != b'ustar\0'
                or header[263:265] != b'00' or header[156] not in (0, ord('0'), ord('5'))):
            raise ValueError('unsupported asset archive format or type')
        raw_size = header[124:136].strip(b' \0')
        if not raw_size or any(c not in b'01234567' for c in raw_size):
            raise ValueError('invalid asset archive size')
        size = int(raw_size, 8)
        if size > MAX_SINGLE or (header[156] == ord('5') and size):
            raise ValueError('asset archive entry size limit')
        offset += 512 + ((size + 511) // 512) * 512
        if offset > len(archive):
            raise ValueError('truncated asset archive entry')
    assets = {}
    seen = set()
    total = 0
    entries = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
        for member in tar:
            entries += 1
            if entries > 512 or member.pax_headers:
                raise ValueError('asset archive entry or extension limit')
            name = member.name
            if name.startswith('./'):
                name = name[2:]
            identity = name.rstrip('/') if member.isdir() else name
            if identity in seen:
                raise ValueError('duplicate asset archive entry')
            seen.add(identity)
            if member.isdir():
                if name in ('', '.'):
                    continue
                if not valid_name(name.rstrip('/')):
                    raise ValueError('invalid asset directory')
                continue
            if (not member.isfile() or member.sparse is not None
                    or not valid_name(name) or name in assets):
                raise ValueError('unsafe or duplicate asset archive entry')
            if not 0 < member.size <= MAX_SINGLE or len(assets) >= MAX_ASSETS:
                raise ValueError('asset size or count limit')
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError('asset total limit')
            stream = tar.extractfile(member)
            data = stream.read(MAX_SINGLE + 1)
            if len(data) != member.size:
                raise ValueError('truncated asset')
            assets[name] = data
    pack = bytearray(MAGIC + struct.pack('<H', len(assets)))
    for name, data in sorted(assets.items()):
        encoded = name.encode('ascii')
        pack.extend(struct.pack('<HI', len(encoded), len(data)))
        pack.extend(encoded)
        pack.extend(data)
    return bytes(pack)

# Base64 wraps at 76 columns. General diagnostics retain their original 16 MiB
# budget; only a single syntactically framed public-asset envelope is additional.
MAX_DIAGNOSTICS = 16 * 1024 * 1024
MAX_ASSET_BASE64 = 4 * ((MAX_ARCHIVE + 2) // 3)
MAX_ASSET_ENVELOPE = MAX_ASSET_BASE64 + 2 * ((MAX_ASSET_BASE64 + 75) // 76) + 128
MAX_TRANSPORT = MAX_DIAGNOSTICS + MAX_ASSET_ENVELOPE


class ConsoleBudget:
    def __init__(self, diagnostics_limit=MAX_DIAGNOSTICS, limit_message="executor output limit exceeded"):
        self.diagnostics_limit = diagnostics_limit
        self.limit_message = limit_message
        self.pending = bytearray()
        self.long_line = False
        self.inside = False
        self.seen = False
        self.diagnostics = 0
        self.asset_bytes = 0
        self.total = 0

    def feed(self, chunk):
        self.total += len(chunk)
        if self.total > self.diagnostics_limit + MAX_ASSET_ENVELOPE:
            raise ValueError('executor transport limit')
        self.pending.extend(chunk)
        while True:
            end = self.pending.find(b'\n')
            if end < 0:
                break
            line = bytes(self.pending[:end + 1])
            del self.pending[:end + 1]
            self._line(line)
        if len(self.pending) > 4096:
            if self.inside:
                raise ValueError('asset base64 line limit')
            self._diagnostic(len(self.pending))
            self.pending.clear()
            self.long_line = True

    def _diagnostic(self, size):
        self.diagnostics += size
        if self.diagnostics > self.diagnostics_limit:
            raise ValueError(self.limit_message)

    def _line(self, line):
        normalized = line.replace(b'\r\n', b'\n')
        if not self.inside:
            if not self.long_line and normalized == b'NOXIDE_ASSETS_BEGIN\n':
                if self.seen:
                    raise ValueError('duplicate asset envelope')
                self.inside = self.seen = True
                self.asset_bytes += len(line)
            else:
                self._diagnostic(len(line))
            self.long_line = False
        else:
            self.asset_bytes += len(line)
            if normalized == b'NOXIDE_ASSETS_END\n':
                self.inside = False
            else:
                content = normalized[:-1]
                if not 0 < len(content) <= 76 or any(c not in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in content):
                    raise ValueError('asset base64 grammar')
            if self.asset_bytes > MAX_ASSET_ENVELOPE:
                raise ValueError('asset envelope limit')

    def finish(self):
        if self.pending:
            if self.inside:
                raise ValueError('incomplete asset envelope')
            self._diagnostic(len(self.pending))
            self.pending.clear()
        if self.inside:
            raise ValueError('incomplete asset envelope')
