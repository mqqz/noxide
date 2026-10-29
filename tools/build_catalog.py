"""Bounded lock/catalog validation shared by staging and installed-kit packaging."""
import json
import posixpath
import shlex
import re
import tomllib

REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
LOCK_LIMIT = 131072


def display(value):
    return json.dumps(str(value)[:160], ensure_ascii=True)


def lock_packages(raw):
    if raw is None:
        raise ValueError('missing lockfile')
    if len(raw) > LOCK_LIMIT:
        raise ValueError('lockfile size limit')
    try:
        document = tomllib.loads(raw.decode())
        packages = document['package']
        if not isinstance(packages, list) or not packages or len(packages) > 2048:
            raise ValueError()
        for p in packages:
            if not isinstance(p, dict) or not all(isinstance(p.get(k), str) for k in ('name', 'version')):
                raise ValueError()
            if any(k in p and not isinstance(p[k], str) for k in ('source', 'checksum')):
                raise ValueError()
            if not re.fullmatch(r'[A-Za-z0-9_-]+', p['name']) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', p['version']):
                raise ValueError()
        return packages
    except (ValueError, KeyError, UnicodeError, TypeError):
        raise ValueError('missing or malformed lockfile; run noxide deps resolve with the same catalog') from None


def catalog_packages(raw):
    packages = lock_packages(raw)
    seen, selected, todo = set(), [], ['noxide', 'wit-bindgen']
    while todo:
        reference = todo.pop().split()
        for p in packages:
            identity = (p['name'], p['version'], p.get('source'), p.get('checksum'))
            if identity in seen or p['name'] != reference[0] or (len(reference) > 1 and p['version'] != reference[1]):
                continue
            seen.add(identity)
            todo.extend(p.get('dependencies', []))
            if 'source' in p and p['source'] != REGISTRY:
                raise ValueError('unsupported trusted catalog source')
            selected.append(p)
    return selected


def path_packages(files, manifest='src/examples/private-notes/Cargo.toml'):
    """Only staged, reachable path packages may have source-free lock entries."""
    result, visited, todo = set(), set(), [manifest]
    while todo:
        path = todo.pop()
        if path in visited:
            continue
        visited.add(path)
        if path not in files:
            raise ValueError('unsupported path dependency outside staged source')
        data = files[path][0]
        doc = tomllib.loads(data.decode())
        trusted = path.startswith('src/crates/')
        package = doc.get('package', {})
        if not trusted and ('workspace' in package or any(isinstance(v, dict) and v.get('workspace') for v in package.values()) or doc.get('workspace', {})):
            raise ValueError('unsupported workspace inheritance or application workspace')
        version = package.get('version')
        if trusted and isinstance(version, dict):
            version = tomllib.loads(files['src/Cargo.toml'][0].decode())['workspace']['package']['version']
        if not isinstance(package.get('name'), str) or not isinstance(version, str):
            raise ValueError('unsupported package identity or workspace inheritance')
        result.add((package['name'], version))
        tables = [doc]
        tables.extend(doc.get('target', {}).values())
        if not trusted and any(k in doc for k in ('patch', 'replace')):
            raise ValueError('unsupported source override')
        for table in tables:
            for kind in ('dependencies', 'build-dependencies', 'dev-dependencies'):
                for name, dep in table.get(kind, {}).items():
                    if not isinstance(dep, dict):
                        continue
                    base = posixpath.dirname(path)
                    if trusted and dep.get('workspace'):
                        dep = tomllib.loads(files['src/Cargo.toml'][0].decode())['workspace']['dependencies'][name]
                        base = 'src'
                    if not isinstance(dep, dict):
                        continue
                    if any(k in dep for k in ('git', 'registry', 'registry-index', 'workspace')):
                        raise ValueError('unsupported dependency source or workspace inheritance')
                    if 'path' in dep:
                        target = posixpath.normpath(posixpath.join(base, dep['path'], 'Cargo.toml'))
                        if not target.startswith('src/') or (not trusted and not target.startswith('src/examples/private-notes/') and target != 'src/crates/noxide/Cargo.toml'):
                            raise ValueError('unsupported escaping path dependency')
                        todo.append(target)
    return result


def validate_lock(raw, catalog, paths):
    packages = lock_packages(raw)
    approved = {(p['name'], p['version'], p.get('source')): p.get('checksum') for p in catalog if 'source' in p}
    for p in packages:
        name, version, source = p['name'], p['version'], p.get('source')
        if source is None:
            if (name, version) not in paths or 'checksum' in p:
                raise ValueError('unsupported source-free package ' + display(name))
            continue
        if source != REGISTRY:
            raise ValueError('unsupported locked package source for ' + display(name))
        key = (name, version, source)
        if key not in approved:
            versions = sorted({v for n, v, s in approved if n == name})
            raise ValueError('locked package outside catalog: ' + display(name) + ' ' + display(version) + '; approved versions: ' + display(', '.join(versions) or 'none') + '; run noxide deps resolve with the same catalog selection (constraints may require a manifest or trusted catalog change)')
        if p.get('checksum') != approved[key]:
            raise ValueError('locked package checksum mismatch for ' + display(name))
    return packages


def summary(old, new):
    try:
        before = {(p['name'], p['version'], p.get('source'), p.get('checksum')) for p in lock_packages(old)}
    except (ValueError, TypeError):
        return 'Comparison unavailable: old lockfile missing or malformed.'
    after = {(p['name'], p['version'], p.get('source'), p.get('checksum')) for p in lock_packages(new)}
    changes = [('removed', p) for p in before - after] + [('added', p) for p in after - before]
    changes.sort(key=lambda item: (item[0], item[1][0], item[1][1]))
    lines = [f'{kind} {display(p[0])} {display(p[1])}' for kind, p in changes[:32]]
    if len(changes) > 32:
        lines.append(f'{len(changes) - 32} further package identity changes omitted')
    return '\n'.join(lines) or 'Package identities unchanged.'


def shell_command(arguments):
    """POSIX shell quoting, with control bytes represented by printf escapes."""
    def quote(argument):
        if any(ord(c) < 32 or ord(c) == 127 for c in argument):
            # Refuse terminal-control paths before staging/publication.
            raise ValueError('command paths must not contain control characters')
        return shlex.quote(argument)
    return ' '.join(quote(str(argument)) for argument in arguments)


def safe_log(raw):
    """Bounded callers retain diagnostics without terminal controls or URLs."""
    def redact(match):
        token = match[0]
        if b'://' not in token:
            return token
        return b'[redacted URL]' if len(token) >= 14 else b'URL'
    raw = re.sub(rb'\S+', redact, raw)
    return bytes(b for b in raw if b in (10, 13) or 32 <= b < 127)
