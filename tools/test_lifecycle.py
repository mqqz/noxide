#!/usr/bin/env python3
"""Exercise the installed CLI with trusted generated sources and local HTTP only."""
import argparse
import http.cookiejar
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent

class RetryBusyGet(urllib.request.BaseHandler):
    """Retry bounded busy GETs, including GETs reached after a successful POST."""
    handler_order = 499  # Run before HTTPDefaultErrorHandler raises HTTPError.
    retries = 5
    delay = 0.2

    def http_error_503(self, request, response, code, message, headers):
        if request.get_method() != 'GET':
            return None
        remaining = getattr(request, '_noxide_busy_retries', self.retries)
        if remaining == 0:
            return None
        request._noxide_busy_retries = remaining - 1
        response.close()
        time.sleep(self.delay)
        return self.parent.open(request, timeout=request.timeout)

class Forms(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.forms = []
        self.current = None
        self.feed(html)
    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == 'form':
            self.current = (attributes.get('action', ''), {})
        if self.current and tag in ('input', 'textarea') and 'name' in attributes:
            self.current[1][attributes['name']] = attributes.get('value', '')
    def handle_endtag(self, tag):
        if tag == 'form' and self.current:
            self.forms.append(self.current)
            self.current = None

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/noxide')
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=False)
    root = options.output.resolve()
    environment = dict(os.environ, XDG_STATE_HOME=str(root / 'state'), CARGO_HOME=str(root / 'empty-cargo'))
    cli = str(options.cli.resolve())
    app = root / 'my-forum'
    subprocess.run([cli, 'new', str(app)], env=environment, check=True)
    expected = json.loads((ROOT / 'examples/private-notes/manifest.json').read_text())
    master, slave = pty.openpty()
    process = subprocess.Popen([cli, 'dev'], cwd=app, env=environment, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    log = bytearray()
    cursor = 0
    def until(token, seconds=180):
        nonlocal cursor
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            found = log.find(token.encode(), cursor)
            if found >= 0:
                cursor = found + len(token)
                return
            if select.select([master], [], [], 0.2)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    chunk = b''
                if not chunk:
                    raise AssertionError('dev exited: ' + log.decode(errors='replace'))
                log.extend(chunk)
            if process.poll() is not None:
                raise AssertionError('dev exited: ' + log.decode(errors='replace'))
        raise AssertionError('timed out waiting for ' + token + ': ' + log.decode(errors='replace'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), RetryBusyGet())
    origin = 'http://localhost:8080'
    def get(path='/'):
        return opener.open(origin + path, timeout=5).read().decode()
    def submit(html, required, values):
        action, fields = next(form for form in Forms(html).forms if required in form[1])
        fields.update(values)
        request = urllib.request.Request(origin + action, data=urllib.parse.urlencode(fields).encode(), headers={'Origin': origin})
        return opener.open(request, timeout=5).read().decode()
    def login():
        return submit(get('/login'), 'username', {'username':'alice', 'password':'trusted fixture password'})
    try:
        until('Type approve:')
        bundle = Path(json.loads((app / 'target/noxide/latest.json').read_text()))
        contract = json.loads((bundle / 'manifest.json').read_text())
        assert contract['resources'] == expected['resources']
        assert len(contract['operations']) == 5
        assert {operation['kind'] for operation in contract['operations']} == {'list', 'read', 'create', 'update', 'delete'}
        assert all(operation['policy'] == {'any': [['owner']]} for operation in contract['operations'])
        assert {route['path'] for route in contract['routes']} == {'/', '/notes/{note}'}
        assert {action['name'] for action in contract['actions']} == {'Create note', 'Edit note', 'Delete note'}
        os.write(master, b'approve\n')
        until('Runtime listening')
        submit(get('/register'), 'username', {'username':'alice', 'password':'trusted fixture password'})
        notes = login()
        assert 'No notes yet' in notes
        shown = submit(notes, 'body', {'body':'Persistent lifecycle note'})
        assert 'Persistent lifecycle note' in shown
        source = app / 'src/lib.rs'
        original = source.read_text()
        previous = (app / 'target/noxide/latest.json').read_bytes()
        source.write_text(original + '\nthis is deliberately invalid Rust\n')
        until('Build failed; serving the previous successful build')
        assert (app / 'target/noxide/latest.json').read_bytes() == previous
        assert 'Persistent lifecycle note' in get('/')
        source.write_text(original.replace('Private notes', 'My private notes'))
        until('Runtime listening')
        assert (app / 'target/noxide/latest.json').read_bytes() != previous
        assert 'Persistent lifecycle note' in login()
        source.write_text(original.replace('max_bytes = 4096', 'max_bytes = 4095'))
        until('Type approve:')
        os.write(master, b'no\n')
        until('contract not approved')
        assert 'Persistent lifecycle note' in get('/')
        source.write_text(original)
    finally:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        os.close(master)
        (root / 'dev.log').write_bytes(log)
    assert process.returncode == 0, process.returncode
    subprocess.run([cli, 'test'], cwd=app, env=environment, check=True)
    subprocess.run([cli, 'build'], cwd=app, env=environment, check=True)
    rejected = subprocess.run([cli, 'serve'], cwd=app, env=environment, stdin=subprocess.DEVNULL, capture_output=True)
    assert rejected.returncode != 0 and b'contract approval requires a terminal' in rejected.stderr
    bundle = Path(json.loads((app / 'target/noxide/latest.json').read_text()))
    digest = subprocess.check_output([cli, 'contract-hash', str(bundle / 'manifest.json')], env=environment, text=True).strip()
    subprocess.run([cli, 'approve', digest], cwd=app, env=environment, check=True)
    with (root / 'serve.log').open('wb') as log_file:
        serving = subprocess.Popen([cli, 'serve'], cwd=app, env=environment, stdout=log_file, stderr=subprocess.STDOUT)
        try:
            # Cold component compilation can exceed 10 seconds on CI runners.
            # Use the same bounded startup allowance as the dev process.
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                if serving.poll() is not None:
                    raise AssertionError(
                        f'serve exited with {serving.returncode}: '
                        + (root / 'serve.log').read_text(errors='replace'))
                try:
                    assert 'Sign in' in get('/login')
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError(
                    'serve did not start within 180 seconds: '
                    + (root / 'serve.log').read_text(errors='replace'))
        finally:
            serving.send_signal(signal.SIGTERM)
            serving.wait(timeout=10)
    assert serving.returncode == 0
    print('Generated-project lifecycle passed, including registration, persistence, rebuild failure, contract rejection, and separate serving approval.')

if __name__ == '__main__':
    main()
