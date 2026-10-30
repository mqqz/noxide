#!/usr/bin/env python3
"""Check lifecycle GET retries against a local server without replaying POSTs."""
import http.cookiejar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
import urllib.error
import urllib.request

from test_lifecycle import RetryBusyGet


class LifecycleHttpTests(unittest.TestCase):
    def setUp(self):
        self.gets = 0
        self.posts = 0
        self.busy = 0
        self.get_status = 200
        self.post_status = 303
        self.cookies = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                fixture.gets += 1
                fixture.cookies.append(self.headers.get('Cookie'))
                status = 503 if fixture.gets <= fixture.busy else fixture.get_status
                body = b'page'
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                fixture.posts += 1
                self.rfile.read(int(self.headers.get('Content-Length', '0')))
                self.send_response(fixture.post_status)
                self.send_header('Content-Length', '0')
                if fixture.post_status == 303:
                    self.send_header('Location', '/notes')
                    self.send_header('Set-Cookie', 'session=fixture; Path=/')
                self.end_headers()

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f'http://127.0.0.1:{self.server.server_port}'
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            RetryBusyGet(),
        )

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())

    def test_busy_redirect_retries_only_get_and_preserves_session(self):
        self.busy = 2
        request = urllib.request.Request(self.origin + '/login', data=b'fixture')
        with self.opener.open(request, timeout=5) as response:
            self.assertEqual(response.read(), b'page')
        self.assertEqual(self.posts, 1)
        self.assertEqual(self.gets, 3)
        self.assertEqual(self.cookies, ['session=fixture'] * 3)

    def test_busy_post_fails_without_retry(self):
        self.post_status = 503
        request = urllib.request.Request(self.origin + '/login', data=b'fixture')
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(request, timeout=5)
        error.exception.close()
        self.assertEqual(error.exception.code, 503)
        self.assertEqual(self.posts, 1)
        self.assertEqual(self.gets, 0)

    def test_persistent_busy_get_exhausts_bound(self):
        self.get_status = 503
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(self.origin + '/notes', timeout=5)
        error.exception.close()
        self.assertEqual(error.exception.code, 503)
        self.assertEqual(self.gets, RetryBusyGet.retries + 1)

    def test_other_get_failures_are_not_retried(self):
        self.get_status = 500
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(self.origin + '/notes', timeout=5)
        error.exception.close()
        self.assertEqual(error.exception.code, 500)
        self.assertEqual(self.gets, 1)


if __name__ == '__main__':
    unittest.main()
