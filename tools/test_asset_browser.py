#!/usr/bin/env python3
"""NoJS rich-document browser regression with an all-attempt recording proxy.

The fixture must come from assets::document::tests::browser_fixture. This checks
rendered fixture output, not the integrated Application HTTP path.
"""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.parse
from test_browser import ELEMENT, call, port, ready

CSP="default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--geckodriver',default='geckodriver')
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    fixture=json.loads(args.fixtures.read_text())
    routes={a['path']:(a['mime'],bytes(a['bytes'])) for a in fixture['assets']}
    attempts=[]
    authority='noxide-asset-test.invalid'
    class Proxy(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_CONNECT(self):
            attempts.append({'method':'CONNECT','url':self.path,'allowed':False});self.send_error(403)
        def do_GET(self):
            url=urllib.parse.urlsplit(self.path)
            allowed=url.scheme=='http' and url.netloc==authority and not url.query and url.path in ({'/', '/login', '/favicon.ico'} | set(routes))
            attempts.append({'method':'GET','url':self.path,'allowed':allowed})
            if not allowed:self.send_error(403);return
            if url.path=='/':mime,payload='text/html; charset=utf-8',fixture['html'].encode()
            elif url.path=='/login':mime,payload='text/html; charset=utf-8',b'<!doctype html><html><body><p id="host-control">Host login</p></body></html>'
            elif url.path in routes:mime,payload=routes[url.path]
            else:self.send_error(404);return
            self.send_response_only(200);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(payload)));self.send_header('Content-Security-Policy',CSP);self.send_header('X-Content-Type-Options','nosniff');self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(payload)
    proxy=ThreadingHTTPServer(('127.0.0.1',0),Proxy);proxy.daemon_threads=True
    threading.Thread(target=proxy.serve_forever,daemon=True).start()
    endpoint=f'http://127.0.0.1:{port()}'
    session=None
    with (args.output/'browser.log').open('w') as log:
        driver=subprocess.Popen([args.geckodriver,'--host','127.0.0.1','--port',endpoint.rsplit(':',1)[1]],stdout=log,stderr=subprocess.STDOUT,env={**os.environ,'MOZ_REMOTE_SETTINGS_DEVTOOLS':'1'})
        try:
            ready(endpoint+'/status')
            # Firefox Utils.shouldSkipRemoteActivity recognizes this automation
            # dummy URL; the browser still uses the recording proxy for all loads.
            prefs={'javascript.enabled':False,'network.proxy.type':1,'network.proxy.http':'127.0.0.1','network.proxy.http_port':proxy.server_port,'network.proxy.ssl':'127.0.0.1','network.proxy.ssl_port':proxy.server_port,'network.proxy.no_proxies_on':'','network.proxy.allow_hijacking_localhost':True,'network.dns.disablePrefetch':True,'network.prefetch-next':False,'network.captive-portal-service.enabled':False,'network.connectivity-service.enabled':False,'app.update.auto':False,'datareporting.healthreport.uploadEnabled':False,'toolkit.telemetry.enabled':False,'dom.push.enabled':False,'services.settings.server':'data:,#remote-settings-dummy/v1'}
            result=call(endpoint+'/session','POST',{'capabilities':{'alwaysMatch':{'browserName':'firefox','moz:firefoxOptions':{'args':['-headless'],'prefs':prefs}}}})
            session=endpoint+'/session/'+result['sessionId']
            def find(selector):return call(session+'/element','POST',{'using':'css selector','value':selector})[ELEMENT]
            def css(selector,name):return call(session+'/element/'+find(selector)+'/css/'+name)
            call(session+'/url','POST',{'url':f'http://{authority}/'})
            assert call(session+'/elements','POST',{'using':'css selector','value':'script'})==[]
            assert css('#host-control','color')=='rgb(0, 0, 0)'
            assert css('.noxide-app p','color')=='rgb(1, 2, 3)'
            assert call(session+'/element/'+find('img')+'/attribute/alt')=='A red pixel'
            assert call(session+'/element/'+find('nav')+'/attribute/aria-label')=='Example navigation'
            assert len(call(session+'/elements','POST',{'using':'css selector','value':'table caption'}))==1
            call(session+'/element/'+find('summary')+'/click','POST',{})
            assert call(session+'/element/'+find('details')+'/property/open') is True
            # Wait a bounded interval for deferred font/image work, without script.
            until=time.monotonic()+5
            while time.monotonic()<until:
                paths={urllib.parse.urlsplit(a['url']).path for a in attempts if a['allowed']}
                needed={a['path'] for a in fixture['assets']}
                if needed<=paths:break
                time.sleep(.1)
            assert needed<=paths,('missing asset requests',needed-paths)
            before=len(attempts);call(session+'/url','POST',{'url':f'http://{authority}/login'})
            assert css('#host-control','color')=='rgb(0, 0, 0)'
            assert not any('/_noxide/assets/' in a['url'] for a in attempts[before:])
            assert not any('attacker.invalid' in a['url'] for a in attempts)
            assert all(a['allowed'] for a in attempts),('external attempt',attempts)
            (args.output/'result.json').write_text(json.dumps({'browser':result['capabilities']['browserVersion'],'javascript_enabled':False,'attempts':attempts,'scope':'rendered fixture; integrated Application not covered'},indent=2))
            print('NoJS asset fixture: scoped CSS, image/font requests, native details/table/nav and all-attempt proxy checks passed')
        finally:
            (args.output/'attempts.json').write_text(json.dumps(attempts,indent=2))
            if session:
                try:call(session,'DELETE')
                except Exception:pass
            driver.terminate()
            try:driver.wait(timeout=5)
            except subprocess.TimeoutExpired:driver.kill();driver.wait()
            proxy.shutdown();proxy.server_close()

if __name__=='__main__':main()
