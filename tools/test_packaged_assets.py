#!/usr/bin/env python3
"""Actual packaged-component NoJS asset proof with deny-all recording proxy.

Requires the trusted public-articles bundle built by the selected CLI executor.
No browser or application request is permitted outside the local test origin.
"""
import argparse
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.parse
from test_browser import ELEMENT,call,port,ready

class Links(HTMLParser):
    def __init__(self):super().__init__();self.styles=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='link' and a.get('rel')=='stylesheet':self.styles.append(a['href'])

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle',type=Path,required=True);p.add_argument('--cli',type=Path,required=True)
    p.add_argument('--geckodriver',default='geckodriver');p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    bundle=args.bundle.resolve();cli=args.cli.resolve();m=json.loads((bundle/'manifest.json').read_text());assert len(m['assets'])==3
    backend=port();authority=f'localhost:{backend}';origin='http://'+authority
    config={'database':{'sqlite':'assets.db'},'keys':'keys.json','component':str(bundle/'public_articles.component.wasm'),'manifest':str(bundle/'manifest.json'),'assets':str((args.output/'served.pack').resolve()),'approved_contract':subprocess.check_output([cli,'contract-hash',bundle/'manifest.json'],text=True).strip(),'origin':origin,'listen':{'tcp':f'127.0.0.1:{backend}'},'registration':'open'}
    (args.output/'served.pack').write_bytes((bundle/'assets.pack').read_bytes())
    path=args.output/'runtime.json';path.write_text(json.dumps(config))
    subprocess.run([cli,'init',path],check=True,capture_output=True)
    subprocess.run([cli,'schema','indexes',path],check=True,capture_output=True)
    password=args.output/'password';password.write_text('Explicit asset regression password');password.chmod(0o600)
    subprocess.run([cli,'account',path,'proof',password],check=True,capture_output=True);password.unlink()
    # Startup independently rejects post-build tampering, substituted declarations,
    # omitted packs and wrong media before any listener is created.
    bad_pack=args.output/'tampered.pack';data=bytearray((bundle/'assets.pack').read_bytes());data[-1]^=1;bad_pack.write_bytes(data)
    negatives=[]
    for kind in ['pack-tamper','missing-pack','digest','media','name']:
        forged=dict(config)
        if kind=='pack-tamper':forged['assets']=str(bad_pack.resolve())
        elif kind=='missing-pack':forged.pop('assets')
        else:
            changed=json.loads(json.dumps(m))
            if kind=='digest':changed['assets'][0]['digest']='0'*64
            elif kind=='media':changed['assets'][0]['media_type']='png'
            else:changed['assets'][0]['name']='../private'
            file=args.output/(kind+'.json');file.write_text(json.dumps(changed));forged['manifest']=str(file.resolve())
        file=args.output/(kind+'-runtime.json');file.write_text(json.dumps(forged))
        result=subprocess.run([cli,'validate',file],capture_output=True,timeout=20)
        assert result.returncode!=0,kind
        negatives.append({'case':kind,'exit':result.returncode,'stderr':result.stderr.decode(errors='replace')})
    (args.output/'startup-negatives.json').write_text(json.dumps(negatives,indent=2))
    attempts=[];allowed={'/','/assets_demo','/assets_preview','/login','/register','/account','/logout','/favicon.ico'}
    def backend_get(resource):
        c=http.client.HTTPConnection('127.0.0.1',backend,timeout=10);c.request('GET',resource,headers={'Host':authority});r=c.getresponse();data=r.read(4*1024*1024+1);assert len(data)<=4*1024*1024;headers={k.lower():v for k,v in r.getheaders()};status=r.status;c.close();return status,headers,data
    class Proxy(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_CONNECT(self):attempts.append({'method':'CONNECT','url':self.path,'allowed':False});self.send_error(403)
        def forward(self):
            u=urllib.parse.urlsplit(self.path);ok=u.scheme=='http' and u.netloc==authority and not u.query and u.path in allowed
            record={'method':self.command,'url':self.path,'allowed':ok};attempts.append(record)
            if not ok:self.send_error(403);return
            size=int(self.headers.get('Content-Length','0'));assert size<=65536
            headers={k:v for k,v in self.headers.items() if k.lower() not in ('host','connection','proxy-connection')};headers['Host']=authority
            c=http.client.HTTPConnection('127.0.0.1',backend,timeout=10)
            try:
                c.request(self.command,u.path,self.rfile.read(size) if size else None,headers);r=c.getresponse();payload=r.read(4*1024*1024+1);assert len(payload)<=4*1024*1024
                assert r.getheader('Date') is None and r.getheader('Server') is None
                record.update(status=r.status,mime=r.getheader('Content-Type'),bytes=len(payload))
                self.send_response_only(r.status)
                for k,v in r.getheaders():
                    if k.lower() not in ('connection','transfer-encoding','content-length'):self.send_header(k,v)
                self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
            finally:c.close()
        do_GET=forward;do_POST=forward
    proxy=ThreadingHTTPServer(('127.0.0.1',0),Proxy);proxy.daemon_threads=True
    threading.Thread(target=proxy.serve_forever,daemon=True).start()
    endpoint=f'http://127.0.0.1:{port()}';session=None
    with (args.output/'server.log').open('w') as server_log,(args.output/'browser.log').open('w') as browser_log:
        server=subprocess.Popen([cli,'serve',path],stdout=server_log,stderr=subprocess.STDOUT)
        driver=subprocess.Popen([args.geckodriver,'--host','127.0.0.1','--port',endpoint.rsplit(':',1)[1]],stdout=browser_log,stderr=subprocess.STDOUT,env={**os.environ,'MOZ_REMOTE_SETTINGS_DEVTOOLS':'1'})
        try:
            ready(origin+'/assets_demo');ready(endpoint+'/status')
            status,headers,html=backend_get('/assets_demo');assert status==200
            links=Links();links.feed(html.decode());assert len(links.styles)==1
            expected=set(links.styles)|{'/_noxide/assets/'+a['digest'] for a in m['assets'] if a['media_type']!='css'};allowed.update(expected)
            for resource in expected:
                status,h,data=backend_get(resource);assert status==200
                assert h.get('cache-control')=='no-store' and h.get('x-content-type-options')=='nosniff'
                assert 'etag' not in h and 'last-modified' not in h
                assert hashlib.sha256(data).hexdigest()==resource.rsplit('/',1)[1]
                assert "img-src 'self'" in h['content-security-policy'] and "font-src 'self'" in h['content-security-policy']
            immutable_path=links.styles[0];immutable_bytes=backend_get(immutable_path)[2]
            modified=bytearray((args.output/'served.pack').read_bytes());modified[-1]^=1;(args.output/'served.pack').write_bytes(modified)
            assert backend_get(immutable_path)[2]==immutable_bytes
            rejected=subprocess.run([cli,'validate',path],capture_output=True,timeout=20);assert rejected.returncode!=0
            for alias in [next(iter(expected))+'?x=1',next(iter(expected))+'/',next(iter(expected)).upper(),next(iter(expected)).replace('/_noxide','/%5fnoxide'), '/_noxide/assets/'+next(a['digest'] for a in m['assets'] if a['media_type']=='css')]:assert backend_get(alias)[0]==404,alias
            prefs={'javascript.enabled':False,'network.proxy.type':1,'network.proxy.http':'127.0.0.1','network.proxy.http_port':proxy.server_port,'network.proxy.ssl':'127.0.0.1','network.proxy.ssl_port':proxy.server_port,'network.proxy.no_proxies_on':'','network.proxy.allow_hijacking_localhost':True,'network.dns.disablePrefetch':True,'network.prefetch-next':False,'network.captive-portal-service.enabled':False,'network.connectivity-service.enabled':False,'app.update.auto':False,'datareporting.healthreport.uploadEnabled':False,'toolkit.telemetry.enabled':False,'dom.push.enabled':False,'services.settings.server':'data:,#remote-settings-dummy/v1'}
            browser=call(endpoint+'/session','POST',{'capabilities':{'alwaysMatch':{'browserName':'firefox','moz:firefoxOptions':{'args':['-headless'],'prefs':prefs}}}});session=endpoint+'/session/'+browser['sessionId']
            def find(selector):return call(session+'/element','POST',{'using':'css selector','value':selector})[ELEMENT]
            def css(selector,name):return call(session+'/element/'+find(selector)+'/css/'+name)
            def navigate(resource):call(session+'/url','POST',{'url':origin+resource})
            navigate('/assets_demo')
            assert not call(session+'/elements','POST',{'using':'css selector','value':'script'})
            assert css('.noxide-app p','color')=='rgb(12, 34, 56)'
            assert call(session+'/element/'+find('img')+'/attribute/alt')=='An original blue and gold tile'
            assert call(session+'/element/'+find('img')+'/property/naturalWidth')==8
            assert call(session+'/element/'+find('nav')+'/attribute/aria-label')=='Local assets'
            assert len(call(session+'/elements','POST',{'using':'css selector','value':'table caption'}))==1
            call(session+'/element/'+find('summary')+'/click','POST',{});assert call(session+'/element/'+find('details')+'/property/open') is True
            until=time.monotonic()+5
            while time.monotonic()<until:
                loaded={urllib.parse.urlsplit(a['url']).path for a in attempts if a['allowed']}
                if expected<=loaded:break
                time.sleep(.1)
            assert expected<=loaded,expected-loaded
            before=len(attempts);navigate('/register')
            assert not call(session+'/elements','POST',{'using':'css selector','value':'link[rel=stylesheet]'})
            assert not any('/_noxide/assets/' in a['url'] for a in attempts[before:])
            before=len(attempts);navigate('/login')
            assert not call(session+'/elements','POST',{'using':'css selector','value':'link[rel=stylesheet]'})
            assert not any('/_noxide/assets/' in a['url'] for a in attempts[before:])
            call(session+'/element/'+find('input[name=username]')+'/value','POST',{'text':'proof','value':list('proof')})
            value='Explicit asset regression password';call(session+'/element/'+find('input[name=password]')+'/value','POST',{'text':value,'value':list(value)})
            call(session+'/element/'+find('button')+'/click','POST',{})
            navigate('/assets_preview');assert css('.noxide-app a','color')=='rgb(12, 34, 56)'
            assert css('nav[aria-label=Account] a','color')!='rgb(12, 34, 56)'
            before=len(attempts);navigate('/account')
            assert not call(session+'/elements','POST',{'using':'css selector','value':'link[rel=stylesheet]'})
            assert not any('/_noxide/assets/' in a['url'] for a in attempts[before:])
            assert all(a['allowed'] for a in attempts),attempts
            result={'browser':browser['capabilities']['browserVersion'],'javascript_enabled':False,'expected_assets':sorted(expected),'attempts':attempts,'startup_negatives':len(negatives),'post_activation_bytes_immutable':True,'wire_version':m['version'],'scope':'actual packaged component and Application HTTP'}
            (args.output/'result.json').write_text(json.dumps(result,indent=2));print('Packaged NoJS assets: local CSS/PNG/WOFF2, native UI, host style exclusion, tampering and all-attempt checks passed')
        finally:
            (args.output/'attempts.json').write_text(json.dumps(attempts,indent=2))
            if session:
                try:call(session,'DELETE')
                except Exception:pass
            for child in [driver,server]:
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait()
            proxy.shutdown();proxy.server_close()
if __name__=='__main__':main()
