#!/usr/bin/env python3
"""HesabYar v4 LAN snapshot server. Trusted private Wi-Fi only."""
import argparse, json, os, tempfile, threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

lock=threading.RLock()

def make_handler(secret, store):
    class Handler(BaseHTTPRequestHandler):
        def reply(self, code, payload):
            b=json.dumps(payload,ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header('Content-Type','application/json; charset=utf-8')
            self.send_header('Content-Length',str(len(b)))
            self.send_header('Cache-Control','no-store')
            self.send_header('Access-Control-Allow-Origin','*')
            self.send_header('Access-Control-Allow-Methods','GET, PUT, OPTIONS')
            self.send_header('Access-Control-Allow-Headers','Content-Type, X-HesabYar-Token')
            self.end_headers();self.wfile.write(b)
        def do_OPTIONS(self): self.reply(200,{'ok':True})
        def authorized(self):
            import hmac
            if not hmac.compare_digest(self.headers.get('X-HesabYar-Token',''),secret):
                self.reply(401,{'error':'رمز شبکه نادرست است'});return False
            return True
        def read_state(self):
            if store.exists(): return json.loads(store.read_text(encoding='utf-8'))
            return {'revision':0,'data':None}
        def do_GET(self):
            if not self.authorized():return
            with lock:
                state=self.read_state()
            path=urlsplit(self.path).path
            if path=='/api/status':self.reply(200,{'revision':state['revision'],'ok':True})
            elif path=='/api/snapshot':self.reply(200,state)
            else:self.reply(404,{'error':'Not found'})
        def do_PUT(self):
            if not self.authorized():return
            if urlsplit(self.path).path!='/api/snapshot':return self.reply(404,{'error':'Not found'})
            try:
                n=int(self.headers.get('Content-Length','0'))
                if n<2 or n>20_000_000: return self.reply(413,{'error':'حجم فایل معتبر نیست (حداکثر ۲۰ MB)'})
                obj=json.loads(self.rfile.read(n))
                d=obj.get('data');revision=obj.get('revision')
                if not isinstance(d,dict) or any(not isinstance(d.get(k),list) for k in ('customers','transactions','transfers','currencies','rates')):return self.reply(400,{'error':'ساختار اطلاعات نادرست است'})
                with lock:
                    old=self.read_state()
                    if type(revision)!=int or revision!=old['revision']:return self.reply(409,{'error':'نسخهٔ سرور تغییر کرده است؛ اول دوباره بررسی کنید'})
                    new={'revision':revision+1,'data':d}
                    store.parent.mkdir(parents=True,exist_ok=True)
                    fd,tmp=tempfile.mkstemp(dir=store.parent,prefix='.hesabyar-')
                    try:
                        with os.fdopen(fd,'w',encoding='utf-8') as f:
                            json.dump(new,f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
                        os.replace(tmp,store)
                    finally:
                        if os.path.exists(tmp):os.unlink(tmp)
                self.reply(200,{'ok':True,'revision':new['revision']})
            except (ValueError,KeyError,TypeError,json.JSONDecodeError):self.reply(400,{'error':'درخواست نادرست است'})
    return Handler

def main():
    a=argparse.ArgumentParser()
    a.add_argument('--host',default='0.0.0.0');a.add_argument('--port',type=int,default=8765)
    a.add_argument('--data',default='hesabyar-lan-data.json')
    args=a.parse_args()
    secret=os.environ.get('HESABYAR_LAN_TOKEN','')
    if len(secret)<16:raise SystemExit('Set HESABYAR_LAN_TOKEN to a random secret of at least 16 characters.')
    server=ThreadingHTTPServer((args.host,args.port),make_handler(secret,Path(args.data)))
    print(f'HesabYar LAN listening on {args.host}:{args.port} (trusted Wi-Fi only)',flush=True)
    server.serve_forever()
if __name__=='__main__':main()
