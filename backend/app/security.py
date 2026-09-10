import base64,hashlib,hmac,json,os,time
SECRET=os.environ.get('MUSE_SECRET','dev-only-change-me')
def hash_password(p):
 salt=os.urandom(16); dk=hashlib.scrypt(p.encode(),salt=salt,n=2**14,r=8,p=1); return base64.b64encode(salt+dk).decode()
def verify_password(p,h):
 try:
  raw=base64.b64decode(h); got=hashlib.scrypt(p.encode(),salt=raw[:16],n=2**14,r=8,p=1); return hmac.compare_digest(got,raw[16:])
 except Exception:return False
def token(uid):
 p=base64.urlsafe_b64encode(json.dumps({'sub':uid,'exp':int(time.time())+86400}).encode()).decode().rstrip('='); return p+'.'+hmac.new(SECRET.encode(),p.encode(),hashlib.sha256).hexdigest()
def parse_token(t):
 try:
  p,s=t.split('.'); d=json.loads(base64.urlsafe_b64decode(p+'===')); return d['sub'] if d['exp']>=int(time.time()) and hmac.compare_digest(s,hmac.new(SECRET.encode(),p.encode(),hashlib.sha256).hexdigest()) else None
 except Exception:return None
