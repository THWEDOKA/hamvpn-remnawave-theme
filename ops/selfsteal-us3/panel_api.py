# Root-only operational API adapter. Secrets remain inside the panel host.
# Uses a ten-minute session of the existing administrator; no persistent token.
def create_client():
    import subprocess,json,urllib.request,urllib.error,time,base64,hmac,hashlib
    def inspect(name):
     return json.loads(subprocess.check_output(["docker","inspect",name]))[0]
    db=inspect("remnawave-db")
    dbenv=dict(x.split("=",1) for x in db["Config"]["Env"] if "=" in x)
    def query(sql):
     r=subprocess.run(["docker","exec","-i","remnawave-db","psql","-U",dbenv.get("POSTGRES_USER","postgres"),"-d",dbenv.get("POSTGRES_DB","postgres"),"-Atq","-v","ON_ERROR_STOP=1"],input="BEGIN READ ONLY; SET LOCAL statement_timeout=10000; "+sql+"; ROLLBACK;",text=True,capture_output=True,check=True)
     return json.loads(r.stdout)
    app=inspect("remnawave")
    env=dict(x.split("=",1) for x in app["Config"]["Env"] if "=" in x)
    admin=query("SELECT row_to_json(a) FROM (SELECT uuid, username, role FROM admin WHERE role='ADMIN' LIMIT 1) a")
    def b64(x): return base64.urlsafe_b64encode(x).decode().rstrip("=")
    head=b64(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    payload=b64(json.dumps(dict(admin,iat=int(time.time()),exp=int(time.time())+600)).encode())
    signed=head+"."+payload
    secret=env.get("APP_SECRET") or env["JWT_AUTH_SECRET"]
    token=signed+"."+b64(hmac.new(secret.encode(),signed.encode(),hashlib.sha256).digest())
    addr=next(x["IPAddress"] for x in app["NetworkSettings"]["Networks"].values() if x.get("IPAddress"))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def api(method,path,body=None):
     req=urllib.request.Request("http://"+addr+":"+env.get("APP_PORT","3000")+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={"Authorization":"Bearer "+token,"Content-Type":"application/json","X-Remnawave-Client-Type":"browser","X-Forwarded-Proto":"https","X-Forwarded-For":"127.0.0.1"})
     try:
      with opener.open(req,timeout=30) as r:
       data=r.read()
       j=json.loads(data) if data else {}
       return j.get("response",j)
     except urllib.error.HTTPError as e:
      raise RuntimeError("API "+method+" "+path+" HTTP "+str(e.code)) from None
    return api, query
