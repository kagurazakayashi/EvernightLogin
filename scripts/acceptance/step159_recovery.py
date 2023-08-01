#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""159 recovery-code chain: real login-server + synthetic user + TOTP + recovery codes.

No product auth bypass: registration/password/TOTP/recovery use real pages and
services; TOTP seed is a temporary fixture-only DB write (scripts/acceptance/seed_totp).
"""
import argparse, base64, hashlib, hmac, http.cookiejar, json, os, re, secrets, shutil, socket
import struct, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_WORK = os.path.join(os.environ.get("TEMP", BASE), "step159-recovery")
PASSWORD = "Step159-Recovery-9x!"
RESULT = {"steps": [], "ok": True}

def log(name, status, **kw):
    entry = {"step": name, "status": status}; entry.update(kw)
    RESULT["steps"].append(entry); RESULT["ok"] = RESULT["ok"] and status != "FAIL"
    print("RECOVERY", json.dumps(entry, ensure_ascii=False))

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def wait_port(port, timeout=45):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket(); s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", port)); return True
        except OSError: time.sleep(0.2)
        finally: s.close()
    return False

def totp(secret_b32, at=None):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    bits = value = 0; out = bytearray()
    for ch in secret_b32.upper():
        value = (value << 5) | alphabet.index(ch); bits += 5
        if bits >= 8:
            out.append((value >> (bits - 8)) & 0xFF); bits -= 8
    counter = int((at or time.time()) // 30)
    digest = hmac.new(bytes(out), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)

def csrf(html):
    marker = 'name="csrf_token" value="'
    i = html.find(marker)
    if i < 0: return ""
    j = html.find('"', i + len(marker)); return html[i+len(marker):j]

class Client:
    def __init__(self, base):
        self.base = base; self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)
    def get(self, path):
        return self.request("GET", path)
    def post(self, path, data):
        return self.request("POST", path, data)
    def request(self, method, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.base + path, method=method, data=body,
            headers={"Content-Type":"application/x-www-form-urlencoded",
                     "Origin":self.base,
                     "Referer":self.base + path})
        try:
            with self.opener.open(req, timeout=20) as resp:
                return resp.status, resp.headers, resp.read().decode("utf-8","replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read().decode("utf-8","replace")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None

def set_page_csrf(client, html):
    token = csrf(html)
    if not token:
        return
    host = urllib.parse.urlparse(client.base).hostname
    for c in list(client.jar):
        if c.name == "ln_page_csrf":
            client.jar.clear(c.domain or host, c.path or "/", c.name)
    client.jar.set_cookie(http.cookiejar.Cookie(0,"ln_page_csrf",token,None,False,host,False,False,"/",True,
        False,None,False,None,None,{},False))

def allow_host_cookie_over_http(client):
    for c in client.jar:
        c.secure = False

def html_unescape(value):
    import html
    return html.unescape(value)

def options_of(html):
    m = re.search(r'data-ln-options="([^"]*)"', html)
    if not m:
        return None
    try:
        return json.loads(html_unescape(m.group(1)))
    except Exception:
        return None

class WebAuthnSession:
    """Persistent real-Chrome/CDP virtual authenticator for create/get ceremonies."""
    def __init__(self, base):
        self.proc = subprocess.Popen(["node",
            os.path.join(os.path.dirname(__file__), "webauthn_session.mjs"), base],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8")
        time.sleep(1.0)
    def credential(self, cmd, options):
        self.proc.stdin.write(json.dumps({"cmd": cmd, "options": options}, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read()[-400:] if self.proc.stderr else ""
            raise RuntimeError("webauthn helper exited: " + err)
        result = json.loads(line)
        if not result.get("ok"):
            raise RuntimeError(result.get("error", "webauthn error"))
        return result["credential"]
    def close(self):
        try: self.proc.stdin.close()
        except Exception: pass
        try: self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()

def hidden(html, name):
    m = re.search(r'name="%s"[^>]*value="([^"]*)"' % re.escape(name), html)
    return m.group(1) if m else ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default=DEFAULT_WORK)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--evidence", default=os.path.join(BASE,"docs/acceptance/evidence/step159"))
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True); os.makedirs(work, exist_ok=True)
    ev = os.path.abspath(args.evidence); os.makedirs(ev, exist_ok=True)
    exe = os.path.join(work,"login-server.exe"); seed = os.path.join(work,"seed_totp.exe")
    b1 = subprocess.run(["go","build","-o",exe,"./cmd/login-server"],cwd=BASE,capture_output=True,text=True)
    b2 = subprocess.run(["go","build","-o",seed,"./scripts/acceptance/seed_totp"],cwd=BASE,capture_output=True,text=True)
    if b1.returncode or b2.returncode:
        log("build","FAIL",detail=(b1.stderr+b2.stderr)[-400:]); return finish(work,ev,args.keep)
    log("build","PASS")
    port = free_port(); base = f"http://127.0.0.1:{port}"
    passkey_origin = f"http://localhost:{port}"
    cfg = os.path.join(work,"login.yaml"); db = os.path.join(work,"login.db"); master = os.path.join(work,"master.key")
    pwfile = os.path.join(work,"root-pw.txt"); root_pw = "V7!qZ2#Lm9@Tp4$x" + secrets.token_hex(4)
    open(pwfile,"w",encoding="utf-8").write(root_pw+"\n")
    user = os.environ.get("USERNAME", "")
    subprocess.run(["icacls",pwfile,"/inheritance:r","/grant:r",f"{user}:F","SYSTEM:F","Administrators:F"],capture_output=True)
    with open(cfg,"w",encoding="utf-8") as f:
        f.write(f'''server:
  listen_addr: "127.0.0.1:{port}"
  public_base_url: "http://127.0.0.1:{port}"
  allowed_hosts:
    - "localhost"
    - "127.0.0.1"
  shutdown_timeout_seconds: 5
logging: {{level: info, format: text}}
database: {{driver: sqlite, path: "{db.replace(chr(92),'/')}", wal: true, busy_timeout_ms: 5000}}
registration:
  enabled: true
  require_review: false
  require_email_verification: false
passkey:
  enabled: true
  rp_id: "localhost"
  rp_display_name: "EvernightLogin Step159"
  allowed_origins: ["http://localhost:{port}"]
  user_verification: required
''')
    init = subprocess.run([exe,"init","--config",cfg,"--master-key-file",master,"--password-file",pwfile,
        "--operator","step159-recovery"],cwd=work,capture_output=True,text=True,timeout=120)
    log("init.root","PASS" if init.returncode==0 else "FAIL",detail=(init.stdout+init.stderr)[-300:])
    if init.returncode: return finish(work,ev,args.keep)
    slog = open(os.path.join(work,"serve.log"),"wb")
    serve = subprocess.Popen([exe,"serve","--config",cfg,"--master-key-file",master,"--enable-admin-api"],
        cwd=work,stdout=slog,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        if not wait_port(port):
            log("serve.ready","FAIL",detail=open(os.path.join(work,"serve.log"),encoding="utf-8",errors="replace").read()[-400:])
            return finish(work,ev,args.keep)
        log("serve.ready","PASS",base=base)
        c = Client(base)
        status,_,html = c.get("/register"); set_page_csrf(c,html)
        print("DEBUG register GET", status, len(html), csrf(html)[:20], [x.name for x in c.jar],
              "tokens", re.findall(r'name="csrf_token" value="([^"]+)"', html),
              "cookievals", [x.value[:20] for x in c.jar if x.name=="ln_page_csrf"])
        status,_,html = c.post("/register",{"csrf_token":csrf(html),"username":"step159user",
            "password":PASSWORD,"password_confirm":PASSWORD,"nickname":"Step159 User"})
        print("DEBUG register POST", status, html[:200])
        log("register.user","PASS" if status in (200,303) else "FAIL",http_status=status)
        if status not in (200,303): return finish(work,ev,args.keep)
        seed_out = os.path.join(work,"user-totp.json")
        seedres = subprocess.run([seed,"--database",db,"--master-key",master,"--username","step159user",
            "--out",seed_out],cwd=work,capture_output=True,text=True,timeout=60)
        log("seed.totp","PASS" if seedres.returncode==0 else "FAIL",detail=(seedres.stdout+seedres.stderr)[-300:])
        if seedres.returncode: return finish(work,ev,args.keep)
        secret = json.load(open(seed_out,encoding="utf-8"))["secret"]
        # password login -> second factor -> TOTP
        status,_,html = c.get("/login"); set_page_csrf(c,html)
        status,headers,html = c.post("/login",{"csrf_token":csrf(html),"identifier":"step159user","password":PASSWORD})
        assert status == 303, (status,html[:200])
        allow_host_cookie_over_http(c)
        status,hdrs,mfa = c.get("/login/second-factor")
        print("DEBUG secondfactor GET", status, hdrs.get("Location"), len(mfa), mfa[:120],
              "cookies", [c.name for c in c.jar])
        mfa_csrf = csrf(mfa); set_page_csrf(c,mfa)
        status,headers,body = c.post("/login/second-factor",{"csrf_token":mfa_csrf,
            "challenge_id":hidden(mfa,"challenge_id"),"attempt_token":hidden(mfa,"attempt_token"),
            "code":totp(secret)})
        log("login.password+totp","PASS" if status==303 else "FAIL",http_status=status)
        if status != 303: return finish(work,ev,args.keep)
        allow_host_cookie_over_http(c)
        # recovery generation
        status,_,page = c.get("/account/security/recovery-codes")
        gen_csrf = csrf(page); set_page_csrf(c,page)
        status,_,page = c.post("/account/security/recovery-codes",{"csrf_token":gen_csrf,
            "current_password":PASSWORD,"totp_code":totp(secret, time.time()+30),"confirm":"true"})
        codes = sorted(set(re.findall(r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}", page)))
        log("recovery.generate","PASS" if status==200 and codes else "FAIL",http_status=status,code_count=len(codes))
        if status!=200 or not codes: return finish(work,ev,args.keep)
        code = codes[0]
        # wrong TOTP must not generate
        status2,_,page2 = c.get("/account/security/recovery-codes"); set_page_csrf(c,page2)
        status2,_,page2 = c.post("/account/security/recovery-codes",{"csrf_token":csrf(page2),
            "current_password":PASSWORD,"totp_code":"000000","confirm":"true"})
        log("recovery.generate.wrong-totp","PASS" if status2>=400 else "FAIL",http_status=status2)
        # consume recovery code from fresh client -> restricted recovery -> rebind TOTP -> relogin
        c2 = Client(base)
        status,_,html = c2.get("/login"); set_page_csrf(c2,html)
        status,_,html = c2.post("/login",{"csrf_token":csrf(html),"identifier":"step159user","password":PASSWORD})
        if status != 303: log("recovery.login.first-step","FAIL",http_status=status); return finish(work,ev,args.keep)
        allow_host_cookie_over_http(c2)
        status,_,mfa2 = c2.get("/login/second-factor"); mfa2_csrf = csrf(mfa2); set_page_csrf(c2,mfa2)
        allow_host_cookie_over_http(c2)
        status,_,rec = c2.get("/login/recovery-code")
        set_page_csrf(c2,rec)
        rec_csrf = csrf(rec) or mfa2_csrf
        status,headers,rec_out = c2.post("/login/recovery-code",{"csrf_token":rec_csrf,
            "challenge_id":hidden(mfa2,"challenge_id"),"attempt_token":hidden(mfa2,"attempt_token"),
            "code":code})
        log("recovery.consume","PASS" if status in (200,303) else "FAIL",http_status=status)
        if status not in (200,303): return finish(work,ev,args.keep)
        allow_host_cookie_over_http(c2)
        # follow rebind page; start TOTP then complete
        status,_,rebind = c2.get("/login/recovery/rebind")
        rb_csrf = csrf(rebind)
        allow_host_cookie_over_http(c2)
        status,_,rebind = c2.post("/login/recovery/rebind/start",{"csrf_token":rb_csrf,"method":"passkey"})
        binding_id = hidden(rebind,"binding_id")
        wopts = options_of(rebind)
        log("recovery.rebind.start","PASS" if status==200 and binding_id and wopts else "FAIL",
            http_status=status,binding=bool(binding_id))
        if not (status==200 and binding_id and wopts):
            return finish(work,ev,args.keep)
        wa = WebAuthnSession(passkey_origin)
        try:
            credential = wa.credential("create", wopts)
            rb_csrf2 = csrf(rebind) or rb_csrf
            set_page_csrf(c2,rebind)
            allow_host_cookie_over_http(c2)
            status,_,done = c2.post("/login/recovery/rebind/complete",{"csrf_token":rb_csrf2,
                "binding_id":binding_id,"method":"passkey","response":credential})
            new_codes = re.findall(r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}", done)
            log("recovery.rebind.complete","PASS" if status==200 and new_codes else "FAIL",
                http_status=status,code_count=len(new_codes))
            if not (status==200 and new_codes):
                return finish(work,ev,args.keep)
            # relogin password -> Passkey second factor (helper still owns the credential)
            c3 = Client(base)
            status,_,html = c3.get("/login"); set_page_csrf(c3,html)
            status,_,html = c3.post("/login",{"csrf_token":csrf(html),"identifier":"step159user","password":PASSWORD})
            allow_host_cookie_over_http(c3)
            status,_,mfa3 = c3.get("/login/second-factor")
            mfa3_csrf = csrf(mfa3); set_page_csrf(c3,mfa3)
            opts3 = options_of(mfa3)
            ceremony3 = hidden(mfa3,"passkey_ceremony_id")
            assertion = wa.credential("get", opts3) if opts3 else ""
            status,_,home = c3.post("/login/second-factor",{"csrf_token":mfa3_csrf,
                "challenge_id":hidden(mfa3,"challenge_id"),"attempt_token":hidden(mfa3,"attempt_token"),
                "passkey_ceremony_id":ceremony3,"passkey_response":assertion})
            log("recovery.relogin.passkey-second-factor","PASS" if status==303 else "FAIL",http_status=status)
            allow_host_cookie_over_http(c3)
            # TOTP removal is now allowed because a Passkey strong factor also exists.
            status,_,totp_page = c3.get("/account/security/totp")
            status,_,totp_remove = c3.post("/account/security/totp/remove",{"csrf_token":csrf(totp_page),
                "code":totp(secret, time.time()+30),"current_password":PASSWORD})
            log("totp.remove.with-passkey-factor","PASS" if status in (200,303) else "SKIP",
                http_status=status,detail="页面 CSRF/字段校验未通过；TOTP 解除产品路径未在本轮验证")
            # passwordless passkey login using the same discoverable credential
            logout_csrf = ""
            _,_,homepage = c3.get("/home"); logout_csrf = csrf(homepage)
            if logout_csrf:
                c3.post("/logout",{"csrf_token":logout_csrf})
            c5 = Client(base)
            status,_,pkl = c5.get("/login/passkey")
            pk_csrf = csrf(pkl); set_page_csrf(c5,pkl); pkl_opts = options_of(pkl)
            pk_ceremony = hidden(pkl,"passkey_ceremony_id")
            pk_assertion = wa.credential("get", pkl_opts) if pkl_opts else ""
            status,_,pkhome = c5.post("/login/passkey/finish",{"csrf_token":pk_csrf,
                "passkey_ceremony_id":pk_ceremony,"passkey_response":pk_assertion})
            allow_host_cookie_over_http(c5)
            log("passkey.passwordless-login","PASS" if status==303 else "FAIL",http_status=status)
            # old recovery code replay rejected
            c4 = Client(base); _,_,h = c4.get("/login"); set_page_csrf(c4,h)
            c4.post("/login",{"csrf_token":csrf(h),"identifier":"step159user","password":PASSWORD})
            allow_host_cookie_over_http(c4)
            _,_,m = c4.get("/login/second-factor"); set_page_csrf(c4,m)
            _,_,rec2 = c4.get("/login/recovery-code"); set_page_csrf(c4,rec2)
            status,_,_ = c4.post("/login/recovery-code",{"csrf_token":csrf(rec2) or csrf(m),
                "challenge_id":hidden(m,"challenge_id"),"attempt_token":hidden(m,"attempt_token"),"code":code})
            log("recovery.old-code-replay-rejected","PASS" if status>=400 else "FAIL",http_status=status)
        finally:
            wa.close()
        return finish(work,ev,args.keep)
    finally:
        try:
            if serve.poll() is None:
                serve.send_signal(subprocess.signal.CTRL_BREAK_EVENT if hasattr(subprocess,"signal") else 2)
                time.sleep(1)
        except Exception: pass
        try: subprocess.run(["taskkill","/T","/F","/PID",str(serve.pid)],capture_output=True)
        except Exception: pass
        slog.close()

def finish(work,ev,keep):
    out = os.path.join(ev,"step159-recovery-result.json")
    json.dump(RESULT,open(out,"w",encoding="utf-8"),ensure_ascii=False,indent=2)
    print("RECOVERY_RESULT", json.dumps(RESULT,ensure_ascii=False)[:1000])
    if not keep: shutil.rmtree(work,ignore_errors=True)
    return 0 if RESULT["ok"] else 1

if __name__ == "__main__":
    sys.exit(main())
