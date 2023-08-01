#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 163 恢复链真实验收：真实 init/serve + SQLite 备份 → 维护状态 →
restore-preflight/apply → 失败注入回退 → 恢复后旧会话失效/审计可读。
临时目录，不修改真实库；不伪造成功。"""
import hashlib
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORK = os.path.join(os.environ.get("TEMP", BASE), "step163-restore")
STATE = os.path.join(os.environ.get("TEMP", BASE), "step163-restore-state")
RESULT = {"steps": [], "ok": True}


def run(args, timeout=300):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def step(name, status, **kw):
    e = {"step": name, "status": status}
    e.update(kw)
    RESULT["steps"].append(e)
    if status == "FAIL":
        RESULT["ok"] = False
    print("STEP", json.dumps(e, ensure_ascii=False)[:700])


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def protected(path):
    user = os.environ.get("USERNAME", "")
    subprocess.run(["icacls", path, "/inheritance:r", "/grant:r",
                    f"{user}:F", "SYSTEM:F", "Administrators:F"], capture_output=True)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def wait_port(port, timeout=45):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket(); s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", port)); return True
        except OSError:
            time.sleep(0.2)
        finally:
            s.close()
    return False


def get(url, cookie=""):
    req = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")[:200], r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:200], e.headers


def main():
    for p in (WORK, STATE, WORK + "-maintenance"):
        if os.path.isdir(p): shutil.rmtree(p)
    os.makedirs(WORK); os.makedirs(STATE)
    exe = os.path.join(WORK, "login-server.exe"); backup_exe = os.path.join(WORK, "login-backup.exe")
    ctl = os.path.join(WORK, "loginctl.exe")
    for name, pkg in (("server", "./cmd/login-server"), ("backup", "./cmd/login-backup"),
                      ("ctl", "./cmd/loginctl")):
        out = exe if name == "server" else backup_exe if name == "backup" else ctl
        code, _, err = run(["go", "build", "-o", out, pkg])
        if code != 0:
            step("build." + name, "FAIL", detail=err[-300:])
            return 1
    step("build", "PASS")
    db = os.path.join(WORK, "login.db"); master = os.path.join(WORK, "master.key")
    cfg = os.path.join(WORK, "login.yaml"); pw = os.path.join(WORK, "pw.txt")
    open(pw, "w").write("V7q!Lm2#Rp9@Kx4$"); protected(pw)
    port = free_port()
    open(cfg, "w", encoding="utf-8").write(f'''server:
  listen_addr: "127.0.0.1:{port}"
  public_base_url: "http://127.0.0.1:{port}"
  shutdown_timeout_seconds: 5
logging: {{level: info, format: text}}
database: {{driver: sqlite, path: "{db.replace(chr(92), '/')}", wal: true, busy_timeout_ms: 5000}}
''')
    code, out, err = run([exe, "init", "--config", cfg, "--master-key-file", master,
                          "--password-file", pw, "--operator", "step163"])
    step("init", "PASS" if code == 0 else "FAIL", detail=(out + err)[-200:])
    if code != 0: return 1
    outdir = os.path.join(WORK, "backups"); os.makedirs(outdir)
    code, out, err = run([backup_exe, "create", "--database", db, "--key-file", master,
                          "--output", outdir, "--operator", "step163", "--json"])
    step("backup.create", "PASS" if code == 0 else "FAIL", detail=err[-160:])
    if code != 0: return 1
    b0 = [os.path.join(outdir, n) for n in os.listdir(outdir) if n.endswith(".elnbak")][0]

    # 真实 serve + root 密码登录创建会话（进入第二因素等待态也算真实会话行）。
    serve = subprocess.Popen([exe, "serve", "--config", cfg, "--master-key-file", master,
                              "--enable-admin-api"], cwd=WORK,
                             stdout=open(os.path.join(WORK, "serve1.log"), "wb"),
                             stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    cookie = ""
    try:
        if not wait_port(port):
            step("serve.before-restore", "FAIL"); return 1
        step("serve.before-restore", "PASS")
        import re, http.cookiejar
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                             urllib.request.HTTPRedirectHandler())
        with opener.open(urllib.request.Request(f"http://127.0.0.1:{port}/login"), timeout=10) as r:
            body = r.read().decode("utf-8", "replace")
        m = re.search(r'name="csrf_token" value="([^"]+)"', body)
        token = m.group(1) if m else ""
        cookie = http.cookiejar.Cookie(version=0, name="ln_page_csrf", value=token, port=None,
                                       port_specified=False, domain="127.0.0.1",
                                       domain_specified=False, domain_initial_dot=False,
                                       path="/", path_specified=True, secure=False, expires=None,
                                       discard=True, comment=None, comment_url=None, rest={},
                                       rfc2109=False)
        jar.set_cookie(cookie)
        data = urllib.parse.urlencode({"csrf_token": token, "identifier": "root",
                                       "password": "V7q!Lm2#Rp9@Kx4$"}).encode()
        try:
            opener.open(urllib.request.Request(f"http://127.0.0.1:{port}/login", data=data,
                method="POST", headers={"Content-Type": "application/x-www-form-urlencoded",
                "Origin": f"http://127.0.0.1:{port}"}), timeout=10)
        except urllib.error.HTTPError:
            pass
        set_cookie = ""
        for c in jar:
            if c.name == "__Host-login_session":
                set_cookie = "__Host-login_session=" + c.value
        m = re.search(r"__Host-login_session=([^;]+)", set_cookie)
        cookie = "__Host-login_session=" + (m.group(1) if m else "")
        con = sqlite3.connect(db)
        n = con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        con.close()
        step("session.created", "PASS" if n > 0 else "FAIL", sessions=n)
    finally:
        if serve.poll() is None:
            try: serve.send_signal(signal.CTRL_BREAK_EVENT); serve.wait(timeout=8)
            except Exception: subprocess.run(["taskkill", "/T", "/F", "/PID", str(serve.pid)], capture_output=True)
    # 含会话的备份 B1
    code, out, err = run([backup_exe, "create", "--database", db, "--key-file", master,
                          "--output", outdir, "--operator", "step163", "--json"])
    files = sorted([os.path.join(outdir, n) for n in os.listdir(outdir) if n.endswith(".elnbak")],
                   key=os.path.getmtime)
    b1 = files[-1]
    step("backup.with-session", "PASS" if code == 0 else "FAIL", files=len(files))

    # 维护/恢复链
    code, out, err = run([ctl, "restore-init-state", "--database", db, "--state-dir", STATE,
                          "--key-file", master, "--backup-output", outdir,
                          "--operator", "step163", "--reason", "restore e2e", "--confirm", "RESTORE"])
    step("restore.init-state", "PASS" if code == 0 else "FAIL", detail=(out + err)[-160:])
    code, out, err = run([ctl, "maintenance-enter", "--database", db, "--state-dir", STATE,
                          "--key-file", master, "--operator", "step163", "--reason", "restore e2e"])
    step("maintenance.enter", "PASS" if code == 0 else "FAIL", detail=(out + err)[-160:])
    hash_before = sha(db)
    code, out, err = run([ctl, "restore-preflight", "--database", db, "--state-dir", STATE,
                          "--key-file", master, "--backup", b1, "--backup-output", outdir,
                          "--operator", "step163", "--json"])
    step("restore.preflight", "PASS" if code == 0 else "FAIL", detail=err[-160:])
    code, out, err = run([ctl, "restore-apply", "--database", db, "--state-dir", STATE,
                          "--key-file", master, "--backup", b1, "--backup-output", outdir,
                          "--operator", "step163", "--reason", "restore e2e",
                          "--confirm", "RESTORE", "--service-stopped", "--json"])
    apply = {}
    try: apply = json.loads(out)
    except Exception: pass
    step("restore.apply", "PASS" if code == 0 and sha(db) != hash_before else "FAIL",
         revoked=apply.get("revoked"), generation=apply.get("generation"),
         maintenance_exited=apply.get("maintenance_exited"), audit_merged=apply.get("audit_merged"))
    con = sqlite3.connect(db)
    try:
        sessions = con.execute("SELECT COUNT(*) FROM sessions WHERE revoked_at_ms IS NULL").fetchone()[0]
        audit = con.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        try:
            reports = con.execute("SELECT COUNT(*) FROM report_history").fetchone()[0]
        except sqlite3.Error:
            reports = -1
    except Exception as exc:
        sessions, audit, reports = -1, -1, -1
    finally:
        con.close()
    step("restore.old-session-absent", "PASS" if sessions == 0 else "FAIL", active_sessions=sessions)
    step("restore.audit-readable", "PASS" if audit >= 0 else "FAIL", audit_events=audit, reports=reports)

    # 恢复后启动真实 serve，旧 Cookie 不得再访问已认证页面；health 可用。
    serve = subprocess.Popen([exe, "serve", "--config", cfg, "--master-key-file", master],
                             cwd=WORK, stdout=open(os.path.join(WORK, "serve2.log"), "wb"),
                             stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        if wait_port(port):
            h, _, _ = get(f"http://127.0.0.1:{port}/healthz")
            home, _, _ = get(f"http://127.0.0.1:{port}/home", cookie)
            step("restore.old-cookie-invalid", "PASS" if home != 200 else "FAIL",
                 health=h, home_status=home)
        else:
            step("restore.post-serve", "FAIL")
    finally:
        if serve.poll() is None:
            try: serve.send_signal(signal.CTRL_BREAK_EVENT); serve.wait(timeout=8)
            except Exception: subprocess.run(["taskkill", "/T", "/F", "/PID", str(serve.pid)], capture_output=True)

    # 失败注入：损坏备份 + 维护状态，DB 不变。
    code, out, err = run([ctl, "maintenance-enter", "--database", db, "--state-dir", STATE,
                          "--key-file", master, "--operator", "step163", "--reason", "fail inject"])
    hash_fail = sha(db)
    tampered = os.path.join(WORK, "tampered.elnbak")
    data = bytearray(open(b1, "rb").read()); data[len(data) // 2] ^= 0xFF
    open(tampered, "wb").write(data)
    code, out, err = run([ctl, "restore-preflight", "--database", db, "--state-dir", STATE,
                          "--key-file", master, "--backup", tampered, "--backup-output", outdir,
                          "--operator", "step163", "--json"])
    step("restore.tampered-rejected", "PASS" if code != 0 else "FAIL", exit=code)
    step("restore.failure-db-unchanged", "PASS" if sha(db) == hash_fail else "FAIL")
    run([ctl, "maintenance-exit", "--database", db, "--state-dir", STATE,
         "--key-file", master, "--operator", "step163", "--reason", "cleanup"])
    return 0 if RESULT["ok"] else 1


if __name__ == "__main__":
    code = 2
    try:
        code = main()
    except Exception as exc:  # noqa: BLE001
        RESULT["ok"] = False; RESULT["error"] = repr(exc)
    ev = os.path.join(BASE, "docs", "acceptance", "evidence", "step163")
    os.makedirs(ev, exist_ok=True)
    with open(os.path.join(ev, "step163-restore-result.json"), "w", encoding="utf-8") as f:
        json.dump(RESULT, f, ensure_ascii=False, indent=2)
    print("STEP163_RESTORE_RESULT", json.dumps(RESULT, ensure_ascii=False)[:1500])
    sys.exit(code)
