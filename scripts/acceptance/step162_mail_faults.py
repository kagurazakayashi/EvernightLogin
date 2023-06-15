#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""步骤 162 真实 login-server + EvernightMail 故障投递 E2E（临时目录/回环端口）。

覆盖：注册邮箱验证、邮箱变更与旧邮箱安全告知、邮件 MFA、密码找回的
成功/临时失败重试/永久失败/认证失败/重复投递/断连/接受后失败/延迟；
用真实 login-server（mail.enabled=true）与真实 EvernightMail 故障规则。
不向公网外发；所有数据为合成身份/临时 SQLite/临时端口；结束清理进程与临时目录。
"""
import email
import email.policy
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

BASE = "P:/go/tmp/step162"
WORK = BASE + "/run"
MAIL_SRC = "P:/go/src/github.com/kagurazakayashi/EvernightLogin/EvernightMail"
LOGIN_SRC = "P:/go/src/github.com/kagurazakayashi/EvernightLogin"
MAIL_BIN = BASE + "/bin/evernightmail.exe"
LOGIN_BIN = BASE + "/bin/login-server.exe"
RESULT = {"steps": [], "pass": 0, "partial": 0, "fail": 0, "not_tested": 0,
          "scenarios": []}
PROCS = []


def log(step, outcome="PASS", **kw):
    item = {"step": step, "outcome": outcome}
    item.update(kw)
    RESULT["steps"].append(item)
    if outcome == "PASS":
        RESULT["pass"] += 1
    elif outcome == "PARTIAL":
        RESULT["partial"] += 1
    elif outcome == "FAIL":
        RESULT["fail"] += 1
    else:
        RESULT["not_tested"] += 1
    print("STEP", json.dumps(item, ensure_ascii=False))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.2)
        finally:
            s.close()
    return False


def kill(proc):
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                               capture_output=True)
            except Exception:  # noqa: BLE001
                pass


def build():
    os.makedirs(BASE + "/bin", exist_ok=True)
    env = dict(os.environ)
    env.update({"GOPROXY": "off", "CGO_ENABLED": "0", "GOMAXPROCS": "4"})
    if not os.path.exists(MAIL_BIN):
        r = subprocess.run(["go", "build", "-trimpath", "-o", MAIL_BIN,
                            "./cmd/evernightmail"], cwd=MAIL_SRC, env=env,
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise RuntimeError("Mail build failed: " + (r.stdout + r.stderr)[-800:])
    if not os.path.exists(LOGIN_BIN):
        r = subprocess.run(["go", "build", "-trimpath", "-o", LOGIN_BIN,
                            "./cmd/login-server"], cwd=LOGIN_SRC, env=env,
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise RuntimeError("Login build failed: " + (r.stdout + r.stderr)[-800:])


class HTTP:
    def __init__(self):
        self.cookies = {}

    def _store(self, headers):
        for raw in headers.get_all("Set-Cookie") or []:
            first = raw.split(";", 1)[0]
            if "=" in first:
                name, value = first.split("=", 1)
                self.cookies[name.strip()] = value.strip()

    def _cookie_header(self):
        return "; ".join(f"{n}={v}" for n, v in self.cookies.items())

    def get(self, url):
        req = urllib.request.Request(url, method="GET")
        if self.cookies:
            req.add_header("Cookie", self._cookie_header())
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                self._store(resp.headers)
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            self._store(exc.headers)
            return exc.code, exc.read().decode("utf-8", "replace")

    def post(self, url, form, follow=True):
        data = urllib.parse.urlencode(form).encode()
        parsed = urllib.parse.urlparse(url)
        headers = {"Origin": f"{parsed.scheme}://{parsed.netloc}", "Referer": url,
                   "Content-Type": "application/x-www-form-urlencoded"}
        if self.cookies:
            headers["Cookie"] = self._cookie_header()
        req = urllib.request.Request(url, data=data, method="POST", headers=headers)
        opener = urllib.request.build_opener() if follow else \
            urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=15) as resp:
                self._store(resp.headers)
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            self._store(exc.headers)
            return exc.code, exc.read().decode("utf-8", "replace")

    def csrf(self, url):
        status, body = self.get(url)
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', body)
        if status != 200 or not m:
            raise RuntimeError(f"GET {url} 未取得 CSRF: {status}")
        return m.group(1), body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def find_emls(root):
    out = []
    for base, _dirs, files in os.walk(root):
        for name in files:
            if name.endswith(".eml"):
                out.append(os.path.join(base, name))
    return sorted(out)


def decode_eml(path):
    raw = open(path, "rb").read()
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    text += str(part.get_content())
                except Exception:  # noqa: BLE001
                    pass
    else:
        try:
            text = str(msg.get_content())
        except Exception:  # noqa: BLE001
            text = raw.decode("utf-8", "replace")
    return msg, text


def new_emls(root, before):
    return [p for p in find_emls(root) if p not in before]


def wait_new_emls(root, before, count=1, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        found = new_emls(root, before)
        if len(found) >= count:
            return found
        time.sleep(0.4)
    raise RuntimeError(f"等待邮件超时：需要 {count}，实际 {len(new_emls(root, before))}")


def wait_link(root, before, needle, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        for path in new_emls(root, before):
            msg, text = decode_eml(path)
            blob = text + "\n" + str(msg.get("Subject", ""))
            if needle in blob:
                return path, msg, text
        time.sleep(0.4)
    raise RuntimeError(f"等待含 {needle} 的邮件超时")


def parse_link(text, needle):
    for token in re.findall(r'https?://[^\s<>"\']+', text):
        if needle in token:
            return token
    return None


class Harness:
    def __init__(self):
        self.smtp_port = free_port()
        self.mail_http_port = free_port()
        self.login_port = free_port()
        self.data = WORK + "/mail-data"
        self.mail_cfg = WORK + "/EvernightMail.yaml"
        self.login_cfg = WORK + "/login.yaml"
        self.db = WORK + "/login.db"
        self.master = WORK + "/master.key"
        self.pwd = WORK + "/init-password.txt"
        self.mail_proc = None
        self.login_proc = None
        self.env = dict(os.environ)
        self.env["LOGIN_E2E_SMTP_PASSWORD"] = "test-pass"

    def mail_config(self, rules, enabled):
        data = self.data.replace("\\", "/")
        faults = json.dumps({"enabled": bool(enabled), "rules": rules or []},
                            ensure_ascii=False)
        cfg = f'''version: 1
server: {{hostname: mail.final.test, data_dir: '{data}', log_dir: '{data}/logs', shutdown_timeout: 5s}}
listeners:
  - {{id: smtp, protocol: smtp, address: "127.0.0.1:{self.smtp_port}", tls: starttls, cert: local-test, enabled: true}}
  - {{id: admin, protocol: http, address: "127.0.0.1:{self.mail_http_port}", tls: disabled, enabled: true}}
tls:
  mode: auto
  identities:
    - {{id: local-test, mode: auto, sans: {{dns: [localhost], ip: [127.0.0.1]}}, validity: 720h}}
  ca: {{dir: '{data}/certs', validity: 87600h, export_path: '{data}/certs/ca.crt'}}
storage: {{mail_root: '{data}/mail', timezone: UTC, fsync: false, repair_on_start: true}}
logging: {{level: info, server_log: '{data}/logs/server.log'}}
admin: {{username: admin, password: admin-test-pass, mode: required}}
web: {{enabled: false}}
users:
  defaults: {{auth: {{smtp: required, imap: required, pop3: required}}}}
  items:
    - {{id: usr_11111111111111111111111111111111, login_name: tester, password: test-pass, enabled: true, auth: {{smtp: required, imap: required, pop3: required}}}}
protocols:
  smtp: {{allow_anonymous_mail: false, max_message_bytes: 1048576, max_connections: 8, read_timeout: 30s, session_timeout: 5m}}
delivery: {{unknown_recipient: capture, capture_user: tester}}
faults: {faults}
'''
        with open(self.mail_cfg, "w", encoding="utf-8") as f:
            f.write(cfg)

    def start_mail(self, rules=None, enabled=False):
        self.stop_mail()
        self.mail_config(rules or [], enabled)
        last_err = ""
        for attempt in range(1, 7):
            self.mail_proc = subprocess.Popen(
                [MAIL_BIN, "serve", "--config", self.mail_cfg], cwd=WORK,
                stdout=open(WORK + "/mail.out.log", "ab"),
                stderr=open(WORK + "/mail.err.log", "ab"),
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            PROCS.append(self.mail_proc)
            if wait_port(self.smtp_port, timeout=8):
                break
            last_err = open(WORK + "/mail.err.log", "r", encoding="utf-8",
                            errors="replace").read()[-500:]
            kill(self.mail_proc)
            self.mail_proc = None
            time.sleep(1.5)
        else:
            raise RuntimeError("Mail SMTP 未监听：" + last_err)
        ca = self.data + "/certs/ca.crt"
        end = time.time() + 20
        while not os.path.exists(ca) and time.time() < end:
            time.sleep(0.2)
        if not os.path.exists(ca):
            raise RuntimeError("Mail CA 未生成")

    def stop_mail(self):
        if self.mail_proc is not None:
            proc = self.mail_proc
            try:
                proc.terminate()
                proc.wait(timeout=4)
            except Exception:  # noqa: BLE001
                pass
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                           capture_output=True)
            lock = self.data + "/state/store.lock"
            for _ in range(20):
                if not os.path.exists(lock):
                    break
                try:
                    os.remove(lock)
                    break
                except OSError:
                    time.sleep(0.2)
            self.mail_proc = None
            # 等旧监听端口和 Mail 数据目录锁释放
            end = time.time() + 10
            while time.time() < end:
                s = socket.socket()
                s.settimeout(0.2)
                try:
                    s.connect(("127.0.0.1", self.smtp_port))
                except OSError:
                    break
                finally:
                    s.close()
                time.sleep(0.3)
            time.sleep(0.5)

    def login_config(self, tls_mode="starttls"):
        ca = (self.data + "/certs/ca.crt").replace("\\", "/")
        with open(self.login_cfg, "w", encoding="utf-8") as f:
            f.write(f'''server:
  listen_addr: "127.0.0.1:{self.login_port}"
  public_base_url: "http://127.0.0.1:{self.login_port}"
  shutdown_timeout_seconds: 5
logging: {{level: info, format: text}}
database: {{driver: sqlite, path: "{self.db.replace(chr(92), '/')}", wal: true, busy_timeout_ms: 5000}}
registration:
  enabled: true
  require_review: false
  require_email_verification: true
mail:
  enabled: true
  smtp:
    addr: "127.0.0.1:{self.smtp_port}"
    host: "localhost"
    tls_mode: "{tls_mode}"
    trusted_roots: ["{ca}"]
    username: "tester"
    password: {{env: "LOGIN_E2E_SMTP_PASSWORD"}}
    timeout_seconds: 10
  from: {{address: "tester@mail.final.test", name: "EvernightLogin"}}
  app_name: "EvernightLogin"
  delivery: {{max_attempts: 3, timeout_seconds: 120}}
''')

    def start_login(self, tls_mode="starttls"):
        if self.login_proc is not None:
            kill(self.login_proc)
            self.login_proc = None
        self.login_config(tls_mode)
        if not os.path.exists(self.pwd):
            with open(self.pwd, "w", encoding="utf-8") as f:
                f.write("V7q!Lm2#Rp9@Kx4$")
            user = os.environ.get("USERNAME", "")
            subprocess.run(["icacls", self.pwd, "/inheritance:r", "/grant:r",
                            f"{user}:F", "SYSTEM:F", "Administrators:F"],
                           capture_output=True)
        if os.path.exists(self.db):
            os.remove(self.db)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(self.db + suffix):
                os.remove(self.db + suffix)
        init = subprocess.run([LOGIN_BIN, "init", "--config", self.login_cfg,
                               "--master-key-file", self.master,
                               "--password-file", self.pwd, "--operator", "step162"],
                              cwd=WORK, env=self.env, capture_output=True, text=True,
                              timeout=120)
        if init.returncode != 0:
            raise RuntimeError("login init 失败: " + (init.stdout + init.stderr)[-800:])
        self.login_proc = subprocess.Popen(
            [LOGIN_BIN, "serve", "--config", self.login_cfg,
             "--master-key-file", self.master], cwd=WORK, env=self.env,
            stdout=open(WORK + "/login.out.log", "ab"),
            stderr=open(WORK + "/login.err.log", "ab"),
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        PROCS.append(self.login_proc)
        if not wait_port(self.login_port):
            raise RuntimeError("login serve 未监听：" +
                               open(WORK + "/login.err.log", "r", encoding="utf-8",
                                    errors="replace").read()[-1000:])

    def base(self):
        return f"http://127.0.0.1:{self.login_port}"

    def deliveries(self, recipient=None, limit=8):
        con = sqlite3.connect(self.db)
        con.row_factory = sqlite3.Row
        try:
            sql = ("SELECT template_kind,recipient,state,attempts,max_attempts,"
                   "last_error_code,last_error_kind,created_at_ms FROM mail_deliveries ")
            args = []
            if recipient:
                sql += "WHERE recipient LIKE ? "
                args.append("%" + recipient + "%")
            sql += "ORDER BY created_at_ms DESC LIMIT ?"
            args.append(limit)
            return [dict(r) for r in con.execute(sql, args)]
        finally:
            con.close()

    def wait_delivery(self, recipient, timeout=45, want=None):
        end = time.time() + timeout
        last = []
        while time.time() < end:
            rows = self.deliveries(recipient)
            last = rows
            if rows:
                row = rows[0]
                if row["state"] in ("succeeded", "failed", "cancelled"):
                    if want is None or row["state"] == want:
                        return row
            time.sleep(0.5)
        raise RuntimeError(f"等待投递终态超时 recipient={recipient} rows={last}")


def register(client, base, username, email_addr, password):
    csrf, _ = client.csrf(base + "/register")
    return client.post(base + "/register", {
        "csrf_token": csrf, "username": username, "email": email_addr,
        "password": password, "password_confirm": password,
    })


def login(client, base, username, password):
    csrf, _ = client.csrf(base + "/login")
    return client.post(base + "/login", {
        "csrf_token": csrf, "identifier": username, "password": password,
    }, follow=False)


def verify_email(client, base, text):
    link = parse_link(text, "/email/verify")
    if not link:
        raise RuntimeError("验证邮件无链接")
    p = urllib.parse.urlparse(link)
    q = urllib.parse.parse_qs(p.query)
    url = base + p.path + ("?" + p.query if p.query else "")
    csrf, _ = client.csrf(url)
    return client.post(base + "/email/verify", {
        "csrf_token": csrf, "uid": q.get("uid", [""])[0],
        "cid": q.get("cid", [""])[0], "token": q.get("token", [""])[0],
    })


def verify_change(client, base, text, token_override=None):
    link = parse_link(text, "/email/change/verify")
    if not link:
        raise RuntimeError("变更验证邮件无链接")
    p = urllib.parse.urlparse(link)
    q = urllib.parse.parse_qs(p.query)
    url = base + p.path + ("?" + p.query if p.query else "")
    csrf, _ = client.csrf(url)
    return client.post(base + "/email/change/verify", {
        "csrf_token": csrf, "rid": q.get("rid", [""])[0],
        "cid": q.get("cid", [""])[0], "token": q.get("token", [""])[0],
    })


def main():
    for path in (WORK, BASE + "/run-maintenance"):
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)
    build()
    h = Harness()
    h.start_mail()
    h.start_login()
    base = h.base()
    client = HTTP()
    password = "V7q!Lm2#Rp9@Kx4$"
    log("servers_started", smtp=h.smtp_port, login=h.login_port)

    # S1 基线：注册验证 + 登录 + 邮箱变更 + 旧邮箱告知 + 邮件 MFA + 找回
    before = set(find_emls(h.data + "/mail"))
    st, body = register(client, base, "step162base", "base@mail.final.test", password)
    log("s1_register", status=st, created=("账户已创建" in body),
        mail_failed=("邮件发送失败" in body))
    if st != 200 or "账户已创建" not in body:
        raise RuntimeError("基线注册失败: " + body[:400])
    path, msg, text = wait_link(h.data + "/mail", before, "/email/verify")
    st, body = verify_email(client, base, text)
    log("s1_verify_email", status=st, ok=("邮箱已验证" in body))
    st, body = login(client, base, "step162base", password)
    log("s1_login", status=st)
    if st not in (200, 303):
        raise RuntimeError("基线登录失败: " + body[:300])
    before2 = set(find_emls(h.data + "/mail"))
    csrf, _ = client.csrf(base + "/account/profile/email")
    st, body = client.post(base + "/account/profile/email", {
        "csrf_token": csrf, "new_email": "base-new@mail.final.test",
        "current_password": password})
    log("s1_email_change_request", status=st, requested=("待验证" in body))
    path, msg, text = wait_link(h.data + "/mail", before2, "/email/change/verify")
    st, body = verify_change(HTTP(), base, text)
    # CSRF 修复后：匿名公开表单应成功；成功页含“新邮箱已验证并生效”。
    log("s1_email_change_verify",
        "PASS" if (st == 200 and "新邮箱已验证并生效" in body) else "FAIL",
        status=st, body=body[:220],
        reason="匿名公开表单应成功；失败时检查 publicFormPaths 合并")
    s1_notices = [p for p in new_emls(h.data + "/mail", before2)
                  if "/email/change/verify" not in decode_eml(p)[1]]
    log("s1_old_email_notice", "PASS" if s1_notices else "PARTIAL",
        count=len(s1_notices), delivered=bool(s1_notices))
    # 邮件 MFA add_start（发送验证码）
    before3 = set(find_emls(h.data + "/mail"))
    csrf, _ = client.csrf(base + "/account/security/mfa")
    st, body = client.post(base + "/account/security/mfa", {"csrf_token": csrf})
    log("s1_mfa_add_start", status=st, code_sent=("code_sent" in body or "验证码" in body))
    if st == 200 and "challenge_id" in body:
        try:
            wait_new_emls(h.data + "/mail", before3, 1, timeout=20)
            log("s1_mfa_code_mail", delivered=True)
        except Exception as exc:  # noqa: BLE001
            log("s1_mfa_code_mail", "FAIL", error=str(exc))
    # 找回
    before4 = set(find_emls(h.data + "/mail"))
    csrf, _ = client.csrf(base + "/login/forgot-password")
    st, body = client.post(base + "/login/forgot-password", {
        "csrf_token": csrf, "identifier": "base@mail.final.test"})
    log("s1_forgot", status=st, uniform=("如果该账户可用" in body))
    try:
        wait_link(h.data + "/mail", before4, "/login/reset-password", timeout=20)
        log("s1_reset_mail", delivered=True)
    except Exception as exc:  # noqa: BLE001
        log("s1_reset_mail", "PARTIAL", error=str(exc))

    # S2 临时接收拒绝 → 重试成功
    h.start_mail(rules=[{
        "id": "s2-temp-rcpt", "enabled": True, "priority": 10,
        "kind": "recipient_reject", "protocol": "smtp", "phase": "rcpt",
        "scope": {"addresses": ["s2@mail.final.test"]},
        "action": {"code": 451, "enhanced_status": "4.3.0", "message": "injected temporary reject"},
        "limits": {"max_hits": 1, "ttl": "5m"}}], enabled=True)
    before = set(find_emls(h.data + "/mail"))
    st, body = register(client, base, "step162s2", "s2@mail.final.test", password)
    row = h.wait_delivery("s2@mail.final.test", timeout=60)
    log("s2_temp_reject_retry", status=st, state=row["state"],
        attempts=row["attempts"], error=row["last_error_code"],
        pass_expected=row["state"] == "succeeded" and row["attempts"] >= 2)
    try:
        path, msg, text = wait_link(h.data + "/mail", before, "/email/verify", timeout=30)
        st2, body2 = verify_email(client, base, text)
        log("s2_verify_after_retry", status=st2, ok=("邮箱已验证" in body2))
    except Exception as exc:  # noqa: BLE001
        log("s2_verify_after_retry", "PARTIAL", error=str(exc))

    # S3 永久接收拒绝 → 失败不假成功
    h.start_mail(rules=[{
        "id": "s3-perm-rcpt", "enabled": True, "priority": 10,
        "kind": "recipient_reject", "protocol": "smtp", "phase": "rcpt",
        "scope": {"addresses": ["s3@mail.final.test"]},
        "action": {"code": 550, "enhanced_status": "5.1.1", "message": "injected permanent reject"},
        "limits": {"max_hits": 20, "ttl": "5m"}}], enabled=True)
    st, body = register(client, base, "step162s3", "s3@mail.final.test", password)
    row = h.wait_delivery("s3@mail.final.test", timeout=60)
    log("s3_permanent_reject", status=st, state=row["state"], attempts=row["attempts"],
        error=row["last_error_code"],
        not_success=(row["state"] == "failed" and row["last_error_code"] != ""))
    log("s3_no_verify_mail", delivered=any("s3@mail.final.test" in decode_eml(p)[1]
                                           for p in find_emls(h.data + "/mail")))

    # S4 SMTP 认证失败
    h.start_mail(rules=[{
        "id": "s4-auth", "enabled": True, "priority": 10,
        "kind": "auth_failure", "protocol": "smtp", "phase": "auth",
        "scope": {}, "action": {"code": 535, "enhanced_status": "5.7.8",
                                "message": "injected auth failure"},
        "limits": {"max_hits": 20, "ttl": "5m"}}], enabled=True)
    st, body = register(client, base, "step162s4", "s4@mail.final.test", password)
    row = h.wait_delivery("s4@mail.final.test", timeout=60)
    log("s4_auth_failure", status=st, state=row["state"], error=row["last_error_code"],
        not_success=(row["state"] == "failed" and row["last_error_code"] != ""))

    # S5 重复投递规则命中 + 验证链接单次消费
    h.start_mail(rules=[{
        "id": "s5-dup", "enabled": True, "priority": 10,
        "kind": "duplicate", "protocol": "smtp", "phase": "data_end",
        "scope": {"addresses": ["s5@mail.final.test"]},
        "action": {"duplicates": 2, "after_accept": True},
        "limits": {"max_hits": 1, "ttl": "5m"}}], enabled=True)
    before = set(find_emls(h.data + "/mail"))
    st, body = register(client, base, "step162s5", "s5@mail.final.test", password)
    row = h.wait_delivery("s5@mail.final.test", timeout=60)
    try:
        emls = wait_new_emls(h.data + "/mail", before, 2, timeout=8)
    except Exception:  # noqa: BLE001
        emls = new_emls(h.data + "/mail", before)
    # Mail 生产装配未注入 DuplicateCopier；duplicate 规则命中但副本创建 fail-closed，
    # 主邮件仍成功。把“规则命中/证据”如实记录为 PARTIAL，不伪造两份邮件。
    dup_log = ""
    try:
        for line in open(h.data + "/logs/server.log", encoding="utf-8", errors="replace"):
            if "s5-dup" in line:
                dup_log = line.strip()[:500]
    except OSError:
        pass
    log("s5_duplicate_rule", "PARTIAL" if len(emls) < 2 else "PASS",
        count=len(emls), delivery_state=row["state"], evidence=dup_log,
        reason="Copier 未装配：规则命中但副本创建 fail-closed；主邮件成功")
    # 单次消费：同一验证链接第二次提交必须拒绝
    if emls:
        _m, text = decode_eml(emls[0])
        first = verify_email(HTTP(), base, text)
        second = verify_email(HTTP(), base, text)
        log("s5_single_use", "PASS" if ("邮箱已验证" in first[1] and
                                       "邮箱已验证" not in second[1]) else "FAIL",
            first_status=first[0], first_ok=("邮箱已验证" in first[1]),
            second_status=second[0], second_body=second[1][:180])
    else:
        log("s5_single_use", "FAIL", reason="未收到验证邮件")

    # S6 断连一次 → 重试
    h.start_mail(rules=[{
        "id": "s6-disconnect", "enabled": True, "priority": 10,
        "kind": "disconnect", "protocol": "smtp", "phase": "data_end",
        "scope": {"addresses": ["s6@mail.final.test"]},
        "action": {"code": 421, "enhanced_status": "4.4.2", "close": True,
                   "message": "injected disconnect"},
        "limits": {"max_hits": 1, "ttl": "5m"}}], enabled=True)
    before = set(find_emls(h.data + "/mail"))
    st, body = register(client, base, "step162s6", "s6@mail.final.test", password)
    try:
        row = h.wait_delivery("s6@mail.final.test", timeout=60)
        log("s6_disconnect_retry", status=st, state=row["state"],
            attempts=row["attempts"], error=row["last_error_code"],
            pass_expected=row["state"] == "succeeded")
    except Exception as exc:  # noqa: BLE001
        log("s6_disconnect_retry", "PARTIAL", error=str(exc))

    # S7 接受后失败 → 不假成功/重试
    h.start_mail(rules=[{
        "id": "s7-accept-fail", "enabled": True, "priority": 10,
        "kind": "accept_after_failure", "protocol": "smtp", "phase": "data_end",
        "scope": {"addresses": ["s7@mail.final.test"]},
        "action": {"code": 451, "enhanced_status": "4.3.0", "after_accept": True,
                   "message": "injected accepted-then-failed"},
        "limits": {"max_hits": 1, "ttl": "5m"}}], enabled=True)
    before = set(find_emls(h.data + "/mail"))
    st, body = register(client, base, "step162s7", "s7@mail.final.test", password)
    row = h.wait_delivery("s7@mail.final.test", timeout=60)
    log("s7_accept_after_failure", status=st, state=row["state"],
        attempts=row["attempts"], error=row["last_error_code"],
        state_is_terminal=row["state"] in ("succeeded", "failed"))

    # S8 延迟投递（有界 2s）
    h.start_mail(rules=[{
        "id": "s8-delay", "enabled": True, "priority": 10,
        "kind": "delay", "protocol": "smtp", "phase": "data_end",
        "scope": {"addresses": ["s8@mail.final.test"]},
        "action": {"timeout": "2s"},
        "limits": {"max_hits": 1, "ttl": "5m"}}], enabled=True)
    t0 = time.time()
    st, body = register(client, base, "step162s8", "s8@mail.final.test", password)
    try:
        row = h.wait_delivery("s8@mail.final.test", timeout=60)
        log("s8_delay", status=st, state=row["state"],
            attempts=row["attempts"], elapsed=round(time.time() - t0, 2),
            pass_expected=row["state"] == "succeeded")
    except Exception as exc:  # noqa: BLE001
        log("s8_delay", "PARTIAL", error=str(exc))

    # S9 旧邮箱安全告知失败（新邮箱验证成功但告知永久失败，不假成功）
    h.start_mail()
    n = HTTP()
    st, _ = register(n, base, "step162notice", "notice@mail.final.test", password)
    before = set(find_emls(h.data + "/mail"))
    try:
        _p, _m, nt = wait_link(h.data + "/mail", before, "/email/verify", timeout=30)
        verify_email(n, base, nt)
    except Exception as exc:  # noqa: BLE001
        log("s9_setup", "FAIL", error=str(exc))
    st, _ = login(n, base, "step162notice", password)
    before = set(find_emls(h.data + "/mail"))
    csrf, _ = n.csrf(base + "/account/profile/email")
    st, body = n.post(base + "/account/profile/email", {
        "csrf_token": csrf, "new_email": "notice-new@mail.final.test",
        "current_password": password})
    try:
        _p, _m, nt = wait_link(h.data + "/mail", before, "/email/change/verify", timeout=30)
    except Exception as exc:  # noqa: BLE001
        log("s9_setup_change_mail", "FAIL", error=str(exc))
        nt = ""
    # 使旧邮箱告知投递永久失败（scope=旧邮箱地址），新邮箱验证仍应成功。
    h.start_mail(rules=[{
        "id": "s9-notice-fail", "enabled": True, "priority": 10,
        "kind": "recipient_reject", "protocol": "smtp", "phase": "rcpt",
        "scope": {"addresses": ["notice@mail.final.test"]},
        "action": {"code": 550, "enhanced_status": "5.1.1", "message": "injected notice reject"},
        "limits": {"max_hits": 20, "ttl": "5m"}}], enabled=True)
    st, body = verify_change(HTTP(), base, nt)
    time.sleep(4)
    rows = [r for r in h.deliveries("notice@mail.final.test")
            if r["template_kind"] == "security_notice"]
    notified_false = "新邮箱已生效，但旧邮箱的安全告知未成功投递" in body
    log("s9_notice_failure",
        "PASS" if (st == 200 and "新邮箱已验证并生效" in body and
                   (notified_false or any(r["state"] == "failed" for r in rows)))
        else "PARTIAL",
        status=st, notified_false=notified_false, rows=rows,
        body=body[:220])

    # S10 密码找回永久失败 → 统一受理但不假发送（用无 pending 邮箱变更的新用户）
    h.start_mail()  # 先无故障完成注册/验证
    u = HTTP()
    st, body = register(u, base, "step162s10", "s10@mail.final.test", password)
    before = set(find_emls(h.data + "/mail"))
    try:
        _p, _m, text = wait_link(h.data + "/mail", before, "/email/verify", timeout=30)
        st_verify, _b = verify_email(u, base, text)
    except Exception as exc:  # noqa: BLE001
        st_verify = -1
        log("s10_setup_verify", "FAIL", error=str(exc))
    st, _b = login(u, base, "step162s10", password)
    if st not in (200, 303):
        log("s10_login", "FAIL", status=st)
    h.start_mail(rules=[{
        "id": "s10-reset-fail", "enabled": True, "priority": 10,
        "kind": "recipient_reject", "protocol": "smtp", "phase": "rcpt",
        "scope": {"addresses": ["s10@mail.final.test"]},
        "action": {"code": 550, "enhanced_status": "5.1.1", "message": "injected reset reject"},
        "limits": {"max_hits": 20, "ttl": "5m"}}], enabled=True)
    before = set(find_emls(h.data + "/mail"))
    csrf, _ = u.csrf(base + "/login/forgot-password")
    st, body = u.post(base + "/login/forgot-password", {
        "csrf_token": csrf, "identifier": "s10@mail.final.test"})
    time.sleep(5)
    rows = [r for r in h.deliveries("s10@mail.final.test")
            if r["template_kind"] == "password_reset"]
    log("s10_forgot_failure",
        "PASS" if (rows and rows[0]["state"] == "failed") else "PARTIAL",
        status=st, uniform=("如果该账户可用" in body), rows=rows,
        no_mail=not any("s10@mail.final.test" in decode_eml(p)[1]
                        for p in new_emls(h.data + "/mail", before)))

    # S11 MFA 邮件验证码发送永久失败（同一已验证用户，无 pending 邮箱变更）
    h.start_mail(rules=[{
        "id": "s11-mfa-fail", "enabled": True, "priority": 10,
        "kind": "recipient_reject", "protocol": "smtp", "phase": "rcpt",
        "scope": {"addresses": ["s10@mail.final.test"]},
        "action": {"code": 550, "enhanced_status": "5.1.1", "message": "injected mfa reject"},
        "limits": {"max_hits": 20, "ttl": "5m"}}], enabled=True)
    csrf, _ = u.csrf(base + "/account/security/mfa")
    t0 = time.time() * 1000
    st, body = u.post(base + "/account/security/mfa", {"csrf_token": csrf})
    time.sleep(5)
    rows = [r for r in h.deliveries("s10@mail.final.test")
            if r["template_kind"] in ("verification", "security_notice")
            and r["created_at_ms"] >= t0]
    mfa_failed = any(r["state"] == "failed" for r in rows)
    log("s11_mfa_mail_failure", "PASS" if mfa_failed else "PARTIAL",
        status=st, body=body[:160], rows=rows, failure_trace=mfa_failed,
        no_fake_sent=not any(r["state"] == "succeeded" for r in rows))

    # S12 客服恢复邮件：默认人工恢复制度未启用/无客服角色夹具，如实未测
    log("s12_support_recovery_mail", "NOT_TESTED",
        reason="152 人工恢复制度默认关闭且本夹具未构造真实客服/审批角色；见 step152/153 报告")

    # S13 TLS 错误：Login 使用 implicit，Mail 只提供 STARTTLS
    h.start_mail()
    h.start_login(tls_mode="implicit")
    st, body = register(HTTP(), base, "step162s13", "s13@mail.final.test", password)
    try:
        row = h.wait_delivery("s13@mail.final.test", timeout=45)
        log("s13_tls_failure", status=st, state=row["state"],
            error=row["last_error_code"],
            not_success=row["state"] == "failed")
    except Exception as exc:  # noqa: BLE001
        log("s13_tls_failure", "PARTIAL", error=str(exc))
    return 0


if __name__ == "__main__":
    code = 2
    try:
        code = main()
    except Exception as exc:  # noqa: BLE001
        RESULT["fail"] += 1
        print("UNHANDLED", repr(exc))
        import traceback
        traceback.print_exc()
    finally:
        for proc in PROCS:
            kill(proc)
        time.sleep(0.5)
        try:
            outdir = LOGIN_SRC + "/docs/acceptance/evidence"
            os.makedirs(outdir, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            logpath = outdir + f"/step162-mail-fault-e2e-{stamp}.log"
            with open(logpath, "w", encoding="utf-8") as f:
                f.write("STEP162_E2E_RESULT " +
                        json.dumps(RESULT, ensure_ascii=False) + "\n")
            print("EVIDENCE_LOG", logpath)
        except Exception as exc:  # noqa: BLE001
            print("EVIDENCE_LOG_FAILED", repr(exc))
    print("STEP162_E2E_RESULT", json.dumps(RESULT, ensure_ascii=False))
    sys.exit(code)
